"""The existing frontend's single-file scan API."""
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool
from ... import config
from ...services.file_manager import validate_file
from ...workers import tasks
from ..dependencies import reserve_scan_slot

router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post("/scans", dependencies=[Depends(reserve_scan_slot)])
async def scan_file(file: UploadFile = File(...)):
    try:
        try:
            validate_file(file.filename or "", 1)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        content = bytearray()
        while chunk := await file.read(64 * 1024):
            content.extend(chunk)
            if len(content) > config.MAX_FILE_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="The file exceeds the configured upload limit.")
        if not content:
            raise HTTPException(status_code=400, detail="Empty files are not supported.")
        try:
            return await run_in_threadpool(tasks.extract_and_analyze_task, file.filename, bytes(content), file.content_type)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except OSError as exc:
            raise HTTPException(status_code=500, detail="The scan report could not be saved.") from exc
    finally:
        await file.close()


async def read_upload(file: UploadFile) -> bytes:
    content = bytearray()
    while chunk := await file.read(64 * 1024):
        content.extend(chunk)
        if len(content) > config.MAX_FILE_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=f"{file.filename}: file exceeds the configured upload limit.")
    if not content:
        raise HTTPException(status_code=400, detail=f"{file.filename}: empty files are not supported.")
    return bytes(content)


@router.post("/scans/batch", dependencies=[Depends(reserve_scan_slot)])
async def scan_batch(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="At least one file is required.")
    if len(files) > config.MAX_BATCH_FILES:
        raise HTTPException(status_code=413, detail=f"A batch can contain at most {config.MAX_BATCH_FILES} files.")
    uploads = []
    total_size = 0
    try:
        for file in files:
            try:
                validate_file(file.filename or "", 1)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"{file.filename}: {exc}") from exc
            content = await read_upload(file)
            total_size += len(content)
            if total_size > config.MAX_BATCH_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="The batch exceeds the configured total upload limit.")
            uploads.append((file.filename or "", content, file.content_type))

        reports = []
        errors = []
        for filename, content, content_type in uploads:
            try:
                report = await run_in_threadpool(tasks.extract_and_analyze_task, filename, content, content_type)
                reports.append(report)
            except (ValueError, OSError) as exc:
                errors.append({"relative_path": filename.replace("\\", "/"), "error": str(exc)})
        suspicious = sum(report["verdict"] == "suspicious" for report in reports)
        review_required = sum(report["verdict"] == "review_required" for report in reports)
        return {"status": "completed" if not errors else "completed_with_errors",
                "total_files": len(files), "completed_files": len(reports), "failed_files": len(errors),
                "suspicious_files": suspicious, "review_required_files": review_required,
                "no_indicators_files": len(reports) - suspicious - review_required,
                "total_size_bytes": total_size, "reports": reports, "errors": errors}
    finally:
        for file in files:
            await file.close()


@router.get("/capabilities")
def capabilities():
    return {"supported_extensions": sorted(config.ALLOWED_EXTENSIONS), "max_file_size_bytes": config.MAX_FILE_SIZE_BYTES,
            "max_batch_files": config.MAX_BATCH_FILES, "max_batch_size_bytes": config.MAX_BATCH_SIZE_BYTES,
            "max_concurrent_scans": config.MAX_CONCURRENT_SCANS, "model_mode": tasks.engine.classifier.configured_mode(),
            "analysis_type": "static_rules_and_optional_model_inference"}
