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


@router.get("/capabilities")
def capabilities():
    return {"supported_extensions": sorted(config.ALLOWED_EXTENSIONS), "max_file_size_bytes": config.MAX_FILE_SIZE_BYTES,
            "max_concurrent_scans": config.MAX_CONCURRENT_SCANS, "model_mode": tasks.engine.classifier.configured_mode(),
            "analysis_type": "static_rules_and_optional_model_inference"}
