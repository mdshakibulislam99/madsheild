from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile

from ...config import MAX_FILES_PER_SCAN, MAX_SCAN_SIZE_BYTES
from ...services.file_manager import save_uploaded_file, validate_file


router = APIRouter(
    prefix="/api/v1/scans",
    tags=["uploads"],
)


@router.post("")
async def upload_scan(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(
            status_code=400,
            detail="At least one file is required.",
        )

    if len(files) > MAX_FILES_PER_SCAN:
        raise HTTPException(
            status_code=400,
            detail=f"Too many files. Maximum is {MAX_FILES_PER_SCAN}.",
        )

    uploaded_contents = []
    total_size = 0

    for file in files:
        filename = file.filename or ""
        content = await file.read()
        file_size = len(content)

        try:
            validate_file(filename, file_size)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        total_size += file_size

        if total_size > MAX_SCAN_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="The total scan size is too large.",
            )

        uploaded_contents.append((filename, content))

    scan_id = uuid4().hex

    saved_files = [
        save_uploaded_file(filename, content, scan_id)
        for filename, content in uploaded_contents
    ]

    return {
        "scan_id": scan_id,
        "status": "uploaded",
        "file_count": len(saved_files),
        "total_size_bytes": total_size,
        "files": saved_files,
    }