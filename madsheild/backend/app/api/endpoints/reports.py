"""Retrieve a persisted scan by its identifier."""
from fastapi import APIRouter, HTTPException
from ...services.file_manager import load_report

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("/{scan_id}")
def get_report(scan_id: str):
    try:
        return load_report(scan_id)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Scan report not found.") from exc
