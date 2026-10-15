"""Retrieve a persisted scan by its identifier."""
from fastapi import APIRouter, HTTPException, Query
from ...services.file_manager import load_report, list_reports

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("")
def history(offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    return list_reports(offset, limit)


@router.get("/{scan_id}")
def get_report(scan_id: str):
    try:
        return load_report(scan_id)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Scan report not found.") from exc
