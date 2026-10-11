"""Limit simultaneous scans so expensive analysis cannot grow without a bound."""
from threading import BoundedSemaphore
from fastapi import HTTPException
from ..config import MAX_CONCURRENT_SCANS

scan_slots = BoundedSemaphore(MAX_CONCURRENT_SCANS)


def reserve_scan_slot():
    if not scan_slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="All scan workers are busy. Please try again shortly.", headers={"Retry-After": "2"})
    try:
        yield
    finally:
        scan_slots.release()
