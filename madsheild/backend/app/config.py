"""Configuration shared by HTTP routes, storage and analysis."""

import os
from pathlib import Path


def positive_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value < 1:
        raise ValueError(f"{name} must be positive.")
    return value


BACKEND_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BACKEND_DIR.parent / "fontend"
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", str(BACKEND_DIR / "storage"))).resolve()
UPLOADS_DIR = STORAGE_DIR / "uploads"
ALLOWED_EXTENSIONS = frozenset({".txt", ".log", ".csv", ".json", ".md", ".doc", ".docx", ".pdf", ".zip", ".exe", ".dll"})
MAX_FILE_SIZE_BYTES = positive_int("MAX_FILE_SIZE_BYTES", 10 * 1024 * 1024)
MAX_BATCH_FILES = positive_int("MAX_BATCH_FILES", 100)
MAX_BATCH_SIZE_BYTES = positive_int("MAX_BATCH_SIZE_BYTES", 100 * 1024 * 1024)
MAX_TEXT_CHARACTERS = positive_int("MAX_TEXT_CHARACTERS", 2_000_000)
MAX_TEXT_SEGMENTS = positive_int("MAX_TEXT_SEGMENTS", 20_000)
MAX_DOCX_EXPANDED_BYTES = positive_int("MAX_DOCX_EXPANDED_BYTES", 50 * 1024 * 1024)
MAX_PDF_PAGES = positive_int("MAX_PDF_PAGES", 500)
MAX_ARCHIVE_MEMBERS = positive_int("MAX_ARCHIVE_MEMBERS", 2048)
MAX_ARCHIVE_EXPANDED_BYTES = positive_int("MAX_ARCHIVE_EXPANDED_BYTES", 50 * 1024 * 1024)
MAX_ARCHIVE_DEPTH = positive_int("MAX_ARCHIVE_DEPTH", 2)
MAX_CONCURRENT_SCANS = positive_int("MAX_CONCURRENT_SCANS", 2)
ANALYSIS_CACHE_SIZE = positive_int("ANALYSIS_CACHE_SIZE", 64)
ANALYSIS_CACHE_TTL_SECONDS = positive_int("ANALYSIS_CACHE_TTL_SECONDS", 300)
MODEL_PATH = os.getenv("MODEL_PATH", "")
MODEL_ENDPOINT = os.getenv("MODEL_ENDPOINT", "")
MODEL_NAME = os.getenv("MODEL_NAME", "")
MODEL_API_KEY = os.getenv("MODEL_API_KEY", "")
MODEL_TIMEOUT_SECONDS = positive_int("MODEL_TIMEOUT_SECONDS", 30)
MODEL_MAX_SEGMENTS = positive_int("MODEL_MAX_SEGMENTS", 64)
MODEL_MAX_TEXT_CHARACTERS = positive_int("MODEL_MAX_TEXT_CHARACTERS", 64_000)
MODEL_THRESHOLD = float(os.getenv("MODEL_THRESHOLD", "0.8"))
if not 0 < MODEL_THRESHOLD <= 1:
    raise ValueError("MODEL_THRESHOLD must be between 0 (exclusive) and 1.")
