import os
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
PROJECT_DIR = BACKEND_DIR.parent

STORAGE_DIR = PROJECT_DIR / "storage"
UPLOADS_DIR = STORAGE_DIR / "uploads"
SAMPLES_DIR = STORAGE_DIR / "samples"

MAX_FILE_SIZE_BYTES = int(
    os.getenv("MAX_FILE_SIZE_BYTES", str(10 * 1024 * 1024))
)
MAX_FILES_PER_SCAN = int(os.getenv("MAX_FILES_PER_SCAN", "100"))
MAX_SCAN_SIZE_BYTES = int(
    os.getenv("MAX_SCAN_SIZE_BYTES", str(100 * 1024 * 1024))
)

ALLOWED_EXTENSIONS = frozenset({".txt", ".docx"})

MODEL_NAME = os.getenv("MODEL_NAME", "")
MODEL_ENDPOINT = os.getenv("MODEL_ENDPOINT", "")
MODEL_PATH = os.getenv("MODEL_PATH", "")