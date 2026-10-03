from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from ..config import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    UPLOADS_DIR,
)
def validate_file(filename: str, size_bytes: int) -> str:
    if not filename or not filename.strip():
        raise ValueError("Filename is required.")

    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .txt and .docx files are supported.")

    if size_bytes <= 0:
        raise ValueError("Empty files are not supported.")

    if size_bytes > MAX_FILE_SIZE_BYTES:
        raise ValueError("File exceeds the upload size limit.")

    return extension

def calculate_sha256(content: bytes) -> str:
    return sha256(content).hexdigest()

def save_uploaded_file(
    filename: str,
    content: bytes,
    scan_id: str,
) -> dict:
    if not scan_id or not scan_id.isalnum():
        raise ValueError("Invalid scan ID.")

    extension = validate_file(filename, len(content))

    original_filename = Path(filename).name
    stored_name = f"{uuid4().hex}{extension}"

    scan_dir = UPLOADS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    stored_path = scan_dir / stored_name
    stored_path.write_bytes(content)

    return {
        "scan_id": scan_id,
        "original_filename": original_filename,
        "stored_name": stored_name,
        "size_bytes": len(content),
        "sha256": calculate_sha256(content),
    }