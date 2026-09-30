from hashlib import sha256
from pathlib import Path

from ..config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES


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