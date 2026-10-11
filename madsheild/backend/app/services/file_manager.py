"""Quarantined uploads and report persistence. Uploaded files are never executed."""

import json
import re
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from ..config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES, UPLOADS_DIR


def validate_file(filename: str, size_bytes: int) -> str:
    if not filename or not filename.strip() or "\x00" in filename:
        raise ValueError("A valid filename is required.")
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .txt and .docx files are supported.")
    if size_bytes <= 0:
        raise ValueError("Empty files are not supported.")
    if size_bytes > MAX_FILE_SIZE_BYTES:
        raise ValueError("The file exceeds the upload size limit.")
    return extension


def calculate_sha256(content: bytes) -> str:
    return sha256(content).hexdigest()


def scan_directory(scan_id: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", scan_id):
        raise ValueError("Invalid scan ID.")
    return UPLOADS_DIR / scan_id


def save_uploaded_file(filename: str, content: bytes, scan_id: str) -> dict:
    extension = validate_file(filename, len(content))
    directory = scan_directory(scan_id)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    stored_name = f"{uuid4().hex}{extension}"
    with (directory / stored_name).open("xb") as output:
        output.write(content)
    (directory / stored_name).chmod(0o600)
    return {
        "filename": filename.replace("\\", "/").rsplit("/", 1)[-1],
        "stored_name": stored_name,
        "size_bytes": len(content),
        "sha256": calculate_sha256(content),
    }


def save_report(report: dict) -> None:
    directory = scan_directory(report["scan_id"])
    temporary = directory / f"{uuid4().hex}.tmp"
    try:
        with temporary.open("x", encoding="utf-8") as output:
            json.dump(report, output, ensure_ascii=False, allow_nan=False)
        temporary.chmod(0o600)
        temporary.replace(directory / "report.json")
    finally:
        temporary.unlink(missing_ok=True)


def load_report(scan_id: str) -> dict:
    with (scan_directory(scan_id) / "report.json").open(encoding="utf-8") as source:
        return json.load(source)
