"""Bounded text extraction with source locations and reusable numeric features."""

import math
import re
from collections import Counter
from io import BytesIO
from zipfile import BadZipFile, ZipFile

from docx import Document
from docx.table import Table
from docx.text.paragraph import Paragraph

from ..config import MAX_DOCX_EXPANDED_BYTES, MAX_TEXT_CHARACTERS, MAX_TEXT_SEGMENTS


FEATURE_NAMES = (
    "byte_entropy", "text_length", "segment_count", "url_count", "powershell_count",
    "encoded_command_count", "dynamic_execution_count", "download_count",
    "shadow_delete_count", "macro_present", "embedded_object_count",
)
FEATURE_PATTERNS = {
    "url_count": re.compile(r"https?://", re.I),
    "powershell_count": re.compile(r"\b(?:powershell|pwsh)\b", re.I),
    "encoded_command_count": re.compile(r"-(?:enc|encodedcommand)\b", re.I),
    "dynamic_execution_count": re.compile(r"\b(?:eval|exec)\s*\(|\b(?:iex|invoke-expression)\b", re.I),
    "download_count": re.compile(r"\b(?:curl|wget|downloadstring|downloadfile|invoke-webrequest)\b", re.I),
    "shadow_delete_count": re.compile(r"\b(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)\b", re.I),
}


def extract_txt_lines(content: bytes) -> list[dict]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("TXT files must use UTF-8 encoding.") from exc
    if "\x00" in text:
        raise ValueError("The TXT file contains binary data.")
    if len(text) > MAX_TEXT_CHARACTERS:
        raise ValueError("The extracted text exceeds the analysis limit.")
    lines = text.splitlines()
    if len(lines) > MAX_TEXT_SEGMENTS:
        raise ValueError("The file contains too many lines.")
    return [{"line_number": number, "text": line} for number, line in enumerate(lines, 1)]


def inspect_docx(content: bytes) -> dict:
    """Check expansion limits before the document parser reads XML."""
    try:
        with ZipFile(BytesIO(content)) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if len(members) > 2048 or len(names) != len(set(names)):
                raise ValueError("The DOCX archive has too many or duplicate entries.")
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise ValueError("This file is not a valid DOCX document.")
            if sum(member.file_size for member in members) > MAX_DOCX_EXPANDED_BYTES:
                raise ValueError("The expanded DOCX exceeds the analysis limit.")
            for member in members:
                if member.flag_bits & 1:
                    raise ValueError("Encrypted DOCX files are not supported.")
                if member.file_size > 10 * 1024 * 1024:
                    raise ValueError("A DOCX archive entry exceeds the analysis limit.")
                if member.file_size > 1024 * 1024 and member.file_size > max(1, member.compress_size) * 1000:
                    raise ValueError("The DOCX archive has an excessive compression ratio.")
                if member.filename.endswith((".xml", ".rels")):
                    xml = archive.read(member)
                    if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
                        raise ValueError("DOCX files with XML entity declarations are not supported.")
            return {
                "macro_present": int(any(name.lower().endswith("vbaproject.bin") for name in names)),
                "embedded_object_count": sum(name.startswith("word/embeddings/") and not name.endswith("/") for name in names),
            }
    except (BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
        raise ValueError("This file is not a readable DOCX document.") from exc


def extract_docx_paragraphs(content: bytes, *, inspected: bool = False) -> list[dict]:
    if not inspected:
        inspect_docx(content)
    try:
        document = Document(BytesIO(content))
    except Exception as exc:
        raise ValueError("This file is not a readable DOCX document.") from exc
    segments = []
    characters = 0

    def append(text: str, location: dict) -> None:
        nonlocal characters
        characters += len(text)
        if characters > MAX_TEXT_CHARACTERS or len(segments) >= MAX_TEXT_SEGMENTS:
            raise ValueError("The extracted DOCX text exceeds the analysis limit.")
        segments.append({**location, "text": text})

    def walk(container, prefix: dict, depth: int = 0) -> None:
        if depth > 10:
            raise ValueError("DOCX tables are nested too deeply.")
        paragraph_number = table_number = 0
        for block in container.iter_inner_content():
            if isinstance(block, Paragraph):
                paragraph_number += 1
                append(block.text, {**prefix, "paragraph_number": paragraph_number})
            elif isinstance(block, Table):
                table_number += 1
                seen = set()
                for row_number, row in enumerate(block.rows, 1):
                    for cell_number, cell in enumerate(row.cells, 1):
                        if cell._tc in seen:
                            continue
                        seen.add(cell._tc)
                        walk(cell, {**prefix, "table_path": [*prefix.get("table_path", []), table_number],
                                    "table_location": [*prefix.get("table_location", []),
                                                       {"table_number": table_number, "row_number": row_number,
                                                        "cell_number": cell_number}],
                                    "row_number": row_number, "cell_number": cell_number}, depth + 1)

    walk(document, {})
    return segments


def extract_features(content: bytes, extension: str) -> dict:
    archive_features = {"macro_present": 0, "embedded_object_count": 0}
    if extension == ".txt":
        segments = extract_txt_lines(content)
    elif extension == ".docx":
        archive_features = inspect_docx(content)
        segments = extract_docx_paragraphs(content, inspected=True)
    else:
        raise ValueError("Unsupported file type.")
    counts = Counter(content)
    entropy = -sum((count / len(content)) * math.log2(count / len(content)) for count in counts.values()) if content else 0.0
    text = "\n".join(segment["text"] for segment in segments)
    features = {
        "byte_entropy": entropy, "text_length": len(text), "segment_count": len(segments),
        **{name: sum(1 for _ in pattern.finditer(text)) for name, pattern in FEATURE_PATTERNS.items()},
        **archive_features,
    }
    return {"segments": segments, "features": features}
