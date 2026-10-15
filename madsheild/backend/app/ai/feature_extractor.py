"""Bounded text extraction with source locations and reusable numeric features."""

import math
import re
from collections import Counter
from io import BytesIO
from pathlib import PurePosixPath
from zipfile import BadZipFile, ZipFile

from docx import Document
from docx.table import Table
from docx.text.paragraph import Paragraph
from olefile import OleFileIO, isOleFile
from pefile import PE, PEFormatError
from pypdf import PdfReader

from ..config import (ALLOWED_EXTENSIONS, MAX_ARCHIVE_DEPTH, MAX_ARCHIVE_EXPANDED_BYTES,
                      MAX_ARCHIVE_MEMBERS, MAX_DOCX_EXPANDED_BYTES, MAX_PDF_PAGES,
                      MAX_TEXT_CHARACTERS, MAX_TEXT_SEGMENTS)


FEATURE_NAMES = (
    "byte_entropy", "text_length", "segment_count", "url_count", "powershell_count",
    "encoded_command_count", "dynamic_execution_count", "download_count",
    "shadow_delete_count", "macro_present", "embedded_object_count", "archive_member_count",
    "pdf_javascript_count", "pdf_embedded_file_count", "legacy_doc_present", "pe_executable",
    "pe_dll", "pe_suspicious_import_count",
)
FEATURE_PATTERNS = {
    "url_count": re.compile(r"https?://", re.I),
    "powershell_count": re.compile(r"\b(?:powershell|pwsh)\b", re.I),
    "encoded_command_count": re.compile(r"-(?:enc|encodedcommand)\b", re.I),
    "dynamic_execution_count": re.compile(r"\b(?:eval|exec)\s*\(|\b(?:iex|invoke-expression)\b", re.I),
    "download_count": re.compile(r"\b(?:curl|wget|downloadstring|downloadfile|invoke-webrequest)\b", re.I),
    "shadow_delete_count": re.compile(r"\b(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)\b", re.I),
}
TEXT_EXTENSIONS = frozenset({".txt", ".log", ".csv", ".json", ".md"})
ASCII_STRING = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
SUSPICIOUS_IMPORTS = frozenset({"winexec", "shellexecutea", "shellexecutew", "urldownloadtofilea",
                                "urldownloadtofilew", "virtualalloc", "writeprocessmemory",
                                "createremotethread", "internetopena", "internetopenw"})


class SegmentList(list):
    def __init__(self):
        super().__init__()
        self.characters = 0


def append_segment(segments: list[dict], text: str, location: dict) -> None:
    current_characters = segments.characters if isinstance(segments, SegmentList) else sum(len(segment["text"]) for segment in segments)
    if current_characters + len(text) > MAX_TEXT_CHARACTERS:
        raise ValueError("The extracted text exceeds the analysis limit.")
    if len(segments) >= MAX_TEXT_SEGMENTS:
        raise ValueError("The file contains too many text segments.")
    segments.append({**location, "text": text})
    if isinstance(segments, SegmentList):
        segments.characters += len(text)


def extract_txt_lines(content: bytes) -> list[dict]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Text-based files must use UTF-8 encoding.") from exc
    if "\x00" in text:
        raise ValueError("The text-based file contains binary data.")
    if len(text) > MAX_TEXT_CHARACTERS:
        raise ValueError("The extracted text exceeds the analysis limit.")
    lines = text.splitlines()
    if len(lines) > MAX_TEXT_SEGMENTS:
        raise ValueError("The file contains too many lines.")
    return [{"line_number": number, "text": line} for number, line in enumerate(lines, 1)]


def extract_pdf_pages(content: bytes) -> tuple[list[dict], dict]:
    try:
        reader = PdfReader(BytesIO(content), strict=True)
        if reader.is_encrypted:
            raise ValueError("Encrypted PDF files are not supported.")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise ValueError("The PDF contains too many pages.")
        segments = SegmentList()
        for page_number, page in enumerate(reader.pages, 1):
            append_segment(segments, page.extract_text() or "", {"page_number": page_number})
        root = reader.trailer.get("/Root", {})
        names = root.get("/Names", {}) if hasattr(root, "get") else {}
        embedded = names.get("/EmbeddedFiles") if hasattr(names, "get") else None
        return segments, {"pdf_javascript_count": int("/JavaScript" in content.decode("latin1", "ignore")),
                          "pdf_embedded_file_count": int(embedded is not None)}
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("This file is not a readable PDF document.") from exc


def extract_legacy_doc(content: bytes) -> tuple[list[dict], dict]:
    if not isOleFile(BytesIO(content)):
        raise ValueError("This file is not a readable legacy DOC document.")
    try:
        with OleFileIO(BytesIO(content), raise_defects=40) as document:
            streams = ["/".join(path) for path in document.listdir()]
    except Exception as exc:
        raise ValueError("This file is not a readable legacy DOC document.") from exc
    segments = SegmentList()
    for match in ASCII_STRING.finditer(content):
        append_segment(segments, match.group().decode("ascii"), {"scope": "legacy_doc_string"})
    for match in UTF16_STRING.finditer(content):
        append_segment(segments, match.group().decode("utf-16-le"), {"scope": "legacy_doc_string"})
    return segments, {"legacy_doc_present": 1,
                      "macro_present": int(any("vba" in stream.lower() for stream in streams)),
                      "embedded_object_count": sum("objectpool" in stream.lower() for stream in streams)}


def extract_pe(content: bytes, extension: str) -> tuple[list[dict], dict]:
    try:
        binary = PE(data=content, fast_load=True)
        binary.parse_data_directories(directories=[1])
        imports = []
        for entry in getattr(binary, "DIRECTORY_ENTRY_IMPORT", []):
            imports.extend(item.name.decode("ascii", "ignore").lower() for item in entry.imports if item.name)
        is_dll = bool(binary.FILE_HEADER.Characteristics & 0x2000)
    except PEFormatError as exc:
        raise ValueError("This file is not a readable PE executable.") from exc
    finally:
        try:
            binary.close()
        except (UnboundLocalError, AttributeError):
            pass
    segments = SegmentList()
    for match in ASCII_STRING.finditer(content):
        append_segment(segments, match.group().decode("ascii"), {"scope": "pe_string"})
    return segments, {"pe_executable": int(extension == ".exe"), "pe_dll": int(is_dll or extension == ".dll"),
                      "pe_suspicious_import_count": sum(name in SUSPICIOUS_IMPORTS for name in imports)}


def inspect_archive(archive: ZipFile) -> list:
    members = [member for member in archive.infolist() if not member.is_dir()]
    names = [member.filename for member in members]
    if len(members) > MAX_ARCHIVE_MEMBERS or len(names) != len(set(names)):
        raise ValueError("The ZIP archive has too many or duplicate entries.")
    if any(member.flag_bits & 1 for member in members):
        raise ValueError("Encrypted ZIP files are not supported.")
    if any(PurePosixPath(member.filename).is_absolute() or ".." in PurePosixPath(member.filename).parts for member in members):
        raise ValueError("The ZIP archive contains an unsafe member path.")
    if sum(member.file_size for member in members) > MAX_ARCHIVE_EXPANDED_BYTES:
        raise ValueError("The expanded ZIP exceeds the analysis limit.")
    for member in members:
        if member.file_size > 10 * 1024 * 1024 or (member.file_size > 1024 * 1024 and member.file_size > max(1, member.compress_size) * 1000):
            raise ValueError("A ZIP archive member exceeds the analysis limit.")
    return members


def extract_zip(content: bytes, depth: int) -> tuple[list[dict], dict]:
    if depth >= MAX_ARCHIVE_DEPTH:
        raise ValueError("The ZIP archive nesting limit was reached.")
    try:
        with ZipFile(BytesIO(content)) as archive:
            members = inspect_archive(archive)
            segments, aggregate = SegmentList(), {"archive_member_count": 0, "macro_present": 0,
                                        "embedded_object_count": 0, "pdf_javascript_count": 0,
                                        "pdf_embedded_file_count": 0, "legacy_doc_present": 0,
                                        "pe_executable": 0, "pe_dll": 0, "pe_suspicious_import_count": 0}
            for member in members:
                extension = PurePosixPath(member.filename).suffix.lower()
                if extension not in ALLOWED_EXTENSIONS:
                    continue
                nested = extract_features(archive.read(member), extension, depth + 1)
                aggregate["archive_member_count"] += 1
                for name in aggregate:
                    if name != "archive_member_count":
                        aggregate[name] += nested["features"].get(name, 0)
                for segment in nested["segments"]:
                    append_segment(segments, segment["text"], {"archive_member": member.filename,
                                                                 **{key: value for key, value in segment.items() if key != "text"}})
            if not aggregate["archive_member_count"]:
                raise ValueError("The ZIP archive contains no supported files.")
            return segments, aggregate
    except ValueError:
        raise
    except (BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
        raise ValueError("This file is not a readable ZIP archive.") from exc


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


def extract_features(content: bytes, extension: str, depth: int = 0) -> dict:
    archive_features = {"macro_present": 0, "embedded_object_count": 0, "archive_member_count": 0,
                        "pdf_javascript_count": 0, "pdf_embedded_file_count": 0, "legacy_doc_present": 0,
                        "pe_executable": 0, "pe_dll": 0, "pe_suspicious_import_count": 0}
    if extension in TEXT_EXTENSIONS:
        segments = extract_txt_lines(content)
    elif extension == ".docx":
        archive_features.update(inspect_docx(content))
        segments = extract_docx_paragraphs(content, inspected=True)
    elif extension == ".pdf":
        segments, extra = extract_pdf_pages(content)
        archive_features.update(extra)
    elif extension == ".doc":
        segments, extra = extract_legacy_doc(content)
        archive_features.update(extra)
    elif extension == ".zip":
        segments, extra = extract_zip(content, depth)
        archive_features.update(extra)
    elif extension in {".exe", ".dll"}:
        segments, extra = extract_pe(content, extension)
        archive_features.update(extra)
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
