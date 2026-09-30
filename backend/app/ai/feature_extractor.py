from io import BytesIO

from docx import Document
def extract_txt_lines(content: bytes) -> list[dict]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("TXT file must use UTF-8 encoding.") from exc

    return [
        {"line_number": number, "text": line}
        for number, line in enumerate(text.splitlines(), start=1)
    ]

def extract_docx_paragraphs(content: bytes) -> list[dict]:
    document = Document(BytesIO(content))

    return [
        {"paragraph_number": number, "text": paragraph.text}
        for number, paragraph in enumerate(document.paragraphs, start=1)
    ]