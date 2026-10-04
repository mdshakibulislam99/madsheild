import unittest
from io import BytesIO

from docx import Document

from app.ai.feature_extractor import (
    extract_docx_paragraphs,
    extract_txt_lines,
)


class TestFeatureExtractor(unittest.TestCase):
    def test_txt_preserves_blank_lines(self):
        result = extract_txt_lines(b"first\n\nthird")
        self.assertEqual(result, [
            {"line_number": 1, "text": "first"},
            {"line_number": 2, "text": ""},
            {"line_number": 3, "text": "third"},
        ])

    def test_txt_rejects_invalid_utf8(self):
        with self.assertRaises(ValueError):
            extract_txt_lines(b"\xff")

    def test_docx_preserves_blank_paragraphs(self):
        document = Document()
        for text in ["first", "", "third"]:
            document.add_paragraph(text)

        buffer = BytesIO()
        document.save(buffer)
        result = extract_docx_paragraphs(buffer.getvalue())

        self.assertEqual(result, [
            {"paragraph_number": 1, "text": "first"},
            {"paragraph_number": 2, "text": ""},
            {"paragraph_number": 3, "text": "third"},
        ])
