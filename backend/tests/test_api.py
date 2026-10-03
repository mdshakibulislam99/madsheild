import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from backend.app.services import file_manager


class TestFileStorage(unittest.TestCase):
    def setUp(self):
        temporary_dir = TemporaryDirectory()
        self.addCleanup(temporary_dir.cleanup)

        self.uploads_dir = Path(temporary_dir.name) / "uploads"

        storage_patch = patch.object(
            file_manager, "UPLOADS_DIR", self.uploads_dir
        )
        storage_patch.start()
        self.addCleanup(storage_patch.stop)

    def test_saves_content_in_scan_directory(self):
        result = file_manager.save_uploaded_file(
            "../../report.txt", b"hello", "scan123"
        )

        scan_dir = self.uploads_dir / "scan123"
        saved_file = scan_dir / result["stored_name"]

        self.assertEqual(result["original_filename"], "report.txt")
        self.assertEqual(saved_file.read_bytes(), b"hello")
        self.assertEqual(list(scan_dir.iterdir()), [saved_file])

    def test_same_filename_does_not_overwrite(self):
        first = file_manager.save_uploaded_file(
            "report.txt", b"first", "scan123"
        )
        second = file_manager.save_uploaded_file(
            "report.txt", b"second", "scan123"
        )

        self.assertNotEqual(first["stored_name"], second["stored_name"])

        scan_dir = self.uploads_dir / "scan123"
        self.assertEqual(
            (scan_dir / first["stored_name"]).read_bytes(), b"first"
        )
        self.assertEqual(
            (scan_dir / second["stored_name"]).read_bytes(), b"second"
        )

    def test_rejects_invalid_scan_id(self):
        for scan_id in ["../escape", "/tmp/escape", ""]:
            with self.subTest(scan_id=scan_id):
                with self.assertRaises(ValueError):
                    file_manager.save_uploaded_file(
                        "report.txt", b"hello", scan_id
                    )

        self.assertFalse(self.uploads_dir.exists())