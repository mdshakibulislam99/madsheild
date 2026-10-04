# MadSheild Backend

FastAPI service for secure `.txt` and `.docx` uploads. The local AI model is not
connected yet; the upload response currently returns file metadata and SHA256.

## Start locally

From this directory (`madsheild/backend`):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`. Open
`http://127.0.0.1:8000/docs` to try `POST /api/v1/scans`.

The frontend sends one selected file in the `files` multipart field. The
backend validates the extension and size, stores it under
`backend/storage/uploads/<scan_id>/`, and returns the stored filename, size,
and SHA256 hash.
