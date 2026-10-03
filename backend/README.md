# ICS Backend

Python backend for the ICS security project.

## Start

From the repository root, run:

```bash
backend/.venv/bin/python -m uvicorn backend.app.main:app --reload
```

Then open `http://127.0.0.1:8000/docs` to try the API. The current prototype accepts
`.txt` and `.docx` files at `POST /api/v1/scans`, stores them by scan ID, and returns
file metadata and SHA256 hashes. Malware model inference will be connected later.
