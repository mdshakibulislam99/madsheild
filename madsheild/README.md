# MadSheild

MadSheild is a lightweight security-analysis project for checking uploaded files and presenting a simple dashboard for review. The current implementation includes a FastAPI backend, a browser-based frontend, and file upload validation with metadata collection.

## Overview

This project is designed as a foundation for an AI-driven file security analyzer. At the moment, the system validates uploaded files, enforces a 10 MB size limit, calculates a SHA-256 hash, and returns a structured response payload. The dashboard is served from the same backend and provides a clean UI for uploading a file and viewing a scan result.

## Current Features

- File upload endpoint via FastAPI
- File size validation (10 MB max)
- Filename validation
- SHA-256 hashing for uploaded content
- Static frontend served from the same app
- Local dashboard and API documentation routes
- CORS support for local frontend development

## Project Structure

```text
madsheild/
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   └── README.md
├── fontend/
│   ├── assets/
│   ├── dashboard/
│   ├── index.html
│   └── ...
├── core/
│   ├── settings.py
│   ├── urls.py
│   └── ...
├── run.py
├── manage.py
└── README.md
```

## Quick Start

From the project root:

```powershell
cd d:\madsheild-project\madsheild
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r madsheild\backend\requirements.txt
```

Run the app:

```powershell
.\.venv\Scripts\python.exe -m uvicorn madsheild.backend.main:app --reload --host 127.0.0.1 --port 8001
```

Or use the helper script:

```powershell
py run.py
```

Then open:

- http://127.0.0.1:8001/
- http://127.0.0.1:8001/docs
- http://127.0.0.1:8001/health

## API Endpoint

### POST /api/v1/scans

Uploads a file and returns a structured scan payload containing metadata such as:

- filename
- content type
- size in bytes
- SHA-256 hash
- verdict
- risk score
- threat list
- summary

Example response:

```json
{
  "status": "completed",
  "filename": "example.pdf",
  "content_type": "application/pdf",
  "size_bytes": 12345,
  "sha256": "...",
  "verdict": "not_analyzed",
  "risk_score": null,
  "threats": [],
  "summary": "File uploaded successfully. The threat-analysis engine has not been added yet."
}
```

## Development Notes

- The backend is built with FastAPI and uses a static frontend served from the `fontend` directory.
- The project includes Django dependencies, but the active runtime for the security app is the FastAPI backend.
- The current scan workflow is intentionally a scaffold; the true malware/threat-detection engine is still to be implemented.

## License

This project does not currently declare a license. Add a license file if you plan to distribute or publish it publicly.
