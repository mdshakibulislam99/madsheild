# MadShield

A local document security analyzer with a FastAPI backend and an HTML/JavaScript frontend served on the same port. It analyzes individual files or folders containing `.txt` and `.docx` files with static rules and can run inference using an existing model. It does not train a model or execute uploaded content.

## Start locally

Run these commands from the repository root: the directory containing both `run.py` and `madsheild/`.

macOS / Linux:

```sh
python3 -m venv madsheild/backend/.venv
madsheild/backend/.venv/bin/python -m pip install -r madsheild/backend/requirements.txt
madsheild/backend/.venv/bin/python run.py
```

Windows PowerShell:

```powershell
py -m venv madsheild/backend/.venv
.\madsheild\backend\.venv\Scripts\python.exe -m pip install -r madsheild/backend/requirements.txt
.\madsheild\backend\.venv\Scripts\python.exe run.py
```

Keep the terminal open. Visit [the application](http://127.0.0.1:8001/), [API documentation](http://127.0.0.1:8001/docs), or [health check](http://127.0.0.1:8001/health). A separate frontend server is unnecessary.

## Analysis workflow

1. Validate filenames, extensions, file count, and actual upload sizes (10 MiB per file, 100 files and 100 MiB per batch by default).
2. Extract UTF-8 TXT lines or DOCX body/table paragraphs, keeping blank positions and recording line or paragraph numbers.
3. Check static indicators such as encoded PowerShell, download-and-execute commands, shadow-copy deletion, dynamic execution, macros, and embedded objects.
4. Optionally run an existing model. Rule findings and model predictions have separate sources and coverage information.
5. Save the quarantined upload and its report, then display the report in the browser.

Identical content can reuse an in-memory analysis result for five minutes (up to 64 entries). Each upload still gets a new scan ID and saved report. Failed model requests are not cached. The default concurrency limit is two active scans.

`risk_score` is a heuristic rule score, not a malware probability. Without a configured model, `malware_probability` is `null`. `confidence` remains `null` because no calibration evidence is supplied. `no_indicators_found` means that the implemented checks found no indicators; it does not certify a file as safe. Quoted commands in educational documents can trigger rules.

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/scans` | Analyze one multipart file using the field name **file** |
| `POST /api/v1/scans/batch` | Analyze multipart files using repeated **files** fields; preserves safe relative folder paths in reports |
| `GET /api/v1/reports/{scan_id}` | Retrieve a saved report |
| `GET /api/v1/capabilities` | Supported extensions, size limit, concurrency, and model mode |
| `GET /health` | Check whether the server is running |

Example upload:

```sh
curl -F "file=@/absolute/path/example.txt" http://127.0.0.1:8001/api/v1/scans
```

Example batch upload:

```sh
curl -F "files=@/absolute/path/one.txt;filename=folder/one.txt" \
  -F "files=@/absolute/path/two.docx;filename=folder/two.docx" \
  http://127.0.0.1:8001/api/v1/scans/batch
```

Reports include metadata, SHA-256, a verdict (`suspicious`, `review_required`, or `no_indicators_found`), findings with locations, model status/coverage, limitations, cache status, and timings. `timings_ms.total` measures server work before report JSON persistence, excluding network transfer. See [backend configuration and model contracts](backend/README.md).

## Validation

From the repository root:

```sh
madsheild/backend/.venv/bin/python -m unittest discover -s madsheild/backend/tests -p 'test_*.py' -v
```

On Windows, use `.\madsheild\backend\.venv\Scripts\python.exe` instead. Tests cover extraction, document limits, rule locations, synthetic model inference, model failures, caching, uploads, and report retrieval. Synthetic model fixtures validate the interface and calculations; they do not establish detection accuracy.

## Layout

```text
repository root/
├── run.py
├── madsheild/
│   ├── backend/
│   │   ├── main.py                 # Compatibility entry point
│   │   ├── app/
│   │   │   ├── config.py
│   │   │   ├── main.py
│   │   │   ├── api/
│   │   │   │   ├── dependencies.py
│   │   │   │   └── endpoints/
│   │   │   │       ├── upload.py
│   │   │   │       └── reports.py
│   │   │   ├── services/file_manager.py
│   │   │   ├── ai/
│   │   │   │   ├── feature_extractor.py
│   │   │   │   ├── models/classifier.py
│   │   │   │   └── weights/         # Real artifacts are ignored by Git
│   │   │   └── workers/tasks.py
│   │   ├── storage/
│   │   │   ├── uploads/
│   │   │   └── samples/
│   │   ├── tests/
│   │   │   ├── test_api.py
│   │   │   └── test_ai.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   └── fontend/                    # Existing directory spelling retained
│       ├── index.html
│       └── assets/
└── core/                          # Legacy Django scaffold, unused by run.py
```

Python package directories also contain `__init__.py`. Login, registration, navigation history, and API-access pages are outside this implementation stage; existing navigation placeholders remain. Retrieving an individual report does not implement a user history page.

## Container

From the repository root:

```sh
docker build -f madsheild/backend/Dockerfile -t madshield .
docker run --rm -p 127.0.0.1:8001:8001 madshield
```

Container reports are ephemeral unless a writable volume is mounted at `/srv/madshield/madsheild/backend/storage`. Docker execution requires a working Docker installation.

## Current scope

This is a local development application without authentication or automatic storage retention. Keep it bound to loopback; saved reports and uploads need manual cleanup. Quarantine storage is not an operating-system execution sandbox.

TXT input must be UTF-8. DOCX analysis covers body/table text and archive indicators; it does not inspect headers, footers, OCR, or the contents of embedded files. Folder input scans supported files recursively and reports unsupported or unreadable input rather than analyzing it. PDF and executable-file analysis, production deployment controls, and model training are outside this stage. The repository supplies no trained weights, labeled dataset, or accuracy benchmark.
