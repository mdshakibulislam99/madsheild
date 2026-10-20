# MadShield backend

See [application setup and tests](../README.md). The application lives in `app/main.py`; `backend/main.py` is the uvicorn entry point (`main:app`) used by the `run` launcher. Both the frontend and API run on port 8001.

## Analysis and efficiency

The extraction layer supports `.txt`, `.log`, `.csv`, `.json`, `.md`, `.doc`, `.docx`, `.pdf`, `.zip`, `.exe`, and `.dll`. Rules use compiled patterns, return at most 100 findings, and preserve text line numbers, DOCX body/table paragraph locations, PDF page numbers, and ZIP member paths. Uploaded content is never executed.

`workers/tasks.py` coordinates extraction, static rules, optional model inference, storage, and reports. Work runs in a thread pool, with a bounded number of active scans; it does not require Celery or Redis.

The process-local cache keys results by SHA-256, extension, rules version, model configuration/artifact signature, and decision threshold. Copies protect cached data from later mutations. Restarting clears the cache. For a changed remote model, update its versioned `MODEL_NAME` or restart the process; a remote artifact change cannot be detected automatically.

## Configuration

Set environment variables before starting the server. A `.env` file is not loaded automatically. Numeric size/count settings must be positive integers.

| Variable | Default | Purpose |
| --- | --- | --- |
| `STORAGE_DIR` | `backend/storage` | Upload/report location; prefer an absolute path |
| `MAX_FILE_SIZE_BYTES` | 10485760 | Maximum size of one upload |
| `MAX_BATCH_FILES` | 100 | Maximum files in one batch or folder scan |
| `MAX_BATCH_SIZE_BYTES` | 104857600 | Maximum combined size of one batch |
| `MAX_TEXT_CHARACTERS` | 2000000 | Extracted text limit |
| `MAX_TEXT_SEGMENTS` | 20000 | Extracted line/paragraph limit |
| `MAX_DOCX_EXPANDED_BYTES` | 52428800 | Maximum expanded DOCX archive size |
| `MAX_PDF_PAGES` | 500 | Maximum pages read from one PDF |
| `MAX_ARCHIVE_MEMBERS` | 2048 | Maximum non-directory ZIP entries |
| `MAX_ARCHIVE_EXPANDED_BYTES` | 52428800 | Maximum expanded ZIP size |
| `MAX_ARCHIVE_DEPTH` | 2 | Maximum nested ZIP levels |
| `MAX_CONCURRENT_SCANS` | 2 | Active scans allowed in one process |
| `ANALYSIS_CACHE_SIZE` | 64 | Cached document analyses |
| `ANALYSIS_CACHE_TTL_SECONDS` | 300 | Cache lifetime |
| `MODEL_PATH` | empty | Existing local JSON model artifact |
| `MODEL_ENDPOINT` | empty | Existing inference service URL |
| `MODEL_NAME` | empty | Model name/version passed to the service |
| `MODEL_API_KEY` | empty | Optional bearer credential |
| `MODEL_TIMEOUT_SECONDS` | 30 | HTTP timeout setting |
| `MODEL_MAX_SEGMENTS` | 64 | Maximum service inputs per scan |
| `MODEL_MAX_TEXT_CHARACTERS` | 64000 | Maximum text sent to the service |
| `MODEL_THRESHOLD` | 0.8 | Probability threshold for the suspicious verdict |

DOCX and ZIP archives have entry-count, per-entry, expansion-ratio, encryption, and unsafe-path checks. Encrypted PDFs are rejected. Legacy DOC uses OLE structure plus readable strings; EXE/DLL uses static PE metadata, imports, and readable strings. Invalid inputs produce HTTP 4xx responses. When all scan slots are occupied, the server returns 503 with `Retry-After: 2`.

## Existing local model

Obtain the trained artifact and feature/preprocessing specification from the model owner. Configure **one** of `MODEL_PATH` and `MODEL_ENDPOINT`. Missing or invalid models leave static analysis available and model probability unavailable.

The built-in local adapter accepts a JSON linear/logistic classifier, with:

- `format`: `madshield-logistic-v1`.
- `feature_names`: a nonempty list of unique supported feature names.
- `weights`: one finite number per feature.
- `bias`: a finite number.
- Optional `means` (default zeros), `scales` (default ones, each positive), and `model_name`.

Inference calculates `sigmoid(bias + sum(weight * (feature - mean) / scale))`. The artifact must define the positive class as malicious and use the same feature extraction as this backend. This interface cannot infer preprocessing from an arbitrary model file.

Supported features are the names in `ai/feature_extractor.py`, including text-pattern counts, Office archive markers, ZIP member count, PDF structural markers, and PE type/import markers. Entropy uses raw uploaded bytes; text length uses newline-joined extracted segments. Pattern counts use the expressions in `ai/feature_extractor.py`.

The artifact is loaded once and reloaded when its path modification time or size changes. JSON avoids executable pickle loading. PyTorch, pickle, and other model formats require an adapter matching the owner's model; renaming a file to JSON does not convert it. No real weights are included.

From the repository root on macOS/Linux:

```sh
export MODEL_PATH="$PWD/madsheild/backend/app/ai/weights/team-model.json"
cd madsheild/backend && .venv/bin/python -m uvicorn main:app --reload --port 8001
```

On Windows, set `$env:MODEL_PATH` to the absolute artifact path, then use the virtual environment's Python launcher. A local classifier predicts for the whole document and cannot identify a particular malicious line.

## Existing inference service

The service adapter uses the following JSON contract. It is not automatically compatible with chat-model APIs such as Ollama or an arbitrary `/predict` service; those require a matching adapter.

Request:

```json
{
  "model": "team-model-v1",
  "segments": [
    {"id": "0", "text": "example text", "location": {"line_number": 1, "character_offset": 0}}
  ],
  "features": {"text_length": 12, "segment_count": 1}
}
```

The actual `features` object contains all supported features. Response:

```json
{
  "predictions": [
    {"id": "0", "malware_probability": 0.12, "reason": "Model explanation"}
  ]
}
```

Return exactly one prediction per submitted ID. Missing, duplicate, unknown, nonfinite, or out-of-range probabilities invalidate the response. Optional reasons come from the model service and are not independently verified.

Text is split into chunks of up to 2000 characters, limited by the configured segment/character budgets. Reports state how much text was analyzed. Incomplete coverage requests manual review unless other evidence already produces a suspicious verdict. Empty text skips service inference.

The reported service probability is the **maximum segment probability**, not a calibrated document-level probability. Confidence remains unavailable. Reports identify this aggregation explicitly.

Requests have a timeout and a 1 MiB response-size limit. Redirects are disabled. `MODEL_API_KEY` supplies an optional bearer header and is excluded from reports. Only configure a service trusted to receive uploaded document text.

## Storage and reports

Uploads are stored as `storage/uploads/<32-character-scan-id>/<random-name><extension>`, with restricted directory/file permissions where supported. Original names remain metadata; they do not control the storage path. Reports use atomic replacement of `report.json` in the same scan directory. Uploads, reports, credentials, and model weights are ignored by Git and container build context.

`analysis.cache_hit` identifies reuse. On a hit, extraction/rules/model timings are omitted because those stages did not run; `analysis.timings_ms.analysis` measures the current cache lookup. `analysis.timings_ms.total` includes current analysis and upload persistence before report JSON is written; it excludes HTTP transfer and browser rendering. Performance measurements do not establish accuracy or calibrated confidence.

Authentication, a user-history listing, automatic retention, and production deployment controls remain future stages. The batch endpoint analyzes each supported file independently and retains display-only relative paths; it does not execute or recreate the uploaded directory tree on disk.
