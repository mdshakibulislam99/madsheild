# MadSheild Backend

FastAPI backend for the MadSheild security project.

## Windows setup

From the project root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r madsheild\backend\requirements.txt
```

## Start the API

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

The combined frontend and API server is available at `http://127.0.0.1:8001`.
The dashboard is served at `/`, static assets at `/assets`, and interactive API
documentation at `/docs`.

In VS Code, run the `MadSheild: Start development services` task or select
`FastAPI: Debug` from the Run and Debug panel.
