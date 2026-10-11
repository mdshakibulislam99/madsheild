"""Serve the frontend and analysis API on the same port."""
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .config import FRONTEND_DIR
from .api.endpoints import reports, upload

app = FastAPI(title="MadSheild Backend", description="Document static analysis and optional existing-model inference.", version="0.2.0")
app.include_router(upload.router)
app.include_router(reports.router)
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")


@app.get("/", include_in_schema=False)
def root():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "madshield-backend"}
