"""Serve the frontend and analysis API on the same port."""
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from .config import FRONTEND_DIR
from .api.endpoints import reports, upload, auth

app = FastAPI(title="MadSheild Backend", description="Document static analysis and optional existing-model inference.", version="0.2.0")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return validation errors as a plain string so clients never see [object Object]."""
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", []) if p != "body")
        msg = str(err.get("msg", "Invalid value."))
        parts.append(f"{loc}: {msg}" if loc else msg)
    return JSONResponse(status_code=422, content={"detail": "; ".join(parts) or "Invalid request."})


app.include_router(upload.router)
app.include_router(reports.router)
app.include_router(auth.router)
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

# Explicit frontend pages (keep this list in sync with the files in fontend/).
FRONTEND_PAGES = {
    "": "home.html",
    "index.html": "home.html",
    "home.html": "home.html",
    "scan.html": "scan.html",
    "history.html": "history.html",
    "report.html": "report.html",
    "login.html": "login.html",
    "register.html": "register.html",
}


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "madshield-backend"}


@app.get("/", include_in_schema=False)
def root():
    return FileResponse(FRONTEND_DIR / "home.html")


@app.get("/{page_name}", include_in_schema=False)
def frontend_page(page_name: str):
    """Serve a known frontend page; unknown names fall back to 404."""
    target = FRONTEND_PAGES.get(page_name)
    if target is None:
        raise HTTPException(status_code=404, detail="Page not found")
    return FileResponse(FRONTEND_DIR / target)
