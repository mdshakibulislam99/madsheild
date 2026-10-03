from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.endpoints.upload import router as upload_router


app = FastAPI(
    title="MadSheild Backend",
    description="Backend API for defensive file analysis.",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(upload_router)


@app.get("/")
async def root():
    return {
        "service": "madsheild-backend",
        "status": "ok",
    }