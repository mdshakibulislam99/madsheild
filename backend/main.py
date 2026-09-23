from hashlib import sha256

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="MadSheild Backend",
    description="Backend API for defensive file-threat analysis.",
    version="0.1.0",
)

# 允许本地前端连接后端
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

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@app.get("/")
def root():
    return {
        "name": "MadSheild Backend",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/v1/scans")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read(MAX_FILE_SIZE + 1)

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file must have a filename.",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="The file is larger than 10 MB.",
        )

    file_hash = sha256(content).hexdigest()

    # 目前只完成上传、验证和文件信息提取。
    # 真正的病毒检测模块将在后续加入。
    return {
        "status": "completed",
        "filename": file.filename,
        "content_type": file.content_type,
        "size_bytes": len(content),
        "sha256": file_hash,
        "verdict": "not_analyzed",
        "risk_score": None,
        "threats": [],
        "summary": "File uploaded successfully. The threat-analysis engine has not been added yet.",
    }