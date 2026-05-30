import os
import time
import tempfile
import mimetypes
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File, Form
from google import genai

from config import Settings, get_settings
from models.metadata import SecurityDocMetadata, UploadResponse

router = APIRouter(prefix="/upload", tags=["upload"])

ALLOWED_EXTENSIONS = {".pdf", ".md", ".txt"}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB


def verify_admin_token(
    x_admin_token: str = Header(..., alias="X-Admin-Token"),
    settings: Settings = Depends(get_settings),
):
    if x_admin_token != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")


def _upload_one(
    file_bytes: bytes,
    filename: str,
    store_id: str,
    metadata: SecurityDocMetadata,
    settings: Settings,
) -> UploadResponse:
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return UploadResponse(
            success=False, filename=filename,
            framework=metadata.framework, topic=metadata.topic,
            message=f"File type '{ext}' not allowed. Allowed: {ALLOWED_EXTENSIONS}",
        )
    if len(file_bytes) > MAX_FILE_SIZE:
        return UploadResponse(
            success=False, filename=filename,
            framework=metadata.framework, topic=metadata.topic,
            message=f"File exceeds 20 MB limit",
        )

    mime_type = "text/markdown" if ext == ".md" else (mimetypes.guess_type(filename)[0] or "text/plain")

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        operation = client.file_search_stores.upload_to_file_search_store(
            file=tmp_path,
            file_search_store_name=store_id,
            config={
                "display_name": filename,
                "custom_metadata": metadata.to_gemini_metadata(),
                "mime_type": mime_type,
            },
        )

        deadline = time.time() + 300  # 5 min max
        while not operation.done:
            if time.time() > deadline:
                return UploadResponse(
                    success=False, filename=filename,
                    framework=metadata.framework, topic=metadata.topic,
                    message="Upload timed out after 5 minutes",
                )
            time.sleep(2)
            operation = client.operations.get(operation)

        return UploadResponse(
            success=True, filename=filename,
            framework=metadata.framework, topic=metadata.topic,
            message="Uploaded and indexed",
        )
    except Exception as e:
        return UploadResponse(
            success=False, filename=filename,
            framework=metadata.framework, topic=metadata.topic,
            message=str(e),
        )
    finally:
        os.unlink(tmp_path)


@router.post("/", response_model=UploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    store_id: str = Form(...),
    framework: str = Form(..., description="nextjs | supabase | prisma | express | react | firebase | generic"),
    topic: str = Form(..., description="e.g. authentication, rls, sql-injection"),
    owasp: str = Form(None, description="e.g. A01, A03, A07"),
    source: str = Form(None, description="e.g. official-docs, owasp, custom"),
    _: None = Depends(verify_admin_token),
    settings: Settings = Depends(get_settings),
):
    content = await file.read()
    metadata = SecurityDocMetadata(framework=framework, topic=topic, owasp=owasp, source=source)
    return _upload_one(content, file.filename or "unknown", store_id, metadata, settings)


@router.post("/batch", response_model=list[UploadResponse])
async def upload_batch(
    files: list[UploadFile] = File(...),
    store_id: str = Form(...),
    framework: str = Form(...),
    topic: str = Form(...),
    owasp: str = Form(None),
    source: str = Form(None),
    _: None = Depends(verify_admin_token),
    settings: Settings = Depends(get_settings),
):
    """Upload multiple files sharing the same framework/topic metadata."""
    metadata = SecurityDocMetadata(framework=framework, topic=topic, owasp=owasp, source=source)
    results = []
    for file in files:
        content = await file.read()
        results.append(_upload_one(content, file.filename or "unknown", store_id, metadata, settings))
    return results


# ── Store management ───────────────────────────────────────────────────────────

from pydantic import BaseModel


class StoreInfo(BaseModel):
    store_id: str
    display_name: str
    document_count: int


@router.get("/stores", response_model=list[StoreInfo])
async def list_stores(_: None = Depends(verify_admin_token), settings: Settings = Depends(get_settings)):
    client = genai.Client(api_key=settings.GEMINI_API_KEY)
    stores = list(client.file_search_stores.list())
    result = []
    for store in stores:
        try:
            docs = list(client.file_search_stores.documents.list(parent=store.name, config={"pageSize": 100}))
            count = len(docs)
        except Exception:
            count = -1
        result.append(StoreInfo(store_id=store.name, display_name=store.display_name or "", document_count=count))
    return result


@router.post("/stores", response_model=StoreInfo)
async def create_store(
    display_name: str = Form(...),
    _: None = Depends(verify_admin_token),
    settings: Settings = Depends(get_settings),
):
    client = genai.Client(api_key=settings.GEMINI_API_KEY)
    store = client.file_search_stores.create(config={"display_name": display_name})
    return StoreInfo(store_id=store.name, display_name=store.display_name or display_name, document_count=0)
