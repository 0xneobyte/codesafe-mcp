import time
from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File, Form
from pydantic import BaseModel
from google import genai
import tempfile, os

from config import Settings, get_settings

router = APIRouter(tags=["upload"])

ALLOWED_EXTENSIONS = {".pdf", ".md", ".txt", ".json"}


def verify_admin_token(x_admin_token: str = Header(..., alias="X-Admin-Token"), settings: Settings = Depends(get_settings)):
    if x_admin_token != settings.ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")


class StoreInfo(BaseModel):
    store_id: str
    display_name: str
    document_count: int


class UploadResult(BaseModel):
    filename: str
    store_id: str
    success: bool
    message: str


@router.get("/stores", response_model=list[StoreInfo])
async def list_stores(
    _: None = Depends(verify_admin_token),
    settings: Settings = Depends(get_settings),
):
    client = genai.Client(api_key=settings.GEMINI_API_KEY)
    stores = list(client.file_search_stores.list())
    result = []
    for store in stores:
        try:
            docs = list(client.file_search_stores.documents.list(parent=store.name, config={"pageSize": 100}))
            doc_count = len(docs)
        except Exception:
            doc_count = -1
        result.append(StoreInfo(store_id=store.name, display_name=store.display_name or "", document_count=doc_count))
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


@router.post("/upload", response_model=UploadResult)
async def upload_file(
    file: UploadFile = File(...),
    store_id: str = Form(..., description="file_search_stores/xxxx"),
    _: None = Depends(verify_admin_token),
    settings: Settings = Depends(get_settings),
):
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'. Allowed: {ALLOWED_EXTENSIONS}")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    # Write to temp file — Gemini SDK needs a path
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        operation = client.file_search_stores.upload_to_file_search_store(
            file=tmp_path,
            file_search_store_name=store_id,
            config={"display_name": filename},
        )
        # Poll until done (max 120s)
        deadline = time.time() + 120
        while not operation.done and time.time() < deadline:
            time.sleep(2)
            operation = client.operations.get(operation)

        if not operation.done:
            return UploadResult(filename=filename, store_id=store_id, success=False, message="Upload timed out after 120s")

        return UploadResult(filename=filename, store_id=store_id, success=True, message="Uploaded and indexed")
    except Exception as e:
        return UploadResult(filename=filename, store_id=store_id, success=False, message=str(e))
    finally:
        os.unlink(tmp_path)
