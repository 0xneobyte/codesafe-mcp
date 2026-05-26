from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from google import genai
from google.genai import types

from config import Settings, get_settings

router = APIRouter(tags=["query"])
limiter = Limiter(key_func=get_remote_address)


class QueryRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=2000, description="Natural language security question")
    store_id: str | None = Field(None, description="Override store ID (uses GEMINI_STORE_ID if omitted)")


class QueryResponse(BaseModel):
    answer: str
    sources: list[str]
    store_id: str


def verify_api_key(x_api_key: str = Header(..., alias="X-Api-Key"), settings: Settings = Depends(get_settings)):
    if x_api_key != settings.BACKEND_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@router.post("/query", response_model=QueryResponse)
@limiter.limit("30/minute")
async def query_security_kb(
    request: Request,
    body: QueryRequest,
    _: None = Depends(verify_api_key),
    settings: Settings = Depends(get_settings),
):
    store_id = body.store_id or settings.GEMINI_STORE_ID
    if not store_id:
        raise HTTPException(
            status_code=503,
            detail="No File Search Store configured. Upload security docs first and set GEMINI_STORE_ID.",
        )

    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    try:
        file_search = types.FileSearch(file_search_store_names=[store_id])
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=(
                f"You are a security expert. Answer this question using only the uploaded security documentation.\n\n"
                f"Question: {body.query}\n\n"
                f"Be concise and specific. Include code examples when relevant."
            ),
            config=types.GenerateContentConfig(
                tools=[types.Tool(file_search=file_search)]
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Gemini error: {str(e)}")

    # Extract grounded source titles
    sources: list[str] = []
    if response.candidates and response.candidates[0].grounding_metadata:
        gm = response.candidates[0].grounding_metadata
        if hasattr(gm, "grounding_chunks") and gm.grounding_chunks:
            seen: set[str] = set()
            for chunk in gm.grounding_chunks:
                if hasattr(chunk, "retrieved_context"):
                    title = getattr(chunk.retrieved_context, "title", None)
                    if title and title not in seen:
                        seen.add(title)
                        sources.append(title)

    return QueryResponse(answer=response.text, sources=sources, store_id=store_id)
