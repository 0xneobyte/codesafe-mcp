from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel, Field
from typing import Optional
from slowapi import Limiter
from slowapi.util import get_remote_address
from google import genai
from google.genai import types

from config import Settings, get_settings

router = APIRouter(tags=["query"])
limiter = Limiter(key_func=get_remote_address)  # decorators reference this; app.state.limiter is the live instance

VALID_FRAMEWORKS = {"nextjs", "supabase", "prisma", "express", "react", "firebase", "generic"}


class QueryRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=2000)
    framework: Optional[str] = Field(
        None,
        description="Filter results to a specific framework: nextjs | supabase | prisma | express | react | firebase | generic",
    )
    store_id: Optional[str] = Field(None, description="Override store ID (uses GEMINI_STORE_ID env if omitted)")


class QueryResponse(BaseModel):
    answer: str
    sources: list[str]
    framework_filter: Optional[str]
    store_id: str


def verify_api_key(
    x_api_key: str = Header(..., alias="X-Api-Key"),
    settings: Settings = Depends(get_settings),
):
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

    # Build metadata filter if framework provided
    metadata_filter: Optional[str] = None
    if body.framework:
        fw = body.framework.lower().strip()
        if fw not in VALID_FRAMEWORKS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown framework '{fw}'. Valid: {sorted(VALID_FRAMEWORKS)}",
            )
        metadata_filter = f'framework="{fw}"'

    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    file_search_kwargs: dict = {"file_search_store_names": [store_id]}
    if metadata_filter:
        file_search_kwargs["metadata_filter"] = metadata_filter
    file_search = types.FileSearch(**file_search_kwargs)

    system_prompt = (
        "You are a security expert assistant for software developers. "
        "Answer questions using ONLY the uploaded security documentation. "
        "Be concise, specific, and always include code examples when relevant. "
        "If the documentation doesn't cover the question, say so explicitly."
    )

    try:
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=body.query,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                tools=[types.Tool(file_search=file_search)],
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

    return QueryResponse(
        answer=response.text,
        sources=sources,
        framework_filter=body.framework,
        store_id=store_id,
    )
