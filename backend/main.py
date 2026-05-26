from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from config import get_settings
from routers import query, upload

settings = get_settings()

app = FastAPI(
    title="CodeSafe RAG Backend",
    description="Security documentation RAG backend for CodeSafe MCP",
    version="0.1.0",
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # MCP server calls from server-side — no browser CORS needed
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/health")
def health():
    return {"status": "ok", "environment": settings.ENVIRONMENT, "store_configured": bool(settings.GEMINI_STORE_ID)}


# Query endpoint — always mounted
app.include_router(query.router, prefix=settings.API_V1_PREFIX)

# Admin / ingestion endpoints — disabled in production
if settings.ENVIRONMENT != "production":
    app.include_router(upload.router, prefix=settings.API_V1_PREFIX)
