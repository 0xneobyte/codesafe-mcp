# Tool: `get_security_docs`

**File:** `src/tools/get-security-docs.ts`  
**Network:** Yes — FastAPI backend at `CODESAFE_BACKEND_URL`  
**Requires:** Backend running + env vars set in `.mcp.json`

RAG (Retrieval-Augmented Generation) tool. Answers security implementation questions using the CodeSafe knowledge base — 632 official docs from Next.js, Supabase, and React, stored in a Gemini File Search Store.

---

## Input

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string (5–2000 chars) | Yes | Natural language security question |
| `framework` | enum | No | Filter results to specific framework |

**Framework options:** `nextjs` `supabase` `prisma` `express` `react` `firebase` `generic`

---

## How it works

### Environment variables (from `.mcp.json`)

```
CODESAFE_BACKEND_URL=http://localhost:8000
CODESAFE_API_KEY=YOUR_API_KEY_HERE
```

Both must be present — the tool returns an error immediately if either is missing.

### Request flow

1. Tool sends `POST {CODESAFE_BACKEND_URL}/api/v1/query` with:
   - Header: `X-Api-Key: {CODESAFE_API_KEY}`
   - Body: `{ "query": "...", "framework": "nextjs" }` (framework is omitted if not provided)

2. FastAPI backend (`backend/main.py`) receives the request:
   - Validates the API key
   - Builds a Gemini File Search query with optional metadata filter `framework="nextjs"`
   - Queries the store `fileSearchStores/codesafedocs-xg2bc202d4kv` using `gemini-2.5-flash`
   - Returns grounded answer + source filenames

3. Tool returns the answer and sources as-is

### Backend knowledge base

| Framework | Files | Content |
|---|---|---|
| `nextjs` | 251 | Next.js canary docs (routing, server actions, middleware, headers) |
| `supabase` | 309 | Auth, database, RLS, security, storage documentation |
| `react` | 72 | React security best practices |
| Total | 632 | — |

Each file is tagged with metadata: `framework`, `topic`, `category`, `owasp`, `source`.  
When `framework` is passed, the backend filters to only search docs tagged with that framework, improving answer precision.

### Backend endpoints (for reference)

| Endpoint | Auth header | Description |
|---|---|---|
| `GET /health` | None | Liveness check |
| `POST /api/v1/query` | `X-Api-Key` | RAG query — used by this tool |
| `POST /api/v1/upload/` | `X-Admin-Token` | Upload single doc (dev only) |
| `POST /api/v1/upload/batch` | `X-Admin-Token` | Bulk upload (dev only) |

Upload endpoints are **disabled in production** (`ENVIRONMENT=production`).

---

## Output

```json
{
  "answer": "To implement Row Level Security in Supabase, you need to:\n\n1. Enable RLS on the table...\n\n```sql\nALTER TABLE profiles ENABLE ROW LEVEL SECURITY;\n```\n\n2. Create policies...",
  "sources": [
    "supabase/auth/row-level-security.md",
    "supabase/database/policies.md"
  ],
  "framework": "supabase"
}
```

`framework` is only present in the output if it was passed as a filter.

Error if backend is unreachable:
```json
{
  "error": "Could not reach CodeSafe backend at http://localhost:8000/api/v1/query: fetch failed"
}
```

---

## Example call (MCP)

```json
{
  "tool": "get_security_docs",
  "arguments": {
    "query": "How do I prevent SQL injection when using Prisma with raw queries?",
    "framework": "prisma"
  }
}
```

```json
{
  "tool": "get_security_docs",
  "arguments": {
    "query": "What security headers should I add to my Next.js app to prevent XSS?"
  }
}
```

---

## Running the backend locally

```bash
cd backend
conda activate codesafe-backend
uvicorn main:app --reload
# Server starts at http://localhost:8000
```

Verify it's up: `curl http://localhost:8000/health`

---

## Known limitations

- **Backend must be running** — if it's down, this tool returns an error. The other 4 tools still work locally
- `prisma`, `express`, and `firebase` frameworks have no docs in the knowledge base yet — queries for these frameworks fall back to generic search across all docs
- Answer quality depends on what's in the knowledge base — questions about very new framework features (post knowledge base upload date) may return outdated answers
- Gemini File Search API has per-minute rate limits — `SlowAPI` rate limiting is applied on the backend (`POST /api/v1/query`)
- The `framework` filter uses exact metadata matching — passing a framework with no matching docs returns a degraded answer, not an error
