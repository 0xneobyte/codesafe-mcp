# CodeSafe MCP

Security guardrails for AI-assisted coding: an MCP server that gives Claude Code (and other MCP-compatible assistants) six tools to catch security issues in real time, before insecure code, leaked secrets, or fake packages ever ship.

## Why

AI assistants write code fast, but speed comes with risk: hardcoded secrets left in generated code, packages that don't exist or are typosquatted, and dependencies with known CVEs slipping through unnoticed. CodeSafe MCP plugs directly into the assistant's workflow and calls the right check automatically, instead of relying on the developer to remember to run one.

## Tools

| Tool | What it does | Network |
|---|---|---|
| `analyze_security` | Scans a code snippet for OWASP Top 10 issues using a rule engine, with line numbers and fix examples | No |
| `scan_secrets` | Catches hardcoded keys, tokens, and passwords: in a file, a whole directory, or full git history | No |
| `audit_dependencies` | Checks a dependency manifest against the OSV.dev vulnerability database in real time | Yes, OSV.dev |
| `verify_package_safety` | Blocks hallucinated, typosquatted, or newly-published packages before install | Yes, npm / PyPI |
| `get_security_docs` | Answers security questions via retrieval over real framework documentation (Next.js, Supabase, React) | Yes, FastAPI backend |
| `setup_codesafe_enforcement` | One-time setup that hard-blocks unsafe package installs for the whole team | No |

See the [wiki](../../wiki) for full parameter references and examples per tool.

## Architecture

```
Claude Code  --stdio-->  CodeSafe MCP (TypeScript)  --HTTPS-->  RAG Backend (FastAPI + Gemini)
```

The MCP server runs locally over stdio and handles five of the six tools with zero setup. `get_security_docs` additionally needs the Python backend running, which retrieves answers from a Gemini File Search Store seeded with official framework docs.

## Quick start

```bash
git clone https://github.com/0xneobyte/codesafe-mcp.git
cd codesafe-mcp
npm install
npm run build
```

Add the server to your MCP config (`.mcp.json`):

```json
{
  "mcpServers": {
    "codesafe": {
      "type": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/codesafe-mcp/build/index.js"],
      "env": {
        "CODESAFE_BACKEND_URL": "http://localhost:8000",
        "CODESAFE_API_KEY": "YOUR_API_KEY_HERE"
      }
    }
  }
}
```

Five of the six tools work immediately after this. For `get_security_docs`, see the backend setup section in the [wiki](../../wiki).

## Project

Built for **NIT 3004, Capstone Project 2**, Group E.
