# Tool: `scan_secrets`

**File:** `src/tools/scan-secrets.ts`  
**Network:** None — fully local  
**OWASP:** A02 — Cryptographic Failures

Scans code or file content for hardcoded secrets using two independent passes: regex pattern matching and Shannon entropy analysis. Three optional features: auto-fix generation, git history scanning, and cross-file data flow tracking.

---

## Input

| Parameter | Type | Required | Description |
|---|---|---|---|
| `code` | string (max 50 000 chars) | Yes | Raw code or file content to scan |
| `filename` | string | No | Filename hint — affects severity adjustment |
| `repoPath` | string | No | Absolute path to git repo root — enables git history scan |
| `additionalFiles` | array (max 20) | No | Other files in the project — enables cross-file data flow tracking |

---

## How the scan works

### Pass 1 — Regex pattern matching (`src/lib/secret-patterns.ts`)

18 named patterns checked in order:

| Pattern name | What it matches | Base severity |
|---|---|---|
| Supabase Service Role Key | JWT starting with `eyJhbGci...` | critical |
| Supabase URL | `*.supabase.co` URLs | high |
| OpenAI API Key | `sk-...` (32+ chars) | critical |
| Anthropic API Key | `sk-ant-...` (40+ chars) | critical |
| Google API Key | `AIza...` (35 chars) | critical |
| GitHub PAT | `ghp_...` (36 chars) | critical |
| GitHub OAuth Token | `gho_...` (36 chars) | critical |
| AWS Access Key ID | `AKIA...` (16 chars) | critical |
| Stripe Live Secret | `sk_live_...` | critical |
| Stripe Test Secret | `sk_test_...` | high |
| MongoDB URI | `mongodb://` or `mongodb+srv://` | critical |
| Private Key Block | `-----BEGIN ... PRIVATE KEY-----` | critical |
| Hardcoded Password | `password =` / `passwd:` etc. (captures full assignment) | high |
| Hardcoded Secret | `secret =` / `api_secret:` etc. (captures full assignment) | critical |
| Hardcoded Token | `token =` / `access_token:` etc. (captures full assignment) | high |
| Firebase Config Key | `AIzaSy...` (33 chars) | critical |
| Twilio Auth Token | `SK` + 32 hex chars | critical |
| SendGrid API Key | `SG.xxx.xxx` | critical |

**Allowlist** — values matching these are silently skipped:
`example`, `placeholder`, `your-key-here`, `changeme`, `dummy`, `fake`, `test-key`, `xxxx`, `1234567890`

**Deduplication** — same raw value only reported once even if it appears multiple times.

### Pass 2 — Shannon entropy analysis (`src/lib/entropy.ts`)

Scans every string literal (16+ chars) for information density:

- Threshold: **4.5 bits/char**
- entropy ≥ 5.0 → `high` confidence → `critical` severity
- entropy 4.5–5.0 → `medium` confidence → `high` severity
- Skips: URLs, file paths, natural language sentences, short hex strings (< 32 chars)
- Skips anything already caught by Pass 1

### Severity adjustment by filename

| File type | Detection | Effect |
|---|---|---|
| `.env` | ends with `.env` | always `critical` |
| `.example` / `.sample` | contains `.example.` | downgraded to `info` |
| test file | path has `/test/` or `.spec.` | downgraded to `low` |
| normal | everything else | unchanged |

---

## Feature 1: Auto-fix (always returned when findings exist)

For every non-info finding, generates:

1. **`fixedCode`** — the original code with secrets replaced by `process.env.VAR_NAME`
2. **`envSnippet`** — ready-to-paste `.env` lines showing which vars to fill in

**How replacement works:**

For keyword patterns (`Hardcoded Password/Secret/Token`), the regex captures the full assignment like `password = "hunter2"`. The fix extracts only the trailing quoted portion (`"hunter2"`) and replaces that — avoiding broken output like `const process.env.DB_PASSWORD`.

For bare-value patterns (`sk-abc...`, `ghp_...`, etc.), tries wrapping the value in each quote type to find the occurrence in context, then replaces the quoted form.

**Env var name mapping:**

| Secret type | Env var name |
|---|---|
| OpenAI API Key | `OPENAI_API_KEY` |
| Anthropic API Key | `ANTHROPIC_API_KEY` |
| Supabase Service Role Key | `SUPABASE_SERVICE_ROLE_KEY` |
| AWS Access Key ID | `AWS_ACCESS_KEY_ID` |
| Stripe Live Secret Key | `STRIPE_SECRET_KEY` |
| MongoDB URI | `MONGODB_URI` |
| Hardcoded Password | `DB_PASSWORD` |
| Hardcoded Token | `AUTH_TOKEN` |
| High Entropy String | `SECRET_{line}` |
| … | (see `ENV_VAR_NAMES` in source) |

**Example:**

Input code:
```ts
const password = "hunter2secret";
const openaiKey = "sk-projXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
```

`autoFix.fixedCode`:
```ts
const password = process.env.DB_PASSWORD;
const openaiKey = process.env.OPENAI_API_KEY;
```

`autoFix.envSnippet`:
```
# Add to your .env file:
DB_PASSWORD=
OPENAI_API_KEY=
```

---

## Feature 2: Git history scan (`repoPath` required)

Runs `git log -p --all -n 500` on the repo and scans every **added line** (`+` prefix in diffs) across all commits and all branches, looking for the same 18 regex patterns.

**What it catches that the code scan misses:** secrets that were committed and then deleted. They're gone from your working tree but still in git history and fully recoverable by anyone with repo access.

**Deduplication:** same secret type + same first 12 chars of value = one finding across all commits (avoids reporting the same rotated key 50 times).

**Secret values are redacted in `addedLine`** — the diff line preview shows `sk-p****` not the full value.

**Output:**
```json
{
  "gitHistory": {
    "scanned": true,
    "totalCommitFindings": 3,
    "commitFindings": [
      {
        "commit": "a1b2c3d4",
        "date": "2025-11-20",
        "message": "fix: update config",
        "file": "lib/config.ts",
        "type": "OpenAI API Key",
        "severity": "critical",
        "preview": "sk-p****",
        "addedLine": "const apiKey = \"sk-p****\""
      }
    ]
  }
}
```

---

## Feature 3: Data flow tracking (`additionalFiles` required)

After finding a secret in the primary file, extracts the variable name holding it (e.g. `apiKey` from `const apiKey = "sk-..."`). Then checks each additional file for an `import` or `require` statement that references that variable name.

If an importing file has `"use client"` at the top, the risk is `critical` — the secret will be bundled into the browser. Otherwise `high`.

**Only triggers on actual import linkage** — bare variable name usage in unrelated code is not flagged (avoids false positives on common names like `key`, `config`).

**Output:**
```json
{
  "dataFlow": {
    "totalRisks": 1,
    "risks": [
      {
        "secretType": "OpenAI API Key",
        "varName": "apiKey",
        "definedIn": "lib/config.ts",
        "exposedIn": "components/Chat.tsx",
        "isClientExposed": true,
        "severity": "critical",
        "description": "\"apiKey\" (OpenAI API Key) is imported into the client component \"components/Chat.tsx\" — it will be bundled into the browser and exposed to all users."
      }
    ]
  }
}
```

---

## Full output shape

```json
{
  "summary": "2 secrets found (1 critical, 1 high)",
  "filename": "lib/config.ts",
  "totalFindings": 2,
  "findings": [ ... ],
  "autoFix": {
    "fixedCode": "...",
    "envSnippet": "# Add to your .env file:\nOPENAI_API_KEY=",
    "changesApplied": 2
  },
  "gitHistory": { ... },
  "dataFlow": { ... }
}
```

`gitHistory` only present when `repoPath` is passed.  
`dataFlow` only present when `additionalFiles` is passed and risks are found.  
`autoFix` only present when findings exist.

---

## Known limitations

- Regex patterns match format only — cannot verify if a key is active
- Entropy pass has false positives on minified JS, base64 assets, and UUIDs
- Auto-fix won't substitute correctly if the secret appears in a complex template expression (e.g. inside a JSX attribute with concatenation) — `changesApplied` will be less than `totalFindings` in that case
- Data flow requires explicit `import`/`require` — re-exports through an index barrel or dynamic imports are not detected
- Git history scan reads last 500 commits and 20MB max output — very old history in large repos may be truncated
