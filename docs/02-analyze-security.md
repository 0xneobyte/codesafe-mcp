# Tool: `analyze_security`

**File:** `src/tools/analyze-security.ts`  
**Network:** None — fully local  
**OWASP:** Multiple categories (A01–A09)

Analyzes code for security vulnerabilities using a rule engine with 20+ regex rules. Rules are filtered by framework and code context before running, so you only get relevant findings.

---

## Input

| Parameter | Type | Required | Default | Options |
|---|---|---|---|---|
| `code` | string (max 50 000 chars) | Yes | — | Any code |
| `framework` | enum | No | `generic` | `nextjs` `react` `supabase` `firebase` `prisma` `drizzle` `express` `generic` |
| `context` | enum | No | `generic` | `api_route` `database_query` `auth_handler` `config` `component` `generic` |

---

## How it works

### Rule filtering

Each rule has `frameworks[]` and `contexts[]` arrays. Before scanning, rules are filtered to only those where:

```
rule.frameworks includes framework  OR  rule.frameworks includes "generic"
AND
rule.contexts includes context  OR  rule.contexts includes "generic"
```

This means passing `framework: "nextjs"` + `context: "api_route"` runs a much tighter, more accurate rule set than the default `generic/generic`.

### Rule evaluation

For each matching rule, the regex is run against the full code string. If a match is found, additional smart guards kick in:

| Rule ID | Extra guard |
|---|---|
| `next-server-action-no-auth` | Skipped if code already contains `getServerSession`, `getSession`, `auth()`, `currentUser`, `userId =`, or `session =` |
| `supabase-rls-disabled` | Skipped if `context === "component"` (client-side Supabase queries don't need RLS concern) |
| `express-no-helmet` | Skipped if `"helmet"` appears anywhere in the code |
| `next-api-no-method-check` | Skipped if `req.method` appears anywhere in the code |

Only the **first match per rule** is reported (one finding per rule, not one per occurrence).

### All 20+ rules

#### Next.js
| Rule ID | What it catches | Severity | OWASP |
|---|---|---|---|
| `next-server-action-no-auth` | `"use server"` with no visible auth check | high | A01 |
| `next-env-client-leak` | `NEXT_PUBLIC_SECRET/KEY/TOKEN/...` env var names | critical | A02 |
| `next-headers-missing-csp` | `headers()` block without Content-Security-Policy | medium | A05 |
| `next-api-no-method-check` | Handler function accepting `req` with no `req.method` check | medium | A01 |

#### React
| Rule ID | What it catches | Severity | OWASP |
|---|---|---|---|
| `react-dangerously-set-html` | `dangerouslySetInnerHTML={{ ` | high | A03 (XSS) |
| `react-href-user-input` | Dynamic `href={...}` (potential `javascript:` injection) | medium | A03 (XSS) |

#### Supabase
| Rule ID | What it catches | Severity | OWASP |
|---|---|---|---|
| `supabase-service-role-client` | `createClient(... SERVICE_ROLE ...)` | critical | A01 |
| `supabase-rls-disabled` | `.from(...).select` in server context | medium | A01 |
| `supabase-no-anon-check` | `supabase.auth.getUser()` / `getSession()` without null check | low | A07 |

#### Prisma
| Rule ID | What it catches | Severity | OWASP |
|---|---|---|---|
| `prisma-raw-query-interpolation` | `` $queryRaw`... ${variable}` `` | critical | A03 (SQL) |
| `prisma-unsafe-raw` | `$queryRawUnsafe` / `$executeRawUnsafe` | critical | A03 (SQL) |

#### Express
| Rule ID | What it catches | Severity | OWASP |
|---|---|---|---|
| `express-no-helmet` | `express()` without `helmet` anywhere | high | A05 |
| `express-no-rate-limit` | `app.post/put/delete(...)` without rate limiting | medium | A04 |
| `express-req-body-nosql` | `find/findOne/updateOne/deleteOne(req.body)` | critical | A03 (NoSQL) |

#### Firebase
| Rule ID | What it catches | Severity | OWASP |
|---|---|---|---|
| `firebase-allow-all-read` | `allow read: if true` | critical | A01 |
| `firebase-allow-all-write` | `allow write: if true` | critical | A01 |

#### Generic (all frameworks)
| Rule ID | What it catches | Severity | OWASP |
|---|---|---|---|
| `generic-sql-template-interpolation` | `` query(`... ${variable}`) `` | critical | A03 (SQL) |
| `generic-eval-usage` | `eval(` | critical | A03 |
| `generic-console-log-secrets` | `console.log(... password/token/secret ...)` | high | A09 |
| `generic-http-not-https` | Non-localhost `http://` URLs in strings | medium | A02 |
| `generic-jwt-no-verify` | `jwt.decode(` or `atob(... token ...)` | critical | A02 |
| `generic-cors-wildcard` | `origin: "*"` or `Access-Control-Allow-Origin: "*"` | high | A05 |
| `generic-no-input-validation` | `req.body/query/params.x` without `.parse`/`.validate`/`zod`/`joi` | medium | A03 |

---

## Output

```json
{
  "summary": "2 security issues found (1 critical, 1 high)",
  "framework": "prisma",
  "context": "database_query",
  "totalFindings": 2,
  "findings": [
    {
      "ruleId": "prisma-raw-query-interpolation",
      "name": "Raw SQL with string interpolation",
      "severity": "critical",
      "owasp": "A03 — Injection (SQL Injection)",
      "line": 12,
      "description": "Raw Prisma query with template literal interpolation...",
      "fix": "Use Prisma.sql tagged template: `prisma.$queryRaw(Prisma.sql`SELECT...`)`"
    }
  ]
}
```

Findings sorted: critical → high → medium → low.

---

## Example call (MCP)

```json
{
  "tool": "analyze_security",
  "arguments": {
    "code": "const result = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`",
    "framework": "prisma",
    "context": "database_query"
  }
}
```

---

## Known limitations

- Pattern matching only — no real AST parsing, so complex multi-line patterns may not match
- `next-server-action-no-auth` has a false-negative rate: any mention of auth-looking identifiers suppresses it even if they're in unrelated code
- The `supabase-rls-disabled` rule fires on any `.from().select()` — it's a reminder check, not a proof RLS is off
