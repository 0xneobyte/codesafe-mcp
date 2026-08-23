# Tool: `verify_package_safety`

**File:** `src/tools/verify-package-safety.ts`  
**Network:** Yes — npm registry + npm downloads API (or PyPI)  
**Data file:** `src/data/popular-packages.json` (100 popular npm packages)

Checks whether a package is safe to install before `npm install` or `pip install`. Detects three supply chain threats: hallucinated packages, typosquatting, and suspicious new packages.

---

## Input

| Parameter | Type | Required | Default | Options |
|---|---|---|---|---|
| `packageName` | string | Yes | — | The exact package name to check |
| `packageManager` | enum | No | `npm` | `npm` `pypi` |

---

## How it works

### Step 1 — Typosquat detection (local, no network)

Loads `src/data/popular-packages.json` at module startup (not per call). The list contains 100 well-known npm packages like `react`, `lodash`, `axios`, `express`, etc.

For the given package name, computes **Levenshtein edit distance** (`src/lib/levenshtein.ts`) against every package in the list:

```
"lodahs" vs "lodash"  →  edit distance 2  (swap 'h' and 's')
"requst"  vs "request" →  edit distance 1  (missing 'e')
"react"   vs "react"   →  edit distance 0  (exact match — NOT a typosquat)
```

- Edit distance 0 = exact match with popular package → skip typosquat check
- Edit distance 1 → risk escalates to `critical`
- Edit distance 2 → risk escalates to `high`
- Edit distance > 2 → no typosquat signal

### Step 2 — Registry lookup

**npm:**
Two parallel fetches:
1. `GET https://registry.npmjs.org/{name}` — metadata (creation date, description, maintainers)
2. `GET https://api.npmjs.org/downloads/point/last-month/{name}` — 30-day download count

If the registry returns 404 → package does not exist → `risk: "hallucinated"`, return immediately.

**PyPI:**
One fetch: `GET https://pypi.org/pypi/{name}/json`  
If 404 → `risk: "hallucinated"`.  
Note: PyPI download count is not available via the public API, so `monthlyDownloads` is always `null` for PyPI packages.

### Step 3 — Risk signal evaluation

After registry data is available, additional signals are checked in order:

| Signal | Condition | Risk level |
|---|---|---|
| Typosquat (strong) | edit distance = 1 | `critical` |
| Typosquat (moderate) | edit distance = 2 | `high` |
| Very new package | age < 7 days | `suspicious` (if not already critical/high) |
| New package | age 7–30 days | `warn` (if currently safe) |
| Very low downloads | < 100/month | `suspicious` (if currently safe or warn) |
| Low downloads | 100–999/month | `warn` (if currently safe) |
| Very new + very low | age < 7 days AND downloads < 100 | escalates to `suspicious` |

Risk levels in ascending order of danger: `safe` → `warn` → `suspicious` → `high` → `critical` → `hallucinated`

Risk never decreases once set — signals can only escalate it.

### Step 4 — Verdict

| Risk | Verdict prefix |
|---|---|
| `hallucinated` | `HALLUCINATED — The package "x" does not exist...` |
| `critical` | `HIGH RISK — "x" looks like a typosquat of "y"...` |
| `high` | `SUSPICIOUS — "x" is similar to "y"...` |
| `suspicious` | `SUSPICIOUS — [flags joined]. Classic supply chain attack pattern.` |
| `warn` | `WARNING — [flags joined]. Proceed with caution.` |
| `safe` | `Safe — well-established package with N monthly downloads` |

---

## Output

```json
{
  "package": "lodahs",
  "packageManager": "npm",
  "risk": "critical",
  "exists": true,
  "monthlyDownloads": 42,
  "ageInDays": 3,
  "description": "A utility library",
  "typosquatMatch": {
    "similarTo": "lodash",
    "editDistance": 2
  },
  "flags": [
    "Name is 2 edits away from popular package \"lodash\"",
    "Package created only 3 days ago",
    "Only 42 downloads last month — very low"
  ],
  "verdict": "HIGH RISK — \"lodahs\" looks like a typosquat of \"lodash\" ...",
  "recommendation": "Confirm you meant \"lodash\""
}
```

Hallucinated package (doesn't exist):
```json
{
  "package": "made-up-pkg",
  "risk": "hallucinated",
  "exists": false,
  "verdict": "HALLUCINATED — The package \"made-up-pkg\" does not exist on the npm registry.",
  "recommendation": "Check the package name for typos."
}
```

Safe package:
```json
{
  "package": "lodash",
  "risk": "safe",
  "exists": true,
  "monthlyDownloads": 52000000,
  "ageInDays": 4200,
  "verdict": "Safe — well-established package with 52,000,000 monthly downloads",
  "flags": []
}
```

---

## Example call (MCP)

```json
{
  "tool": "verify_package_safety",
  "arguments": {
    "packageName": "requst",
    "packageManager": "npm"
  }
}
```

---

## Known limitations

- Popular package list is only 100 npm packages — a typosquat against a less popular package won't be caught
- PyPI has no download count data via public API, so `monthlyDownloads` is always `null` for Python packages
- Levenshtein distance of ≤2 can produce false positives for short package names (e.g. `fs` vs `ts` — edit distance 1 but neither is a typosquat of the other)
- Does not check for known malicious packages by name (no blocklist) — only structural signals
- The popular packages list at `src/data/popular-packages.json` is static and must be manually updated
