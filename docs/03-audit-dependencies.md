# Tool: `audit_dependencies`

**File:** `src/tools/audit-dependencies.ts`  
**Network:** Yes — `POST https://api.osv.dev/v1/querybatch`  
**OWASP:** A06 — Vulnerable & Outdated Components

Parses a dependency manifest and queries the OSV.dev database for known CVEs against every package in a single batch request.

---

## Input

| Parameter | Type | Required | Default | Options |
|---|---|---|---|---|
| `manifest` | string | Yes | — | Raw file contents of the dependency file |
| `ecosystem` | enum | No | `npm` | `npm` `pypi` `go` `cargo` `maven` |

---

## How it works

### Step 1 — Manifest parsing

Four parsers, one per ecosystem:

**npm** (`package.json`)
- `JSON.parse()` the manifest
- Merges `dependencies` and `devDependencies`
- Strips semver prefix chars (`^`, `~`, `>=`) from version strings
- e.g. `"^18.2.0"` → version `"18.2.0"`

**pypi** (`requirements.txt`)
- Splits by newline, strips comments (`#`)
- Parses `package==1.0.0` (pinned) and `package` (unpinned, version `null`)
- Handles extras and markers: `requests[security]==2.28.0; python_requires>=3.8`

**go** (`go.mod`)
- Matches lines like `github.com/gin-gonic/gin v1.9.1`
- Captures module path + version

**cargo** (`Cargo.toml`)
- Matches `serde = "1.0"` and `serde = { version = "1.0", features = [...] }`

### Step 2 — OSV.dev batch query

Sends all packages in a single `POST /v1/querybatch`:

```json
{
  "queries": [
    { "version": "18.2.0", "package": { "name": "react", "ecosystem": "npm" } },
    { "version": "6.21.0", "package": { "name": "lodash", "ecosystem": "npm" } }
  ]
}
```

OSV ecosystem name mapping:

| Manifest | OSV ecosystem |
|---|---|
| npm | `npm` |
| pypi | `PyPI` |
| go | `Go` |
| cargo | `crates.io` |
| maven | `Maven` |

Packages without a version are still queried (OSV returns all known vulns for the package).

### Step 3 — Severity classification

OSV returns CVSS scores in the `severity[].score` field (CVSS v2/v3 vector strings or numeric). The tool extracts the score component:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  →  9.8
```

CVSS → severity mapping:

| CVSS score | Severity |
|---|---|
| ≥ 9.0 | critical |
| ≥ 7.0 | high |
| ≥ 4.0 | medium |
| < 4.0 | low |

If no CVSS score is present, defaults to `medium`.

### Step 4 — Result building

For each vulnerability:
- Extracts `CVE-XXXX-XXXXX` alias from `vuln.aliases[]`
- Extracts `fixed` version from `vuln.affected[].ranges[].events`
- Builds a fix string: `"Upgrade lodash to 4.17.21 or later"`
- Packages with zero vulns are added to the `clean[]` list

---

## Output

```json
{
  "summary": "2 vulnerabilities found across 1 package (1 critical, 1 high)",
  "ecosystem": "npm",
  "findings": [
    {
      "package": "lodash",
      "installedVersion": "4.17.4",
      "patchedVersion": "4.17.21",
      "severity": "critical",
      "cvssScore": 9.8,
      "owasp": "A06 — Vulnerable & Outdated Components",
      "cve": "CVE-2021-23337",
      "osvId": "GHSA-35jh-r3h4-6jhm",
      "summary": "Command Injection in lodash",
      "fix": "Upgrade lodash to 4.17.21 or later"
    }
  ],
  "clean": ["react@18.2.0", "typescript@5.0.4"]
}
```

If all packages are clean: `{ "summary": "All 42 packages clean — no known vulnerabilities", "findings": [], "clean": [...] }`

Findings sorted: critical → high → medium → low.

---

## Example call (MCP)

```json
{
  "tool": "audit_dependencies",
  "arguments": {
    "manifest": "{ \"dependencies\": { \"lodash\": \"^4.17.4\", \"express\": \"^4.17.1\" } }",
    "ecosystem": "npm"
  }
}
```

---

## Known limitations

- OSV.dev is the only data source — it may lag behind NVD by hours or days for brand-new CVEs
- Unpinned versions (no `==` in requirements.txt, `*` in package.json) are queried without a version, so OSV returns all historical vulns for the package — this can be noisy
- `maven` parsing is not implemented (parsers exist for npm/pypi/go/cargo only) — passing `ecosystem: "maven"` will throw an error
- Network timeout is Node's default fetch timeout (~30s); very large manifests (hundreds of packages) may be slow but the batch API handles them in one round-trip
