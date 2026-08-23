import { z } from "zod";
import * as fs from "fs";
import * as path from "path";
import type { ToolResponse } from "../types.js";

export const setupEnforcementSchema = {
  projectPath: z
    .string()
    .min(1)
    .describe("Absolute path to the project root directory to configure enforcement in"),
};

const CLAUDE_MD_RULE = `
## CodeSafe MCP — Security Tools (Mandatory)

This project has CodeSafe MCP enabled. You have access to three security tools. Use them as described below — do not skip them.

### 1. scan_secrets

Call \`scan_secrets\` whenever:
- The user asks to scan the codebase, a file, or a directory for secrets, credentials, hardcoded keys, or sensitive values
- You are about to write or have just written code that contains API keys, tokens, passwords, connection strings, or private keys
- The user asks about hardcoded environment variables or exposed credentials
- The user asks to check git history for leaked secrets

Use \`directory\` param to scan a whole codebase in one call. Use \`additionalFiles\` to check if a secret flows into a client component.

### 2. verify_package_safety

Call \`verify_package_safety\` before writing or editing ANY dependency file (package.json, requirements.txt, pyproject.toml, Pipfile) and before running any install command:

1. Call it for **every** package you are about to add — use \`packages[]\` batch mode for multiple
2. Only proceed if risk is \`safe\` or \`warn\`
3. Do NOT add the package if risk is \`suspicious\`, \`high\`, \`critical\`, or \`hallucinated\`

Never skip this — hallucinated, typosquatted, and newly published packages are real supply chain threats.

### 3. get_security_docs

Call \`get_security_docs\` before writing any security-sensitive code:
- Authentication, session management, or JWT handling
- Row Level Security or database access policies
- CORS configuration or security headers
- Input validation or SQL query construction
- Secrets handling or environment variable patterns
- Any API route with access control requirements

Pass the \`framework\` param when known (nextjs, supabase, prisma, express, react, firebase) for more precise answers.
`;

const DEP_FILES = [
  "package.json",
  "requirements.txt",
  "requirements-dev.txt",
  "requirements-prod.txt",
  "pyproject.toml",
  "Pipfile",
];

// Hook script written to .codesafe/check-packages.sh.
// Calls the CodeSafe backend for full supply chain analysis on every package
// before it is written to a dependency file or installed.
function getHookScript(backendUrl: string, apiKey: string): string {
  const endpoint = `${backendUrl}/api/v1/package/verify`;
  return `#!/usr/bin/env bash
# CodeSafe package safety hook
# Fires before Write, Edit, and Bash tool calls.
# Calls the CodeSafe backend for full supply chain analysis (typosquat, age, downloads).
# Packages published within 48 hours or flagged as suspicious/high/critical/hallucinated are blocked.

set -uo pipefail

input=$(cat)

printf '%s' "$input" | python3 << 'PYEOF'
import sys, json, urllib.request, urllib.error

BACKEND = "${endpoint}"
API_KEY = "${apiKey}"
BLOCK_RISKS = {"suspicious", "high", "critical", "hallucinated"}

try:
    d = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)

tool_name = d.get("tool_name", "")
ti = d.get("tool_input", {})

import re

DEP_FILE_RE = re.compile(
    r"(package\\.json|requirements[\\w\\-]*\\.txt|pyproject\\.toml|Pipfile)$"
)

def is_npm_file(fp): return fp.endswith("package.json")
def is_py_file(fp): return bool(re.search(r"(requirements[\\w\\-]*\\.txt|pyproject\\.toml|Pipfile)$", fp))

def strip_py_version(pkg):
    return re.sub(r"[>=<!;\\s#\\[].*", "", pkg).strip()

def strip_npm_version(pkg):
    if pkg.startswith("@"):
        parts = pkg[1:].split("@", 1)
        return "@" + parts[0]
    return pkg.split("@")[0]

def call_backend(name, manager):
    body = json.dumps({"packageName": name, "packageManager": manager}).encode()
    req = urllib.request.Request(
        BACKEND,
        data=body,
        headers={"Content-Type": "application/json", "X-Api-Key": API_KEY},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"CodeSafe backend error {e.code} for {name}\\n")
        return None
    except Exception as e:
        sys.stderr.write(f"CodeSafe backend unreachable ({e}) — skipping check for {name}\\n")
        return None

def check(name, manager):
    if not name or name.startswith("-"):
        return
    result = call_backend(name, manager)
    if result is None:
        return  # backend unreachable — do not block
    risk = result.get("risk", "safe")
    verdict = result.get("verdict", "")
    flags = result.get("flags", [])
    sys.stderr.write(f"\\nCodeSafe [{risk.upper()}] {name}: {verdict}\\n")
    for flag in flags:
        sys.stderr.write(f"  • {flag}\\n")
    if risk in BLOCK_RISKS:
        rec = result.get("recommendation", "")
        sys.stderr.write(f"  ❌ BLOCKED — {rec}\\n")
        sys.exit(1)
    sys.stderr.write(f"  ✓ Allowed\\n")

NON_PKG_KEYS = {
    "name","version","description","main","module","exports","types","typings",
    "scripts","dependencies","devDependencies","peerDependencies","optionalDependencies",
    "bundledDependencies","license","author","repository","homepage","bugs","keywords",
    "files","bin","engines","os","cpu","private","publishConfig","workspaces","resolutions",
}

def extract_npm_from_full(content):
    try:
        data = json.loads(content)
        pkgs = {}
        for section in ("dependencies","devDependencies","peerDependencies","optionalDependencies"):
            pkgs.update(data.get(section, {}))
        return list(pkgs.keys())
    except json.JSONDecodeError:
        return []

def extract_npm_from_fragment(fragment):
    found = []
    for m in re.finditer(r'"(@?[a-zA-Z0-9][a-zA-Z0-9\\-._/]*)"\\ *:', fragment):
        key = m.group(1)
        if key not in NON_PKG_KEYS and not key.startswith("_"):
            found.append(key)
    return found

def extract_py(content):
    pkgs = []
    for line in content.splitlines():
        name = strip_py_version(line)
        if name and not name.startswith(("#", "-", ".")):
            pkgs.append(name)
    return pkgs


# Write: full file being created
if tool_name == "Write":
    fp = ti.get("file_path", "")
    if not DEP_FILE_RE.search(fp):
        sys.exit(0)
    content = ti.get("content", "")
    if is_npm_file(fp):
        for pkg in extract_npm_from_full(content):
            check(pkg, "npm")
    elif is_py_file(fp):
        for pkg in extract_py(content):
            check(pkg, "pypi")

# Edit: only the new content being inserted
elif tool_name == "Edit":
    fp = ti.get("file_path", "")
    if not DEP_FILE_RE.search(fp):
        sys.exit(0)
    new_str = ti.get("new_string", "")
    if is_npm_file(fp):
        for pkg in extract_npm_from_fragment(new_str):
            check(pkg, "npm")
    elif is_py_file(fp):
        for pkg in extract_py(new_str):
            check(pkg, "pypi")

# Bash: install commands — final backup
elif tool_name == "Bash":
    cmd = ti.get("command", "")

    m = re.match(r"^npm (?:install|i|add)\\s+(.*)", cmd)
    if m:
        for pkg in m.group(1).split():
            check(strip_npm_version(pkg), "npm")

    m = re.match(r"^pip3? install\\s+(.*)", cmd)
    if m:
        args = m.group(1)
        req = re.search(r"-r\\s+(\\S+)", args)
        if req:
            import os
            req_file = req.group(1)
            if os.path.exists(req_file):
                with open(req_file) as f:
                    for line in f:
                        name = strip_py_version(line)
                        if name:
                            check(name, "pypi")
        else:
            for pkg in args.split():
                if not pkg.startswith("-"):
                    check(strip_py_version(pkg), "pypi")

sys.exit(0)
PYEOF
`;
}

export async function setupEnforcementHandler({
  projectPath,
}: {
  projectPath: string;
}): Promise<ToolResponse> {
  if (!fs.existsSync(projectPath)) {
    return {
      content: [
        { type: "text", text: JSON.stringify({ error: `Project path does not exist: ${projectPath}` }) },
      ],
    };
  }

  const backendUrl = process.env.CODESAFE_BACKEND_URL ?? "http://localhost:8000";
  const apiKey = process.env.CODESAFE_API_KEY ?? "";
  const results: string[] = [];

  // 1. Write CLAUDE.md rule
  const claudeMdPath = path.join(projectPath, "CLAUDE.md");
  const marker = "## Package Safety — Mandatory (CodeSafe)";

  if (fs.existsSync(claudeMdPath)) {
    const existing = fs.readFileSync(claudeMdPath, "utf-8");
    if (!existing.includes(marker)) {
      fs.appendFileSync(claudeMdPath, "\n" + CLAUDE_MD_RULE);
      results.push("✓ Appended package safety rule to CLAUDE.md");
    } else {
      results.push("ℹ CLAUDE.md already contains package safety rule — skipped");
    }
  } else {
    fs.writeFileSync(claudeMdPath, CLAUDE_MD_RULE.trimStart());
    results.push("✓ Created CLAUDE.md with package safety rule");
  }

  // 2. Write hook script
  const codesafeDir = path.join(projectPath, ".codesafe");
  if (!fs.existsSync(codesafeDir)) {
    fs.mkdirSync(codesafeDir, { recursive: true });
  }
  const scriptPath = path.join(codesafeDir, "check-packages.sh");
  fs.writeFileSync(scriptPath, getHookScript(backendUrl, apiKey));
  fs.chmodSync(scriptPath, 0o755);
  results.push("✓ Created hook script at .codesafe/check-packages.sh");

  // 3. Merge .claude/settings.json — hooks for Write, Edit, Bash
  const claudeDir = path.join(projectPath, ".claude");
  if (!fs.existsSync(claudeDir)) {
    fs.mkdirSync(claudeDir, { recursive: true });
  }

  const settingsPath = path.join(claudeDir, "settings.json");
  let settings: Record<string, unknown> = {};
  if (fs.existsSync(settingsPath)) {
    try {
      settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    } catch {
      settings = {};
    }
  }

  const hooks = (settings.hooks ?? {}) as Record<string, unknown[]>;
  const preToolUse = (hooks.PreToolUse ?? []) as Array<Record<string, unknown>>;

  const alreadyConfigured = preToolUse.some((entry) => {
    const entryHooks = entry.hooks as Array<Record<string, unknown>> | undefined;
    return entryHooks?.some(
      (h) => typeof h.command === "string" && h.command.includes("check-packages.sh")
    );
  });

  if (!alreadyConfigured) {
    for (const toolName of ["Write", "Edit", "Bash"]) {
      preToolUse.push({
        matcher: toolName,
        hooks: [{ type: "command", command: `bash "${scriptPath}"` }],
      });
    }
    hooks.PreToolUse = preToolUse;
    settings.hooks = hooks;
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
    results.push("✓ Added Write, Edit, and Bash PreToolUse hooks to .claude/settings.json");
  } else {
    results.push("ℹ Hooks already configured in .claude/settings.json — skipped");
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            success: true,
            projectPath,
            results,
            watchedFiles: DEP_FILES,
            backendUrl,
            checks: [
              "Hallucination — package does not exist on registry",
              "Typosquat — name within edit distance 1-2 of a popular package",
              "48-hour rule — packages published in last 48h are blocked",
              "Age — packages < 7 days flagged suspicious, < 30 days warned",
              "Downloads — < 100/month suspicious, < 1000/month warned",
            ],
            enforcementOrder: [
              "1. AI calls verify_package_safety for each package (batch supported)",
              "2. Write/Edit hook fires → full supply chain check before file is saved",
              "3. Bash hook fires → full supply chain check before npm/pip install runs",
            ],
            note: "Commit .codesafe/ and .claude/settings.json so the whole team is protected.",
          },
          null,
          2
        ),
      },
    ],
  };
}
