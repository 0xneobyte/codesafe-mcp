import { z } from "zod";
import { execFileSync } from "child_process";
import { readdirSync, statSync, readFileSync } from "fs";
import { join, extname, basename, relative } from "path";
import type { ToolResponse } from "../types.js";
import { toToolResponse, toErrorResponse } from "../types.js";
import { SECRET_PATTERNS, isAllowlisted } from "../lib/secret-patterns.js";
import { extractHighEntropyStrings } from "../lib/entropy.js";

export const scanSecretsSchema = {
  code: z.string().max(50000).optional().describe(
    "Code or file content to scan. Required unless 'directory' is provided."
  ),
  filename: z.string().optional().describe(
    "Filename for context (e.g. .env, config.ts) — affects severity adjustment."
  ),
  directory: z.string().optional().describe(
    "Absolute path to a directory. Recursively scans all source files (.ts, .js, .py, .env, .yaml, etc.), " +
    "skipping node_modules, .git, build, dist, and other generated dirs. " +
    "Returns per-file findings with auto-fix for each. Use this to scan a whole codebase in one call."
  ),
  repoPath: z.string().optional().describe(
    "Absolute path to the git repository root. When provided, also scans full git commit history for secrets ever committed — even if later removed."
  ),
  additionalFiles: z.array(z.object({
    filename: z.string(),
    code: z.string().max(50000),
  })).max(20).optional().describe(
    "Other files to check for secret data flow. If a secret from the primary file is imported into a client component, it is flagged as client-exposed."
  ),
};

// ─── Types ─────────────────────────────────────────────────────────────────────

interface Finding {
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp: string;
  line: number;
  preview: string;
  description: string;
  fix: string;
  entropy?: number;
}

interface InternalFinding extends Finding {
  _rawValue: string;
}

interface GitFinding {
  commit: string;
  date: string;
  message: string;
  file: string;
  type: string;
  severity: "critical" | "high";
  preview: string;
  addedLine: string;
}

interface DataFlowRisk {
  secretType: string;
  varName: string;
  definedIn: string;
  exposedIn: string;
  isClientExposed: boolean;
  severity: "critical" | "high" | "medium";
  description: string;
}

interface FileResult {
  filename: string;
  totalFindings: number;
  findings: Finding[];
  autoFix: { fixedCode: string; envSnippet: string; changesApplied: number };
}

// ─── Constants ─────────────────────────────────────────────────────────────────

const ENV_VAR_NAMES: Record<string, string> = {
  "Supabase Service Role Key": "SUPABASE_SERVICE_ROLE_KEY",
  "Supabase URL": "NEXT_PUBLIC_SUPABASE_URL",
  "OpenAI API Key": "OPENAI_API_KEY",
  "Anthropic API Key": "ANTHROPIC_API_KEY",
  "Google API Key": "GOOGLE_API_KEY",
  "GitHub Personal Access Token": "GITHUB_TOKEN",
  "GitHub OAuth Token": "GITHUB_OAUTH_TOKEN",
  "AWS Access Key ID": "AWS_ACCESS_KEY_ID",
  "Stripe Live Secret Key": "STRIPE_SECRET_KEY",
  "Stripe Test Secret Key": "STRIPE_TEST_SECRET_KEY",
  "MongoDB Connection String": "MONGODB_URI",
  "Private Key Block": "PRIVATE_KEY",
  "Hardcoded Password": "DB_PASSWORD",
  "Hardcoded Secret": "SECRET_KEY",
  "Hardcoded Token": "AUTH_TOKEN",
  "Firebase Config Key": "FIREBASE_API_KEY",
  "Twilio Auth Token": "TWILIO_AUTH_TOKEN",
  "SendGrid API Key": "SENDGRID_API_KEY",
};

const FIX_MAP: Record<string, string> = {
  "Supabase Service Role Key": "Move to server-side environment variable (SUPABASE_SERVICE_ROLE_KEY). Never expose in client code — it bypasses RLS.",
  "Supabase URL": "Move to environment variable (NEXT_PUBLIC_SUPABASE_URL). The URL itself is low risk but should not be hardcoded.",
  "OpenAI API Key": "Move to environment variable (OPENAI_API_KEY). Rotate the key immediately if committed to a repository.",
  "Anthropic API Key": "Move to environment variable (ANTHROPIC_API_KEY). Rotate immediately if exposed.",
  "Google API Key": "Move to environment variable. Restrict the key to specific APIs and referrers in Google Cloud Console.",
  "GitHub Personal Access Token": "Revoke this token on GitHub immediately. Use environment variables or GitHub Actions secrets.",
  "GitHub OAuth Token": "Revoke this token on GitHub. Use environment variables.",
  "AWS Access Key ID": "Rotate in AWS IAM immediately. Store in environment variables or AWS Secrets Manager.",
  "Stripe Live Secret Key": "Rotate in Stripe Dashboard immediately. Use environment variables — never commit live keys.",
  "Stripe Test Secret Key": "Move to environment variable (STRIPE_SECRET_KEY). Test keys are lower risk but still bad practice to hardcode.",
  "MongoDB Connection String": "Move to environment variable (MONGODB_URI). Connection strings include credentials.",
  "Private Key Block": "Never commit private keys to source control. Use a secrets manager or environment variable.",
  "Hardcoded Password": "Move to environment variable. Use a secrets manager for production credentials.",
  "Hardcoded Secret": "Move to environment variable. Never hardcode secrets in source code.",
  "Hardcoded Token": "Move to environment variable. Rotate the token if this was committed.",
  "Firebase Config Key": "Firebase config keys are client-safe when protected by Firebase Security Rules, but should still be in environment variables.",
  "Twilio Auth Token": "Rotate in Twilio Console immediately. Store in environment variable (TWILIO_AUTH_TOKEN).",
  "SendGrid API Key": "Rotate in SendGrid immediately. Store in environment variable (SENDGRID_API_KEY).",
};

const DESC_MAP: Record<string, string> = {
  "Supabase Service Role Key": "Supabase service_role key found in source code. This key bypasses Row Level Security and has full database access.",
  "OpenAI API Key": "OpenAI API key hardcoded in source. Exposure leads to unauthorized API usage and billing charges.",
  "Anthropic API Key": "Anthropic API key hardcoded in source. Exposure leads to unauthorized API usage.",
  "AWS Access Key ID": "AWS Access Key ID found. Combined with a secret key this grants AWS account access.",
  "Stripe Live Secret Key": "Stripe live secret key found. This allows full Stripe account access including charges and refunds.",
  "MongoDB Connection String": "MongoDB connection string with embedded credentials found in source code.",
  "Private Key Block": "Private key block found in source code. This may allow impersonation or decryption of sensitive data.",
  "Hardcoded Password": "Password hardcoded in source code — visible to anyone with read access to the repository.",
  "Hardcoded Secret": "Secret value hardcoded in source code.",
  "Hardcoded Token": "Authentication token hardcoded in source code.",
};

// Extensions and directories for directory scanning
const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rb", ".php", ".sh",
  ".json", ".yaml", ".yml", ".toml",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "build", "dist", "out", ".next",
  "coverage", ".cache", "__pycache__", "venv", ".venv",
  "vendor", ".turbo", ".vercel", "target", "bin", "obj",
]);

const MAX_FILE_BYTES = 50_000;
const MAX_FILES = 500;

// ─── Helpers ───────────────────────────────────────────────────────────────────

function getLineNumber(code: string, index: number): number {
  return code.slice(0, index).split("\n").length;
}

function fileContext(filename?: string): "env" | "example" | "test" | "normal" {
  if (!filename) return "normal";
  const f = filename.toLowerCase();
  if (f.endsWith(".env") || f === ".env" || f.includes("/.env") || basename(f).startsWith(".env")) return "env";
  if (f.includes(".example.") || f.includes(".sample.") || f.endsWith(".example") || f.endsWith(".sample")) return "example";
  if (f.includes("/test/") || f.includes("/__tests__/") || f.includes(".test.") || f.includes(".spec.")) return "test";
  return "normal";
}

function adjustSeverity(
  base: "critical" | "high",
  ctx: ReturnType<typeof fileContext>
): Finding["severity"] {
  if (ctx === "env") return "critical";
  if (ctx === "example") return "info";
  if (ctx === "test") return "low";
  return base;
}

function shouldScanFile(name: string): boolean {
  const b = basename(name).toLowerCase();
  if (b.startsWith(".env")) return true;
  return SCAN_EXTENSIONS.has(extname(name).toLowerCase());
}

// ─── Directory walker ──────────────────────────────────────────────────────────

function walkDirectory(dir: string): string[] {
  const files: string[] = [];

  function walk(current: string) {
    if (files.length >= MAX_FILES) return;
    let names: string[];
    try {
      names = readdirSync(current) as string[];
    } catch {
      return;
    }
    for (const name of names) {
      if (files.length >= MAX_FILES) break;
      const full = join(current, name);
      try {
        const st = statSync(full);
        if (st.isDirectory()) {
          if (!SKIP_DIRS.has(name)) walk(full);
        } else if (st.isFile() && shouldScanFile(name) && st.size <= MAX_FILE_BYTES) {
          files.push(full);
        }
      } catch { /* skip unreadable */ }
    }
  }

  walk(dir);
  return files;
}

// ─── Core scan (single file) ───────────────────────────────────────────────────

function scanSingleFile(code: string, filename?: string): InternalFinding[] {
  const ctx = fileContext(filename);
  const internalFindings: InternalFinding[] = [];
  const seenValues = new Set<string>();

  // Pass 1: Named regex patterns
  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(code)) !== null) {
      const value = match[0];
      if (isAllowlisted(value) || seenValues.has(value)) continue;
      seenValues.add(value);
      internalFindings.push({
        type: name,
        severity: adjustSeverity(severity, ctx),
        owasp: "A02 — Cryptographic Failures",
        line: getLineNumber(code, match.index),
        preview: value.slice(0, 4) + "****",
        description: DESC_MAP[name] ?? `${name} found in source code.`,
        fix: FIX_MAP[name] ?? "Move this value to an environment variable.",
        _rawValue: value,
      });
    }
  }

  // Pass 2: Shannon entropy
  for (const ef of extractHighEntropyStrings(code)) {
    if (isAllowlisted(ef.value)) continue;
    if (internalFindings.some((f) => ef.value.startsWith(f.preview.slice(0, 4)))) continue;
    if (seenValues.has(ef.value)) continue;
    seenValues.add(ef.value);
    const base: "critical" | "high" = ef.confidence === "high" ? "critical" : "high";
    internalFindings.push({
      type: "High Entropy String (possible secret)",
      severity: adjustSeverity(base, ctx),
      owasp: "A02 — Cryptographic Failures",
      line: ef.line,
      preview: ef.preview,
      entropy: ef.entropy,
      description: `High-entropy string detected (entropy: ${ef.entropy} bits/char) — likely a hardcoded token or key.`,
      fix: "If this is a secret, move it to an environment variable.",
      _rawValue: ef.value,
    });
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  internalFindings.sort(
    (a, b) => (severityOrder[a.severity] - severityOrder[b.severity]) || (a.line - b.line)
  );

  return internalFindings;
}

function toPublicFindings(internal: InternalFinding[]): Finding[] {
  return internal.map(({ _rawValue: _, ...f }) => f as Finding);
}

// ─── Auto-fix ─────────────────────────────────────────────────────────────────

function generateAutoFix(
  code: string,
  findings: InternalFinding[]
): { fixedCode: string; envSnippet: string; changesApplied: number } {
  let fixedCode = code;
  const envEntries = new Map<string, true>();
  let changesApplied = 0;

  for (const finding of findings) {
    if (finding.severity === "info") continue;

    const rawValue = finding._rawValue;
    const envVarName = ENV_VAR_NAMES[finding.type] ?? `SECRET_${finding.line}`;
    let replaced = false;

    // Keyword patterns (Hardcoded Password/Secret/Token) capture the whole assignment
    // e.g. rawValue = `password = "hunter2"` — extract just the trailing quoted portion
    const trailingQuoted = rawValue.match(/(['"`])([^'"` ]{4,})\1\s*$/);
    if (trailingQuoted) {
      const quotedPart = trailingQuoted[0].trim();
      if (fixedCode.includes(quotedPart)) {
        fixedCode = fixedCode.split(quotedPart).join(`process.env.${envVarName}`);
        replaced = true;
        changesApplied++;
      }
    }

    if (!replaced) {
      for (const q of ['"', "'", "`"]) {
        const quoted = `${q}${rawValue}${q}`;
        if (fixedCode.includes(quoted)) {
          fixedCode = fixedCode.split(quoted).join(`process.env.${envVarName}`);
          replaced = true;
          changesApplied++;
          break;
        }
      }
    }

    if (!replaced && fixedCode.includes(rawValue)) {
      fixedCode = fixedCode.split(rawValue).join(`process.env.${envVarName}`);
      changesApplied++;
    }

    envEntries.set(envVarName, true);
  }

  const envSnippet =
    envEntries.size === 0
      ? ""
      : "# Add to your .env file:\n" + [...envEntries.keys()].map((k) => `${k}=`).join("\n");

  return { fixedCode, envSnippet, changesApplied };
}

// ─── Git history ───────────────────────────────────────────────────────────────

function scanGitHistory(repoPath: string): {
  scanned: boolean;
  commitFindings: GitFinding[];
  error?: string;
} {
  let output: string;
  try {
    output = execFileSync(
      "git",
      ["log", "-p", "--all", "-n", "500", "--format=CODESAFE%x09%H%x09%aI%x09%s"],
      { cwd: repoPath, encoding: "utf-8", maxBuffer: 20 * 1024 * 1024, timeout: 30000 }
    );
  } catch (err) {
    return {
      scanned: false,
      commitFindings: [],
      error: `git log failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const commitFindings: GitFinding[] = [];
  const seen = new Set<string>();
  let currentCommit = "", currentDate = "", currentMessage = "", currentFile = "";

  for (const line of output.split("\n")) {
    if (line.startsWith("CODESAFE\t")) {
      const parts = line.slice("CODESAFE\t".length).split("\t");
      currentCommit = (parts[0] ?? "").slice(0, 8);
      currentDate = (parts[1] ?? "").split("T")[0] ?? "";
      currentMessage = (parts[2] ?? "").slice(0, 80);
      continue;
    }
    if (line.startsWith("+++ b/")) { currentFile = line.slice(6); continue; }
    if (!line.startsWith("+") || line.startsWith("+++")) continue;

    const content = line.slice(1);
    for (const { name, pattern, severity } of SECRET_PATTERNS) {
      const re = new RegExp(pattern.source, "g");
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const value = match[0];
        if (isAllowlisted(value)) continue;
        const dedupeKey = `${name}:${value.slice(0, 12)}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        const redactedLine = content.trim().replace(value, value.slice(0, 4) + "****").slice(0, 120);
        commitFindings.push({
          commit: currentCommit, date: currentDate, message: currentMessage,
          file: currentFile, type: name, severity,
          preview: value.slice(0, 4) + "****",
          addedLine: redactedLine,
        });
      }
    }
  }

  return { scanned: true, commitFindings };
}

// ─── Data flow ─────────────────────────────────────────────────────────────────

function analyzeDataFlow(
  findings: InternalFinding[],
  code: string,
  primaryFilename: string | undefined,
  additionalFiles: Array<{ filename: string; code: string }>
): DataFlowRisk[] {
  if (additionalFiles.length === 0 || findings.length === 0) return [];

  const codeLines = code.split("\n");
  const risks: DataFlowRisk[] = [];
  const reportedPairs = new Set<string>();

  for (const finding of findings) {
    if (finding.severity === "info") continue;
    const lineContent = codeLines[finding.line - 1] ?? "";
    const varMatch = lineContent.match(/(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)/);
    if (!varMatch) continue;
    const varName = varMatch[1];

    for (const { filename: targetFile, code: targetCode } of additionalFiles) {
      const pairKey = `${varName}:${targetFile}`;
      if (reportedPairs.has(pairKey)) continue;

      const isImported =
        new RegExp(`import[^'"\\n]*\\b${varName}\\b`).test(targetCode) ||
        new RegExp(`require[^'"\\n]*\\b${varName}\\b`).test(targetCode);
      if (!isImported) continue;
      reportedPairs.add(pairKey);

      const isClientExposed = /["']use client["']/.test(targetCode);
      const severity: "critical" | "high" | "medium" = isClientExposed ? "critical" : "high";

      risks.push({
        secretType: finding.type, varName,
        definedIn: primaryFilename ?? "primary file",
        exposedIn: targetFile, isClientExposed, severity,
        description: isClientExposed
          ? `"${varName}" (${finding.type}) is imported into the client component "${targetFile}" — it will be bundled into the browser and exposed to all users.`
          : `"${varName}" (${finding.type}) from "${primaryFilename ?? "primary file"}" is imported into "${targetFile}". Verify it does not reach the client.`,
      });
    }
  }

  return risks;
}

// ─── Handler ───────────────────────────────────────────────────────────────────

export async function scanSecretsHandler(input: {
  code?: string;
  filename?: string;
  directory?: string;
  repoPath?: string;
  additionalFiles?: Array<{ filename: string; code: string }>;
}): Promise<ToolResponse> {
  const { code, filename, directory, repoPath, additionalFiles = [] } = input;

  if (!code && !directory) {
    return toErrorResponse("Provide either 'code' (single file) or 'directory' (whole codebase scan).");
  }

  // ── Directory mode ────────────────────────────────────────────────────────────
  if (directory) {
    let filePaths: string[];
    try {
      filePaths = walkDirectory(directory);
    } catch (err) {
      return toErrorResponse(`Could not read directory: ${err instanceof Error ? err.message : String(err)}`);
    }

    if (filePaths.length === 0) {
      return toToolResponse({
        summary: "No scannable files found in directory",
        mode: "directory",
        directory,
        filesScanned: 0,
        filesWithFindings: 0,
        totalFindings: 0,
        results: [],
      });
    }

    const results: FileResult[] = [];
    let totalFindings = 0;
    let totalCritical = 0;
    let totalHigh = 0;

    for (const filePath of filePaths) {
      let fileCode: string;
      try {
        fileCode = readFileSync(filePath, "utf-8");
      } catch {
        continue;
      }

      const relPath = relative(directory, filePath);
      const internal = scanSingleFile(fileCode, relPath);
      if (internal.length === 0) continue;

      const findings = toPublicFindings(internal);
      const autoFix = generateAutoFix(fileCode, internal);

      totalFindings += findings.length;
      totalCritical += findings.filter((f) => f.severity === "critical").length;
      totalHigh += findings.filter((f) => f.severity === "high").length;

      results.push({
        filename: relPath,
        totalFindings: findings.length,
        findings,
        autoFix,
      });
    }

    // Sort files: most findings first
    results.sort((a, b) => b.totalFindings - a.totalFindings);

    const parts: string[] = [];
    if (totalCritical) parts.push(`${totalCritical} critical`);
    if (totalHigh) parts.push(`${totalHigh} high`);
    const rest = totalFindings - totalCritical - totalHigh;
    if (rest) parts.push(`${rest} other`);

    const summary = totalFindings === 0
      ? `All ${filePaths.length} files clean — no secrets detected`
      : `${totalFindings} secret${totalFindings === 1 ? "" : "s"} found across ${results.length} file${results.length === 1 ? "" : "s"}${parts.length ? ` (${parts.join(", ")})` : ""}`;

    // Git history still works in directory mode if repoPath is provided
    let gitHistory: ReturnType<typeof scanGitHistory> & { totalCommitFindings: number } | undefined;
    if (repoPath) {
      const gh = scanGitHistory(repoPath);
      gitHistory = { ...gh, totalCommitFindings: gh.commitFindings.length };
    }

    return toToolResponse({
      summary,
      mode: "directory",
      directory,
      filesScanned: filePaths.length,
      filesWithFindings: results.length,
      cleanFilesCount: filePaths.length - results.length,
      totalFindings,
      results,
      ...(gitHistory && { gitHistory }),
    });
  }

  // ── Single file mode ──────────────────────────────────────────────────────────
  const fileCode = code!;
  const internalFindings = scanSingleFile(fileCode, filename);
  const autoFix = generateAutoFix(fileCode, internalFindings);

  let gitHistory:
    | { scanned: boolean; totalCommitFindings: number; commitFindings: GitFinding[]; error?: string }
    | undefined;
  if (repoPath) {
    const result = scanGitHistory(repoPath);
    gitHistory = {
      scanned: result.scanned,
      totalCommitFindings: result.commitFindings.length,
      commitFindings: result.commitFindings,
      ...(result.error && { error: result.error }),
    };
  }

  const dataFlowRisks = analyzeDataFlow(internalFindings, fileCode, filename, additionalFiles);
  const findings = toPublicFindings(internalFindings);

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  let summary: string;
  if (findings.length === 0) {
    summary = "No secrets detected";
  } else {
    const parts: string[] = [];
    if (criticalCount) parts.push(`${criticalCount} critical`);
    if (highCount) parts.push(`${highCount} high`);
    const rest = findings.length - criticalCount - highCount;
    if (rest) parts.push(`${rest} other`);
    summary = `${findings.length} secret${findings.length === 1 ? "" : "s"} found (${parts.join(", ")})`;
  }

  return toToolResponse({
    summary,
    mode: "file",
    filename: filename ?? null,
    totalFindings: findings.length,
    findings,
    ...(findings.length === 0 && { clean: true }),
    ...(findings.length > 0 && { autoFix }),
    ...(gitHistory && { gitHistory }),
    ...(dataFlowRisks.length > 0 && {
      dataFlow: { totalRisks: dataFlowRisks.length, risks: dataFlowRisks },
    }),
  });
}
