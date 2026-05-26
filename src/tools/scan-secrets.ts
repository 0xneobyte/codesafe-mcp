import { z } from "zod";
import type { ToolResponse } from "../types.js";
import { toToolResponse } from "../types.js";
import { SECRET_PATTERNS, isAllowlisted } from "../lib/secret-patterns.js";
import { extractHighEntropyStrings } from "../lib/entropy.js";

export const scanSecretsSchema = {
  code: z.string().min(1).max(50000).describe(
    "The code or file content to scan for hardcoded secrets, API keys, and credentials"
  ),
  filename: z
    .string()
    .optional()
    .describe("Optional filename for context (e.g. .env, config.ts)"),
};

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

function getLineNumber(code: string, index: number): number {
  return code.slice(0, index).split("\n").length;
}

function fileContext(filename?: string): "env" | "example" | "test" | "normal" {
  if (!filename) return "normal";
  const f = filename.toLowerCase();
  if (f.endsWith(".env") || f === ".env" || f.includes("/.env")) return "env";
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

export async function scanSecretsHandler(input: {
  code: string;
  filename?: string;
}): Promise<ToolResponse> {
  const { code, filename } = input;
  const ctx = fileContext(filename);
  const findings: Finding[] = [];
  const seenValues = new Set<string>();

  // Step 1: Regex pattern matching
  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(code)) !== null) {
      const value = match[0];
      if (isAllowlisted(value)) continue;
      if (seenValues.has(value)) continue;
      seenValues.add(value);
      const line = getLineNumber(code, match.index);
      const adjustedSeverity = adjustSeverity(severity, ctx);
      findings.push({
        type: name,
        severity: adjustedSeverity,
        owasp: "A02 — Cryptographic Failures",
        line,
        preview: value.slice(0, 4) + "****",
        description: DESC_MAP[name] ?? `${name} found in source code.`,
        fix: FIX_MAP[name] ?? "Move this value to an environment variable.",
      });
    }
  }

  // Step 2: Shannon entropy analysis
  const entropyFindings = extractHighEntropyStrings(code);
  for (const ef of entropyFindings) {
    if (isAllowlisted(ef.value)) continue;
    // Skip if already caught by regex (same preview prefix)
    const alreadyCaught = findings.some((f) => ef.value.startsWith(f.preview.slice(0, 4)));
    if (alreadyCaught) continue;
    if (seenValues.has(ef.value)) continue;
    seenValues.add(ef.value);
    const entropyBaseSeverity: "critical" | "high" = ef.confidence === "high" ? "critical" : "high";
    const adjustedSeverity = adjustSeverity(entropyBaseSeverity, ctx);
    findings.push({
      type: `High Entropy String (possible secret)`,
      severity: adjustedSeverity,
      owasp: "A02 — Cryptographic Failures",
      line: ef.line,
      preview: ef.preview,
      entropy: ef.entropy,
      description: `High-entropy string detected (entropy: ${ef.entropy} bits/char) — likely a hardcoded token or key.`,
      fix: "If this is a secret, move it to an environment variable.",
    });
  }

  // Sort by severity then line number
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (severityOrder[a.severity] - severityOrder[b.severity]) || (a.line - b.line));

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
    filename: filename ?? null,
    totalFindings: findings.length,
    findings,
    ...(findings.length === 0 && { clean: true }),
  });
}
