import { z } from "zod";
import type { ToolResponse } from "../types.js";
import { toToolResponse, toErrorResponse } from "../types.js";

export const auditDependenciesSchema = {
  manifest: z.string().min(1).describe(
    "Contents of package.json, requirements.txt, go.mod, or similar dependency manifest"
  ),
  ecosystem: z
    .enum(["npm", "pypi", "go", "maven", "cargo"])
    .default("npm")
    .describe("The package ecosystem to audit"),
};

interface Package {
  name: string;
  version: string | null;
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVuln[] }>;
}

// ─── Manifest parsers ──────────────────────────────────────────────────────────

function parseNpm(manifest: string): Package[] {
  try {
    const json = JSON.parse(manifest);
    const deps = { ...json.dependencies, ...json.devDependencies };
    return Object.entries(deps).map(([name, raw]) => ({
      name,
      version: String(raw).replace(/^[^0-9]*/, "").split(" ")[0] ?? null,
    }));
  } catch {
    throw new Error("Invalid package.json — could not parse JSON");
  }
}

function parsePypi(manifest: string): Package[] {
  return manifest
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => {
      const eqMatch = l.match(/^([A-Za-z0-9_.\-]+)==([^\s,;]+)/);
      if (eqMatch) return { name: eqMatch[1], version: eqMatch[2] };
      const nameOnly = l.match(/^([A-Za-z0-9_.\-]+)/);
      return nameOnly ? { name: nameOnly[1], version: null } : null;
    })
    .filter((p): p is Package => p !== null);
}

function parseGo(manifest: string): Package[] {
  const results: Package[] = [];
  for (const line of manifest.split("\n")) {
    const m = line.trim().match(/^([a-z0-9./\-]+)\s+(v[^\s]+)/i);
    if (m) results.push({ name: m[1], version: m[2] });
  }
  return results;
}

function parseCargo(manifest: string): Package[] {
  const results: Package[] = [];
  const pkgRe = /^([a-z0-9_\-]+)\s*=\s*(?:"([^"]+)"|{[^}]*version\s*=\s*"([^"]+)"[^}]*})/im;
  for (const line of manifest.split("\n")) {
    const m = line.match(pkgRe);
    if (m) results.push({ name: m[1], version: m[2] ?? m[3] ?? null });
  }
  return results;
}

function parseManifest(manifest: string, ecosystem: string): Package[] {
  switch (ecosystem) {
    case "npm": return parseNpm(manifest);
    case "pypi": return parsePypi(manifest);
    case "go": return parseGo(manifest);
    case "cargo": return parseCargo(manifest);
    default: throw new Error(`Unsupported ecosystem: ${ecosystem}`);
  }
}

// ─── OSV.dev query ─────────────────────────────────────────────────────────────

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  go: "Go",
  maven: "Maven",
  cargo: "crates.io",
};

async function queryOsv(packages: Package[], ecosystem: string): Promise<OsvBatchResponse> {
  const osvEco = ECOSYSTEM_MAP[ecosystem] ?? ecosystem;
  const queries = packages.map((pkg) => ({
    ...(pkg.version ? { version: pkg.version } : {}),
    package: { name: pkg.name, ecosystem: osvEco },
  }));

  const res = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });

  if (!res.ok) throw new Error(`OSV.dev returned ${res.status}: ${await res.text()}`);
  return res.json() as Promise<OsvBatchResponse>;
}

// ─── Severity parsing ──────────────────────────────────────────────────────────

function parseCvssScore(scoreStr: string): number | null {
  const m = scoreStr.match(/\/(\d+\.\d+)$/) ?? scoreStr.match(/^(\d+\.\d+)$/);
  return m ? parseFloat(m[1]) : null;
}

function cvssToSeverity(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function getVulnSeverity(vuln: OsvVuln): { severity: "critical" | "high" | "medium" | "low"; cvssScore: number | null } {
  for (const s of vuln.severity ?? []) {
    const score = parseCvssScore(s.score);
    if (score !== null) return { severity: cvssToSeverity(score), cvssScore: score };
  }
  return { severity: "medium", cvssScore: null };
}

function getPatchedVersion(vuln: OsvVuln): string | null {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      const fixed = range.events.find((e) => e.fixed);
      if (fixed?.fixed) return fixed.fixed;
    }
  }
  return null;
}

function getCve(vuln: OsvVuln): string | null {
  return vuln.aliases?.find((a) => a.startsWith("CVE-")) ?? null;
}

// ─── Handler ───────────────────────────────────────────────────────────────────

export async function auditDependenciesHandler(input: {
  manifest: string;
  ecosystem: string;
}): Promise<ToolResponse> {
  const { manifest, ecosystem } = input;

  let packages: Package[];
  try {
    packages = parseManifest(manifest, ecosystem);
  } catch (err) {
    return toErrorResponse(err instanceof Error ? err.message : String(err));
  }

  if (packages.length === 0) {
    return toToolResponse({ summary: "No packages found in manifest", ecosystem, findings: [], clean: [] });
  }

  let osvResponse: OsvBatchResponse;
  try {
    osvResponse = await queryOsv(packages, ecosystem);
  } catch (err) {
    return toErrorResponse(`OSV.dev query failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  const findings: Array<Record<string, unknown>> = [];
  const clean: string[] = [];

  packages.forEach((pkg, i) => {
    const vulns = osvResponse.results[i]?.vulns ?? [];
    if (vulns.length === 0) {
      clean.push(`${pkg.name}@${pkg.version ?? "unknown"}`);
      return;
    }
    for (const vuln of vulns) {
      const { severity, cvssScore } = getVulnSeverity(vuln);
      const patchedVersion = getPatchedVersion(vuln);
      const cve = getCve(vuln);
      findings.push({
        package: pkg.name,
        installedVersion: pkg.version ?? "unknown",
        patchedVersion,
        severity,
        cvssScore,
        owasp: "A06 — Vulnerable & Outdated Components",
        cve,
        osvId: vuln.id,
        summary: vuln.summary ?? "No description available",
        fix: patchedVersion
          ? `Upgrade ${pkg.name} to ${patchedVersion} or later`
          : `Check ${vuln.id} for remediation guidance`,
      });
    }
  });

  findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity as keyof typeof order] ?? 99) - (order[b.severity as keyof typeof order] ?? 99);
  });

  const critCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  let summary: string;
  if (findings.length === 0) {
    summary = `All ${packages.length} packages clean — no known vulnerabilities`;
  } else {
    const parts: string[] = [];
    if (critCount) parts.push(`${critCount} critical`);
    if (highCount) parts.push(`${highCount} high`);
    const rest = findings.length - critCount - highCount;
    if (rest) parts.push(`${rest} other`);
    summary = `${findings.length} vulnerabilit${findings.length === 1 ? "y" : "ies"} found across ${new Set(findings.map((f) => f.package)).size} package${new Set(findings.map((f) => f.package)).size === 1 ? "" : "s"} (${parts.join(", ")})`;
  }

  return toToolResponse({ summary, ecosystem, findings, clean });
}
