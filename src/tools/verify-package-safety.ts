import { z } from "zod";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { join, dirname } from "path";
import type { ToolResponse } from "../types.js";
import { toToolResponse, toErrorResponse } from "../types.js";
import { levenshtein } from "../lib/levenshtein.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const POPULAR_PACKAGES: string[] = JSON.parse(
  readFileSync(join(__dirname, "../data/popular-packages.json"), "utf-8")
);

export const verifyPackageSafetySchema = {
  packageName: z
    .string()
    .min(1)
    .optional()
    .describe("Single package name to check"),
  packageManager: z
    .enum(["npm", "pypi"])
    .default("npm")
    .describe("Package registry — used with packageName"),
  packages: z
    .array(
      z.object({
        packageName: z.string().min(1),
        packageManager: z.enum(["npm", "pypi"]).default("npm"),
      })
    )
    .optional()
    .describe("Batch mode: list of packages to check at once. Use this when adding multiple packages to a dependency file."),
};

// ── Backend API call ──────────────────────────────────────────────────────────

const BACKEND_URL = process.env.CODESAFE_BACKEND_URL ?? "http://localhost:8000";
const API_KEY = process.env.CODESAFE_API_KEY ?? "";
const API_PREFIX = "/api/v1";

interface BackendResult {
  package: string;
  packageManager: string;
  risk: string;
  exists: boolean;
  monthlyDownloads?: number | null;
  ageInDays?: number | null;
  ageInHours?: number | null;
  description?: string | null;
  typosquatMatch?: { similarTo: string; editDistance: number } | null;
  flags: string[];
  verdict: string;
  recommendation?: string | null;
  blocked: boolean;
}

async function callBackendSingle(packageName: string, packageManager: string): Promise<BackendResult> {
  const res = await fetch(`${BACKEND_URL}${API_PREFIX}/package/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Api-Key": API_KEY },
    body: JSON.stringify({ packageName, packageManager }),
  });
  if (!res.ok) throw new Error(`Backend error: ${res.status}`);
  return res.json() as Promise<BackendResult>;
}

async function callBackendBatch(
  packages: Array<{ packageName: string; packageManager: string }>
): Promise<BackendResult[]> {
  const res = await fetch(`${BACKEND_URL}${API_PREFIX}/package/verify-batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Api-Key": API_KEY },
    body: JSON.stringify({ packages }),
  });
  if (!res.ok) throw new Error(`Backend error: ${res.status}`);
  return res.json() as Promise<BackendResult[]>;
}

// ── Local fallback (used when backend is unavailable) ─────────────────────────

interface NpmMetadata {
  time?: { created?: string };
  description?: string;
}

interface NpmDownloads {
  downloads?: number;
}

interface PypiMetadata {
  info?: { summary?: string };
  urls?: Array<{ upload_time?: string }>;
}

async function fetchNpmMetadata(name: string): Promise<{ meta: NpmMetadata | null; downloads: number | null }> {
  const [metaRes, dlRes] = await Promise.all([
    fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`),
    fetch(`https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(name)}`),
  ]);
  if (metaRes.status === 404) return { meta: null, downloads: null };
  if (!metaRes.ok) throw new Error(`npm registry error: ${metaRes.status}`);
  const meta = await metaRes.json() as NpmMetadata;
  const dlData: NpmDownloads = dlRes.ok ? await dlRes.json() as NpmDownloads : {};
  return { meta, downloads: dlData.downloads ?? null };
}

async function fetchPypiMetadata(name: string): Promise<{ meta: PypiMetadata | null }> {
  const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (res.status === 404) return { meta: null };
  if (!res.ok) throw new Error(`PyPI error: ${res.status}`);
  return { meta: await res.json() as PypiMetadata };
}

function detectTyposquat(name: string): { similarTo: string; editDistance: number } | null {
  const lower = name.toLowerCase();
  let best: { similarTo: string; editDistance: number } | null = null;
  for (const popular of POPULAR_PACKAGES) {
    if (popular === lower) return null;
    const dist = levenshtein(lower, popular.toLowerCase());
    if (dist <= 2 && (best === null || dist < best.editDistance)) {
      best = { similarTo: popular, editDistance: dist };
    }
  }
  return best;
}

function hoursAgo(iso: string): number {
  return (Date.now() - new Date(iso).getTime()) / 3_600_000;
}

const TOO_NEW_HOURS = 48;

async function localCheck(packageName: string, packageManager: string): Promise<BackendResult> {
  const typosquat = detectTyposquat(packageName);

  let exists = false;
  let downloads: number | null = null;
  let createdIso: string | null = null;
  let description: string | null = null;

  if (packageManager === "npm") {
    const { meta, downloads: dl } = await fetchNpmMetadata(packageName);
    if (meta === null) {
      return {
        package: packageName, packageManager, risk: "hallucinated", exists: false,
        flags: [],
        verdict: `HALLUCINATED — "${packageName}" does not exist on npm. Do not install.`,
        recommendation: typosquat ? `Did you mean "${typosquat.similarTo}"?` : "Check for typos.",
        typosquatMatch: typosquat, blocked: true,
      };
    }
    exists = true;
    downloads = dl;
    createdIso = meta.time?.created ?? null;
    description = meta.description ?? null;
  } else {
    const { meta } = await fetchPypiMetadata(packageName);
    if (meta === null) {
      return {
        package: packageName, packageManager, risk: "hallucinated", exists: false,
        flags: [],
        verdict: `HALLUCINATED — "${packageName}" does not exist on PyPI. Do not install.`,
        recommendation: "Check for typos.",
        typosquatMatch: typosquat, blocked: true,
      };
    }
    exists = true;
    createdIso = meta.urls?.[0]?.upload_time ?? null;
    description = meta.info?.summary ?? null;
  }

  const hours = createdIso ? hoursAgo(createdIso) : null;
  const ageInDays = hours !== null ? Math.round(hours / 24 * 10) / 10 : null;

  type Risk = "safe" | "warn" | "suspicious" | "high" | "critical";
  let risk: Risk = "safe";
  const flags: string[] = [];

  if (typosquat) {
    if (typosquat.editDistance === 1) { risk = "critical"; flags.push(`Name is 1 edit away from popular package "${typosquat.similarTo}" — strong typosquat signal`); }
    else { risk = "high"; flags.push(`Name is 2 edits away from popular package "${typosquat.similarTo}"`); }
  }

  if (hours !== null) {
    if (hours < TOO_NEW_HOURS) {
      if (risk !== "critical" && risk !== "high") risk = "suspicious";
      flags.push(`Published only ${Math.floor(hours)}h ago — within the ${TOO_NEW_HOURS}h high-risk window`);
    } else if (hours < 7 * 24) {
      if (risk === "safe") risk = "suspicious";
      flags.push(`Package created only ${Math.floor(hours / 24)} day(s) ago`);
    } else if (hours < 30 * 24) {
      if (risk === "safe") risk = "warn";
      flags.push(`Package is relatively new (${Math.floor(hours / 24)} days old)`);
    }
  }

  if (downloads !== null) {
    if (downloads < 100) { if (risk === "safe" || risk === "warn") risk = "suspicious"; flags.push(`Only ${downloads.toLocaleString()} downloads last month — very low`); }
    else if (downloads < 1000) { if (risk === "safe") risk = "warn"; flags.push(`Only ${downloads.toLocaleString()} downloads last month`); }
  }

  if (hours !== null && hours < TOO_NEW_HOURS && downloads !== null && downloads < 100 && risk !== "critical" && risk !== "high") {
    risk = "suspicious";
  }

  let verdict: string;
  let recommendation: string | null = null;

  switch (risk) {
    case "critical":
      verdict = `HIGH RISK — "${packageName}" looks like a typosquat of "${typosquat!.similarTo}" (edit distance ${typosquat!.editDistance}). ${flags.join(". ")}. Do NOT install.`;
      recommendation = `Use "${typosquat!.similarTo}" instead`;
      break;
    case "high":
      verdict = `SUSPICIOUS — "${packageName}" is similar to "${typosquat!.similarTo}" (edit distance ${typosquat!.editDistance}). ${flags.join(". ")}. Verify carefully.`;
      recommendation = `Confirm you meant "${typosquat!.similarTo}"`;
      break;
    case "suspicious":
      verdict = `SUSPICIOUS — ${flags.join(". ")}. Classic supply chain attack pattern.`;
      recommendation = "Verify through trusted sources before installing.";
      break;
    case "warn":
      verdict = `WARNING — ${flags.join(". ")}. Proceed with caution.`;
      recommendation = "Verify the package is legitimate before installing in production.";
      break;
    default:
      verdict = `Safe — well-established package${downloads ? ` with ${downloads.toLocaleString()} monthly downloads` : ""}`;
  }

  const BLOCK_RISKS = new Set(["suspicious", "high", "critical", "hallucinated"]);

  return {
    package: packageName, packageManager, risk, exists,
    monthlyDownloads: downloads, ageInDays, ageInHours: hours !== null ? Math.round(hours * 10) / 10 : null,
    description, typosquatMatch: typosquat, flags, verdict, recommendation,
    blocked: BLOCK_RISKS.has(risk),
  };
}

// ── Handler ───────────────────────────────────────────────────────────────────

export async function verifyPackageSafetyHandler(input: {
  packageName?: string;
  packageManager?: string;
  packages?: Array<{ packageName: string; packageManager?: string }>;
}): Promise<ToolResponse> {
  const { packageName, packageManager = "npm", packages } = input;

  // Batch mode
  if (packages && packages.length > 0) {
    const normalised = packages.map((p) => ({
      packageName: p.packageName,
      packageManager: (p.packageManager ?? "npm") as string,
    }));

    let results: BackendResult[];
    try {
      results = await callBackendBatch(normalised);
    } catch {
      // Fall back to local checks in parallel
      results = await Promise.all(
        normalised.map((p) => localCheck(p.packageName, p.packageManager))
      );
    }

    const blocked = results.filter((r) => r.blocked);
    return toToolResponse({ results, anyBlocked: blocked.length > 0, blocked: blocked.map((r) => r.package) });
  }

  // Single mode
  if (!packageName) {
    return toErrorResponse("Provide either packageName or packages[]");
  }

  try {
    const result = await callBackendSingle(packageName, packageManager);
    return toToolResponse(result);
  } catch {
    // Backend unavailable — run local check
    try {
      const result = await localCheck(packageName, packageManager);
      return toToolResponse(result);
    } catch (err) {
      return toErrorResponse(`Check failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
