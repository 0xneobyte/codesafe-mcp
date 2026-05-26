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
  packageName: z.string().min(1).describe("The npm or PyPI package name to check"),
  packageManager: z
    .enum(["npm", "pypi"])
    .default("npm")
    .describe("Package registry to check against"),
};

interface NpmMetadata {
  time?: { created?: string };
  "dist-tags"?: { latest?: string };
  description?: string;
  maintainers?: Array<{ name: string }>;
}

interface NpmDownloads {
  downloads?: number;
}

interface PypiMetadata {
  info?: { summary?: string; author?: string; version?: string };
  urls?: Array<{ upload_time?: string }>;
}

interface TyposquatMatch {
  similarTo: string;
  editDistance: number;
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

async function fetchPypiMetadata(name: string): Promise<{ meta: PypiMetadata | null; downloads: number | null }> {
  const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (res.status === 404) return { meta: null, downloads: null };
  if (!res.ok) throw new Error(`PyPI error: ${res.status}`);
  const meta = await res.json() as PypiMetadata;
  return { meta, downloads: null };
}

function detectTyposquat(name: string): TyposquatMatch | null {
  const lower = name.toLowerCase();
  let best: TyposquatMatch | null = null;
  for (const popular of POPULAR_PACKAGES) {
    if (popular === lower) return null; // exact match — it IS a popular package
    const dist = levenshtein(lower, popular.toLowerCase());
    if (dist <= 2 && (best === null || dist < best.editDistance)) {
      best = { similarTo: popular, editDistance: dist };
    }
  }
  return best;
}

function ageInDays(createdAt: string): number {
  return Math.floor((Date.now() - new Date(createdAt).getTime()) / 86_400_000);
}

export async function verifyPackageSafetyHandler(input: {
  packageName: string;
  packageManager: string;
}): Promise<ToolResponse> {
  const { packageName, packageManager } = input;

  // Step 1: Typosquat check (local, no network needed)
  const typosquat = detectTyposquat(packageName);

  // Step 2: Registry lookup
  let exists = false;
  let downloads: number | null = null;
  let createdAt: string | null = null;
  let description: string | null = null;

  try {
    if (packageManager === "npm") {
      const { meta, downloads: dl } = await fetchNpmMetadata(packageName);
      if (meta === null) {
        // Package doesn't exist — hallucinated
        return toToolResponse({
          package: packageName,
          packageManager,
          risk: "hallucinated",
          exists: false,
          verdict: `HALLUCINATED — The package "${packageName}" does not exist on the npm registry. Do not install it.`,
          recommendation: typosquat
            ? `Did you mean "${typosquat.similarTo}"?`
            : "Check the package name for typos.",
          typosquatMatch: typosquat,
        });
      }
      exists = true;
      downloads = dl;
      createdAt = meta.time?.created ?? null;
      description = meta.description ?? null;
    } else {
      const { meta } = await fetchPypiMetadata(packageName);
      if (meta === null) {
        return toToolResponse({
          package: packageName,
          packageManager,
          risk: "hallucinated",
          exists: false,
          verdict: `HALLUCINATED — The package "${packageName}" does not exist on PyPI. Do not install it.`,
          recommendation: "Check the package name for typos.",
          typosquatMatch: typosquat,
        });
      }
      exists = true;
      const uploadTime = meta.urls?.[0]?.upload_time ?? null;
      createdAt = uploadTime;
      description = meta.info?.summary ?? null;
    }
  } catch (err) {
    return toErrorResponse(`Registry lookup failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Step 3: Evaluate signals
  const age = createdAt ? ageInDays(createdAt) : null;

  type Risk = "hallucinated" | "critical" | "high" | "suspicious" | "warn" | "safe";
  let risk: Risk = "safe";
  const flags: string[] = [];

  if (typosquat) {
    if (typosquat.editDistance === 1) {
      risk = "critical";
      flags.push(`Name is 1 edit away from popular package "${typosquat.similarTo}" — strong typosquat signal`);
    } else {
      risk = "high";
      flags.push(`Name is 2 edits away from popular package "${typosquat.similarTo}"`);
    }
  }

  if (age !== null) {
    if (age < 7) {
      if (risk === "safe") risk = "suspicious";
      flags.push(`Package created only ${age} day${age === 1 ? "" : "s"} ago`);
    } else if (age < 30) {
      if (risk === "safe") risk = "warn";
      flags.push(`Package is relatively new (${age} days old)`);
    }
  }

  if (downloads !== null) {
    if (downloads < 100) {
      if (risk === "safe" || risk === "warn") risk = "suspicious";
      flags.push(`Only ${downloads.toLocaleString()} downloads last month — very low`);
    } else if (downloads < 1000) {
      if (risk === "safe") risk = "warn";
      flags.push(`Only ${downloads.toLocaleString()} downloads last month`);
    }
  }

  // Combine: very new + very low downloads → escalate
  if (age !== null && age < 7 && downloads !== null && downloads < 100 && risk !== "critical") {
    risk = "suspicious";
  }

  // Build verdict
  let verdict: string;
  let recommendation: string | null = null;

  switch (risk) {
    case "critical":
      verdict = `HIGH RISK — "${packageName}" looks like a typosquat of "${typosquat!.similarTo}" (edit distance ${typosquat!.editDistance}). ${flags.join(". ")}. Do NOT install.`;
      recommendation = `Use "${typosquat!.similarTo}" instead`;
      break;
    case "high":
      verdict = `SUSPICIOUS — "${packageName}" is similar to "${typosquat!.similarTo}" (edit distance ${typosquat!.editDistance}). ${flags.join(". ")}. Verify carefully before installing.`;
      recommendation = `Confirm you meant "${typosquat!.similarTo}"`;
      break;
    case "suspicious":
      verdict = `SUSPICIOUS — ${flags.join(". ")}. Classic supply chain attack pattern.`;
      recommendation = "Verify this package through trusted sources before installing.";
      break;
    case "warn":
      verdict = `WARNING — ${flags.join(". ")}. Proceed with caution.`;
      recommendation = "Verify the package is legitimate before installing in production.";
      break;
    default:
      verdict = `Safe — well-established package${downloads ? ` with ${downloads.toLocaleString()} monthly downloads` : ""}`;
  }

  return toToolResponse({
    package: packageName,
    packageManager,
    risk,
    exists,
    monthlyDownloads: downloads,
    ageInDays: age,
    description,
    typosquatMatch: typosquat,
    flags,
    verdict,
    recommendation,
  });
}
