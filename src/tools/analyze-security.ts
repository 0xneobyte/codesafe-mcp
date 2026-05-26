import { z } from "zod";
import type { ToolResponse } from "../types.js";
import { toToolResponse } from "../types.js";

export const analyzeSecuritySchema = {
  code: z.string().min(1).max(50000).describe(
    "The code snippet to analyze for security vulnerabilities"
  ),
  framework: z
    .enum(["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express", "generic"])
    .default("generic")
    .describe("The framework or stack the code belongs to"),
  context: z
    .enum(["api_route", "database_query", "auth_handler", "config", "component", "generic"])
    .default("generic")
    .describe("The type of code being analyzed for more accurate rules"),
};

interface Rule {
  id: string;
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium" | "low";
  owasp: string;
  description: string;
  fix: string;
  frameworks: string[];
  contexts: string[];
}

// ─── Rule definitions ──────────────────────────────────────────────────────────

const RULES: Rule[] = [
  // ── Next.js ──────────────────────────────────────────────────────────────────
  {
    id: "next-server-action-no-auth",
    name: "Server Action without authentication check",
    pattern: /["']use server["']/,
    severity: "high",
    owasp: "A01 — Broken Access Control",
    description: "Server Action found with no visible auth check. Without authentication, any user can invoke this action.",
    fix: "Add auth check at the top: `const session = await getServerSession(); if (!session) throw new Error('Unauthorized');`",
    frameworks: ["nextjs"],
    contexts: ["api_route", "generic"],
  },
  {
    id: "next-env-client-leak",
    name: "Server env variable exposed to client",
    pattern: /NEXT_PUBLIC_(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|SERVICE_ROLE)/i,
    severity: "critical",
    owasp: "A02 — Cryptographic Failures",
    description: "Sensitive value is prefixed with NEXT_PUBLIC_ — this is bundled into the client and visible to all users.",
    fix: "Remove the NEXT_PUBLIC_ prefix. Access this value server-side only via process.env.",
    frameworks: ["nextjs"],
    contexts: ["config", "generic", "component", "api_route"],
  },
  {
    id: "next-headers-missing-csp",
    name: "Next.js config without Content-Security-Policy",
    pattern: /headers\s*\(\s*\)\s*\{[\s\S]*?return\s*\[[\s\S]*?\]/,
    severity: "medium",
    owasp: "A05 — Security Misconfiguration",
    description: "Custom headers defined but no Content-Security-Policy header detected.",
    fix: "Add a CSP header: `{ key: 'Content-Security-Policy', value: \"default-src 'self'\" }`",
    frameworks: ["nextjs"],
    contexts: ["config"],
  },
  {
    id: "next-api-no-method-check",
    name: "API route with no HTTP method validation",
    pattern: /export\s+(?:async\s+)?(?:default\s+)?function\s+\w+\s*\(\s*req\s*[,:)]/,
    severity: "medium",
    owasp: "A01 — Broken Access Control",
    description: "API route handler does not appear to check req.method — all HTTP methods will be accepted.",
    fix: "Add method check: `if (req.method !== 'POST') return res.status(405).end();`",
    frameworks: ["nextjs"],
    contexts: ["api_route"],
  },

  // ── React ─────────────────────────────────────────────────────────────────────
  {
    id: "react-dangerously-set-html",
    name: "dangerouslySetInnerHTML usage",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/,
    severity: "high",
    owasp: "A03 — Injection (XSS)",
    description: "dangerouslySetInnerHTML can introduce XSS if the content is user-controlled or from an untrusted source.",
    fix: "Sanitize with DOMPurify: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}`. Or restructure to avoid raw HTML injection.",
    frameworks: ["react", "nextjs"],
    contexts: ["component", "generic"],
  },
  {
    id: "react-href-user-input",
    name: "Potential javascript: URI in href",
    pattern: /href\s*=\s*\{(?:[^{}]|\{[^{}]*\})*\}/,
    severity: "medium",
    owasp: "A03 — Injection (XSS)",
    description: "Dynamic href value — if user-controlled, an attacker could inject `javascript:` URIs.",
    fix: "Validate that the URL starts with `https://` or `/` before using it in href. Use a URL allowlist.",
    frameworks: ["react", "nextjs"],
    contexts: ["component"],
  },

  // ── Supabase ──────────────────────────────────────────────────────────────────
  {
    id: "supabase-service-role-client",
    name: "Supabase client created with service_role key",
    pattern: /createClient\s*\([^)]*SERVICE_ROLE[^)]*\)/i,
    severity: "critical",
    owasp: "A01 — Broken Access Control",
    description: "Supabase client initialized with service_role key bypasses Row Level Security entirely.",
    fix: "Use the anon key for client-side code. Only use service_role in server-side code that deliberately needs to bypass RLS.",
    frameworks: ["supabase"],
    contexts: ["generic", "api_route", "database_query", "auth_handler"],
  },
  {
    id: "supabase-rls-disabled",
    name: "RLS appears to be disabled",
    pattern: /\.from\s*\([^)]+\)\s*\.select/,
    severity: "medium",
    owasp: "A01 — Broken Access Control",
    description: "Supabase query found — ensure Row Level Security is enabled on this table.",
    fix: "Enable RLS: `ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;` and create appropriate policies.",
    frameworks: ["supabase"],
    contexts: ["database_query", "api_route", "generic"],
  },
  {
    id: "supabase-no-anon-check",
    name: "Supabase auth without session validation",
    pattern: /supabase\.auth\.getUser\(\)|supabase\.auth\.getSession\(\)/,
    severity: "low",
    owasp: "A07 — Identification & Authentication Failures",
    description: "Auth session retrieved but no null-check visible. Unauthenticated users may proceed if the check is missing.",
    fix: "Always check: `const { data: { user } } = await supabase.auth.getUser(); if (!user) redirect('/login');`",
    frameworks: ["supabase"],
    contexts: ["auth_handler", "api_route", "generic"],
  },

  // ── Prisma ────────────────────────────────────────────────────────────────────
  {
    id: "prisma-raw-query-interpolation",
    name: "Raw SQL with string interpolation",
    pattern: /\$queryRaw`[^`]*\$\{|prisma\.\$executeRaw`[^`]*\$\{/,
    severity: "critical",
    owasp: "A03 — Injection (SQL Injection)",
    description: "Raw Prisma query with template literal interpolation detected — this is vulnerable to SQL injection.",
    fix: "Use Prisma.sql tagged template: `prisma.$queryRaw(Prisma.sql\\`SELECT * FROM users WHERE id = ${userId}\\`)` which safely parameterizes values.",
    frameworks: ["prisma"],
    contexts: ["database_query", "generic"],
  },
  {
    id: "prisma-unsafe-raw",
    name: "Unsafe raw query execution",
    pattern: /\$queryRawUnsafe|executeRawUnsafe/,
    severity: "critical",
    owasp: "A03 — Injection (SQL Injection)",
    description: "$queryRawUnsafe or $executeRawUnsafe used — these skip Prisma's parameterization entirely.",
    fix: "Replace with $queryRaw or $executeRaw with Prisma.sql parameterization.",
    frameworks: ["prisma"],
    contexts: ["database_query", "generic"],
  },

  // ── Express ───────────────────────────────────────────────────────────────────
  {
    id: "express-no-helmet",
    name: "Express app without Helmet",
    pattern: /express\(\)(?![\s\S]*helmet)/,
    severity: "high",
    owasp: "A05 — Security Misconfiguration",
    description: "Express application initialized without Helmet middleware — security headers are not set.",
    fix: "Add `app.use(helmet())` right after `const app = express()` to set secure HTTP headers.",
    frameworks: ["express"],
    contexts: ["config", "generic"],
  },
  {
    id: "express-no-rate-limit",
    name: "Express route without rate limiting",
    pattern: /app\.(post|put|delete)\s*\(\s*["']/i,
    severity: "medium",
    owasp: "A04 — Insecure Design",
    description: "Express mutation route without visible rate limiting — vulnerable to brute force and abuse.",
    fix: "Apply express-rate-limit: `const limiter = rateLimit({ windowMs: 15*60*1000, max: 100 }); app.use(limiter);`",
    frameworks: ["express"],
    contexts: ["api_route", "generic"],
  },
  {
    id: "express-req-body-nosql",
    name: "MongoDB query with unvalidated req.body",
    pattern: /(?:find|findOne|updateOne|deleteOne)\s*\(\s*req\.body/i,
    severity: "critical",
    owasp: "A03 — Injection (NoSQL Injection)",
    description: "MongoDB query constructed directly from req.body — vulnerable to NoSQL injection via `$where`, `$gt`, etc.",
    fix: "Validate and sanitize req.body with zod or express-validator before using in MongoDB queries. Never pass raw req.body to MongoDB.",
    frameworks: ["express", "generic"],
    contexts: ["api_route", "database_query", "generic"],
  },

  // ── Firebase ──────────────────────────────────────────────────────────────────
  {
    id: "firebase-allow-all-read",
    name: "Firestore rules allow all reads",
    pattern: /allow\s+read\s*:\s*if\s+true/,
    severity: "critical",
    owasp: "A01 — Broken Access Control",
    description: "Firestore security rule allows all reads without authentication or ownership check.",
    fix: "Replace `if true` with `if request.auth != null` or a more specific ownership rule.",
    frameworks: ["firebase"],
    contexts: ["config", "generic"],
  },
  {
    id: "firebase-allow-all-write",
    name: "Firestore rules allow all writes",
    pattern: /allow\s+write\s*:\s*if\s+true/,
    severity: "critical",
    owasp: "A01 — Broken Access Control",
    description: "Firestore security rule allows all writes — anyone can modify this collection.",
    fix: "Replace `if true` with `if request.auth.uid == resource.data.userId` or appropriate ownership check.",
    frameworks: ["firebase"],
    contexts: ["config", "generic"],
  },

  // ── Generic ───────────────────────────────────────────────────────────────────
  {
    id: "generic-sql-template-interpolation",
    name: "SQL query with template literal interpolation",
    pattern: /(?:query|execute|raw)\s*\(`[^`]*\$\{/i,
    severity: "critical",
    owasp: "A03 — Injection (SQL Injection)",
    description: "SQL query built with template literal string interpolation — vulnerable to SQL injection.",
    fix: "Use parameterized queries: pass variables as separate parameters, not interpolated into the SQL string.",
    frameworks: ["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express", "generic"],
    contexts: ["api_route", "database_query", "auth_handler", "generic"],
  },
  {
    id: "generic-eval-usage",
    name: "eval() usage",
    pattern: /(?<![a-zA-Z])eval\s*\(/,
    severity: "critical",
    owasp: "A03 — Injection",
    description: "eval() executes arbitrary code — if any input reaches eval(), it's a code injection vulnerability.",
    fix: "Remove eval(). Use JSON.parse() for data, or restructure to avoid dynamic code execution.",
    frameworks: ["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express", "generic"],
    contexts: ["api_route", "database_query", "auth_handler", "config", "component", "generic"],
  },
  {
    id: "generic-console-log-secrets",
    name: "Potential secret logged to console",
    pattern: /console\.log\s*\([^)]*(?:password|token|secret|key|auth)[^)]*\)/i,
    severity: "high",
    owasp: "A09 — Security Logging & Monitoring Failures",
    description: "Sensitive data may be logged to console — visible in server logs, browser DevTools, or error tracking.",
    fix: "Remove sensitive data from logs. If debugging, use a logger with log-level filtering and PII redaction.",
    frameworks: ["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express", "generic"],
    contexts: ["api_route", "database_query", "auth_handler", "config", "component", "generic"],
  },
  {
    id: "generic-http-not-https",
    name: "HTTP URL used instead of HTTPS",
    pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1)[^"']+["']/,
    severity: "medium",
    owasp: "A02 — Cryptographic Failures",
    description: "HTTP URL detected — data transmitted in plaintext, vulnerable to interception.",
    fix: "Use HTTPS for all external URLs.",
    frameworks: ["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express", "generic"],
    contexts: ["api_route", "database_query", "auth_handler", "config", "component", "generic"],
  },
  {
    id: "generic-jwt-no-verify",
    name: "JWT decoded without verification",
    pattern: /jwt\.decode\s*\(|atob\s*\([^)]*token[^)]*\)/i,
    severity: "critical",
    owasp: "A02 — Cryptographic Failures",
    description: "JWT is decoded but not verified — an attacker can forge any payload by crafting a token.",
    fix: "Use jwt.verify(token, secret) instead of jwt.decode(). Always verify the signature.",
    frameworks: ["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express", "generic"],
    contexts: ["auth_handler", "api_route", "generic"],
  },
  {
    id: "generic-cors-wildcard",
    name: "CORS wildcard origin",
    pattern: /(?:origin|Access-Control-Allow-Origin)\s*[=:]\s*["']\*["']/,
    severity: "high",
    owasp: "A05 — Security Misconfiguration",
    description: "CORS configured to allow all origins — any website can make credentialed requests to this API.",
    fix: "Restrict to specific origins: `origin: ['https://your-app.com']` or use an allowlist function.",
    frameworks: ["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express", "generic"],
    contexts: ["api_route", "config", "generic"],
  },
  {
    id: "generic-no-input-validation",
    name: "User input used without validation",
    pattern: /req\.(?:body|query|params)\.[a-zA-Z]+(?!\s*(?:&&|schema|\.parse|\.validate|\.safeParse|zod|joi|yup))/,
    severity: "medium",
    owasp: "A03 — Injection",
    description: "Request input used directly without visible schema validation.",
    fix: "Validate all inputs with zod, joi, or express-validator before using them in queries or responses.",
    frameworks: ["nextjs", "express", "generic"],
    contexts: ["api_route", "database_query", "generic"],
  },
];

// ─── Handler ───────────────────────────────────────────────────────────────────

export async function analyzeSecurityHandler(input: {
  code: string;
  framework: string;
  context: string;
}): Promise<ToolResponse> {
  const { code, framework, context } = input;

  const applicableRules = RULES.filter(
    (r) =>
      (r.frameworks.includes(framework) || r.frameworks.includes("generic")) &&
      (r.contexts.includes(context) || r.contexts.includes("generic"))
  );

  interface Finding {
    ruleId: string;
    name: string;
    severity: string;
    owasp: string;
    line: number;
    description: string;
    fix: string;
  }

  const findings: Finding[] = [];
  const lines = code.split("\n");

  for (const rule of applicableRules) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");

    // Check full code for match
    let match: RegExpExecArray | null;
    re.lastIndex = 0;
    const firstMatch = re.exec(code);
    if (!firstMatch) continue;

    // Find line number
    const lineNum = code.slice(0, firstMatch.index).split("\n").length;

    // For server-action rule, only flag if no auth-looking code exists nearby
    if (rule.id === "next-server-action-no-auth") {
      const hasAuthCheck = /getServerSession|getSession|auth\(\)|currentUser|userId\s*=|session\s*=/i.test(code);
      if (hasAuthCheck) continue;
    }

    // For supabase RLS query rule, only flag if it's a server-side context
    if (rule.id === "supabase-rls-disabled" && context === "component") continue;

    // For express no-helmet, only flag if "helmet" doesn't appear anywhere in code
    if (rule.id === "express-no-helmet" && /helmet/i.test(code)) continue;

    // For API no-method-check, skip if code already has method checking
    if (rule.id === "next-api-no-method-check" && /req\.method/i.test(code)) continue;

    findings.push({
      ruleId: rule.id,
      name: rule.name,
      severity: rule.severity,
      owasp: rule.owasp,
      line: lineNum,
      description: rule.description,
      fix: rule.fix,
    });
  }

  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (order[a.severity as keyof typeof order] ?? 99) - (order[b.severity as keyof typeof order] ?? 99));

  const critCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  let summary: string;
  if (findings.length === 0) {
    summary = `No security issues found in ${framework} ${context} code`;
  } else {
    const parts: string[] = [];
    if (critCount) parts.push(`${critCount} critical`);
    if (highCount) parts.push(`${highCount} high`);
    const rest = findings.length - critCount - highCount;
    if (rest) parts.push(`${rest} other`);
    summary = `${findings.length} security issue${findings.length === 1 ? "" : "s"} found (${parts.join(", ")})`;
  }

  return toToolResponse({
    summary,
    framework,
    context,
    totalFindings: findings.length,
    findings,
    ...(findings.length === 0 && { clean: true }),
  });
}
