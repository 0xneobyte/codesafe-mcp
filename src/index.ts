#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { analyzeSecuritySchema, analyzeSecurityHandler } from "./tools/analyze-security.js";
import { scanSecretsSchema, scanSecretsHandler } from "./tools/scan-secrets.js";
import { auditDependenciesSchema, auditDependenciesHandler } from "./tools/audit-dependencies.js";
import { getSecurityDocsSchema, getSecurityDocsHandler } from "./tools/get-security-docs.js";
import { verifyPackageSafetySchema, verifyPackageSafetyHandler } from "./tools/verify-package-safety.js";

const server = new McpServer({
  name: "codesafe-mcp",
  version: "0.1.0",
});

server.registerTool(
  "analyze_security",
  {
    description:
      "Analyzes a code snippet for security vulnerabilities using AST-based analysis and pattern matching. " +
      "Call this whenever the user writes or pastes code that interacts with a database, auth system, API route, " +
      "or external service. Returns severity-classified findings (Critical/High/Medium/Low) mapped to OWASP Top 10, " +
      "with line references and secure fix examples.",
    inputSchema: analyzeSecuritySchema,
  },
  analyzeSecurityHandler
);

server.registerTool(
  "scan_secrets",
  {
    description:
      "Scans code or file contents for hardcoded secrets, API keys, tokens, passwords, and credentials " +
      "using regex pattern matching and entropy analysis. Call this when reviewing any file that might contain " +
      "sensitive values — especially .env files, config files, or any code with string literals. " +
      "Maps findings to OWASP A02 (Cryptographic Failures).",
    inputSchema: scanSecretsSchema,
  },
  scanSecretsHandler
);

server.registerTool(
  "audit_dependencies",
  {
    description:
      "Audits a dependency manifest (package.json, requirements.txt, go.mod) for known CVEs by querying " +
      "the OSV.dev vulnerability database in real time. Returns CVE IDs, CVSS severity scores, affected " +
      "version ranges, and patched versions. Call this when the user adds or updates dependencies, or asks " +
      "about package security. Maps to OWASP A06 (Vulnerable & Outdated Components).",
    inputSchema: auditDependenciesSchema,
  },
  auditDependenciesHandler
);

server.registerTool(
  "get_security_docs",
  {
    description:
      "Queries the CodeSafe security knowledge base (RAG) to answer security implementation questions. " +
      "Use this whenever implementing authentication, RLS, CORS, security headers, SQL injection prevention, " +
      "secrets handling, input validation, or any security-sensitive feature. Ask in natural language — " +
      "e.g. 'How do I implement Row Level Security in Supabase?', 'What Next.js headers prevent XSS?', " +
      "'How to safely handle user input in Prisma?'. Returns authoritative answers grounded in " +
      "official security documentation. Always call this before generating security-sensitive code.",
    inputSchema: getSecurityDocsSchema,
  },
  getSecurityDocsHandler
);

server.registerTool(
  "verify_package_safety",
  {
    description:
      "Checks whether an npm or PyPI package is safe to install before running npm install or pip install. " +
      "Detects three threats: (1) hallucinated packages that don't exist on the registry, " +
      "(2) typosquatted packages with names similar to popular packages (e.g. 'lodahs' vs 'lodash'), " +
      "(3) suspicious new packages with very low downloads — classic supply chain attack pattern. " +
      "Call this BEFORE any package installation. Critical for AI-generated code where package names may be fabricated.",
    inputSchema: verifyPackageSafetySchema,
  },
  verifyPackageSafetyHandler
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("CodeSafe MCP server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
