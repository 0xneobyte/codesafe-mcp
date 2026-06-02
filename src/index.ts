#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { analyzeSecuritySchema, analyzeSecurityHandler } from "./tools/analyze-security.js";
import { scanSecretsSchema, scanSecretsHandler } from "./tools/scan-secrets.js";
import { auditDependenciesSchema, auditDependenciesHandler } from "./tools/audit-dependencies.js";
import { getSecurityDocsSchema, getSecurityDocsHandler } from "./tools/get-security-docs.js";
import { verifyPackageSafetySchema, verifyPackageSafetyHandler } from "./tools/verify-package-safety.js";
import { setupEnforcementSchema, setupEnforcementHandler } from "./tools/setup-enforcement.js";

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
      "Scans code for hardcoded secrets, API keys, tokens, passwords, and credentials " +
      "using regex pattern matching and entropy analysis. Maps findings to OWASP A02 (Cryptographic Failures). " +
      "Four capabilities: " +
      "(1) 'code' param — scans a single file or snippet. " +
      "(2) 'directory' param — recursively scans an entire codebase in one call, returning per-file findings and auto-fix for each file. Use this when the user asks to scan a project, folder, or whole codebase. " +
      "(3) 'repoPath' — scans full git commit history for secrets ever committed, even if later removed. " +
      "(4) 'additionalFiles' — tracks whether a secret flows into a client component. " +
      "Always returns auto-fix: the corrected code with process.env substitutions and a .env snippet.",
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

server.registerTool(
  "setup_codesafe_enforcement",
  {
    description:
      "One-time setup that enforces package safety checks in a project. " +
      "Writes a mandatory CLAUDE.md rule instructing AI agents to call verify_package_safety before any npm/pip install. " +
      "Also creates a .codesafe/check-packages.sh hook script and wires it into .claude/settings.json as a PreToolUse hook, " +
      "so Claude Code hard-blocks installs of packages that don't exist on the npm/PyPI registry. " +
      "Call this once per project to protect the entire team. Commit the generated files to enforce for all contributors.",
    inputSchema: setupEnforcementSchema,
  },
  setupEnforcementHandler
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
