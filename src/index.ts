#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { analyzeSecuritySchema, analyzeSecurityHandler } from "./tools/analyze-security.js";
import { scanSecretsSchema, scanSecretsHandler } from "./tools/scan-secrets.js";
import { auditDependenciesSchema, auditDependenciesHandler } from "./tools/audit-dependencies.js";
import { getSecurityDocsSchema, getSecurityDocsHandler } from "./tools/get-security-docs.js";

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
      "Retrieves the latest official security documentation for a specific framework and topic using " +
      "Gemini-powered semantic search over pre-indexed security docs. Use this to fetch up-to-date " +
      "remediation guidance when a vulnerability is detected, or when the user asks how to securely " +
      "implement authentication, authorization, RLS, CORS, security headers, or similar topics. " +
      "Optionally filter by OWASP category for more precise, token-efficient results.",
    inputSchema: getSecurityDocsSchema,
  },
  getSecurityDocsHandler
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
