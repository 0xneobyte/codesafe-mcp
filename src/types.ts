export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type OWASPCategory =
  | "A01" // Broken Access Control
  | "A02" // Cryptographic Failures
  | "A03" // Injection
  | "A04" // Insecure Design
  | "A05" // Security Misconfiguration
  | "A06" // Vulnerable & Outdated Components
  | "A07" // Identification & Authentication Failures
  | "A08" // Software & Data Integrity Failures
  | "A09" // Security Logging & Monitoring Failures
  | "A10"; // Server-Side Request Forgery

export type Framework =
  | "nextjs"
  | "react"
  | "supabase"
  | "firebase"
  | "prisma"
  | "drizzle"
  | "express"
  | "generic";

export interface SecurityFinding {
  ruleId: string;
  severity: Severity;
  owasp: OWASPCategory;
  line?: number;
  description: string;
  fix: string;
  reference: string;
}

export interface ToolResponse {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
}

export function toToolResponse(data: unknown): ToolResponse {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  };
}

export function toErrorResponse(message: string): ToolResponse {
  return {
    content: [{ type: "text", text: JSON.stringify({ error: message }) }],
  };
}
