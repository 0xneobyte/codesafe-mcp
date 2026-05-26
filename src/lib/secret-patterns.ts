export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: "critical" | "high";
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: "Supabase Service Role Key", pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, severity: "critical" },
  { name: "Supabase URL", pattern: /https:\/\/[a-z0-9]{20}\.supabase\.co/g, severity: "high" },
  { name: "OpenAI API Key", pattern: /sk-[a-zA-Z0-9]{32,}/g, severity: "critical" },
  { name: "Anthropic API Key", pattern: /sk-ant-[a-zA-Z0-9\-_]{40,}/g, severity: "critical" },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: "critical" },
  { name: "GitHub Personal Access Token", pattern: /ghp_[a-zA-Z0-9]{36}/g, severity: "critical" },
  { name: "GitHub OAuth Token", pattern: /gho_[a-zA-Z0-9]{36}/g, severity: "critical" },
  { name: "AWS Access Key ID", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
  { name: "Stripe Live Secret Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical" },
  { name: "Stripe Test Secret Key", pattern: /sk_test_[0-9a-zA-Z]{24,}/g, severity: "high" },
  { name: "MongoDB Connection String", pattern: /mongodb(?:\+srv)?:\/\/[^"'\s]+/g, severity: "critical" },
  { name: "Private Key Block", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "critical" },
  { name: "Hardcoded Password", pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{6,}["']/gi, severity: "high" },
  { name: "Hardcoded Secret", pattern: /(?:secret|api_secret)\s*[=:]\s*["'][^"']{8,}["']/gi, severity: "critical" },
  { name: "Hardcoded Token", pattern: /(?:token|auth_token|access_token)\s*[=:]\s*["'][^"']{8,}["']/gi, severity: "high" },
  { name: "Firebase Config Key", pattern: /AIzaSy[0-9A-Za-z\-_]{33}/g, severity: "critical" },
  { name: "Twilio Auth Token", pattern: /SK[0-9a-fA-F]{32}/g, severity: "critical" },
  { name: "SendGrid API Key", pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: "critical" },
];

export const ALLOWLIST_PATTERNS = [
  /example/i,
  /placeholder/i,
  /your[-_]?key[-_]?here/i,
  /changeme/i,
  /dummy/i,
  /fake/i,
  /test[-_]?key/i,
  /xxxx/i,
  /1234567890/,
];

export function isAllowlisted(value: string): boolean {
  return ALLOWLIST_PATTERNS.some((p) => p.test(value));
}
