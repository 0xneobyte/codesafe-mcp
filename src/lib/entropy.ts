export function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

const STRING_LITERAL_RE = /(?:"([^"\\]{16,}(?:\\.[^"\\]*)*)"|'([^'\\]{16,}(?:\\.[^'\\]*)*)'|`([^`\\]{16,}(?:\\.[^`\\]*)*)`)/g;
const URL_RE = /^https?:\/\//i;
const PATH_RE = /^[./\\]/;
const SENTENCE_RE = /\s{2,}|[.!?]\s/;
const HEX_ONLY_RE = /^[0-9a-f]+$/i;

export interface EntropyFinding {
  value: string;
  preview: string;
  entropy: number;
  line: number;
  confidence: "high" | "medium";
}

export function extractHighEntropyStrings(code: string, threshold = 4.5): EntropyFinding[] {
  const lines = code.split("\n");
  const findings: EntropyFinding[] = [];

  lines.forEach((line, lineIdx) => {
    let match: RegExpExecArray | null;
    STRING_LITERAL_RE.lastIndex = 0;
    while ((match = STRING_LITERAL_RE.exec(line)) !== null) {
      const value = match[1] ?? match[2] ?? match[3];
      if (!value) continue;
      if (URL_RE.test(value) || PATH_RE.test(value) || SENTENCE_RE.test(value)) continue;
      if (HEX_ONLY_RE.test(value) && value.length < 32) continue;
      const entropy = shannonEntropy(value);
      if (entropy >= threshold) {
        findings.push({
          value,
          preview: value.slice(0, 4) + "****",
          entropy: Math.round(entropy * 100) / 100,
          line: lineIdx + 1,
          confidence: entropy >= 5.0 ? "high" : "medium",
        });
      }
    }
  });

  return findings;
}
