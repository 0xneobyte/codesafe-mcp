import { z } from "zod";
import type { ToolResponse } from "../types.js";
import { toToolResponse } from "../types.js";

export const getSecurityDocsSchema = {
  framework: z
    .enum(["nextjs", "react", "supabase", "firebase", "prisma", "drizzle", "express"])
    .describe("The framework to retrieve security documentation for"),
  topic: z
    .string()
    .min(1)
    .max(200)
    .describe(
      "The security topic to retrieve docs for (e.g. 'row-level-security', 'authentication', 'cors', 'headers')"
    ),
  owasp: z
    .enum(["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"])
    .optional()
    .describe("Optional OWASP category to filter docs by (narrows results and reduces tokens)"),
};

export async function getSecurityDocsHandler(input: {
  framework: string;
  topic: string;
  owasp?: string;
}): Promise<ToolResponse> {
  // TODO: implement Gemini File Search retrieval
  // - Query Gemini File Search Store with metadata filter:
  //     framework=input.framework AND owasp=input.owasp (if provided)
  // - Semantic search within filtered subset using input.topic as query
  // - Return relevant security doc chunks with source citations
  // - Uses pre-indexed security docs from GitHub repos (see scripts/index-docs.ts)
  return toToolResponse({
    status: "stub",
    message: "get_security_docs tool — coming soon",
    received: { framework: input.framework, topic: input.topic, owasp: input.owasp },
  });
}
