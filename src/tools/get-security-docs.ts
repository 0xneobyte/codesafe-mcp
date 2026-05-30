import { z } from "zod";
import { toToolResponse, toErrorResponse } from "../types.js";
import type { ToolResponse } from "../types.js";

export const getSecurityDocsSchema = {
  query: z
    .string()
    .min(5)
    .max(2000)
    .describe(
      "Natural language security question, e.g. 'How do I implement Row Level Security in Supabase?' " +
      "or 'What headers should I set in Next.js to prevent XSS?' or 'How to prevent SQL injection in Prisma?'"
    ),
  framework: z
    .enum(["nextjs", "supabase", "prisma", "express", "react", "firebase", "generic"])
    .optional()
    .describe(
      "Optional: filter results to a specific framework. " +
      "Pass this when you know which framework the user is working with — improves answer precision."
    ),
};

interface BackendQueryResponse {
  answer: string;
  sources: string[];
  framework_filter: string | null;
  store_id: string;
}

export async function getSecurityDocsHandler(input: {
  query: string;
  framework?: string;
}): Promise<ToolResponse> {
  const backendUrl = process.env.CODESAFE_BACKEND_URL;
  const apiKey = process.env.CODESAFE_API_KEY;

  if (!backendUrl) {
    return toErrorResponse(
      "CODESAFE_BACKEND_URL is not set. " +
      "Add it to your MCP config env: CODESAFE_BACKEND_URL=https://your-backend-url"
    );
  }
  if (!apiKey) {
    return toErrorResponse(
      "CODESAFE_API_KEY is not set. " +
      "Add it to your MCP config env: CODESAFE_API_KEY=your-backend-api-key"
    );
  }

  const url = `${backendUrl.replace(/\/$/, "")}/api/v1/query`;

  let data: BackendQueryResponse;
  try {
    const body: Record<string, string> = { query: input.query };
    if (input.framework) body.framework = input.framework;

    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Api-Key": apiKey,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      return toErrorResponse(`Backend returned ${res.status}: ${text}`);
    }

    data = await res.json() as BackendQueryResponse;
  } catch (err) {
    return toErrorResponse(
      `Could not reach CodeSafe backend at ${url}: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  return toToolResponse({
    answer: data.answer,
    sources: data.sources,
    ...(data.framework_filter && { framework: data.framework_filter }),
  });
}
