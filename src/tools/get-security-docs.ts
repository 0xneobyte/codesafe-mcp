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
};

interface BackendQueryResponse {
  answer: string;
  sources: string[];
  store_id: string;
}

export async function getSecurityDocsHandler(input: { query: string }): Promise<ToolResponse> {
  const backendUrl = process.env.CODESAFE_BACKEND_URL;
  const apiKey = process.env.CODESAFE_API_KEY;

  if (!backendUrl) {
    return toErrorResponse(
      "CODESAFE_BACKEND_URL is not set. " +
      "Add it to your MCP config: CODESAFE_BACKEND_URL=https://your-backend-url"
    );
  }
  if (!apiKey) {
    return toErrorResponse(
      "CODESAFE_API_KEY is not set. " +
      "Add it to your MCP config: CODESAFE_API_KEY=your-backend-api-key"
    );
  }

  const url = `${backendUrl.replace(/\/$/, "")}/api/v1/query`;

  let data: BackendQueryResponse;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Api-Key": apiKey,
      },
      body: JSON.stringify({ query: input.query }),
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
    query: input.query,
  });
}
