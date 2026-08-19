export interface HttpResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
  latencyMs: number;
}

export function isMcpTarget(target: string): boolean {
  return target.startsWith("mcp://");
}

export async function sendPrompt(
  target: string,
  prompt: string,
  options?: { timeout?: number; headers?: Record<string, string> }
): Promise<HttpResponse> {
  const start = Date.now();
  const timeout = options?.timeout ?? 30_000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(target, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
      body: JSON.stringify({
        messages: [{ role: "user", content: prompt }],
      }),
      signal: controller.signal,
    });

    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k] = v;
    });

    return {
      status: res.status,
      body,
      headers,
      latencyMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

export function extractResponseText(body: string): string {
  try {
    const json = JSON.parse(body);
    // OpenAI-compatible format
    if (json.choices?.[0]?.message?.content) {
      return json.choices[0].message.content;
    }
    // Anthropic format
    if (json.content?.[0]?.text) {
      return json.content[0].text;
    }
    // Simple message format
    if (json.message) return json.message;
    if (json.response) return json.response;
    if (json.text) return json.text;
    if (json.output) return json.output;
    // Fallback to raw body
    return body;
  } catch {
    return body;
  }
}
