import type {
  DesktopCodexAuthStatus,
  DesktopConsoleAutonomyMode,
  DesktopConsoleDecisionResponse,
  DesktopConsoleEvent,
  DesktopConsoleRole,
  DesktopConsoleSession,
} from "@0sec/shared";

/* ── CSRF control token ────────────────────────────────────── */

/**
 * Read the per-session control token injected by the server into the HTML
 * response. The same `/api/console` endpoints the dashboard uses, served
 * through the same Vite/Express pipeline, include this meta tag.
 */
function getControlToken(): string | null {
  const meta = document.querySelector('meta[name="0sec-control-token"]');
  return meta?.getAttribute("content") ?? null;
}

/* ── Generic fetch helper ───────────────────────────────────── */

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as Record<string, string> | undefined) ?? {}),
  };

  const token = getControlToken();
  if (token) headers["X-0sec-Control-Token"] = token;

  const response = await fetch(path, { ...init, headers });

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const data = (await response.json()) as { error?: string };
      if (data.error) message = data.error;
    } catch {
      // Non-JSON error body — stick with status text.
    }
    throw new Error(message);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) {
    throw new Error(
      `API returned ${contentType || "non-JSON content"} for ${path}. ` +
        "Serve through `0sec dashboard`.",
    );
  }

  return response.json() as Promise<T>;
}

/* ── Console session endpoints ──────────────────────────────── */

function sessionUrl(sessionId: string): string {
  return `/api/console/sessions/${encodeURIComponent(sessionId)}`;
}

async function getSessions(): Promise<DesktopConsoleSession[]> {
  const data = await fetchJson<{ sessions: DesktopConsoleSession[] }>(
    "/api/console/sessions",
  );
  return data.sessions;
}

async function createSession(input?: {
  target?: string;
  role?: DesktopConsoleRole;
  autonomyMode?: DesktopConsoleAutonomyMode;
}): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>(
    "/api/console/sessions",
    { method: "POST", body: JSON.stringify(input ?? {}) },
  );
  return data.session;
}

async function getEvents(
  sessionId: string,
  after: number,
): Promise<DesktopConsoleEvent[]> {
  const data = await fetchJson<{ events: DesktopConsoleEvent[] }>(
    `${sessionUrl(sessionId)}/events?after=${encodeURIComponent(String(after))}`,
  );
  return data.events;
}

async function sendMessage(
  sessionId: string,
  text: string,
): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>(
    `${sessionUrl(sessionId)}/messages`,
    { method: "POST", body: JSON.stringify({ text }) },
  );
  return data.session;
}

async function cancelTurn(sessionId: string): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>(
    `${sessionUrl(sessionId)}/cancel`,
    { method: "POST", body: JSON.stringify({}) },
  );
  return data.session;
}

async function resolveDecision(
  sessionId: string,
  decisionId: string,
  response: DesktopConsoleDecisionResponse,
): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>(
    `${sessionUrl(sessionId)}/decisions/${encodeURIComponent(decisionId)}`,
    { method: "POST", body: JSON.stringify(response) },
  );
  return data.session;
}

/* ── Codex auth endpoints ────────────────────────────────────── */

async function getCodexAuthStatus(): Promise<DesktopCodexAuthStatus> {
  const data = await fetchJson<{ status: DesktopCodexAuthStatus }>(
    "/api/console/providers/codex",
  );
  return data.status;
}

async function startCodexDeviceAuth(): Promise<DesktopCodexAuthStatus> {
  const data = await fetchJson<{ status: DesktopCodexAuthStatus }>(
    "/api/console/providers/codex/device-auth",
    { method: "POST", body: JSON.stringify({}) },
  );
  return data.status;
}

async function cancelCodexDeviceAuth(): Promise<DesktopCodexAuthStatus> {
  const data = await fetchJson<{ status: DesktopCodexAuthStatus }>(
    "/api/console/providers/codex/device-auth",
    { method: "DELETE" },
  );
  return data.status;
}

/* ── Exported API object ─────────────────────────────────────── */

export const api = {
  getSessions,
  createSession,
  getEvents,
  sendMessage,
  cancelTurn,
  resolveDecision,
  getCodexAuthStatus,
  startCodexDeviceAuth,
  cancelCodexDeviceAuth,
} as const;
