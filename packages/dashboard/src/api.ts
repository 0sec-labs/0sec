import type {
  DashboardResponse,
  FindingFamilyResponse,
  FindingWorkflowStatus,
  RecentEventsResponse,
  ScanEventsResponse,
  ScanFindingsResponse,
  ScanRecord,
} from "./types";
import type {
  DesktopCodexAuthStatus,
  DesktopConsoleAutonomyMode,
  DesktopConsoleDecisionResponse,
  DesktopConsoleEvent,
  DesktopConsoleRole,
  DesktopConsoleSession,
} from "@0sec/shared";

/** Read the per-session control token injected by the dashboard server. */
function getControlToken(): string | null {
  const meta = document.querySelector('meta[name="0sec-control-token"]');
  return meta?.getAttribute("content") ?? null;
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> ?? {}),
  };
  // Attach the control token to all requests — the server only enforces it
  // on /api/control/ endpoints, but sending it unconditionally is simpler.
  const token = getControlToken();
  if (token) headers["X-0sec-Control-Token"] = token;

  const response = await fetch(path, {
    ...init,
    headers,
  });

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const data = await response.json() as { error?: string };
      if (data.error) message = data.error;
    } catch {
      // Ignore JSON parse failures for non-JSON error bodies.
    }
    throw new Error(message);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) {
    throw new Error(
      `Dashboard API returned ${contentType || "non-JSON content"} for ${path}. Serve the UI through \`0sec dashboard\`.`,
    );
  }
  return response.json() as Promise<T>;
}

export function getDashboard(): Promise<DashboardResponse> {
  return fetchJson("/api/dashboard");
}

export async function getScans(): Promise<ScanRecord[]> {
  const data = await fetchJson<{ scans: ScanRecord[] }>("/api/scans");
  return data.scans;
}

export async function getScan(scanId: string): Promise<ScanRecord> {
  const data = await fetchJson<{ scan: ScanRecord }>(`/api/scans/${encodeURIComponent(scanId)}`);
  return data.scan;
}

export function getScanEvents(scanId: string): Promise<ScanEventsResponse> {
  return fetchJson(`/api/scans/${encodeURIComponent(scanId)}/events`);
}

export function getRecentEvents(limit = 20): Promise<RecentEventsResponse> {
  return fetchJson(`/api/events/recent?limit=${encodeURIComponent(String(limit))}`);
}

export function getScanFindings(scanId: string): Promise<ScanFindingsResponse> {
  return fetchJson(`/api/scans/${encodeURIComponent(scanId)}/findings`);
}

export function getFindingFamily(fingerprint: string): Promise<FindingFamilyResponse> {
  return fetchJson(`/api/finding-family/${encodeURIComponent(fingerprint)}`);
}

export function updateFindingFamilyTriage(
  fingerprint: string,
  triageStatus: "new" | "accepted" | "suppressed",
  triageNote: string,
): Promise<{ ok: true }> {
  return fetchJson(`/api/finding-family/${encodeURIComponent(fingerprint)}/triage`, {
    method: "POST",
    body: JSON.stringify({ triageStatus, triageNote }),
  });
}

export function updateFindingFamilyWorkflow(
  fingerprint: string,
  workflowStatus: FindingWorkflowStatus,
  workflowAssignee: string,
): Promise<{ ok: true }> {
  return fetchJson(`/api/finding-family/${encodeURIComponent(fingerprint)}/workflow`, {
    method: "POST",
    body: JSON.stringify({ workflowStatus, workflowAssignee }),
  });
}

export function recoverStaleWorkers(staleAfterMs = 30_000): Promise<{ ok: true; recovered: number }> {
  return fetchJson("/api/control/recover-stale-workers", {
    method: "POST",
    body: JSON.stringify({ staleAfterMs }),
  });
}

export function pruneStoppedWorkers(): Promise<{ ok: true; deleted: number }> {
  return fetchJson("/api/control/prune-stopped-workers", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function resetDatabase(seed: "verification" | "empty"): Promise<{
  ok: true;
  path: string;
  seed: "verification" | "empty";
  scans: number;
  families: number;
  workers: number;
}> {
  return fetchJson("/api/control/reset-database", {
    method: "POST",
    body: JSON.stringify({ seed }),
  });
}

export function startDaemon(args?: {
  label?: string;
  pollIntervalMs?: number;
}): Promise<{ ok: true; pid: number | null; label: string }> {
  return fetchJson("/api/control/start-daemon", {
    method: "POST",
    body: JSON.stringify(args ?? {}),
  });
}

export function stopDaemon(): Promise<{ ok: true; stopped: number }> {
  return fetchJson("/api/control/stop-daemon", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function launchRun(args: {
  target: string;
  depth: "quick" | "default" | "deep";
  mode: "probe" | "deep" | "mcp" | "web";
  runtime: "api" | "claude" | "codex" | "gemini" | "auto";
  ensureDaemon?: boolean;
}): Promise<{ ok: true; pid: number | null }> {
  return fetchJson("/api/control/launch-run", {
    method: "POST",
    body: JSON.stringify(args),
  });
}

export async function getDesktopConsoleSessions(): Promise<DesktopConsoleSession[]> {
  const data = await fetchJson<{ sessions: DesktopConsoleSession[] }>("/api/console/sessions");
  return data.sessions;
}

export async function createDesktopConsoleSession(input: {
  target?: string;
  role?: DesktopConsoleRole;
  autonomyMode?: DesktopConsoleAutonomyMode;
}): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>("/api/console/sessions", {
    method: "POST",
    body: JSON.stringify(input),
  });
  return data.session;
}

export async function getDesktopConsoleEvents(sessionId: string, after: number): Promise<DesktopConsoleEvent[]> {
  const data = await fetchJson<{ events: DesktopConsoleEvent[] }>(
    `/api/console/sessions/${encodeURIComponent(sessionId)}/events?after=${encodeURIComponent(String(after))}`,
  );
  return data.events;
}

export async function sendDesktopConsoleMessage(sessionId: string, text: string): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>(
    `/api/console/sessions/${encodeURIComponent(sessionId)}/messages`,
    { method: "POST", body: JSON.stringify({ text }) },
  );
  return data.session;
}

export async function cancelDesktopConsoleTurn(sessionId: string): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>(
    `/api/console/sessions/${encodeURIComponent(sessionId)}/cancel`,
    { method: "POST", body: JSON.stringify({}) },
  );
  return data.session;
}

export async function resolveDesktopConsoleDecision(
  sessionId: string,
  decisionId: string,
  response: DesktopConsoleDecisionResponse,
): Promise<DesktopConsoleSession> {
  const data = await fetchJson<{ session: DesktopConsoleSession }>(
    `/api/console/sessions/${encodeURIComponent(sessionId)}/decisions/${encodeURIComponent(decisionId)}`,
    { method: "POST", body: JSON.stringify(response) },
  );
  return data.session;
}

export async function getDesktopCodexAuthStatus(): Promise<DesktopCodexAuthStatus> {
  const data = await fetchJson<{ status: DesktopCodexAuthStatus }>("/api/console/providers/codex");
  return data.status;
}

export async function startDesktopCodexDeviceAuth(): Promise<DesktopCodexAuthStatus> {
  const data = await fetchJson<{ status: DesktopCodexAuthStatus }>("/api/console/providers/codex/device-auth", {
    method: "POST",
    body: JSON.stringify({}),
  });
  return data.status;
}

export async function cancelDesktopCodexDeviceAuth(): Promise<DesktopCodexAuthStatus> {
  const data = await fetchJson<{ status: DesktopCodexAuthStatus }>("/api/console/providers/codex/device-auth", {
    method: "DELETE",
  });
  return data.status;
}
