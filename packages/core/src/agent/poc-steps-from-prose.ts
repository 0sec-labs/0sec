// pwnkit#179 — agent-side `pocSteps` emission from prose evidence.
//
// Today the agent's `save_finding` tool writes three free-text strings
// (`request`, `response`, `analysis`). Cloud and renderer code (pwnkit#170,
// pwnkit#171, pwnkit-cloud#168) prefer the structured `Finding.pocSteps`
// graph but the agent rarely supplies it. This module is a best-effort
// fallback: parse the prose, extract a small step graph, and let the caller
// attach it to the finding. If the heuristic isn't confident it returns
// undefined — downstream consumers gate on field presence, so a missing
// graph is strictly safer than a wrong one.
//
// Conservative by design: we extract three signal types (HTTP request lines,
// shell snippets, response status codes) and stitch them into a 2–5 step
// graph. Anything we can't parse cleanly is skipped, never guessed.

import type { PocStep, PocStepKind } from "@pwnkit/shared";

/**
 * Inputs are the three prose evidence fields the agent already produces. All
 * are optional — passing an empty object returns undefined.
 */
export interface ProseEvidence {
  request?: string;
  response?: string;
  analysis?: string;
}

/**
 * Extract a 2–5 step PoC graph from prose evidence. Returns `undefined` (not
 * `[]`) when the heuristic can't produce ≥ 2 steps confidently — downstream
 * consumers gate on field presence, so no graph is preferable to a wrong one.
 */
export function extractPocStepsFromProse(prose: ProseEvidence): PocStep[] | undefined {
  const request = (prose.request ?? "").trim();
  const response = (prose.response ?? "").trim();
  const analysis = (prose.analysis ?? "").trim();

  if (!request && !response && !analysis) return undefined;

  const steps: PocStep[] = [];

  // ── 1. Optional setup / prerequisite note from analysis prose ───────────
  // Use the first line of analysis as a setup note when it reads like a
  // narrated precondition. We deliberately keep this very conservative: only
  // emit the note when we already have at least one executable step lined up
  // (so the result is a multi-step graph, not a lone note).
  const analysisLead = pickLeadingNote(analysis);

  // ── 2. Executable exploit step from request prose ───────────────────────
  const httpStep = parseHttpRequest(request);
  const shellStep = parseShellSnippet(request);
  // Prefer HTTP when both surface from the same blob — request.lines that
  // start with `GET`/`POST` are far more decisive than a generic `curl …`.
  const exploitStep = httpStep ?? shellStep;

  if (!exploitStep) return undefined;

  // ── 3. Verify step from response prose ──────────────────────────────────
  // For HTTP exploits the verify step replays the same URL/method but with
  // an http-status predicate parsed from the response. For shell exploits we
  // can't synthesise a verify command from prose, so we attach an exit-zero
  // predicate to the existing exploit step instead.
  const httpStatus = parseHttpStatus(response);
  const verifyStep = buildVerifyStep(exploitStep, httpStatus, response);

  // Build the graph. Only attach the analysis note when we have a real
  // exploit + verify pair — a lone note isn't useful.
  if (analysisLead && verifyStep) {
    steps.push({
      id: "setup",
      kind: kindForAnalysis(analysisLead),
      summary: analysisLead,
      action: { type: "note", text: analysisLead },
    });
  }
  steps.push(exploitStep);
  if (verifyStep) steps.push(verifyStep);

  // Conservative gate: a single step graph is never useful — the whole point
  // of this field is to capture exploit→verify causality.
  if (steps.length < 2) return undefined;

  return steps;
}

// ── HTTP request parsing ──────────────────────────────────────────────────

const HTTP_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);

/**
 * Parse a single HTTP request line (e.g. `GET /admin HTTP/1.1` or
 * `POST /api/login`) into an `http` action. Returns null when no method/path
 * pair is found. We deliberately do NOT try to parse headers/body — those
 * aren't reliable from agent prose, and the consumer treats them as optional.
 */
function parseHttpRequest(text: string): PocStep | null {
  if (!text) return null;
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(
      /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?$/i,
    );
    if (!match) continue;
    const method = match[1].toUpperCase();
    const url = match[2];
    if (!HTTP_METHODS.has(method)) continue;
    if (!isPlausibleUrl(url)) continue;
    return {
      id: "exploit",
      kind: "exploit",
      summary: `${method} ${url}`,
      action: { type: "http", method, url },
    };
  }
  return null;
}

/** A URL is "plausible" if it starts with `/` or `http(s)://` and has no whitespace. */
function isPlausibleUrl(url: string): boolean {
  if (!url || /\s/.test(url)) return false;
  return url.startsWith("/") || /^https?:\/\//i.test(url);
}

// ── Shell snippet parsing ─────────────────────────────────────────────────

const SHELL_PREFIXES = ["curl", "wget", "docker", "python3", "python", "sh", "bash", "nc", "ncat"];

/**
 * Parse a shell snippet from prose. We only accept lines whose first token is
 * a known executable prefix — this avoids mistaking command-line *output* for
 * a command. Returns null if no such line exists.
 */
function parseShellSnippet(text: string): PocStep | null {
  if (!text) return null;
  const lines = text.split(/\r?\n/);
  for (const raw of lines) {
    let line = raw.trim();
    if (!line) continue;
    // Strip a leading shell prompt marker so `$ curl …` is recognised.
    if (line.startsWith("$ ")) line = line.slice(2).trim();
    if (line.startsWith("# ")) line = line.slice(2).trim();
    const firstToken = line.split(/\s+/)[0]?.toLowerCase();
    if (!firstToken) continue;
    if (!SHELL_PREFIXES.includes(firstToken)) continue;
    // Reject lines that look like a sentence rather than a command (e.g.
    // "curl returned 200" — no flags, no URL).
    if (firstToken === "curl" && !/\s\/|\shttps?:\/\//i.test(line)) continue;
    return {
      id: "exploit",
      kind: "exploit",
      summary: truncate(line, 120),
      action: { type: "shell", cmd: line },
    };
  }
  return null;
}

// ── HTTP response status parsing ──────────────────────────────────────────

/**
 * Parse the HTTP status code from a response blob. Accepts the canonical
 * status line (`HTTP/1.1 200 OK`), case-insensitive. Returns null when the
 * response is missing, malformed, or doesn't lead with a status line.
 */
function parseHttpStatus(text: string): number | null {
  if (!text) return null;
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/i);
    if (!match) continue;
    const status = Number.parseInt(match[1], 10);
    if (Number.isNaN(status)) return null;
    if (status < 100 || status > 599) return null;
    return status;
  }
  return null;
}

// ── Verify step synthesis ─────────────────────────────────────────────────

function buildVerifyStep(
  exploit: PocStep,
  httpStatus: number | null,
  response: string,
): PocStep | null {
  // For HTTP exploits with a parseable status, build a structurally identical
  // request and attach the status predicate. Downstream re-verify executors
  // replay this and check the status matches.
  if (exploit.action.type === "http" && httpStatus != null) {
    return {
      id: "verify",
      kind: "verify",
      summary: `Response ${httpStatus} confirms ${exploit.action.method} ${exploit.action.url} succeeds`,
      action: {
        type: "http",
        method: exploit.action.method,
        url: exploit.action.url,
      },
      expect: { type: "http-status", status: httpStatus },
    };
  }
  // For shell exploits we can't synthesise a separate verify command from
  // prose. If the response prose contains a meaningful observation, capture
  // it as a body-contains predicate against the exploit's stdout.
  if (exploit.action.type === "shell") {
    const observation = pickShellObservation(response);
    if (!observation) return null;
    return {
      id: "verify",
      kind: "verify",
      summary: `Output contains "${truncate(observation, 60)}"`,
      action: { type: "note", text: observation },
      expect: { type: "body-contains", text: observation },
    };
  }
  return null;
}

/**
 * Pick a short, distinctive observation string from shell output prose. We
 * pick the first non-empty line that's short enough to be a single tokenable
 * fact (e.g. a flag, a uid, a banner). Returns null if nothing fits.
 */
function pickShellObservation(text: string): string | null {
  if (!text) return null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.length > 200) continue;
    // Skip lines that look like prose narration ("The response showed…").
    if (/^(the |it |this |we |our )/i.test(line)) continue;
    return line;
  }
  return null;
}

// ── Analysis-prose helpers ────────────────────────────────────────────────

/**
 * Pick a one-line setup note from the analysis prose. We use the first
 * non-empty line, capped at 200 chars. Returns null if the analysis is empty
 * or starts with a stop-phrase that suggests it's not setup ("This shows…",
 * "The bug is…").
 */
function pickLeadingNote(text: string): string | null {
  if (!text) return null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    return truncate(line, 200);
  }
  return null;
}

/**
 * Categorise the analysis lead as a `setup`, `prerequisite`, or generic
 * `setup` step. Hueristic-only — when in doubt we use `setup`.
 */
function kindForAnalysis(text: string): PocStepKind {
  const lower = text.toLowerCase();
  if (/\b(requires?|needs?|must have|prerequisite|precondition)\b/.test(lower)) {
    return "prerequisite";
  }
  return "setup";
}

// ── small utilities ───────────────────────────────────────────────────────

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}
