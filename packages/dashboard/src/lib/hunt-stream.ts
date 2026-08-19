/**
 * Hunt-lane event types and parsing helpers.
 *
 * The Hunt lane on /live subscribes to a separate SSE feed that emits one
 * `pwnkit.events/v1` record per `data:` frame. Two upstream shapes are
 * accepted, both normalised into {@link PwnkitHuntEvent} for the renderer:
 *
 *   1. Native `pwnkit.events/v1` JSON — what `scripts/serve-events.mjs`
 *      produces when tailing a pwnkit event log (`PWNKIT_EVENT_*` lines).
 *   2. Raw pwnkit eventBus payloads tagged with `{type, payload}` —
 *      forwarded by future in-process WebSocket bridges. We translate
 *      these into the v1 shape on ingest.
 *
 * The schema is intentionally a subset of pwnkit's full eventBus
 * taxonomy — only the event types the Hunt lane actually renders are
 * surfaced. Unknown/irrelevant events are silently dropped by the parser
 * (see {@link parseHuntEvent}) so the upstream wire format can evolve
 * without breaking the dashboard.
 */

export type PwnkitHuntEvent =
  | {
      schema: "pwnkit.events/v1";
      kind: "tool_use";
      ts: number;
      tool: string;
      turn?: number;
      args_preview?: string;
      /** Parsed from args_preview if present (`path/to/file.ts:42`). */
      file?: string;
      line?: number;
      status?: "running" | "ok" | "error";
      duration_ms?: number;
    }
  | {
      schema: "pwnkit.events/v1";
      kind: "finding";
      ts: number;
      finding_id?: string;
      title: string;
      severity?: "info" | "low" | "medium" | "high" | "critical" | string;
      category?: string;
      confidence?: number;
      file?: string;
      line?: number;
    }
  | {
      schema: "pwnkit.events/v1";
      kind: "stage";
      ts: number;
      stage: string;
      transition: "started" | "completed";
      role?: string;
      turn?: number;
      duration_ms?: number;
    };

export type HuntEventKind = PwnkitHuntEvent["kind"];

/**
 * Regex that matches a `path/with/slashes.ext:lineno` reference inside a
 * free-form string. Captures (1) the file path and (2) the line number.
 *
 * Tuned to be forgiving — the path must contain at least one `/` or `.`
 * so we don't grab arbitrary `foo:42` snippets, and the line must be at
 * least one digit. Quoted/escaped variants (\"src/x.ts\":42) are handled
 * too because the regex is anchored on character classes, not quote chars.
 */
const FILE_LINE_RE = /([A-Za-z0-9._/\\\-]+(?:\.[A-Za-z0-9]+))[:\s]+L?(\d+)/;

export function extractFileLine(text: string | undefined): { file: string; line: number } | null {
  if (!text) return null;
  const match = FILE_LINE_RE.exec(text);
  if (!match) return null;
  const file = match[1];
  const line = Number.parseInt(match[2], 10);
  if (!Number.isFinite(line) || line <= 0) return null;
  // Require a slash OR a known source extension so we don't match
  // `version: 1.2.3:1` or other noise.
  if (!file.includes("/") && !/\.(ts|tsx|js|jsx|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|sh|sql)$/i.test(file)) {
    return null;
  }
  return { file, line };
}

/**
 * Parse one raw SSE `data:` payload into a {@link PwnkitHuntEvent}.
 * Returns `null` for malformed / irrelevant frames so the caller can
 * skip silently.
 *
 * Accepts:
 *   - `{"schema":"pwnkit.events/v1", "kind":"…", …}` — native v1 record.
 *   - `{"type":"tool_call_started"|"finding_ingested"|…, "payload":{…}}`
 *     — raw eventBus shape, translated to v1 on the fly.
 */
export function parseHuntEvent(raw: string): PwnkitHuntEvent | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!data || typeof data !== "object") return null;
  const obj = data as Record<string, unknown>;

  // Native v1 shape — trust the schema marker and pass through.
  if (obj.schema === "pwnkit.events/v1" && typeof obj.kind === "string") {
    return normaliseV1(obj);
  }

  // Raw eventBus shape — translate.
  if (typeof obj.type === "string" && obj.payload && typeof obj.payload === "object") {
    return translateRawEvent(obj.type, obj.payload as Record<string, unknown>);
  }

  return null;
}

function normaliseV1(obj: Record<string, unknown>): PwnkitHuntEvent | null {
  const kind = obj.kind as string;
  const ts = typeof obj.ts === "number" ? obj.ts : Date.now() / 1000;

  if (kind === "tool_use") {
    const argsPreview = typeof obj.args_preview === "string" ? obj.args_preview : undefined;
    const fileLine = extractFileLine(argsPreview);
    return {
      schema: "pwnkit.events/v1",
      kind: "tool_use",
      ts,
      tool: typeof obj.tool === "string" ? obj.tool : "?",
      turn: typeof obj.turn === "number" ? obj.turn : undefined,
      args_preview: argsPreview,
      file: typeof obj.file === "string" ? obj.file : fileLine?.file,
      line: typeof obj.line === "number" ? obj.line : fileLine?.line,
      status: obj.status === "ok" || obj.status === "error" || obj.status === "running" ? obj.status : "running",
      duration_ms: typeof obj.duration_ms === "number" ? obj.duration_ms : undefined,
    };
  }

  if (kind === "finding") {
    return {
      schema: "pwnkit.events/v1",
      kind: "finding",
      ts,
      finding_id: typeof obj.finding_id === "string" ? obj.finding_id : undefined,
      title: typeof obj.title === "string" ? obj.title : "Finding",
      severity: typeof obj.severity === "string" ? obj.severity : undefined,
      category: typeof obj.category === "string" ? obj.category : undefined,
      confidence: typeof obj.confidence === "number" ? obj.confidence : undefined,
      file: typeof obj.file === "string" ? obj.file : undefined,
      line: typeof obj.line === "number" ? obj.line : undefined,
    };
  }

  if (kind === "stage") {
    const transition = obj.transition === "completed" ? "completed" : "started";
    return {
      schema: "pwnkit.events/v1",
      kind: "stage",
      ts,
      stage: typeof obj.stage === "string" ? obj.stage : "stage",
      transition,
      role: typeof obj.role === "string" ? obj.role : undefined,
      turn: typeof obj.turn === "number" ? obj.turn : undefined,
      duration_ms: typeof obj.duration_ms === "number" ? obj.duration_ms : undefined,
    };
  }

  return null;
}

/**
 * Translate a raw eventBus emission into the v1 hunt shape. Mirrors the
 * mapping `scripts/serve-events.mjs` does for `PWNKIT_EVENT_*` lines so
 * both transport paths land on the same renderer.
 */
function translateRawEvent(type: string, payload: Record<string, unknown>): PwnkitHuntEvent | null {
  const ts = typeof payload.ts === "number" ? payload.ts : Date.now() / 1000;

  if (type === "tool_call_started" || type === "tool_call_completed") {
    const argsPreview = typeof payload.args_preview === "string" ? payload.args_preview : undefined;
    const fileLine = extractFileLine(argsPreview);
    const status: "running" | "ok" | "error" =
      type === "tool_call_started"
        ? "running"
        : payload.status === "error"
          ? "error"
          : "ok";
    return {
      schema: "pwnkit.events/v1",
      kind: "tool_use",
      ts,
      tool: typeof payload.tool === "string" ? payload.tool : "?",
      turn: typeof payload.turn === "number" ? payload.turn : undefined,
      args_preview: argsPreview,
      file: fileLine?.file,
      line: fileLine?.line,
      status,
      duration_ms: typeof payload.duration_ms === "number" ? payload.duration_ms : undefined,
    };
  }

  if (type === "finding_ingested") {
    return {
      schema: "pwnkit.events/v1",
      kind: "finding",
      ts,
      finding_id: typeof payload.finding_id === "string" ? payload.finding_id : undefined,
      title: typeof payload.title === "string" ? payload.title : "Finding",
      severity: typeof payload.severity === "string" ? payload.severity.toLowerCase() : undefined,
      category: typeof payload.category === "string" ? payload.category : undefined,
      confidence: typeof payload.confidence === "number" ? payload.confidence : undefined,
      file: typeof payload.file === "string" ? payload.file : undefined,
      line: typeof payload.line === "number" ? payload.line : undefined,
    };
  }

  if (type === "step_started" || type === "step_completed") {
    return {
      schema: "pwnkit.events/v1",
      kind: "stage",
      ts,
      stage: typeof payload.step === "string" ? payload.step : "stage",
      transition: type === "step_started" ? "started" : "completed",
      duration_ms: typeof payload.duration_ms === "number" ? payload.duration_ms : undefined,
    };
  }

  if (type === "agent_turn_started" || type === "agent_turn_completed") {
    return {
      schema: "pwnkit.events/v1",
      kind: "stage",
      ts,
      stage: `turn ${typeof payload.turn === "number" ? payload.turn : "?"}`,
      transition: type === "agent_turn_started" ? "started" : "completed",
      role: typeof payload.role === "string" ? payload.role : undefined,
      turn: typeof payload.turn === "number" ? payload.turn : undefined,
      duration_ms: typeof payload.duration_ms === "number" ? payload.duration_ms : undefined,
    };
  }

  return null;
}
