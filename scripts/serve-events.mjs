#!/usr/bin/env node
// SSE bridge for the live dashboard (0sec#370).
//
// Two modes, mutually compatible — pass either or both:
//
//   1. GemmaForge ND-JSON (default `/events`):
//        node scripts/serve-events.mjs <events.ndjson>
//      Tails the file and re-emits each non-empty line as `data: <line>`
//      to anyone connected at `/events`. The dashboard's Probe + Lead
//      lanes consume this stream (`?events=http://localhost:8765/events`).
//
//   2. 0sec hunt feed (`/hunt-events`):
//        node scripts/serve-events.mjs --0sec-log <0sec-stdout.log>
//      Tails a file containing `0SEC_EVENT_<TYPE> {json}` lines (what
//      core/src/events/bus.ts:cloudEventSink writes when
//      0SEC_CLOUD_EVENTS=1) and translates each into the unified
//      `0sec.events/v1` JSON shape the Hunt lane renders. The
//      dashboard's Hunt lane consumes this stream
//      (`?huntEvents=http://localhost:8765/hunt-events`).
//
// Why a separate endpoint instead of multiplexing both into `/events`:
// the two upstream streams are produced by different processes (the
// gemmaforge scanner and a 0sec scan), often started at different
// times, and they use distinct schemas. Keeping them on two endpoints
// lets the dashboard subscribe independently, reconnect independently,
// and renders the lanes correctly when only one source is live.
//
// CORS is permissive (`*`) since this only ever runs locally.

import { createReadStream, statSync, watch } from "node:fs";
import { createServer } from "node:http";
import { resolve } from "node:path";

const argv = process.argv.slice(2);
if (argv.length === 0 || argv[0] === "--help") {
  console.error("usage: serve-events.mjs [<events.ndjson>] [--0sec-log <path>] [--port 8765]");
  console.error("  at least one of <events.ndjson> or --0sec-log must be provided");
  process.exit(1);
}

const portIdx = argv.indexOf("--port");
const port = portIdx >= 0 ? Number(argv[portIdx + 1]) : 8765;
const osecIdx = argv.indexOf("--0sec-log");
const osecLog = osecIdx >= 0 ? resolve(argv[osecIdx + 1]) : null;
const positional = argv.filter((arg, idx) => {
  if (arg.startsWith("--")) return false;
  if (idx > 0 && (argv[idx - 1] === "--port" || argv[idx - 1] === "--0sec-log")) return false;
  return true;
});
const gemmaFile = positional[0] ? resolve(positional[0]) : null;

if (!gemmaFile && !osecLog) {
  console.error("error: provide a gemmaforge events file and/or --0sec-log <path>");
  process.exit(1);
}

/** @type {Map<string, Set<import("node:http").ServerResponse>>} */
const channels = new Map();
channels.set("events", new Set());
channels.set("hunt-events", new Set());

function broadcast(channel, line) {
  const clients = channels.get(channel);
  if (!clients || clients.size === 0) return;
  const payload = `data: ${line}\n\n`;
  for (const res of clients) res.write(payload);
}

/**
 * Tail an ND-JSON file. Each non-empty line is passed to `onLine`.
 * Internally keeps a byte offset + carry-over buffer so partial trailing
 * lines aren't dropped or duplicated on the next file-change tick.
 */
function tail(file, onLine) {
  let offset;
  let pending = "";
  try { offset = statSync(file).size; } catch { offset = 0; }

  function pump() {
    let size;
    try { size = statSync(file).size; } catch { return; }
    if (size <= offset) {
      // File truncated (rotation) — restart from the new size.
      offset = Math.min(offset, size);
      return;
    }
    const stream = createReadStream(file, { start: offset, end: size - 1, encoding: "utf8" });
    stream.on("data", (chunk) => { pending += chunk; });
    stream.on("end", () => {
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) onLine(trimmed);
      }
      offset = size;
    });
  }

  try {
    watch(file, { persistent: true }, () => pump());
  } catch (err) {
    console.error(`serve-events: cannot watch ${file}: ${err?.message ?? err}`);
  }
}

if (gemmaFile) {
  tail(gemmaFile, (line) => broadcast("events", line));
}

if (osecLog) {
  tail(osecLog, (line) => {
    const translated = translateOsecLine(line);
    if (translated) broadcast("hunt-events", translated);
  });
}

/**
 * Convert one `0SEC_EVENT_<TYPE> {…}` line into a `0sec.events/v1`
 * JSON string. Returns null for unrecognised / unmapped event types so
 * we don't spam the Hunt lane with token-level deltas, planner pings,
 * etc. Mirrors the translator in `dashboard/src/lib/hunt-stream.ts`.
 */
function translateOsecLine(line) {
  const match = /^0SEC_EVENT_([A-Z_]+)\s+(\{.*\})\s*$/.exec(line);
  if (!match) return null;
  const type = match[1].toLowerCase();
  let payload;
  try { payload = JSON.parse(match[2]); } catch { return null; }
  if (!payload || typeof payload !== "object") return null;

  // Best-effort wall-clock timestamp. 0sec's eventBus payloads don't
  // currently carry one; the dashboard treats this as fractional seconds.
  const ts = Date.now() / 1000;

  if (type === "tool_call_started" || type === "tool_call_completed") {
    const argsPreview = typeof payload.args_preview === "string" ? payload.args_preview : undefined;
    const fileLine = extractFileLine(argsPreview);
    return JSON.stringify({
      schema: "0sec.events/v1",
      kind: "tool_use",
      ts,
      tool: typeof payload.tool === "string" ? payload.tool : "?",
      turn: typeof payload.turn === "number" ? payload.turn : undefined,
      args_preview: argsPreview,
      file: fileLine?.file,
      line: fileLine?.line,
      status: type === "tool_call_started"
        ? "running"
        : payload.status === "error" ? "error" : "ok",
      duration_ms: typeof payload.duration_ms === "number" ? payload.duration_ms : undefined,
    });
  }

  if (type === "finding_ingested") {
    return JSON.stringify({
      schema: "0sec.events/v1",
      kind: "finding",
      ts,
      finding_id: payload.finding_id,
      title: payload.title ?? "Finding",
      severity: typeof payload.severity === "string" ? payload.severity.toLowerCase() : undefined,
      category: payload.category,
      confidence: payload.confidence,
      file: payload.file,
      line: payload.line,
    });
  }

  if (type === "step_started" || type === "step_completed") {
    return JSON.stringify({
      schema: "0sec.events/v1",
      kind: "stage",
      ts,
      stage: typeof payload.step === "string" ? payload.step : "stage",
      transition: type === "step_started" ? "started" : "completed",
      duration_ms: payload.duration_ms,
    });
  }

  if (type === "agent_turn_started" || type === "agent_turn_completed") {
    return JSON.stringify({
      schema: "0sec.events/v1",
      kind: "stage",
      ts,
      stage: `turn ${typeof payload.turn === "number" ? payload.turn : "?"}`,
      transition: type === "agent_turn_started" ? "started" : "completed",
      role: payload.role,
      turn: payload.turn,
      duration_ms: payload.duration_ms,
    });
  }

  return null;
}

/** Path-and-line extractor matching the dashboard helper. */
function extractFileLine(text) {
  if (!text) return null;
  const re = /([A-Za-z0-9._/\\\-]+(?:\.[A-Za-z0-9]+))[:\s]+L?(\d+)/;
  const match = re.exec(text);
  if (!match) return null;
  const file = match[1];
  const line = Number.parseInt(match[2], 10);
  if (!Number.isFinite(line) || line <= 0) return null;
  if (!file.includes("/") && !/\.(ts|tsx|js|jsx|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|sh|sql)$/i.test(file)) {
    return null;
  }
  return { file, line };
}

const server = createServer((req, res) => {
  const url = req.url ?? "/";
  let channel = null;
  if (url.startsWith("/events")) channel = "events";
  else if (url.startsWith("/hunt-events")) channel = "hunt-events";
  else {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });
  const source = channel === "events" ? (gemmaFile ?? "(no file)") : (osecLog ?? "(no file)");
  res.write(`: connected to ${source}\n\n`);
  channels.get(channel).add(res);
  req.on("close", () => channels.get(channel).delete(res));
});

server.listen(port, () => {
  if (gemmaFile) {
    console.error(`serve-events: tailing ${gemmaFile} → http://localhost:${port}/events`);
  }
  if (osecLog) {
    console.error(`serve-events: tailing ${osecLog} → http://localhost:${port}/hunt-events`);
  }
});
