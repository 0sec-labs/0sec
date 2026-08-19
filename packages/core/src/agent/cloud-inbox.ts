// 0sec/packages/core/src/agent/cloud-inbox.ts
//
// #978 — cloud control-channel drain (ADR-060). The agent loop already injects
// "pending user messages" into the conversation each turn via the synchronous
// `getPendingUserMessages()` callback (originally the local TUI interrupt hook,
// native-loop.ts). In cloud mode there's no TUI — operator steers arrive in the
// scan's inbox (`scan_messages`, written by the dashboard's "Steer this scan").
//
// This module bridges the two: a background poller GETs the scan's inbox
// (`/scans/:id/inbox`, which atomically claims + marks-consumed every unconsumed
// human message) into a buffer, drained synchronously by `getPendingUserMessages`.
// So an operator steer flips from `pending` → consumed and lands in the agent's
// context at its next turn as an `[Operator steer]` user message. Best-effort
// throughout: a network blip never disturbs the scan.

import { getCloudSinkConfig, type CloudSinkConfig } from "../cloud-sink.js";

const POLL_MS = 3000;

export interface CloudInboxPoller {
  /** Synchronous drain of buffered steers — wired as getPendingUserMessages. */
  drain(): string[];
  /** Stop the background poll (call when the scan ends). */
  stop(): void;
}

export function startCloudInboxPoller(
  config: CloudSinkConfig,
): CloudInboxPoller {
  const buffer: string[] = [];
  let stopped = false;

  const headers: Record<string, string> = {
    "X-0sec-Scan-Id": config.scanId,
  };
  if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(
    config.scanId,
  )}/inbox`;

  const poll = async (): Promise<void> => {
    if (stopped) return;
    try {
      const res = await fetch(url, { headers });
      if (!res.ok) return;
      const rows = (await res.json()) as Array<{
        role?: unknown;
        kind?: unknown;
        body?: unknown;
      }>;
      if (!Array.isArray(rows)) return;
      for (const r of rows) {
        if (
          r.role === "human" &&
          typeof r.body === "string" &&
          r.body.trim().length > 0
        ) {
          const prefix =
            r.kind === "approval" ? "[Operator approval]" : "[Operator steer]";
          buffer.push(`${prefix}: ${r.body.trim()}`);
        }
      }
    } catch {
      // best-effort — the agent runs fine without inbound steers.
    }
  };

  const handle = setInterval(() => void poll(), POLL_MS);
  // Don't keep the process alive solely for the poller.
  if (typeof (handle as { unref?: () => void }).unref === "function") {
    (handle as { unref: () => void }).unref();
  }

  return {
    drain() {
      if (buffer.length === 0) return [];
      return buffer.splice(0, buffer.length);
    },
    stop() {
      stopped = true;
      clearInterval(handle);
    },
  };
}

/**
 * Start the inbox poller iff we're running under a cloud sink (0SEC_CLOUD_SINK
 * + scan id set). Returns null in local-only mode — callers fall back to their
 * own getPendingUserMessages (TUI) or none.
 */
export function maybeStartCloudInboxPoller(): CloudInboxPoller | null {
  const cfg = getCloudSinkConfig();
  if (!cfg) return null;
  return startCloudInboxPoller(cfg);
}
