/**
 * Local feedback capture.
 *
 * Feedback is appended to a file on the operator's own machine and is
 * never transmitted anywhere. A security tool that quietly posted session
 * commentary to a vendor endpoint would be exfiltrating engagement
 * context, so the only honest default is a local file whose path is shown
 * back to the operator, leaving the decision to share entirely with them.
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export interface FeedbackEntry {
  message: string;
  /** ISO timestamp. Injected so the formatter stays deterministic. */
  timestamp: string;
  version?: string;
  model?: string;
  mode?: string;
}

export interface FeedbackResult {
  ok: boolean;
  path: string;
  error?: string;
}

export function feedbackFilePath(homeDir?: string): string {
  return join(homeDir ?? homedir(), ".0sec", "feedback.md");
}

/** Render one entry as a Markdown block. Pure, so it is unit-testable. */
export function formatFeedbackEntry(entry: FeedbackEntry): string {
  const context = [
    entry.version ? `version ${entry.version}` : null,
    entry.model ? `model ${entry.model}` : null,
    entry.mode ? `mode ${entry.mode}` : null,
  ].filter((part): part is string => part !== null);

  const lines = [`## ${entry.timestamp}`];
  if (context.length > 0) lines.push(`_${context.join(" · ")}_`);
  lines.push("", entry.message.trim(), "");
  return `${lines.join("\n")}\n`;
}

/**
 * Append an entry. Never throws — a read-only home directory must not take
 * down the console, so failure is reported through the return value.
 */
export function appendFeedback(entry: FeedbackEntry, homeDir?: string): FeedbackResult {
  const path = feedbackFilePath(homeDir);
  try {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, formatFeedbackEntry(entry), "utf8");
    return { ok: true, path };
  } catch (error) {
    return {
      ok: false,
      path,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
