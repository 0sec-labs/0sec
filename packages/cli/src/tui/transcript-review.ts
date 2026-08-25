import type { ChatEntry } from "./chat/types.js";
import {
  renderMarkdown,
  spansToText,
} from "./markdown.js";
import { repeatSuffix } from "./transcript.js";
import {
  planTranscript,
  type TranscriptDetail,
} from "./transcript-style.js";
import { sanitizeTuiText } from "./text.js";

export type TranscriptReviewTone =
  | "user"
  | "assistant"
  | "reasoning"
  | "tool"
  | "failure"
  | "notice"
  | "fold";

export interface TranscriptReviewLine {
  text: string;
  tone: TranscriptReviewTone;
  turn: number;
  entryId?: string;
}

export interface TranscriptReviewDocument {
  lines: TranscriptReviewLine[];
  text: string;
}

export interface TranscriptReviewOptions {
  width: number;
  detail: TranscriptDetail;
  expandedTurns?: ReadonlySet<number>;
}

function markdownLines(source: string, width: number): string[] {
  const lines: string[] = [];
  const blockWidth = Math.max(8, width);

  for (const block of renderMarkdown(source, blockWidth)) {
    if (block.kind === "rule") {
      lines.push("─".repeat(Math.max(3, Math.min(blockWidth, 80))));
      continue;
    }

    if (block.kind === "code") {
      for (const line of block.lines) lines.push(`  ${line}`);
      continue;
    }

    if (block.kind === "table") {
      lines.push(block.header.map(spansToText).join(" │ "));
      for (const row of block.rows) lines.push(row.map(spansToText).join(" │ "));
      continue;
    }

    if (block.kind === "listItem") {
      for (const [index, line] of block.lines.entries()) {
        const prefix = index === 0
          ? `${" ".repeat(block.indent)}${block.marker} `
          : " ".repeat(block.indent + block.marker.length + 1);
        lines.push(`${prefix}${spansToText(line)}`);
      }
      continue;
    }

    const prefix = block.kind === "heading"
      ? `${"#".repeat(block.level)} `
      : block.kind === "quote"
        ? "│ "
        : "";
    for (const line of block.lines) lines.push(`${prefix}${spansToText(line)}`);
  }

  return lines;
}

function detailLines(value: unknown): string[] {
  if (typeof value !== "string") return [];
  return value
    .replace(/\r/g, "")
    .split("\n")
    .map((line) => sanitizeTuiText(line))
    .filter(Boolean);
}

function reviewDetail(entry: ChatEntry, detail: TranscriptDetail): string[] {
  if (detail === "expanded") {
    const rich = entry.commandOutput ?? entry.editDiff ?? entry.webAnswer;
    if (rich) return detailLines(rich);
  }
  return detailLines(entry.detail);
}

function pushLines(
  document: TranscriptReviewLine[],
  lines: readonly string[],
  tone: TranscriptReviewTone,
  entry: ChatEntry,
  indent: string = "",
): void {
  for (const text of lines) {
    if (!text) continue;
    document.push({ text: `${indent}${text}`, tone, turn: entry.turn, entryId: entry.id });
  }
}

function compileEntry(
  document: TranscriptReviewLine[],
  entry: ChatEntry,
  options: TranscriptReviewOptions,
): void {
  const width = Math.max(8, options.width - 2);
  const repeat = repeatSuffix(entry.repeat);

  if (entry.kind === "user" || entry.kind === "assistant") {
    const tone = entry.kind === "user" ? "user" : "assistant";
    document.push({
      text: `${entry.kind === "user" ? "OPERATOR" : "0SEC"}${repeat}`,
      tone,
      turn: entry.turn,
      entryId: entry.id,
    });
    pushLines(document, markdownLines(entry.text, width), tone, entry, "  ");
    return;
  }

  if (entry.kind === "reasoning") {
    document.push({ text: `THINKING${repeat}`, tone: "reasoning", turn: entry.turn, entryId: entry.id });
    pushLines(document, markdownLines(entry.text, width), "reasoning", entry, "  ");
    return;
  }

  if (entry.kind === "tool" || entry.kind === "subagent") {
    const failed = entry.success === false || entry.subagentOutcome === "failed";
    const tone = failed ? "failure" : "tool";
    const state = failed ? "failed" : entry.success === undefined && entry.subagentOutcome === undefined ? "running" : "done";
    const label = entry.kind === "subagent" ? "AGENT" : "TOOL";
    const args = entry.toolArgs ? ` · ${entry.toolArgs}` : "";
    document.push({ text: `${label} ${state} · ${entry.text}${args}${repeat}`, tone, turn: entry.turn, entryId: entry.id });
    pushLines(document, reviewDetail(entry, options.detail), tone, entry, "  ");
    if (entry.subagentSummary) pushLines(document, detailLines(entry.subagentSummary), tone, entry, "  ");
    if (entry.subagentError) pushLines(document, detailLines(entry.subagentError), "failure", entry, "  ");
    return;
  }

  const tone = entry.kind === "error" ? "failure" : "notice";
  document.push({ text: `${entry.text}${repeat}`, tone, turn: entry.turn, entryId: entry.id });
  pushLines(document, detailLines(entry.detail), tone, entry, "  ");
}

/**
 * Compile canonical chat entries into a deterministic, line-oriented review
 * document. Native TextBufferView owns final terminal wrapping and scrolling.
 */
export function compileTranscriptReview(
  entries: readonly ChatEntry[],
  options: TranscriptReviewOptions,
): TranscriptReviewDocument {
  const lines: TranscriptReviewLine[] = [];
  const plan = planTranscript(entries, options.detail, options.expandedTurns);

  for (const item of plan) {
    if (item.type === "fold") {
      lines.push({ text: `▸ ${item.summary}`, tone: "fold", turn: item.turn });
      continue;
    }

    compileEntry(lines, item.entry, options);
    lines.push({ text: "", tone: "notice", turn: item.entry.turn, entryId: item.entry.id });
  }

  while (lines.at(-1)?.text === "") lines.pop();
  return { lines, text: lines.map((line) => line.text).join("\n") };
}
