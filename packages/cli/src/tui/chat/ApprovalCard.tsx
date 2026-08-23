/** @jsxImportSource @opentui/react */
import React from "react";
import { fitTuiText, sanitizeTuiText } from "../text.js";
import type { SelectorItem } from "../selector.js";
import type { Theme } from "../theme-context.js";

/** The item id that grants. Everything else declines. */
export const APPROVAL_GRANT_ID = "grant";
export const APPROVAL_DENY_ID = "deny";

/**
 * Turn a tool call's arguments into readable `key: value` lines — one per row,
 * so the approval card can show WHAT is being authorized instead of a truncated
 * one-line JSON blob. A scalar becomes its own line; a nested object/array is
 * compacted to JSON on that key's line (still readable, still one row). The
 * per-row truncation happens at render time against the panel width, which is
 * what keeps the card's height predictable.
 */
export function argumentSummaryLines(args: unknown): string[] {
  if (args === undefined || args === null) return [];
  if (typeof args !== "object") return [sanitizeTuiText(String(args))];
  const entries = Array.isArray(args)
    ? args.map((value, index) => [String(index), value] as const)
    : Object.entries(args as Record<string, unknown>);
  if (entries.length === 0) return [];
  return entries.map(([key, value]) => {
    const rendered = typeof value === "string" ? value : JSON.stringify(value) ?? String(value);
    return sanitizeTuiText(`${key}: ${rendered}`);
  });
}

/**
 * One pending authorization decision, projected onto the selector.
 *
 * The pending promise itself stays in the `pending*` state it always lived
 * in — this is only a presentation + dispatch view over it, so the unmount
 * cleanup that resolves every outstanding prompt to a DENIAL keeps working
 * untouched.
 */
export type ApprovalPrompt = {
  /**
   * The pending record this prompt speaks for. Object identity, so a new
   * request gets a fresh selector position and a repeat of an identical
   * request is still its own decision.
   */
  owner: object;
  title: string;
  /** What is being decided — tool name, hosts, path, reason. */
  context: string;
  /** The subject of the decision, shown prominently (e.g. the tool name). */
  subject?: string;
  /**
   * Readable, one-per-row detail lines (pretty-printed `key: value` arguments,
   * or a short human summary) — never a truncated single-line JSON blob. Each
   * line is truncated (not wrapped) to the panel width so the card's height
   * stays predictable.
   */
  bodyLines?: string[];
  items: SelectorItem[];
  borderColor: string;
  titleColor: string;
  /** Applies the chosen item. Guarded to run at most once per `owner`. */
  decide: (id: string) => void;
  /**
   * Esc / dismissal. ALWAYS the declining outcome: an operator must never be
   * able to grant authority by walking away from the prompt.
   */
  decline: () => void;
};

/**
 * Total rows an {@link ApprovalCard} occupies for the content it will render.
 *
 * The card is a rail + background block (no top/bottom border and no vertical
 * padding), so its height is exactly its content rows. Stating it as a pure
 * function lets the column reserve precisely what the card paints — the same
 * anti-collapse contract every other stacked panel obeys.
 */
export function approvalCardRows({
  hasSubject,
  bodyRows,
  choiceRows,
}: {
  hasSubject: boolean;
  bodyRows: number;
  choiceRows: number;
}): number {
  return 1 /* title */
    + (hasSubject ? 1 : 0)
    + (bodyRows > 0 ? bodyRows + 1 /* blank spacer under the args */ : 0)
    + 1 /* blank spacer above the choices */
    + Math.max(1, choiceRows)
    + 1 /* hint */;
}

/**
 * A pending authorization decision, drawn as a prominent-but-calm card.
 *
 * This replaces the old cramped bordered picker for approvals: it keeps the
 * SAME selector reducer, dispatch and key bindings (the caller owns those),
 * and only changes the surface. A decision is an important moment, so the tool
 * name and its arguments are shown READABLY — one `key: value` row each, each
 * truncated (never wrapped) so the card's height is exactly what was reserved —
 * and the two choices read as clean rows with a single accent on the selected
 * one, its consequence aligned to the right. The framing is the same thin
 * accent rail + faint panel background as the composer and the operator's own
 * turns, not a heavy four-sided box; `red` stays reserved for errors.
 */
export function ApprovalCard({
  title,
  progress,
  subject,
  body,
  choices,
  activeIndex,
  hint,
  accent,
  contentWidth,
  height,
  theme,
}: {
  title: string;
  progress: string;
  subject?: string;
  /** Already-sliced, render-ready detail rows (may end in a "+N more" line). */
  body: string[];
  choices: SelectorItem[];
  activeIndex: number;
  hint: string;
  /** The card's tone — WARNING for scope gates, INFO for the co-pilot gate. */
  accent: string;
  contentWidth: number;
  height: number;
  theme: Theme;
}) {
  const { PANEL_ALT, MUTED, TEXT, PRIMARY } = theme;
  // Conservative inner width: rail (1) + paddingX (1 each side) = 3 cells of
  // chrome, rounded up to 4 so every explicit allocation clears the edge.
  const innerWidth = Math.max(1, contentWidth - 4);
  const progressWidth = Math.min(innerWidth, progress.length);
  const titleGap = progressWidth > 0 && innerWidth - progressWidth > 1 ? 1 : 0;
  const titleWidth = Math.max(1, innerWidth - progressWidth - titleGap);
  const labelWidth = Math.max(1, Math.min(Math.max(1, innerWidth - 2), Math.floor(innerWidth * 0.5)));
  const afterLabel = innerWidth - 2 - labelWidth;
  const metaGap = afterLabel > 1 ? 1 : 0;
  const metaWidth = Math.max(0, afterLabel - metaGap);

  return (
    <box flexDirection="row" width={contentWidth} minWidth={0} height={height} flexShrink={0} marginTop={1} backgroundColor={PANEL_ALT}>
      <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={accent} />
      <box flexDirection="column" flexGrow={1} minWidth={0} paddingX={1}>
        <box flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
          <box width={titleWidth} flexShrink={0} minWidth={0}>
            <text fg={accent}>{fitTuiText(title, titleWidth)}</text>
          </box>
          {progressWidth > 0 ? (
            <box width={progressWidth} flexShrink={0} minWidth={0} marginLeft={titleGap}>
              <text fg={MUTED}>{fitTuiText(progress, progressWidth, { mode: "middle" })}</text>
            </box>
          ) : null}
        </box>
        {subject ? (
          <box width={innerWidth} flexShrink={0} minWidth={0}>
            <text fg={TEXT}>{fitTuiText(subject, innerWidth)}</text>
          </box>
        ) : null}
        {body.length > 0 ? (
          <>
            {body.map((line, index) => (
              <box key={`body-${index}`} width={innerWidth} flexShrink={0} minWidth={0}>
                <text fg={MUTED}>{fitTuiText(line, innerWidth, { mode: "middle" })}</text>
              </box>
            ))}
            <text fg={MUTED}> </text>
          </>
        ) : null}
        <text fg={MUTED}> </text>
        {choices.map((item, offset) => {
          const active = offset === activeIndex;
          return (
            <box key={item.id} flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
              <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{active ? "›" : " "}</text>
              <box width={labelWidth} flexShrink={0} minWidth={0} marginLeft={1}>
                <text fg={active ? PRIMARY : TEXT}>{fitTuiText(item.label, labelWidth)}</text>
              </box>
              {metaWidth > 0 ? (
                <box width={metaWidth} flexShrink={0} minWidth={0} marginLeft={metaGap}>
                  <text fg={MUTED}>{fitTuiText(item.meta ?? "", metaWidth, { mode: "middle" })}</text>
                </box>
              ) : null}
            </box>
          );
        })}
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(hint, innerWidth)}</text>
        </box>
      </box>
    </box>
  );
}
