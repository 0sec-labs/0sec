/**
 * Pure state model for the `ask_operator` question modal.
 *
 * The core `ask_operator` tool pauses a turn and hands the console a typed
 * {@link OperatorQuestionRequest}; the operator answers and the console resolves
 * an {@link OperatorQuestionAnswer}. This module owns the *behaviour* of that
 * modal — cursor movement over the answerable rows, single/multi option
 * selection, and the free-text field — as a reducer over a plain object, so the
 * React/OpenTUI component is a dumb projection of it (mirroring selector.ts).
 *
 * Nothing here imports React, OpenTUI, or touches I/O, and NOTHING here grants
 * authority: answering a question widens no scope and approves no tool. It only
 * collects the operator's selections + optional custom text and builds the
 * answer the tool awaits.
 */

import type {
  OperatorQuestionRequest,
  OperatorQuestionAnswer,
  OperatorQuestionAnswerItem,
} from "@0sec/core";

/** One answerable (navigable) row: an option toggle, or a question's free-text field. */
export interface OperatorNavRow {
  questionIndex: number;
  kind: "option" | "custom";
  /** Set only for `kind: "option"`; indexes into that question's `options`. */
  optionIndex?: number;
}

export interface OperatorQuestionState {
  request: OperatorQuestionRequest;
  /** Cursor into {@link navRows}. */
  index: number;
  /** Every answerable row, in render order (options then the custom field). */
  navRows: OperatorNavRow[];
  /** Selected option labels per question, in selection order. */
  selected: string[][];
  /** Free-text answer per question (empty when untouched / not allowed). */
  custom: string[];
}

/**
 * One row of the render plan: answerable rows carry a `navIndex` (equal to their
 * position in {@link OperatorQuestionState.navRows}); `header`/`prose` rows are
 * display-only. The component maps this to `<text>` and uses `navIndex` to place
 * the highlight and to scroll the active row into view.
 */
export interface OperatorDisplayRow {
  type: "header" | "prose" | "option" | "custom";
  questionIndex: number;
  /** Present iff the row is answerable (option or custom). */
  navIndex?: number;
  /** header / prose text. */
  text?: string;
  /** option: */
  label?: string;
  recommended?: boolean;
  description?: string;
  selected?: boolean;
  multiSelect?: boolean;
  /** custom: current typed text. */
  customText?: string;
}

/** Build the ordered list of answerable rows for a request. */
function buildNavRows(request: OperatorQuestionRequest): OperatorNavRow[] {
  const rows: OperatorNavRow[] = [];
  request.questions.forEach((question, questionIndex) => {
    (question.options ?? []).forEach((_, optionIndex) => {
      rows.push({ questionIndex, kind: "option", optionIndex });
    });
    if (question.allowCustom) rows.push({ questionIndex, kind: "custom" });
  });
  return rows;
}

export function createOperatorQuestionState(
  request: OperatorQuestionRequest,
): OperatorQuestionState {
  return {
    request,
    index: 0,
    navRows: buildNavRows(request),
    selected: request.questions.map(() => []),
    custom: request.questions.map(() => ""),
  };
}

/** The row the cursor is on, or undefined when there is nothing to answer. */
export function operatorActiveRow(state: OperatorQuestionState): OperatorNavRow | undefined {
  return state.navRows[state.index];
}

/** Move the cursor one answerable row, clamped (no wrap). */
export function operatorMove(
  state: OperatorQuestionState,
  dir: "up" | "down",
): OperatorQuestionState {
  const total = state.navRows.length;
  if (total === 0) return state;
  const next = dir === "up" ? state.index - 1 : state.index + 1;
  return { ...state, index: Math.min(Math.max(next, 0), total - 1) };
}

/**
 * Toggle the highlighted option. Multi-select adds/removes the label; single
 * select behaves like a radio that can also be cleared (selecting an option
 * replaces the question's selection; re-selecting it clears it). A no-op on a
 * custom row.
 */
export function operatorToggle(state: OperatorQuestionState): OperatorQuestionState {
  const row = operatorActiveRow(state);
  if (!row || row.kind !== "option" || row.optionIndex === undefined) return state;
  const question = state.request.questions[row.questionIndex];
  const option = question?.options?.[row.optionIndex];
  if (!option) return state;
  const label = option.label;
  const current = state.selected[row.questionIndex] ?? [];
  const has = current.includes(label);
  let nextForQuestion: string[];
  if (question?.multiSelect) {
    nextForQuestion = has ? current.filter((l) => l !== label) : [...current, label];
  } else {
    nextForQuestion = has ? [] : [label];
  }
  const selected = state.selected.map((s, i) => (i === row.questionIndex ? nextForQuestion : s));
  return { ...state, selected };
}

/** Append a character to the active custom field (no-op elsewhere). */
export function operatorAppend(
  state: OperatorQuestionState,
  char: string,
): OperatorQuestionState {
  const row = operatorActiveRow(state);
  if (!row || row.kind !== "custom") return state;
  const custom = state.custom.map((c, i) => (i === row.questionIndex ? c + char : c));
  return { ...state, custom };
}

/** Delete the last character of the active custom field (no-op elsewhere). */
export function operatorBackspace(state: OperatorQuestionState): OperatorQuestionState {
  const row = operatorActiveRow(state);
  if (!row || row.kind !== "custom") return state;
  const custom = state.custom.map((c, i) => (i === row.questionIndex ? c.slice(0, -1) : c));
  return { ...state, custom };
}

/** True when any question offers options (drives the "space toggle" hint). */
export function operatorHasOptions(state: OperatorQuestionState): boolean {
  return state.request.questions.some((q) => (q.options?.length ?? 0) > 0);
}

/**
 * The render plan: header + prose per question, then its option rows and (when
 * allowed) its custom field. Answerable rows carry `navIndex`; the component
 * highlights the row whose `navIndex === state.index`.
 */
export function planOperatorRows(state: OperatorQuestionState): OperatorDisplayRow[] {
  const rows: OperatorDisplayRow[] = [];
  let nav = 0;
  state.request.questions.forEach((question, questionIndex) => {
    rows.push({ type: "header", questionIndex, text: question.header });
    rows.push({ type: "prose", questionIndex, text: question.question });
    (question.options ?? []).forEach((option) => {
      rows.push({
        type: "option",
        questionIndex,
        navIndex: nav++,
        label: option.label,
        recommended: option.recommended === true,
        description: option.description,
        selected: (state.selected[questionIndex] ?? []).includes(option.label),
        multiSelect: question.multiSelect === true,
      });
    });
    if (question.allowCustom) {
      rows.push({
        type: "custom",
        questionIndex,
        navIndex: nav++,
        customText: state.custom[questionIndex] ?? "",
      });
    }
  });
  return rows;
}

/** Display-row index of the answerable row the cursor is on, or 0. */
export function operatorActiveDisplayIndex(
  rows: readonly OperatorDisplayRow[],
  cursor: number,
): number {
  const at = rows.findIndex((row) => row.navIndex === cursor);
  return at >= 0 ? at : 0;
}

/**
 * Build the answer the tool awaits. Each question yields an item keyed by its
 * `header`; `selectedLabels` / `customText` are omitted when empty so the tool's
 * downstream shaping (which drops empties) is mirrored exactly.
 */
export function buildOperatorAnswer(state: OperatorQuestionState): OperatorQuestionAnswer {
  const answers: OperatorQuestionAnswerItem[] = state.request.questions.map((question, i) => {
    const item: OperatorQuestionAnswerItem = { header: question.header };
    const labels = state.selected[i] ?? [];
    if (labels.length > 0) item.selectedLabels = labels;
    const text = (state.custom[i] ?? "").trim();
    if (text.length > 0) item.customText = text;
    return item;
  });
  return { requestId: state.request.requestId, answers };
}
