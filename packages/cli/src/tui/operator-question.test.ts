import { describe, expect, it } from "vitest";
import type { OperatorQuestionRequest } from "@0sec/core";
import {
  buildOperatorAnswer,
  createOperatorQuestionState,
  operatorActiveDisplayIndex,
  operatorActiveRow,
  operatorAppend,
  operatorBackspace,
  operatorHasOptions,
  operatorMove,
  operatorToggle,
  planOperatorRows,
} from "./operator-question.js";

const request: OperatorQuestionRequest = {
  requestId: "req-1",
  questions: [
    {
      header: "Priority",
      question: "Which host should I attack first?",
      options: [
        { label: "api.example.com", recommended: true },
        { label: "admin.example.com" },
        { label: "cdn.example.com" },
      ],
    },
    {
      header: "Approach",
      question: "Pick any that apply, or type your own.",
      options: [{ label: "SQLi" }, { label: "SSRF" }],
      multiSelect: true,
      allowCustom: true,
    },
  ],
};

describe("operator-question state", () => {
  it("enumerates every option plus each custom field as a navigable row", () => {
    const state = createOperatorQuestionState(request);
    // 3 options (q0) + 2 options (q1) + 1 custom (q1) = 6.
    expect(state.navRows).toHaveLength(6);
    expect(state.navRows[5]).toEqual({ questionIndex: 1, kind: "custom" });
    expect(operatorHasOptions(state)).toBe(true);
  });

  it("clamps cursor movement without wrapping", () => {
    let state = createOperatorQuestionState(request);
    state = operatorMove(state, "up");
    expect(state.index).toBe(0);
    for (let i = 0; i < 20; i += 1) state = operatorMove(state, "down");
    expect(state.index).toBe(state.navRows.length - 1);
  });

  it("single-select replaces the selection and can clear it", () => {
    let state = createOperatorQuestionState(request);
    state = operatorToggle(state); // select api.example.com
    expect(state.selected[0]).toEqual(["api.example.com"]);
    state = operatorMove(state, "down");
    state = operatorToggle(state); // select admin.example.com -> replaces
    expect(state.selected[0]).toEqual(["admin.example.com"]);
    state = operatorToggle(state); // toggle same off
    expect(state.selected[0]).toEqual([]);
  });

  it("multi-select accumulates and removes labels", () => {
    let state = createOperatorQuestionState(request);
    state = { ...state, index: 3 }; // first option of q1 (SQLi)
    state = operatorToggle(state);
    state = operatorMove(state, "down");
    state = operatorToggle(state); // SSRF
    expect(state.selected[1]).toEqual(["SQLi", "SSRF"]);
    state = { ...state, index: 3 };
    state = operatorToggle(state); // remove SQLi
    expect(state.selected[1]).toEqual(["SSRF"]);
  });

  it("types into the active custom field only", () => {
    let state = createOperatorQuestionState(request);
    // custom row is the last nav row (index 5).
    state = { ...state, index: 5 };
    expect(operatorActiveRow(state)?.kind).toBe("custom");
    for (const ch of "path traversal") state = operatorAppend(state, ch);
    expect(state.custom[1]).toBe("path traversal");
    state = operatorBackspace(state);
    expect(state.custom[1]).toBe("path traversa");
    // append is a no-op on an option row.
    const before = { ...state, index: 0 };
    expect(operatorAppend(before, "x").custom[1]).toBe("path traversa");
  });

  it("builds an answer keyed by header, omitting empties and trimming custom", () => {
    let state = createOperatorQuestionState(request);
    state = operatorToggle(state); // q0 -> api.example.com
    state = { ...state, index: 5 };
    for (const ch of "  RCE  ") state = operatorAppend(state, ch);
    const answer = buildOperatorAnswer(state);
    expect(answer.requestId).toBe("req-1");
    expect(answer.answers[0]).toEqual({ header: "Priority", selectedLabels: ["api.example.com"] });
    expect(answer.answers[1]).toEqual({ header: "Approach", customText: "RCE" });
  });

  it("plans display rows with headers, prose and navigable rows", () => {
    const state = createOperatorQuestionState(request);
    const rows = planOperatorRows(state);
    expect(rows[0]).toMatchObject({ type: "header", text: "Priority" });
    expect(rows[1]).toMatchObject({ type: "prose" });
    expect(rows[2]).toMatchObject({ type: "option", navIndex: 0, recommended: true });
    // The active display index resolves a cursor to its display row.
    expect(operatorActiveDisplayIndex(rows, 0)).toBe(2);
    expect(rows[operatorActiveDisplayIndex(rows, 5)].type).toBe("custom");
  });

  it("handles a custom-only question (no options)", () => {
    const req: OperatorQuestionRequest = {
      requestId: "r2",
      questions: [{ header: "Note", question: "Anything to add?", allowCustom: true }],
    };
    let state = createOperatorQuestionState(req);
    expect(state.navRows).toHaveLength(1);
    expect(operatorHasOptions(state)).toBe(false);
    state = operatorToggle(state); // no-op, no option under cursor
    expect(state.selected[0]).toEqual([]);
  });
});
