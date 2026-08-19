import { describe, expect, it } from "vitest";
import { JSFUCK_ALERT_PAYLOAD, JSFUCK_XSS_PAYLOAD } from "./payloads.js";

describe("JSFUCK_ALERT_PAYLOAD", () => {
  it("only contains the six JSFuck characters []()!+", () => {
    const allowed = new Set("[]()!+".split(""));
    const offending: string[] = [];
    for (const ch of JSFUCK_ALERT_PAYLOAD) {
      if (!allowed.has(ch)) {
        offending.push(ch);
      }
    }
    expect(offending).toEqual([]);
  });

  it("contains no letters, digits, or angle brackets (XBEN-010 filter shape)", () => {
    expect(JSFUCK_ALERT_PAYLOAD).not.toMatch(/[a-zA-Z]/);
    expect(JSFUCK_ALERT_PAYLOAD).not.toMatch(/[0-9]/);
    expect(JSFUCK_ALERT_PAYLOAD).not.toMatch(/[<>]/);
  });

  it("is non-trivially long (real JSFuck encodings of alert(1) are >1000 chars)", () => {
    expect(JSFUCK_ALERT_PAYLOAD.length).toBeGreaterThan(1000);
  });

  it("evaluates and triggers alert(1)", () => {
    let alertArg: unknown = null;
    // Provide a fake `alert` in scope for the eval'd payload.
    const alert = (x: unknown) => {
      alertArg = x;
    };
    // Reference `alert` so the linter / TS sees it as used; payload calls it via global lookup.
    void alert;
    // The JSFuck payload resolves `alert` from the global scope, so we have to
    // stash it on globalThis for the eval to find it.
    (globalThis as unknown as { alert: (x: unknown) => void }).alert = alert;
    try {
      // eslint-disable-next-line no-eval
      (0, eval)(JSFUCK_ALERT_PAYLOAD);
    } finally {
      delete (globalThis as unknown as { alert?: unknown }).alert;
    }
    expect(alertArg).toBe(1);
  });
});

describe("JSFUCK_XSS_PAYLOAD", () => {
  it("only contains the six JSFuck characters []()!+", () => {
    const allowed = new Set("[]()!+".split(""));
    const offending: string[] = [];
    for (const ch of JSFUCK_XSS_PAYLOAD) {
      if (!allowed.has(ch)) offending.push(ch);
    }
    expect(offending).toEqual([]);
  });

  it("contains no letters, digits, or angle brackets (XBEN-010 filter shape)", () => {
    expect(JSFUCK_XSS_PAYLOAD).not.toMatch(/[a-zA-Z]/);
    expect(JSFUCK_XSS_PAYLOAD).not.toMatch(/[0-9]/);
    expect(JSFUCK_XSS_PAYLOAD).not.toMatch(/[<>]/);
  });

  it("is non-trivially long", () => {
    expect(JSFUCK_XSS_PAYLOAD.length).toBeGreaterThan(3000);
  });

  it("evaluates and triggers alert('XSS')", () => {
    let alertArg: unknown = null;
    const alert = (x: unknown) => {
      alertArg = x;
    };
    void alert;
    (globalThis as unknown as { alert: (x: unknown) => void }).alert = alert;
    try {
      // eslint-disable-next-line no-eval
      (0, eval)(JSFUCK_XSS_PAYLOAD);
    } finally {
      delete (globalThis as unknown as { alert?: unknown }).alert;
    }
    expect(alertArg).toBe("XSS");
  });
});
