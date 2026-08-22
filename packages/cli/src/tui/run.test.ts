import { describe, expect, it } from "vitest";
import {
  buildCrashFeedbackMessage,
  crashStackLines,
  describeFeedbackOutcome,
  resolveCrashKey,
  sanitizeCrashText,
  type CrashInfo,
} from "./run.js";

const crash: CrashInfo = {
  message: "Cannot read properties of undefined (reading 'x')",
  stack: [
    "TypeError: Cannot read properties of undefined (reading 'x')",
    "    at ChatScreen (/home/op/.0sec/run.tsx:1200:5)",
    "    at renderWithHooks (/node_modules/react/index.js:1:1)",
  ].join("\n"),
};

describe("sanitizeCrashText", () => {
  it("redacts common secret shapes", () => {
    const dirty = [
      "token=sk-abcdefghijklmnopqrstuvwxyz012345",
      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      "AKIAIOSFODNN7EXAMPLE",
      "authorization: Bearer eyJhbGciOi.abc.def",
      "password=hunter2secret",
    ].join(" ");
    const clean = sanitizeCrashText(dirty);
    expect(clean).not.toContain("sk-abcdefghijklmnopqrstuvwxyz");
    expect(clean).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    expect(clean).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(clean).not.toContain("hunter2secret");
    expect(clean).toContain("[redacted]");
  });

  it("leaves ordinary stack text intact", () => {
    expect(sanitizeCrashText("at ChatScreen (run.tsx:12:3)")).toBe("at ChatScreen (run.tsx:12:3)");
  });

  it("treats undefined as empty", () => {
    expect(sanitizeCrashText(undefined)).toBe("");
  });
});

describe("crashStackLines", () => {
  it("trims, drops blanks and caps at max", () => {
    const lines = crashStackLines(crash.stack, 2);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("TypeError: Cannot read properties of undefined (reading 'x')");
    expect(lines[1]).toBe("at ChatScreen (/home/op/.0sec/run.tsx:1200:5)");
  });

  it("returns nothing for max 0", () => {
    expect(crashStackLines(crash.stack, 0)).toEqual([]);
  });
});

describe("buildCrashFeedbackMessage", () => {
  it("prepends the note, then a delimited sanitized report", () => {
    const message = buildCrashFeedbackMessage("it died opening findings", crash, 3);
    expect(message.startsWith("it died opening findings\n\n")).toBe(true);
    expect(message).toContain("--- TUI crash report ---");
    expect(message).toContain("error: Cannot read properties of undefined (reading 'x')");
    expect(message).toContain("stack:");
  });

  it("omits the note block when the note is blank", () => {
    const message = buildCrashFeedbackMessage("   ", crash);
    expect(message.startsWith("--- TUI crash report ---")).toBe(true);
  });

  it("redacts secrets that appear in the message or stack", () => {
    const message = buildCrashFeedbackMessage("", {
      message: "boom with token=sk-abcdefghijklmnopqrstuvwxyz012345",
      stack: "at f (ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789)",
    });
    expect(message).not.toContain("sk-abcdefghijklmnopqrstuvwxyz");
    expect(message).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  });

  it("falls back to a placeholder for an empty message", () => {
    expect(buildCrashFeedbackMessage("", { message: "", stack: "" })).toContain("error: unknown TUI error");
  });
});

describe("resolveCrashKey", () => {
  it("maps r/f/q in the options view", () => {
    expect(resolveCrashKey("options", { name: "r" })).toEqual({ type: "restart" });
    expect(resolveCrashKey("options", { name: "f" })).toEqual({ type: "feedback" });
    expect(resolveCrashKey("options", { name: "q" })).toEqual({ type: "quit" });
    expect(resolveCrashKey("options", { name: "escape" })).toEqual({ type: "quit" });
    expect(resolveCrashKey("options", { name: "x" })).toEqual({ type: "none" });
  });

  it("offers the same commands from the result view", () => {
    expect(resolveCrashKey("result", { name: "r" })).toEqual({ type: "restart" });
    expect(resolveCrashKey("result", { name: "f" })).toEqual({ type: "feedback" });
    expect(resolveCrashKey("result", { name: "q" })).toEqual({ type: "quit" });
  });

  it("treats letters as text in the feedback view", () => {
    expect(resolveCrashKey("feedback", { name: "r", sequence: "r" })).toEqual({ type: "append", text: "r" });
    expect(resolveCrashKey("feedback", { name: "q", sequence: "q" })).toEqual({ type: "append", text: "q" });
    expect(resolveCrashKey("feedback", { name: "return" })).toEqual({ type: "submit" });
    expect(resolveCrashKey("feedback", { name: "escape" })).toEqual({ type: "back" });
    expect(resolveCrashKey("feedback", { name: "backspace" })).toEqual({ type: "backspace" });
  });

  it("does not append control chords as text", () => {
    expect(resolveCrashKey("feedback", { ctrl: true, name: "a", sequence: "" })).toEqual({ type: "none" });
    expect(resolveCrashKey("feedback", { meta: true, name: "v", sequence: "v" })).toEqual({ type: "none" });
  });

  it("ctrl+c quits from every view", () => {
    for (const view of ["options", "feedback", "submitting", "result"] as const) {
      expect(resolveCrashKey(view, { ctrl: true, name: "c" })).toEqual({ type: "quit" });
    }
  });

  it("swallows keys while submitting", () => {
    expect(resolveCrashKey("submitting", { name: "r" })).toEqual({ type: "none" });
  });
});

describe("describeFeedbackOutcome", () => {
  const local = { ok: true, path: "/home/op/.0sec/feedback.md" };

  it("reports success when both save and submit succeed", () => {
    const out = describeFeedbackOutcome(local, { ok: true });
    expect(out.tone).toBe("ok");
    expect(out.text).toContain("submitted");
  });

  it("reports a saved-locally skip as ok", () => {
    const out = describeFeedbackOutcome(local, { ok: false, skipped: "no-endpoint", error: "No feedback endpoint configured. Saved locally only." });
    expect(out.tone).toBe("ok");
    expect(out.text).toContain("locally");
  });

  it("reports a network failure as an error but notes the local save", () => {
    const out = describeFeedbackOutcome(local, { ok: false, error: "timed out" });
    expect(out.tone).toBe("err");
    expect(out.text).toContain("Saved locally");
    expect(out.text).toContain("timed out");
  });

  it("reports a local save failure as an error", () => {
    const out = describeFeedbackOutcome({ ok: false, path: local.path, error: "EACCES" }, { ok: false, skipped: "no-endpoint" });
    expect(out.tone).toBe("err");
    expect(out.text).toContain("Could not save");
  });
});
