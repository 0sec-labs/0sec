import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { appendFeedback, feedbackFilePath, formatFeedbackEntry } from "./feedback.js";

const temps: string[] = [];
function tempHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-feedback-"));
  temps.push(dir);
  return dir;
}

afterEach(() => {
  while (temps.length > 0) {
    const dir = temps.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("feedbackFilePath", () => {
  it("lives under the operator's own 0sec directory", () => {
    expect(feedbackFilePath("/home/op")).toBe("/home/op/.0sec/feedback.md");
  });
});

describe("formatFeedbackEntry", () => {
  it("renders a timestamped markdown block", () => {
    const out = formatFeedbackEntry({ message: "the picker is great", timestamp: "2026-08-22T10:00:00.000Z" });
    expect(out).toContain("## 2026-08-22T10:00:00.000Z");
    expect(out).toContain("the picker is great");
  });

  it("includes context only when supplied", () => {
    const bare = formatFeedbackEntry({ message: "x", timestamp: "t" });
    expect(bare).not.toContain("_");
    const rich = formatFeedbackEntry({
      message: "x",
      timestamp: "t",
      version: "0.13.0",
      model: "gpt-5.5",
      mode: "Standard",
    });
    expect(rich).toContain("_version 0.13.0 · model gpt-5.5 · mode Standard_");
  });

  it("trims the message body", () => {
    expect(formatFeedbackEntry({ message: "  padded  ", timestamp: "t" })).toContain("\npadded\n");
  });
});

describe("appendFeedback", () => {
  it("writes the entry and reports the path", () => {
    const home = tempHome();
    const result = appendFeedback({ message: "first", timestamp: "t1" }, home);
    expect(result.ok).toBe(true);
    expect(readFileSync(result.path, "utf8")).toContain("first");
  });

  it("appends rather than overwriting", () => {
    const home = tempHome();
    appendFeedback({ message: "first", timestamp: "t1" }, home);
    const second = appendFeedback({ message: "second", timestamp: "t2" }, home);
    const body = readFileSync(second.path, "utf8");
    expect(body).toContain("first");
    expect(body).toContain("second");
  });

  it("reports failure instead of throwing when the path is unwritable", () => {
    const home = tempHome();
    // A regular file where the .0sec directory needs to be.
    writeFileSync(join(home, ".0sec"), "not a directory", "utf8");
    const result = appendFeedback({ message: "nope", timestamp: "t" }, home);
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });
});
