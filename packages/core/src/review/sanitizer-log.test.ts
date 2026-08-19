import { describe, expect, it } from "vitest";
import { parseSanitizerLog, renderSanitizerVerdict } from "./sanitizer-log.js";

describe("parseSanitizerLog", () => {
  it("parses canonical AddressSanitizer heap-buffer-overflow output", () => {
    const log = `
==90673==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000fb at pc 0x000108868a95 bp 0x7fff573979a0 sp 0x7fff57397998
READ of size 1 at 0x6020000000fb thread T0
    #0 0x108868a94 in main example_HeapOutOfBounds.cc:5:10
0x6020000000fb is located 0 bytes to the right of 11-byte region [0x6020000000f0,0x6020000000fb)
SUMMARY: AddressSanitizer: heap-buffer-overflow example_HeapOutOfBounds.cc:5:10 in main
`;

    const verdict = parseSanitizerLog(log);
    expect(verdict).toMatchObject({
      sanitizer: "asan",
      kind: "heap-buffer-overflow",
      primitive: "read",
      category: "out-of-bounds-read",
      sourceFile: "example_HeapOutOfBounds.cc",
      sourceLine: 5,
      accessSize: 1,
      allocSize: 11,
    });
  });

  it("maps AddressSanitizer heap-use-after-free to use-after-free", () => {
    const log = `
==9442==ERROR: AddressSanitizer: heap-use-after-free on address 0x7f7ddab8c084 at pc 0x403c8c bp 0x7fff87fb82d0 sp 0x7fff87fb82c8
WRITE of size 4 at 0x7f7ddab8c084 thread T0
    #0 0x403c8b in main example_UseAfterFree.cc:5:7
SUMMARY: AddressSanitizer: heap-use-after-free example_UseAfterFree.cc:5:7 in main
`;

    const verdict = parseSanitizerLog(log);
    expect(verdict).toMatchObject({
      sanitizer: "asan",
      kind: "heap-use-after-free",
      primitive: "write",
      category: "use-after-free",
      sourceFile: "example_UseAfterFree.cc",
      sourceLine: 5,
      accessSize: 4,
    });
  });

  it("parses canonical UndefinedBehaviorSanitizer signed integer overflow output", () => {
    const log = "test.cc:3:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'";

    const verdict = parseSanitizerLog(log);
    expect(verdict).toMatchObject({
      sanitizer: "ubsan",
      kind: "signed-integer-overflow",
      category: "integer-overflow",
      primitive: "unknown",
      sourceFile: "test.cc",
      sourceLine: 3,
    });
  });

  it("returns null for non-sanitizer text", () => {
    expect(parseSanitizerLog("compiler warning: unused variable")).toBeNull();
  });

  it("renders a concise verdict summary", () => {
    const verdict = parseSanitizerLog("test.cc:3:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'");
    expect(verdict).not.toBeNull();
    expect(renderSanitizerVerdict(verdict!)).toBe(
      "UBSAN signed-integer-overflow; category=integer-overflow; primitive=unknown; source=test.cc:3",
    );
  });
});
