import { describe, expect, it } from "vitest";
import { assessCraftCandidateIdentity } from "./craft-candidate-identity.js";

const overflowInParseHeader = `
==17==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0xabc in parse_header /src/parser.c:42:8
    #1 0xdef in LLVMFuzzerTestOneInput /src/fuzz.c:11:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42:8 in parse_header
`;

describe("assessCraftCandidateIdentity", () => {
  it("accepts a sanitizer class and explicit function that both match", () => {
    expect(
      assessCraftCandidateIdentity(
        "A heap buffer overflow occurs in `parse_header()` when a malformed header is parsed.",
        overflowInParseHeader,
      ),
    ).toMatchObject({
      status: "match",
      expectedCrashClass: "overflow",
      observedCrashClass: "overflow",
      expectedFunction: "parse_header",
      stackFunctions: expect.arrayContaining(["parse_header"]),
    });
  });

  it("rejects a self-test whose sanitizer class contradicts the description", () => {
    const identity = assessCraftCandidateIdentity(
      "A use-after-free occurs in `parse_header()`.",
      overflowInParseHeader,
    );

    expect(identity.status).toBe("mismatch");
    expect(identity.reasons.join(" ")).toContain("expects use-after-free");
  });

  it("rejects a self-test whose stack omits the explicitly named function", () => {
    const identity = assessCraftCandidateIdentity(
      "A heap-buffer-overflow occurs in `decode_chunk()`.",
      overflowInParseHeader,
    );

    expect(identity.status).toBe("mismatch");
    expect(identity.reasons.join(" ")).toContain("decode_chunk");
  });

  it("rejects a raw segfault without sanitizer evidence", () => {
    expect(
      assessCraftCandidateIdentity("A heap-buffer-overflow occurs in `parse_header()`.", "Segmentation fault"),
    ).toMatchObject({ status: "mismatch" });
  });

  it("keeps vague descriptions inconclusive rather than inventing an anchor", () => {
    expect(
      assessCraftCandidateIdentity("A malformed input causes a crash.", overflowInParseHeader),
    ).toMatchObject({ status: "inconclusive" });
  });
});
