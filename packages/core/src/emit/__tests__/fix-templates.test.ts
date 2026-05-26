import { describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import {
  createDefaultFixTemplateRegistry,
  hardCodedSecretTemplate,
  integerTruncationGuardTemplate,
  missingInputValidationTemplate,
  renderUnifiedDiff,
  templateIdForCategory,
} from "../fix-templates.js";

// Compact test-finding factory. Every test starts from one of these and
// tweaks only the fields it cares about — keeps the per-test noise low.
function mkFinding(extra: Partial<Finding> = {}): Finding {
  return {
    id: "fnd-test-1",
    templateId: "tpl-test",
    title: "Test finding",
    description: "Issue at src/router.ts:42",
    severity: "medium",
    category: "information-disclosure",
    status: "verified",
    evidence: { request: "", response: "", analysis: "src/router.ts:42 — apiKey literal" },
    timestamp: 0,
    ...extra,
  };
}

// String normalisation — strip trailing whitespace, normalise line endings.
function norm(s: string): string {
  return s.replace(/\r\n/g, "\n").split("\n").map((l) => l.replace(/\s+$/, "")).join("\n").trim();
}

describe("templateIdForCategory", () => {
  it("maps the three starter categories", () => {
    expect(templateIdForCategory("information-disclosure")).toBe("hard_coded_secret");
    expect(templateIdForCategory("missing-validation")).toBe("missing_input_validation");
    expect(templateIdForCategory("integer-truncation")).toBe("integer_truncation_guard");
    expect(templateIdForCategory("integer-overflow")).toBe("integer_truncation_guard");
  });

  it("returns null for unsupported categories", () => {
    expect(templateIdForCategory("xss")).toBeNull();
    expect(templateIdForCategory("ssrf")).toBeNull();
  });
});

describe("hardCodedSecretTemplate", () => {
  it("emits a process.env replacement when an anchor is present", () => {
    const finding = mkFinding({
      title: "Hard-coded apiKey in router",
      description: "Found apiKey literal in src/router.ts:42",
      evidence: { request: "", response: "", analysis: "src/router.ts:42 — apiKey literal" },
    });
    const diff = hardCodedSecretTemplate(finding);
    expect(diff).not.toBeNull();
    expect(diff!.filePath).toBe("src/router.ts");
    expect(diff!.language).toBe("typescript");
    const rendered = renderUnifiedDiff(diff!);
    expect(rendered).toContain("--- a/src/router.ts");
    expect(rendered).toContain("+++ b/src/router.ts");
    expect(rendered).toContain("@@ -42,1 +42,2 @@");
    expect(rendered).toContain("process.env.APIKEY");
  });

  it("returns null when no file anchor can be found", () => {
    const finding = mkFinding({
      description: "Something happened but no file path",
      evidence: { request: "", response: "", analysis: "" },
    });
    expect(hardCodedSecretTemplate(finding)).toBeNull();
  });

  it("uses python comment style for .py files", () => {
    const finding = mkFinding({
      description: "Hard-coded secret at api/server.py:10",
      evidence: { request: "", response: "", analysis: "api/server.py:10" },
    });
    const diff = hardCodedSecretTemplate(finding);
    expect(diff).not.toBeNull();
    const rendered = renderUnifiedDiff(diff!);
    expect(rendered).toMatch(/^-# TODO: secret literal removed/m);
    expect(rendered).toContain('os.environ["');
  });
});

describe("missingInputValidationTemplate", () => {
  it("inserts a TS guard at function entry", () => {
    const finding = mkFinding({
      category: "missing-validation",
      title: "Missing validation on parameter userId",
      description: "Handler at src/handlers/user.ts:15 accepts parameter userId without validation",
      evidence: { request: "", response: "", analysis: "src/handlers/user.ts:15" },
    });
    const diff = missingInputValidationTemplate(finding);
    expect(diff).not.toBeNull();
    const rendered = renderUnifiedDiff(diff!);
    expect(rendered).toContain('typeof userId !== "string"');
    expect(rendered).toContain("pwnkit#377 starter guard");
  });

  it("uses isinstance for python", () => {
    const finding = mkFinding({
      category: "missing-validation",
      title: "Missing validation on parameter name",
      description: "Handler in api/views.py:5 accepts parameter name without validation",
      evidence: { request: "", response: "", analysis: "api/views.py:5" },
    });
    const diff = missingInputValidationTemplate(finding);
    expect(diff).not.toBeNull();
    expect(renderUnifiedDiff(diff!)).toContain("isinstance(name, str)");
  });
});

describe("integerTruncationGuardTemplate", () => {
  it("emits a SIZE_MAX guard for C files", () => {
    const finding = mkFinding({
      category: "integer-truncation",
      title: "Integer truncation in alloc",
      description: "Allocation in kernel/mem.c:120 uses parameter count without bound check",
      evidence: { request: "", response: "", analysis: "kernel/mem.c:120" },
    });
    const diff = integerTruncationGuardTemplate(finding);
    expect(diff).not.toBeNull();
    const rendered = renderUnifiedDiff(diff!);
    expect(rendered).toContain("if (count > SIZE_MAX / sizeof(*ptr))");
    expect(rendered).toContain("return -EINVAL;");
  });

  it("declines to emit for non-C languages", () => {
    const finding = mkFinding({
      category: "integer-truncation",
      title: "Integer truncation",
      description: "Path src/util.ts:30 uses size without bound check",
      evidence: { request: "", response: "", analysis: "src/util.ts:30" },
    });
    expect(integerTruncationGuardTemplate(finding)).toBeNull();
  });
});

describe("createDefaultFixTemplateRegistry", () => {
  it("ships the three starter templates", () => {
    const reg = createDefaultFixTemplateRegistry();
    expect(reg.ids().sort()).toEqual([
      "hard_coded_secret",
      "integer_truncation_guard",
      "missing_input_validation",
    ]);
  });

  it("dispatches via category lookup", () => {
    const reg = createDefaultFixTemplateRegistry();
    const finding = mkFinding({
      category: "missing-validation",
      description: "Handler at src/x.ts:7 accepts parameter id",
      evidence: { request: "", response: "", analysis: "src/x.ts:7" },
    });
    const diff = reg.apply(finding);
    expect(diff).not.toBeNull();
    expect(norm(renderUnifiedDiff(diff!))).toContain("typeof id !== \"string\"");
  });

  it("returns null for unsupported categories", () => {
    const reg = createDefaultFixTemplateRegistry();
    expect(reg.apply(mkFinding({ category: "xss" }))).toBeNull();
  });
});

describe("renderUnifiedDiff", () => {
  it("renders header + hunk in canonical shape", () => {
    const rendered = renderUnifiedDiff({
      filePath: "a/b.ts",
      summary: "demo",
      hunks: [
        {
          oldStart: 10,
          newStart: 10,
          lines: [
            { kind: "ctx", text: "const x = 1;" },
            { kind: "del", text: "const y = 2;" },
            { kind: "add", text: "const y = 3;" },
          ],
        },
      ],
    });
    expect(norm(rendered)).toBe(
      norm(
        [
          "--- a/a/b.ts",
          "+++ b/a/b.ts",
          "@@ -10,2 +10,2 @@",
          " const x = 1;",
          "-const y = 2;",
          "+const y = 3;",
        ].join("\n"),
      ),
    );
  });
});
