import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  parseFindingsFromCliOutput,
  validateFileRef,
} from "./findings-parser.js";

/**
 * Tests for #286 — control-flow audit H5: validate file:line existence in
 * `parseStructuredBlocks` so the agent can't smuggle a fabricated path
 * through to a downstream H1 advisory.
 */

describe("validateFileRef", () => {
  let scope: string;

  beforeEach(() => {
    scope = mkdtempSync(join(tmpdir(), "pwnkit-parser-test-"));
    writeFileSync(join(scope, "package.json"), "{}");
    mkdirSync(join(scope, "src"));
    writeFileSync(join(scope, "src", "index.ts"), "// real file");
  });

  afterEach(() => {
    rmSync(scope, { recursive: true, force: true });
  });

  it("accepts a real file with a line ref", () => {
    expect(validateFileRef("package.json:1", scope)).toEqual({ valid: true });
    expect(validateFileRef("src/index.ts:5", scope)).toEqual({ valid: true });
  });

  it("accepts a real file without a line ref", () => {
    expect(validateFileRef("package.json", scope)).toEqual({ valid: true });
  });

  it("rejects a fabricated path that doesn't exist", () => {
    const result = validateFileRef("app/users.php:43", scope);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("fabricated path");
    expect(result.reason).toContain("app/users.php");
  });

  it("rejects path traversal that escapes scope", () => {
    const result = validateFileRef("../../../etc/passwd", scope);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("fabricated path");
  });

  it("rejects absolute paths", () => {
    const result = validateFileRef("/etc/passwd", scope);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("fabricated path");
  });

  it("returns valid when no scopePath is provided (preserves existing behaviour)", () => {
    expect(validateFileRef("anything.ts:99", undefined)).toEqual({ valid: true });
    expect(validateFileRef("../../../etc/passwd", undefined)).toEqual({ valid: true });
  });

  it("returns valid for an empty file ref (nothing to validate)", () => {
    expect(validateFileRef("", scope)).toEqual({ valid: true });
    expect(validateFileRef("   ", scope)).toEqual({ valid: true });
  });
});

describe("parseFindingsFromCliOutput — structured blocks with scopePath", () => {
  let scope: string;

  beforeEach(() => {
    scope = mkdtempSync(join(tmpdir(), "pwnkit-parser-test-"));
    writeFileSync(join(scope, "package.json"), "{}");
    mkdirSync(join(scope, "src"));
    writeFileSync(join(scope, "src", "index.ts"), "// real file");
  });

  afterEach(() => {
    rmSync(scope, { recursive: true, force: true });
  });

  it("leaves a finding unchanged when its file ref is real", () => {
    const output = `
---FINDING---
title: Real bug
severity: high
category: injection
description: Something bad in package.json
file: package.json:1
---END---
`;
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].status).toBe("discovered");
    expect(findings[0].triageNote).toBeUndefined();
  });

  it("downgrades a finding citing a fabricated path", () => {
    const output = `
---FINDING---
title: Fabricated bug
severity: critical
category: injection
description: SQL injection in app/users.php
file: app/users.php:43
---END---
`;
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
    expect(findings[0].status).toBe("false-positive");
    expect(findings[0].triageNote).toContain("fabricated path");
    expect(findings[0].triageNote).toContain("app/users.php");
    // Title and description should be preserved so the operator can audit
    // what the agent claimed.
    expect(findings[0].title).toBe("Fabricated bug");
  });

  it("preserves existing behaviour when no scopePath is provided", () => {
    const output = `
---FINDING---
title: Unchecked finding
severity: high
category: injection
description: Something
file: app/users.php:43
---END---
`;
    const findings = parseFindingsFromCliOutput(output);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].status).toBe("discovered");
    expect(findings[0].triageNote).toBeUndefined();
  });

  it("parses linux-kernel structured fields without folding them into category", () => {
    mkdirSync(join(scope, "fs", "nfsd"), { recursive: true });
    writeFileSync(join(scope, "fs", "nfsd", "vfs.c"), "int vulnerable(void) { return 0; }\n");
    const output = `
---FINDING---
title: nfsd sibling candidate
severity: high
category: use-after-free
subsystem: fs/nfsd
description: Sibling bug in the same crash family.
file: fs/nfsd/vfs.c:1
hypothesis: true
confidence: 0.4
reproducer_shape: none
reproducer: static-only
---END---
`;
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe("use-after-free");
    expect(findings[0].confidence).toBe(0.4);
    expect(findings[0].evidence.analysis).toContain("Subsystem: fs/nfsd");
    expect(findings[0].evidence.analysis).toContain("Hypothesis: true");
  });

  it("handles a mixed batch — 2 valid + 1 fabricated", () => {
    const output = `
---FINDING---
title: Real bug A
severity: high
category: injection
description: Bug in package.json
file: package.json:1
---END---
---FINDING---
title: Fabricated bug
severity: critical
category: injection
description: Bug in nonexistent file
file: app/users.php:43
---END---
---FINDING---
title: Real bug B
severity: medium
category: auth
description: Bug in src/index.ts
file: src/index.ts:1
---END---
`;
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(3);

    const real = findings.filter((f) => f.status === "discovered");
    const fabricated = findings.filter((f) => f.status === "false-positive");
    expect(real).toHaveLength(2);
    expect(fabricated).toHaveLength(1);
    expect(fabricated[0].title).toBe("Fabricated bug");
    expect(fabricated[0].severity).toBe("info");
    expect(fabricated[0].triageNote).toContain("fabricated path");

    expect(real.map((f) => f.title).sort()).toEqual(["Real bug A", "Real bug B"]);
    expect(real.every((f) => f.triageNote === undefined)).toBe(true);
  });

  it("blocks path traversal in structured blocks", () => {
    const output = `
---FINDING---
title: Traversal attempt
severity: critical
category: injection
description: Reading sensitive files
file: ../../../etc/passwd
---END---
`;
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
    expect(findings[0].status).toBe("false-positive");
    expect(findings[0].triageNote).toContain("fabricated path");
  });

  it("promotes a C/C++ structured finding when sanitizer_log parses", () => {
    mkdirSync(join(scope, "src"), { recursive: true });
    writeFileSync(join(scope, "src", "decoder.c"), "int decode(void) { return 0; }");
    const output = `
---FINDING---
title: Decoder reads past allocation
severity: high
category: other
description: The decoder reads past the allocated packet.
file: src/decoder.c:1
harness: /tmp/pwnkit-harness/decoder/harness.c
sanitizer_log: ==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000fb at pc 0x401000 bp 0x7fff sp 0x7fff
READ of size 1 at 0x6020000000fb thread T0
    #0 0x401000 in decode src/decoder.c:1:3
0x6020000000fb is located 0 bytes to the right of 11-byte region [0x6020000000f0,0x6020000000fb)
SUMMARY: AddressSanitizer: heap-buffer-overflow src/decoder.c:1:3 in decode
tier: 1
---END---
`;
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe("confirmed");
    expect(findings[0].confidence).toBe(0.95);
    expect(findings[0].category).toBe("out-of-bounds-read");
    expect(findings[0].evidence.response).toContain("AddressSanitizer: heap-buffer-overflow");
    expect(findings[0].evidence.analysis).toContain("Sanitizer verdict: ASAN heap-buffer-overflow");
  });
});

describe("parseFindingsFromCliOutput — JSON output with scopePath", () => {
  let scope: string;

  beforeEach(() => {
    scope = mkdtempSync(join(tmpdir(), "pwnkit-parser-test-"));
    writeFileSync(join(scope, "package.json"), "{}");
  });

  afterEach(() => {
    rmSync(scope, { recursive: true, force: true });
  });

  it("downgrades a JSON finding citing a fabricated file", () => {
    const output = JSON.stringify({
      findings: [
        {
          title: "Fabricated JSON bug",
          severity: "critical",
          category: "injection",
          description: "SQL injection",
          file: "app/users.php:43",
        },
      ],
    });
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
    expect(findings[0].status).toBe("false-positive");
    expect(findings[0].triageNote).toContain("fabricated path");
  });

  it("leaves a JSON finding alone when the file is real", () => {
    const output = JSON.stringify({
      findings: [
        {
          title: "Real JSON bug",
          severity: "high",
          category: "injection",
          description: "Issue",
          file: "package.json:1",
        },
      ],
    });
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].status).toBe("discovered");
    expect(findings[0].triageNote).toBeUndefined();
  });

  it("promotes JSON findings with sanitizer_log evidence", () => {
    writeFileSync(join(scope, "test.cc"), "int main() { return 0; }");
    const output = JSON.stringify({
      findings: [
        {
          title: "Integer overflow",
          severity: "medium",
          category: "other",
          description: "UBSan confirms signed overflow.",
          file: "test.cc:3",
          sanitizer_log: "test.cc:3:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'",
        },
      ],
    });
    const findings = parseFindingsFromCliOutput(output, { scopePath: scope });
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe("confirmed");
    expect(findings[0].category).toBe("integer-overflow");
    expect(findings[0].evidence.analysis).toContain("UBSAN signed-integer-overflow");
  });
});
