import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { extractSpecInvariants } from "./extract.js";
import { mapInvariantsToImplementation, runSpecdriftScan } from "./map.js";

function withFixture(fn: (root: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "specdrift-map-test-"));
  try {
    mkdirSync(join(root, "src"));
    mkdirSync(join(root, "vendor"));
    writeFileSync(join(root, "src", "parser.c"), `
int parse_frame(const unsigned char *buf, int remaining, int payload_length) {
  if (payload_length > remaining) return ERR_INVALID_FRAME;
  if (payload_length > 16384) return ERR_INVALID_FRAME;
  return 0;
}
`, "utf8");
    writeFileSync(join(root, "vendor", "ignored.c"), "int payload_length = 999999;\n", "utf8");
    fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("mapInvariantsToImplementation", () => {
  it("maps extracted invariants to candidate implementation snippets", () => withFixture((root) => {
    const extracted = extractSpecInvariants({
      specName: "proto.txt",
      specText: "The payload length MUST be between 0 and 16384 octets. Implementations MUST reject frames whose declared length exceeds the remaining input.",
    });

    const mapped = mapInvariantsToImplementation({ sourceRoot: root, invariants: extracted.invariants, maxFiles: 20 });

    expect(mapped.candidates.length).toBeGreaterThan(0);
    expect(mapped.candidates[0]).toMatchObject({
      file: "src/parser.c",
      status: "candidate",
    });
    expect(mapped.candidates[0]?.snippet).toContain("payload_length");
    expect(mapped.candidates.some((c) => c.file.includes("vendor"))).toBe(false);
  }));

  it("runs the extract+map scan workflow", () => withFixture((root) => {
    const result = runSpecdriftScan({
      specName: "proto.txt",
      specText: "Implementations MUST reject frames whose declared length exceeds the remaining input.",
      sourceRoot: root,
      maxFiles: 20,
    });

    expect(result.stage).toBe("scan");
    expect(result.invariants).toHaveLength(1);
    expect(result.candidates[0]?.file).toBe("src/parser.c");
  }));
});
