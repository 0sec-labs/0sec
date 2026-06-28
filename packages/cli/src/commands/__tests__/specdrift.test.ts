import { describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSpecdriftExtract, runSpecdriftScanCli } from "../specdrift.js";

describe("runSpecdriftExtract", () => {
  it("reads a spec file and returns invariant JSON", async () => {
    const root = mkdtempSync(join(tmpdir(), "specdrift-cli-test-"));
    try {
      const spec = join(root, "proto.txt");
      writeFileSync(spec, "The message type MUST be rejected when it is unknown.\n", "utf8");

      const result = await runSpecdriftExtract({ spec, specName: "proto-spec", maxInvariants: "5" });

      expect(result).toMatchObject({
        mode: "specdrift",
        stage: "extract",
        spec: "proto-spec",
        invariants: [expect.objectContaining({ kind: "rejection" })],
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects invalid max-invariants", async () => {
    await expect(runSpecdriftExtract({ spec: "missing.txt", maxInvariants: "0" })).rejects.toThrow("invalid --max-invariants");
  });

  it("runs extract+map scan against a local source tree", async () => {
    const root = mkdtempSync(join(tmpdir(), "specdrift-cli-scan-test-"));
    try {
      const spec = join(root, "proto.txt");
      const src = join(root, "impl");
      mkdirSync(src);
      writeFileSync(spec, "Implementations MUST reject frames whose declared length exceeds the remaining input.\n", "utf8");
      writeFileSync(join(src, "parser.c"), "int parse(int len, int remaining) { if (len > remaining) return -1; return 0; }\n", "utf8");

      const result = await runSpecdriftScanCli({ spec, source: src, maxFiles: "10" });

      expect(result).toMatchObject({
        mode: "specdrift",
        stage: "scan",
        candidates: [expect.objectContaining({ file: "parser.c" })],
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("requires a source for scan", async () => {
    await expect(runSpecdriftScanCli({ spec: "proto.txt" })).rejects.toThrow("missing required flag: --source");
  });
});
