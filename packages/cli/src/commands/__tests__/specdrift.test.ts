import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSpecdriftExtract } from "../specdrift.js";

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
});
