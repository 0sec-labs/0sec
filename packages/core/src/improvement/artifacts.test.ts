import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { publishEvolutionArtifact, readEvolutionArtifact } from "./artifacts.js";
import { canonicalEvolutionJson } from "./config.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});
function directory(): string {
  const path = mkdtempSync(join(tmpdir(), "0sec-evolution-artifacts-"));
  directories.push(path);
  return path;
}

describe("immutable evolution evidence", () => {
  it("allows identical replay but refuses to replace a retained input or receipt", () => {
    const path = join(directory(), "receipts", "candidate.json");
    publishEvolutionArtifact(path, { candidateId: "one", passed: true });
    publishEvolutionArtifact(path, { passed: true, candidateId: "one" });
    expect(() => publishEvolutionArtifact(path, { candidateId: "two", passed: true })).toThrow(/collision/);
    expect(readEvolutionArtifact(path)).toEqual({ candidateId: "one", passed: true });
  });

  it("never reads or overwrites artifacts through symbolic links", () => {
    const root = directory();
    const target = join(root, "outside.json");
    const alias = join(root, "receipt.json");
    writeFileSync(target, '{"secret":true}', { mode: 0o600 });
    symlinkSync(target, alias);
    expect(() => readEvolutionArtifact(alias)).toThrow();
    expect(() => publishEvolutionArtifact(alias, { secret: false })).toThrow();
    expect(readFileSync(target, "utf8")).toBe('{"secret":true}');
  });

  it("rejects sparse arrays rather than hashing them as different JSON inputs", () => {
    expect(() => canonicalEvolutionJson(new Array(1))).toThrow(/finite JSON/);
    expect(canonicalEvolutionJson([null])).toBe("[null]");
  });
});
