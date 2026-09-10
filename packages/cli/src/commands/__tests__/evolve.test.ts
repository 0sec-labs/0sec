import type * as Core from "@0sec/core";
import { Command } from "commander";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@0sec/core", async (importOriginal) => {
  const actual = await importOriginal<typeof Core>();
  return { ...actual, runEvolution: vi.fn(), executeEvolutionVersion: vi.fn() };
});
import { executeEvolutionVersion, runEvolution } from "@0sec/core";
import { registerEvolveCommand } from "../evolve.js";

const directories: string[] = [];
let output: string[];
let previousExitCode: typeof process.exitCode;

beforeEach(() => {
  vi.resetAllMocks();
  previousExitCode = process.exitCode;
  process.exitCode = 0;
  output = [];
  vi.spyOn(console, "log").mockImplementation((value: unknown) => { output.push(String(value)); });
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = previousExitCode;
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

function configFile(): string {
  const directory = mkdtempSync(join(tmpdir(), "0sec-evolve-cli-"));
  directories.push(directory);
  const path = join(directory, "config.json");
  writeFileSync(path, JSON.stringify({
    schemaVersion: 1, sourceRoot: join(directory, "source"), storePath: join(directory, "store"),
    image: "node:22-alpine", sourcePaths: ["src"], editablePaths: ["src"], command: ["node", "src/worker.js"],
    objective: "Correctly classify unsafe input", computeUsdPerSecond: 0.001,
    repeats: 2, maxOutputBytes: 1024, promotionPolicy: { minimumCases: 3 },
    cases: ["development", "held-out", "negative-control"].flatMap((lane, group) => [0, 1, 2].map((index) => ({
      id: `${lane}-${index}`, lane, input: { index: group * 3 + index }, expected: { unsafe: group !== 2 },
    }))),
  }));
  return path;
}

async function invoke(args: string[]): Promise<void> {
  const command = new Command();
  command.exitOverride();
  registerEvolveCommand(command);
  await command.parseAsync(["evolve", ...args], { from: "user" });
}

describe("evolution CLI failure boundaries", () => {
  it("does not disclose private configuration through a source-tree symlink alias", async () => {
    const original = configFile();
    const raw = readFileSync(original, "utf8");
    const config = JSON.parse(raw);
    mkdirSync(join(config.sourceRoot, "src"), { recursive: true });
    const privatePath = join(config.sourceRoot, "src", "private-config.json");
    const sourceAlias = `${original}.source-alias`;
    symlinkSync(config.sourceRoot, sourceAlias);
    writeFileSync(privatePath, JSON.stringify({ ...config, sourceRoot: sourceAlias }));
    const alias = `${original}.alias`;
    symlinkSync(privatePath, alias);
    let generationStarted = false;
    vi.mocked(runEvolution).mockImplementation(async () => {
      generationStarted = true;
      throw new Error("generation must not start for private source configuration");
    });
    await invoke(["run", "--config", alias, "--allow-source-access", "--json"]);
    expect(generationStarted).toBe(false);
    expect(process.exitCode).toBe(2);
  });

  it("stops watch after a charged failure rather than retrying with an unchanged budget", async () => {
    let incurredCharges = 0;
    vi.mocked(runEvolution).mockImplementation(async () => {
      incurredCharges += 1;
      throw new Error("provider charged before evaluation failed");
    });
    const listenersBefore = process.listenerCount("SIGINT");
    await invoke(["run", "--config", configFile(), "--watch", "--max-passes", "3", "--json"]);
    expect(incurredCharges).toBe(1);
    expect(process.exitCode).toBe(2);
    expect(output.map((line) => JSON.parse(line))).toEqual([{ error: "provider charged before evaluation failed" }]);
    expect(process.listenerCount("SIGINT")).toBe(listenersBefore);
  });

  it("treats a missing exit status as execution failure even without an error string", async () => {
    vi.mocked(executeEvolutionVersion).mockResolvedValue({
      versionId: "pinned-worker",
      execution: { exitCode: null, stdout: "{}", stderr: "", durationMs: 1, timedOut: false },
    });
    await invoke(["exec", "--config", configFile(), "--run-id", "scan", "--input", "{}", "--json"]);
    expect(process.exitCode).toBe(2);
    expect(JSON.parse(output[0]!).execution.exitCode).toBeNull();
  });

  it("rejects a malformed watch limit instead of silently succeeding without running", async () => {
    await invoke(["run", "--config", configFile(), "--watch", "--max-passes", "2x", "--json"]);
    expect(process.exitCode).toBe(2);
    expect(JSON.parse(output[0]!).error).toMatch(/positive integer/);
  });
});
