import { describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runCliPathTraversalReplayFixture } from "./cli-path-traversal-fixture.js";

function writeTestExportCli(dir: string): string {
  const path = join(dir, "test-export-cli.mjs");
  writeFileSync(
    path,
    `#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    out[argv[i].slice(2)] = argv[i + 1];
  }
  return out;
}

function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(root + sep);
}

const args = parseArgs(process.argv.slice(2));
const body = await fetch(new URL("/company/export", args.api)).then((r) => r.json());
const root = resolve(args.output);
await mkdir(root, { recursive: true });
let blocked = false;
for (const [name, content] of Object.entries(body.files || {})) {
  const destination = resolve(root, name);
  if (args.mode === "patched" && !isInside(root, destination)) {
    console.error("blocked path traversal: " + name);
    blocked = true;
    continue;
  }
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, String(content), "utf8");
  console.log("wrote " + destination);
}
if (blocked) process.exitCode = 1;
`,
    { encoding: "utf8", mode: 0o755 },
  );
  return path;
}

function testExportCliArgv(cliPath: string): string[] {
  return [
    process.execPath,
    cliPath,
    "--api",
    "{{apiUrl}}",
    "--output",
    "{{exportDir}}",
    "--mode",
    "{{fixtureMode}}",
  ];
}

describe("runCliPathTraversalReplayFixture", () => {
  it("reproduces the vulnerable Paperclip-style export traversal", async () => {
    const cliRoot = mkdtempSync(join(tmpdir(), "pwnkit-fixture-cli-"));
    try {
      const cliPath = writeTestExportCli(cliRoot);
      const result = await runCliPathTraversalReplayFixture({
        commandArgv: testExportCliArgv(cliPath),
        fixtureMode: "vulnerable",
        engineVersion: "test",
      });

      expect(result.status).toBe("reproduced");
      expect(result.mode).toBe("deterministic_replay");
      expect(result.finding_id).toBe("fixture:cli-path-traversal");
      expect(result.commands).toHaveLength(1);
      expect(result.commands[0].argv).toContain("--output");
      expect(result.commands[0].exit_code).toBe(0);
      expect(result.commands[0].stdout_excerpt).toContain("escaped-marker");
      expect(result.assertions.find((a) => a.kind === "filesystem_exists")?.passed).toBe(true);
      expect(result.assertions.find((a) => a.kind === "path_outside_export_root")?.passed).toBe(true);
      expect(result.assertions.find((a) => a.kind === "path_inside_sandbox")?.passed).toBe(true);
      expect(result.artifacts).toEqual({});
      const escapedDetail = result.assertions.find((a) => a.kind === "filesystem_exists")?.detail ?? "";
      const escapedPath = escapedDetail.replace(/^escaped marker exists at /, "");
      const sandbox = dirname(escapedPath);
      expect(existsSync(sandbox)).toBe(false);
    } finally {
      rmSync(cliRoot, { recursive: true, force: true });
    }
  });

  it("returns not_reproduced when the fixture CLI rejects traversal", async () => {
    const cliRoot = mkdtempSync(join(tmpdir(), "pwnkit-fixture-cli-"));
    try {
      const cliPath = writeTestExportCli(cliRoot);
      const result = await runCliPathTraversalReplayFixture({
        commandArgv: testExportCliArgv(cliPath),
        fixtureMode: "patched",
        engineVersion: "test",
      });

      expect(result.status).toBe("not_reproduced");
      expect(result.commands[0].exit_code).toBe(1);
      expect(result.commands[0].stderr_excerpt).toContain("blocked path traversal");
      expect(result.assertions.find((a) => a.kind === "filesystem_exists")?.passed).toBe(false);
      expect(result.assertions.find((a) => a.kind === "path_outside_export_root")?.passed).toBe(false);
    } finally {
      rmSync(cliRoot, { recursive: true, force: true });
    }
  });

  it("retains the sandbox and artifact refs when requested", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "pwnkit-fixture-retain-"));
    const cliRoot = mkdtempSync(join(tmpdir(), "pwnkit-fixture-cli-"));
    try {
      const cliPath = writeTestExportCli(cliRoot);
      const result = await runCliPathTraversalReplayFixture({
        commandArgv: testExportCliArgv(cliPath),
        artifactDir: sandbox,
        retainArtifacts: true,
        engineVersion: "test",
      });

      expect(result.status).toBe("reproduced");
      expect(result.artifacts.sandbox_ref).toBe(sandbox);
      expect(result.artifacts.harness_ref).toBeTruthy();
      expect(result.artifacts.stdout_ref).toBeTruthy();
      expect(result.artifacts.stderr_ref).toBeTruthy();
      expect(existsSync(result.artifacts.sandbox_ref)).toBe(true);
      expect(existsSync(result.artifacts.harness_ref)).toBe(true);
      expect(existsSync(result.artifacts.stdout_ref)).toBe(true);
      expect(existsSync(result.artifacts.stderr_ref)).toBe(true);
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
      rmSync(cliRoot, { recursive: true, force: true });
    }
  });

  it("returns artifact refs on setup errors when artifact retention is requested", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "pwnkit-fixture-error-"));
    try {
      writeFileSync(join(sandbox, "export"), "not a directory", "utf8");

      const result = await runCliPathTraversalReplayFixture({
        artifactDir: sandbox,
        retainArtifacts: true,
        engineVersion: "test",
      });

      expect(result.status).toBe("error");
      expect(result.commands).toEqual([]);
      expect(result.artifacts.sandbox_ref).toBe(sandbox);
      expect(result.artifacts.export_ref).toBe(join(sandbox, "export"));
      expect(result.artifacts.harness_ref).toBe(join(sandbox, "harness", "harness.json"));
      expect(result.artifacts.stdout_ref).toBe(join(sandbox, "stdout.log"));
      expect(result.artifacts.stderr_ref).toBe(join(sandbox, "stderr.log"));
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });

  it("preserves command output when post-command artifact writes fail", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "pwnkit-fixture-postcmd-error-"));
    const cliRoot = mkdtempSync(join(tmpdir(), "pwnkit-fixture-cli-"));
    try {
      mkdirSync(join(sandbox, "stdout.log"));
      const cliPath = writeTestExportCli(cliRoot);

      const result = await runCliPathTraversalReplayFixture({
        commandArgv: testExportCliArgv(cliPath),
        artifactDir: sandbox,
        retainArtifacts: true,
        engineVersion: "test",
      });

      expect(result.status).toBe("error");
      expect(result.commands).toHaveLength(1);
      expect(result.commands[0].argv).toContain(cliPath);
      expect(result.commands[0].exit_code).toBe(0);
      expect(result.commands[0].stdout_excerpt).toContain("escaped-marker");
      expect(result.error_reason).toBeTruthy();
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
      rmSync(cliRoot, { recursive: true, force: true });
    }
  });

  it("finishes when a command ignores SIGTERM past the timeout", async () => {
    // A 200ms timeout races Node startup under the parallel core suite, before
    // this child can install its SIGTERM handler. Keep the exercise focused on
    // the SIGKILL fallback rather than scheduler load.
    const result = await runCliPathTraversalReplayFixture({
      commandArgv: [
        process.execPath,
        "--input-type=module",
        "-e",
        "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);",
      ],
      timeoutMs: 1_000,
      engineVersion: "test",
    });

    expect(result.status).toBe("error");
    expect(result.commands).toHaveLength(1);
    expect(result.commands[0].exit_code).toBeNull();
    expect(result.assertions.find((a) => a.kind === "command_exit_zero")?.detail).toContain(
      "did not exit after SIGTERM",
    );
  });
});
