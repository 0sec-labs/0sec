import { afterEach, describe, expect, it } from "vitest";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@0sec/shared";
import { createReproductionBundle, runReproductionBundle, type BundleManifest, type BundlePlan } from "./reproduction-bundle.js";

interface Fixture {
  root: string;
  plan: BundlePlan & { finding: Finding };
  save(): void;
  planPath: string;
  bundleDir: string;
  outDir: string;
}
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture(patched = 'console.log("DENIED")'): Fixture {
  const root = mkdtempSync(join(tmpdir(), "0sec-bundle-test-"));
  roots.push(root);
  for (const side of ["vulnerable", "patched"]) mkdirSync(join(root, side));
  writeFileSync(join(root, "vulnerable/app.cjs"), 'console.log("CROSS_TENANT_MARKER")');
  writeFileSync(join(root, "patched/app.cjs"), patched);
  const finding: Finding = {
    id: "bundle-finding", templateId: "test", title: "Unauthorized mutation", description: "Fixture",
    severity: "high", category: "other", status: "verified", timestamp: 0,
    evidence: { request: "fixture", response: "marker" },
    pocSteps: [{ id: "exploit", kind: "exploit", summary: "Observe marker", action: { type: "shell", cmd: "node app.cjs" }, expect: { type: "body-contains", text: "CROSS_TENANT_MARKER" } }],
  };
  const plan: Fixture["plan"] = { version: 1, finding, vulnerable_root: "vulnerable", patched_root: "patched",
    files: { vulnerable: ["app.cjs"], patched: ["app.cjs"] }, runner: "local" };
  const planPath = join(root, "plan.json");
  const save = () => writeFileSync(planPath, JSON.stringify(plan));
  save();
  return { root, plan, save, planPath, bundleDir: join(root, "bundle"), outDir: join(root, "results") };
}

async function replay(f: Fixture) {
  await createReproductionBundle(f.planPath, f.bundleDir);
  return runReproductionBundle({ bundleDir: f.bundleDir, runner: "local", outDir: f.outDir });
}

function alterManifest(f: Fixture, mutate: (manifest: BundleManifest) => void) {
  const path = join(f.bundleDir, "manifest.json");
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  mutate(manifest);
  writeFileSync(path, JSON.stringify(manifest));
}

describe("reproduction bundles", () => {
  it("packages without executing, then replays frozen snapshots after sources change", async () => {
    const f = fixture();
    const sentinel = join(f.root, "executed");
    f.plan.finding.pocSteps![0]!.action = { type: "shell", cmd: `node app.cjs; touch '${sentinel}'` };
    f.save();
    await createReproductionBundle(f.planPath, f.bundleDir);
    expect(existsSync(sentinel)).toBe(false);
    writeFileSync(join(f.root, "vulnerable/app.cjs"), 'throw new Error("source changed")');
    const result = await runReproductionBundle({ bundleDir: f.bundleDir, runner: "local", outDir: f.outDir });
    expect(result.status).toBe("confirmed");
    expect(result.vulnerable.status).toBe("reproduced");
    expect(result.patched.status).toBe("not_reproduced");
    expect(existsSync(sentinel)).toBe(true);
    expect(JSON.parse(readFileSync(join(f.outDir, "result.json"), "utf8")).status).toBe("confirmed");
  });

  it("does not confirm an always-positive PoC", async () => {
    const result = await replay(fixture('console.log("CROSS_TENANT_MARKER")'));
    expect(result.status).toBe("inconclusive");
    expect(result.exitCode).not.toBe(0);
  });

  it("does not treat a patched application crash as a successful negative control", async () => {
    const result = await replay(fixture('throw new Error("broken application")'));
    expect(result.vulnerable.status).toBe("reproduced");
    expect(result.patched.status).toBe("error");
    expect(result.status).toBe("error");
  });

  it("stops on setup failures even when the following exploit would print its marker", async () => {
    const f = fixture();
    f.plan.finding.pocSteps!.unshift({ id: "setup", kind: "setup", summary: "Broken prerequisite", action: { type: "shell", cmd: "exit 1" } });
    f.save();
    const result = await replay(f);
    expect(result.status).toBe("error");
    expect(result.vulnerable.commands.map((command) => command.argv.at(-1))).toEqual(["exit 1"]);
  });

  it("rejects traversal in a tampered patched manifest before running either side", async () => {
    const f = fixture();
    await createReproductionBundle(f.planPath, f.bundleDir);
    alterManifest(f, (m) => { m.patched.files["../../escaped"] = m.patched.files["app.cjs"]; });
    const result = await runReproductionBundle({ bundleDir: f.bundleDir, runner: "local", outDir: f.outDir });
    expect(result.status).toBe("error");
    expect(result.vulnerable.commands).toEqual([]);
    expect(existsSync(join(f.root, "escaped"))).toBe(false);
    expect(existsSync(f.outDir)).toBe(false);
  });

  it("rejects ancestor symlinks in the explicit source allowlist", async () => {
    const f = fixture();
    symlinkSync(join(f.root, "patched"), join(f.root, "vulnerable/link"), "dir");
    f.plan.files.vulnerable = ["link/app.cjs"];
    f.save();
    await expect(createReproductionBundle(f.planPath, f.bundleDir)).rejects.toThrow(/symlink/);
    expect(existsSync(f.bundleDir)).toBe(false);
  });

  it("rejects corrupt snapshots and mismatched sizes before execution", async () => {
    const f = fixture();
    const { manifest } = await createReproductionBundle(f.planPath, f.bundleDir);
    const snapshot = join(f.bundleDir, "files", manifest.patched.files["app.cjs"]!.sha256);
    chmodSync(snapshot, 0o600);
    writeFileSync(snapshot, "tampered");
    const result = await runReproductionBundle({ bundleDir: f.bundleDir, runner: "local", outDir: f.outDir });
    expect(result.status).toBe("error");
    expect(result.vulnerable.commands).toEqual([]);
  });

  it("rejects runtime and runner mismatches without running commands", async () => {
    const f = fixture();
    await createReproductionBundle(f.planPath, f.bundleDir);
    const mismatch = await runReproductionBundle({ bundleDir: f.bundleDir, runner: "docker" });
    expect(mismatch.status).toBe("error");
    expect(mismatch.vulnerable.commands).toEqual([]);
    alterManifest(f, (m) => { m.runner_compatibility.node_version = "v0.0.0"; });
    const runtime = await runReproductionBundle({ bundleDir: f.bundleDir, runner: "local" });
    expect(runtime.status).toBe("error");
    expect(runtime.vulnerable.commands).toEqual([]);
  });

  it("refuses dirty output directories instead of accepting stale evidence", async () => {
    const f = fixture();
    await createReproductionBundle(f.planPath, f.bundleDir);
    mkdirSync(f.outDir);
    writeFileSync(join(f.outDir, "stale"), "keep");
    const result = await runReproductionBundle({ bundleDir: f.bundleDir, runner: "local", outDir: f.outDir });
    expect(result.status).toBe("error");
    expect(readFileSync(join(f.outDir, "stale"), "utf8")).toBe("keep");
  });

  it("resolves file assertions within each replay workspace, not the caller cwd", async () => {
    const f = fixture('console.log("DENIED")');
    writeFileSync(join(f.root, "vulnerable/app.cjs"), 'require("node:fs").writeFileSync("marker", "yes")');
    f.plan.finding.pocSteps![0]!.expect = { type: "file-exists", path: "marker" };
    f.save();
    expect((await replay(f)).status).toBe("confirmed");
  });
});
