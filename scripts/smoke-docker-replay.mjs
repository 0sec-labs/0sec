#!/usr/bin/env node
// Requires built @0sec/core and a usable local Docker daemon. Never silently skips.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DockerRunner, runDeterministicReplay } from "../packages/core/dist/verify/replay-runner.js";
import { createReproductionBundle, runReproductionBundle } from "../packages/core/dist/verify/reproduction-bundle.js";
import { ScopePolicy } from "../packages/core/dist/scope/scope.js";

const docker = (...args) => execFileSync("docker", args, { encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"] }).trim();
const root = mkdtempSync(join(tmpdir(), "0sec-docker-smoke-"));
const resources = [];
const failures = [];
const secret = "0sec-smoke-provider-secret-not-for-containers";
const previousSecret = process.env.ANTHROPIC_API_KEY;
process.env.ANTHROPIC_API_KEY = secret;

function provision(reference) {
  docker("pull", reference);
  const digests = JSON.parse(docker("image", "inspect", reference, "--format", "{{json .RepoDigests}}"));
  assert.ok(digests.length, `No immutable repository digest for ${reference}`);
  console.log(`Image: ${digests[0]}`);
  return digests[0];
}

function finding(steps) {
  return { id: "docker-smoke", templateId: "docker-replay", title: "Docker replay smoke", description: "Disposable local fixture",
    severity: "high", category: "other", status: "discovered", timestamp: 0,
    evidence: { request: "local fixture", response: "marker" }, pocSteps: steps };
}
const shellStep = (cmd, extra = {}) => ({ id: "probe", kind: "exploit", summary: "Run disposable probe",
  action: { type: "shell", cmd, ...extra }, expect: { type: "body-contains", text: "VULNERABLE_MARKER" } });

async function check(name, action) {
  try { await action(); console.log(`PASS ${name}`); }
  catch (error) { failures.push(name); console.error(`FAIL ${name}:`, error); }
}

try {
  console.log(`Docker server: ${docker("info", "--format", "{{.ServerVersion}}")}`);
  const shellImage = provision(process.env.DOCKER_REPLAY_SHELL_IMAGE ?? "alpine:3.20");
  const httpImage = provision(process.env.DOCKER_REPLAY_HTTP_IMAGE ?? "curlimages/curl:8.12.1");
  const runner = new DockerRunner({ shellImage });

  await check("real container hardening and writable workspace", async () => {
    const runDir = join(root, "hardening");
    mkdirSync(runDir);
    const step = shellStep('test "$(id -u)" -ne 0 && test -z "$ANTHROPIC_API_KEY" && test ! -e /sys/class/net/eth0 && ! touch /0sec-root-write 2>/dev/null && printf retained > /work/retained && cat /proc/self/status && printf VULNERABLE_MARKER');
    const { result } = await runDeterministicReplay(finding([step]), { runner, runDir });
    assert.equal(result.status, "reproduced", JSON.stringify(result));
    assert.match(result.commands[0].stdout_excerpt, /CapEff:\s+0+\s/);
    assert.match(result.commands[0].stdout_excerpt, /NoNewPrivs:\s+1/);
    assert.equal(readFileSync(join(runDir, "retained"), "utf8"), "retained");
    assert.ok(!JSON.stringify(result).includes(secret));
  });

  for (const [name, body, expected] of [
    ["patched", "printf DENIED", "confirmed"],
    ["always-positive", "printf VULNERABLE_MARKER", "inconclusive"],
    ["crashed", "exit 1", "error"],
  ]) {
    await check(`bundle negative control: ${name}`, async () => {
      const directory = join(root, name);
      const vulnerable = join(directory, "before");
      const patched = join(directory, "after");
      mkdirSync(vulnerable, { recursive: true });
      mkdirSync(patched);
      writeFileSync(join(vulnerable, "probe.sh"), "printf VULNERABLE_MARKER");
      writeFileSync(join(patched, "probe.sh"), body);
      const plan = { version: 1, finding: finding([shellStep("sh probe.sh")]), vulnerable_root: vulnerable, patched_root: patched,
        files: { vulnerable: ["probe.sh"], patched: ["probe.sh"] }, runner: "docker", docker_shell_image: shellImage };
      const planPath = join(directory, "plan.json");
      writeFileSync(planPath, JSON.stringify(plan));
      const bundleDir = join(directory, "bundle");
      await createReproductionBundle(planPath, bundleDir);
      const result = await runReproductionBundle({ bundleDir, runner: "docker", outDir: join(directory, "results") });
      assert.equal(result.status, expected, JSON.stringify(result));
      assert.equal(result.vulnerable.status, "reproduced", JSON.stringify(result));
      assert.equal(result.exitCode, expected === "confirmed" ? 0 : expected === "error" ? 3 : 1);
    });
  }

  await check("relative shell cwd inside the mounted workspace", async () => {
    const runDir = join(root, "nested-cwd");
    mkdirSync(join(runDir, "nested"), { recursive: true });
    writeFileSync(join(runDir, "nested", "probe.sh"), "printf VULNERABLE_MARKER");
    const { result } = await runDeterministicReplay(finding([shellStep("sh probe.sh", { cwd: "nested" })]), { runner, runDir });
    assert.equal(result.status, "reproduced", JSON.stringify(result));
  });

  await check("explicit Docker action executes the pinned image", async () => {
    const step = { ...shellStep(""), action: { type: "docker", image: shellImage, args: ["sh", "-c", "printf VULNERABLE_MARKER"] } };
    const { result } = await runDeterministicReplay(finding([step]), { runner, runDir: join(root, "docker-action") });
    assert.equal(result.status, "reproduced", JSON.stringify(result));
  });

  await check("timeout removes the real container", async () => {
    const runDir = join(root, "timeout");
    mkdirSync(runDir);
    const result = await runner.exec(shellStep('printf "%s" "$HOSTNAME" > /work/container-id; sleep 60'), { runDir, stepTimeoutMs: 2_000 });
    assert.equal(result.timedOut, true, JSON.stringify(result));
    const id = readFileSync(join(runDir, "container-id"), "utf8");
    assert.match(id, /^[a-f0-9]{12,64}$/);
    assert.throws(() => docker("inspect", id));
  });

  await check("scoped HTTP runs on an isolated network and rejects out-of-scope requests", async () => {
    const network = `0sec-replay-${process.pid}-${Date.now()}`;
    docker("network", "create", "--internal", network);
    resources.push(["network", "rm", network]);
    const id = docker("run", "--detach", "--rm", "--network", network, "--network-alias", "replay-fixture",
      shellImage, "sh", "-c", "mkdir /www; printf VULNERABLE_MARKER > /www/index.html; exec httpd -f -p 8080 -h /www");
    resources.push(["rm", "--force", id]);
    // Wait for the fixture through its own container, not the host network.
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { docker("exec", id, "wget", "-qO-", "http://127.0.0.1:8080"); ready = true; break; }
      catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
    }
    assert.ok(ready, "HTTP fixture never became ready");
    const httpRunner = new DockerRunner({ httpImage, network });
    const scope = ScopePolicy.fromJson({ in_scope: ["replay-fixture"] });
    const step = { ...shellStep(""), action: { type: "http", method: "GET", url: "http://replay-fixture:8080" } };
    const { result } = await runDeterministicReplay(finding([step]), { runner: httpRunner, scope, runDir: join(root, "http") });
    assert.equal(result.status, "reproduced", JSON.stringify(result));
    const denied = await httpRunner.exec({ ...step, action: { ...step.action, url: "http://outside.invalid" } },
      { runDir: join(root, "http"), stepTimeoutMs: 5_000, scope });
    assert.ok(denied.launchError, "Out-of-scope HTTP request was not rejected");
    assert.equal(denied.exitCode, null);
  });

  assert.deepEqual(failures, [], "Real Docker replay smoke failures");
  console.log("All real Docker replay checks passed");
} finally {
  for (const args of resources.reverse()) {
    try { docker(...args); } catch (error) { console.error("Docker fixture cleanup failed:", error.message); process.exitCode = 1; }
  }
  rmSync(root, { recursive: true, force: true });
  if (previousSecret === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = previousSecret;
}
