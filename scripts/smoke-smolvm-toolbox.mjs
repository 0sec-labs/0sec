#!/usr/bin/env node
/** Qualify a provisioned toolbox archive in a real offline, non-root microVM.
 * Build first: docker build --target toolbox -t 0sec-toolbox .
 * Run: node scripts/smoke-smolvm-toolbox.mjs /absolute/path/to/toolbox.tar
 * This checks tool startup and local behavior, not authenticated engagements.
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runSmolvm, resolveSmolvmImage } from "../packages/core/dist/runtime/smolvm.js";

const archive = process.env["0SEC_SMOLVM_IMAGE_ARCHIVE"] || process.argv[2];
assert(archive, "provide a toolbox image archive via argv or 0SEC_SMOLVM_IMAGE_ARCHIVE");
const imageArchive = resolve(archive);
const imageDigest = await resolveSmolvmImage(imageArchive);
const root = mkdtempSync(join(tmpdir(), "0sec-toolbox-qualification-"));

// Nonzero usage exits are explicitly listed and must actually print usage.
const probes = [
  ["node", ["--version"]], ["npm", ["--version"]], ["npx", ["--version"]],
  ["curl", ["--version"]], ["wget", ["--version"]], ["jq", ["--version"]],
  ["git", ["--version"]], ["unzip", ["-v"]], ["xz", ["--version"]],
  ["rg", ["--version"]], ["skopeo", ["--version"]], ["python3", ["--version"]],
  ["sqlmap", ["--version"]], ["nmap", ["--version"]], ["nikto", ["-Version"]],
  ["gobuster", ["version"]], ["hydra", ["-h"], [0, 255]], ["john", []],
  ["ffuf", ["-V"]], ["wfuzz", ["--version"]], ["whatweb", ["--version"]],
  ["wafw00f", ["--version"]], ["dirb", [], [0, 255]], ["ldapsearch", ["-VV"]],
  ["kinit", ["--help"], [2]], ["klist", ["-V"]], ["kdestroy", ["--help"], [2]],
  ["certipy", ["-h"]], ["bloodhound-ce-python", ["-h"]],
  ...["GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py", "psexec.py", "wmiexec.py", "ntlmrelayx.py"]
    .map((name) => [name, ["-h"]]),
  ["azurehound", ["--help"]], ["foxguard", ["--version"]],
];

async function guest(probes) {
  const { default: assert } = await import("node:assert/strict");
  const { spawnSync, execFile } = await import("node:child_process");
  const { readFileSync, writeFileSync } = await import("node:fs");
  const { createServer } = await import("node:http");
  const { promisify } = await import("node:util");
  const run = promisify(execFile);
  assert.equal(process.getuid(), 1000);
  assert.equal(process.getgid(), 1000);
  assert.equal(Number(process.versions.node.split(".")[0]), 24);
  const results = probes.map(([command, args, statuses = [0]]) => {
    const result = spawnSync(command, args, { encoding: "utf8", timeout: 15000, maxBuffer: 1024 * 1024 });
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    const passed = !result.error && !result.signal && statuses.includes(result.status)
      && (result.status === 0 || /usage|syntax|^dirb\s+</im.test(output));
    return { command, status: result.status, passed, diagnostic: passed ? undefined : output.slice(-2000), error: result.error?.message };
  });
  console.log(JSON.stringify({ phase: "tool-startup", results }));
  assert.deepEqual(results.filter((result) => !result.passed), [], "declared tools must all start successfully");
  await run("python3", ["-c", "import requests, bs4"]);
  await run("/opt/ad-tools/bin/python3", ["-c", "import impacket, certipy, bloodhound"]);

  // Exercise TCP connect scanning against a server owned by this guest only.
  const server = createServer((_request, response) => response.end("toolbox-fixture"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const port = server.address().port;
    const { stdout } = await run("nmap", ["-sT", "-Pn", "-n", "-p", String(port), "127.0.0.1", "-oX", "-"], { timeout: 15000 });
    assert(stdout.includes(`portid="${port}"`) && stdout.includes('state="open"'), "nmap must discover the owned listening fixture");
    const response = await run("curl", ["--fail", "--silent", `http://127.0.0.1:${port}/`], { timeout: 10000 });
    assert.equal(response.stdout, "toolbox-fixture");
  } finally { await new Promise((resolve) => server.close(resolve)); }

  const scan = spawnSync("foxguard", ["/snapshot", "--format", "sarif", "--output", "/tmp/findings.sarif"], {
    encoding: "utf8", timeout: 60000, maxBuffer: 1024 * 1024,
  });
  assert(!scan.error && !scan.signal && [0, 1].includes(scan.status), scan.stderr || "Foxguard failed");
  const findings = JSON.parse(readFileSync("/tmp/findings.sarif", "utf8")).runs.flatMap((run) => run.results ?? []);
  const locations = findings.flatMap((finding) => finding.locations ?? []).map((location) => location.physicalLocation);
  assert(locations.some((location) => location.artifactLocation.uri.endsWith("vulnerable.js") && location.region.startLine === 2), "Foxguard must locate the unsafe eval");
  assert(!locations.some((location) => location.artifactLocation.uri.endsWith("clean.js")), "clean control must not be reported");
  assert.throws(() => writeFileSync("/snapshot/vulnerable.js", "changed"), "source mount must remain read-only");
  console.log(JSON.stringify({ outcome: "passed", tools: probes.length, uid: process.getuid(), localNetworkFixture: true, foxguardFindings: findings.length, cleanControl: true }));
}

try {
  const vulnerable = "function execute(userInput) {\n  return eval(userInput);\n}\n";
  writeFileSync(join(root, "vulnerable.js"), vulnerable);
  writeFileSync(join(root, "clean.js"), "function parse(userInput) { return JSON.parse(userInput); }\n");
  console.log(JSON.stringify({ phase: "toolbox-started", imageDigest }));
  const result = await runSmolvm({
    imageArchive, imageDigest, cpus: 2, memoryMb: 3072, storageGb: 4,
    timeoutMs: 180000, maxOutputBytes: 256 * 1024,
    mounts: [{ source: root, target: "/snapshot" }],
    command: ["node", "-e", `(${guest.toString()})(${JSON.stringify(probes)}).catch(e => { console.error(e); process.exitCode = 1; });`],
  });
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  assert.equal(result.error, undefined, JSON.stringify(result));
  assert.equal(result.timedOut, false, JSON.stringify(result));
  assert.equal(result.exitCode, 0, JSON.stringify(result));
  assert.equal((await import("node:fs")).readFileSync(join(root, "vulnerable.js"), "utf8"), vulnerable);
  console.log(JSON.stringify({ outcome: "passed", backend: "smolvm", imageDigest, durationMs: result.durationMs }));
} finally { rmSync(root, { recursive: true, force: true }); }
