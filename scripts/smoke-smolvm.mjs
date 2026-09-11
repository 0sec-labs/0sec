#!/usr/bin/env node
/** Real smolvm qualification. No mocked executor, host fallback, or image pull.
 * Requires built core, smolvm on PATH, virtualization access and a Node image archive.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:http";
import { runSmolvm, resolveSmolvmImage } from "../packages/core/dist/runtime/smolvm.js";

const imageArchive = resolve(process.env["0SEC_SMOLVM_IMAGE_ARCHIVE"] || process.argv[2] || "");
assert(process.env["0SEC_SMOLVM_IMAGE_ARCHIVE"] || process.argv[2], "provide a local Node image archive via argv or 0SEC_SMOLVM_IMAGE_ARCHIVE");
assert.notEqual(process.getuid?.(), 0, "qualification must run as a non-root host user");
const imageDigest = await resolveSmolvmImage(imageArchive);
const root = mkdtempSync(join(tmpdir(), "0sec-smol-qualification-"));
const originalCwd = process.cwd();
const source = join(root, "source");
mkdirSync(source);
writeFileSync(join(source, "fixture.txt"), "unchanged source\n");
const hostMarker = join(root, "host-must-not-run");
const secretName = "OPENAI_API_KEY";
const previousSecret = process.env[secretName];
const previousPath = process.env.PATH;
const results = [];
const defaults = { imageArchive, imageDigest, cpus: 2, memoryMb: 2048, storageGb: 4, timeoutMs: 60000, maxOutputBytes: 65536 };
const fixtureServer = createServer((_request, response) => response.end("controlled host fixture"));

function vmProcesses() {
  return new Set(execFileSync("ps", ["-u", String(process.getuid()), "-o", "pid=,args="], { encoding: "utf8" })
    .split("\n").filter((line) => /(?:^|\/)smolvm-bin(?:\s|$)/.test(line))
    .map((line) => Number(line.trim().split(/\s+/, 1)[0])));
}
const initialProcesses = vmProcesses();
async function check(name, work) {
  const start = performance.now();
  await work();
  assert.equal(existsSync(hostMarker), false, `${name}: a host command or Docker fallback was invoked`);
  const leaked = [...vmProcesses()].filter((pid) => !initialProcesses.has(pid));
  assert.deepEqual(leaked, [], `${name}: smolvm processes survived cleanup`);
  const result = { name, outcome: "passed", durationMs: Math.round(performance.now() - start) };
  results.push(result);
  console.log(JSON.stringify(result));
}
async function execute(code, overrides = {}) {
  return runSmolvm({ ...defaults, command: ["node", "-e", code], ...overrides });
}
function successful(result) {
  assert.equal(result.error, undefined, JSON.stringify(result));
  assert.equal(result.timedOut, false, JSON.stringify(result));
  assert.equal(result.exitCode, 0, JSON.stringify(result));
}
async function rejectedExecution(options) {
  try {
    const result = await runSmolvm(options);
    assert(result.error || result.timedOut || result.exitCode !== 0, "invalid execution was accepted");
  } catch (error) {
    if (error?.code === "ERR_ASSERTION") throw error;
  }
}

try {
  const forbiddenBin = join(root, "forbidden-bin");
  mkdirSync(forbiddenBin);
  for (const tool of ["docker", "podman"]) {
    writeFileSync(join(forbiddenBin, tool), `#!/bin/sh\n: > '${hostMarker.replaceAll("'", "'\\''")}'\nexit 99\n`, { mode: 0o755 });
  }
  process.env.PATH = `${forbiddenBin}:${previousPath ?? ""}`;
  await new Promise((resolve, reject) => {
    fixtureServer.once("error", reject);
    fixtureServer.listen(0, "127.0.0.1", resolve);
  });
  console.log(JSON.stringify({ phase: "qualification-started", imageDigest }));
  await check("offline worker cannot reach controlled host loopback", async () => {
    const port = fixtureServer.address().port;
    assert.equal(await (await fetch(`http://127.0.0.1:${port}`)).text(), "controlled host fixture");
    const result = await execute(`const net=require('node:net'); const s=net.connect(${port},'127.0.0.1');
      s.setTimeout(2000); let done=false; const finish=connected=>{if(done)return;done=true;s.destroy();console.log(JSON.stringify({connected}));};
      s.on('connect',()=>finish(true));s.on('error',()=>finish(false));s.on('timeout',()=>finish(false));`);
    successful(result);
    assert.equal(JSON.parse(result.stdout).connected, false);
  });
  // Ambient project configuration must not expand permissions or inject init.
  writeFileSync(join(root, "Smolfile"), 'net = true\nenv = ["SMOLVM_QUAL_AMBIENT=must-not-leak"]\n');
  process.chdir(root);
  process.env[secretName] = "qualification-canary-not-a-real-credential";
  await check("stdin, argv, non-root, resources, secrets and ambient config", async () => {
    const input = JSON.stringify({ text: "quotes ' \" ; $(false) 雪\n", n: 17 });
    const code = `const fs=require('node:fs'),os=require('node:os'); console.log(JSON.stringify({input:JSON.parse(fs.readFileSync(0,'utf8')),arg:process.argv[1],uid:process.getuid(),cpus:os.cpus().length,memory:os.totalmem(),secret:!!process.env.OPENAI_API_KEY,ambient:!!process.env.SMOLVM_QUAL_AMBIENT,docker:fs.existsSync('/var/run/docker.sock')}));`;
    const result = await runSmolvm({ ...defaults, stdin: input, command: ["node", "-e", code, "literal ' ; $(false) 雪"] });
    successful(result);
    const data = JSON.parse(result.stdout);
    assert.deepEqual(data.input, JSON.parse(input));
    assert.equal(data.arg, "literal ' ; $(false) 雪");
    assert.equal(data.uid, 1000);
    assert.equal(data.cpus, 2);
    assert(data.memory <= 2048 * 1024 * 1024 && data.memory > 1024 * 1024 * 1024);
    assert.equal(data.secret, false);
    assert.equal(data.ambient, false);
    assert.equal(data.docker, false);
  });
  await check("read-only source and writable isolated workspace", async () => {
    const result = await execute(`const fs=require('node:fs'),assert=require('node:assert/strict');
      assert.equal(fs.readFileSync('/snapshot/fixture.txt','utf8'),'unchanged source\\n');
      assert.throws(()=>fs.appendFileSync('/snapshot/fixture.txt','tampered'),e=>e.code==='EROFS');
      fs.mkdirSync('/tmp/qualification-workspace'); fs.cpSync('/snapshot','/tmp/qualification-workspace',{recursive:true});
      fs.writeFileSync('/tmp/qualification-workspace/fixture.txt','guest edit');
      assert.equal(fs.readFileSync('/tmp/qualification-workspace/fixture.txt','utf8'),'guest edit');
      assert.equal(fs.existsSync(${JSON.stringify(root)}),false); console.log('workspace-pass');`,
      { mounts: [{ source, target: "/snapshot" }] });
    successful(result);
    assert.equal(result.stdout.trim(), "workspace-pass");
    assert.equal(readFileSync(join(source, "fixture.txt"), "utf8"), "unchanged source\n");
    const fresh = await execute("console.log(require('node:fs').existsSync('/tmp/qualification-workspace'))");
    successful(fresh);
    assert.equal(fresh.stdout.trim(), "false");
  });
  await check("guest nonzero exit and separated streams", async () => {
    const result = await execute("process.stdout.write('OUT');process.stderr.write('ERR');process.exitCode=23;");
    assert.equal(result.exitCode, 23, JSON.stringify(result));
    assert.equal(result.stdout, "OUT");
    assert.equal(result.stderr, "ERR");
    assert.equal(result.timedOut, false);
  });
  await check("guest disk exhaustion stays within storage cap", async () => {
    const result = await execute(`const fs=require('node:fs'); const home=fs.readFileSync('/etc/passwd','utf8').split('\\n').find(row=>row.split(':')[2]==='1000').split(':')[5]; const fd=fs.openSync(home+'/qualification-disk-limit','w'); const chunk=Buffer.alloc(1024*1024,1); let mib=0;
      try { for(;mib<1200;mib++) fs.writeSync(fd,chunk); throw new Error('storage cap did not stop writes'); }
      catch(e) { if(e.code!=='ENOSPC') throw e; console.log(JSON.stringify({code:e.code,mib})); } finally { fs.closeSync(fd); }`,
      { storageGb: 1 });
    successful(result);
    const data = JSON.parse(result.stdout);
    assert.equal(data.code, "ENOSPC");
    assert(data.mib > 0 && data.mib < 1024);
  });
  await check("archive integrity rejects changed identity", () => rejectedExecution({ ...defaults, imageDigest: `sha256:${"0".repeat(64)}`, command: ["node", "-e", "process.exit(0)"] }));
  await check("missing runtime never runs guest commands on host", async () => {
    await rejectedExecution({ ...defaults, binary: join(root, "missing-smolvm"), command: ["node", "-e", `require('node:fs').writeFileSync(${JSON.stringify(hostMarker)},'escaped')`] });
    assert.equal(existsSync(hostMarker), false);
  });
  await check("pre-cancellation does not boot a worker", async () => {
    const controller = new AbortController(); controller.abort();
    await rejectedExecution({ ...defaults, signal: controller.signal, command: ["node", "-e", "process.exit(0)"] });
  });
  await check("startup deadline closes owned lifecycle", async () => {
    const start = performance.now();
    const result = await execute("setInterval(()=>{},1000)", { timeoutMs: 100 });
    assert.equal(result.timedOut, true, JSON.stringify(result));
    assert(performance.now() - start < 20000, "startup timeout cleanup did not remain bounded");
  });
  const hangingGuest = `process.stdout.write('WORKLOAD_STARTED\\n'); require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'}).unref(); setInterval(()=>{},1000);`;
  await check("running workload deadline removes descendants", async () => {
    const result = await execute(hangingGuest, { timeoutMs: 30000 });
    assert.match(result.stdout, /WORKLOAD_STARTED/, "deadline must exercise a started workload, not just boot");
    assert.equal(result.timedOut, true, JSON.stringify(result));
    assert(result.error);
    assert(result.durationMs < 50000, "running deadline cleanup did not remain bounded");
  });
  await check("running workload cancellation removes descendants", async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const result = await execute(hangingGuest, { signal: controller.signal });
      assert.match(result.stdout, /WORKLOAD_STARTED/, "cancellation must exercise a started workload");
      assert.equal(result.timedOut, false, JSON.stringify(result));
      assert.match(result.error ?? "", /cancel|abort/i);
      assert(result.durationMs < 50000, "cancellation cleanup did not remain bounded");
    } finally { clearTimeout(timer); }
  });
  for (const stream of ["stdout", "stderr"]) {
    await check(`${stream} flood is capped and terminated`, async () => {
      const result = await execute(`process.${stream}.write('x'.repeat(1024*1024));setInterval(()=>{},1000)`, { maxOutputBytes: 4096, timeoutMs: 30000 });
      assert(result.error, JSON.stringify(result));
      assert.equal(result.timedOut, false, "output cap must stop the worker before its deadline");
      assert(Buffer.byteLength(result.stdout) <= 4096);
      assert(Buffer.byteLength(result.stderr) <= 4096);
    });
  }
  console.log(JSON.stringify({ outcome: "passed", backend: "smolvm", imageDigest, cases: results.length }));
} finally {
  await new Promise((resolve) => fixtureServer.close(resolve));
  process.chdir(originalCwd);
  if (previousSecret === undefined) delete process.env[secretName]; else process.env[secretName] = previousSecret;
  if (previousPath === undefined) delete process.env.PATH; else process.env.PATH = previousPath;
  rmSync(root, { recursive: true, force: true });
}
