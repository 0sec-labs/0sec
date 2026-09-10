import { createHash } from "node:crypto";
import {
  chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse, resolve, sep } from "node:path";
import { z } from "zod";
import { findingSchema, VERSION, type Finding, type VerificationResult } from "@0sec/shared";
import type { ScopePolicy } from "../scope/scope.js";
import { DockerRunner, LocalShellRunner, runDeterministicReplay, type ReplayRunner } from "./replay-runner.js";

// Snapshots are bounded and read once, before any PoC executes. The cached bytes
// prevent a vulnerable-side process from changing the patched-side snapshot.
const MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const imageReference = z.string().regex(/^[^\s@]+@sha256:[a-f0-9]{64}$/);
const fileEntrySchema = z.object({
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  size: z.number().int().nonnegative().max(MAX_SNAPSHOT_BYTES),
  mode: z.number().int().min(0).max(0o777),
}).strict();
const filesSchema = z.record(fileEntrySchema).refine((files) => Object.keys(files).length > 0, "file allowlist is empty");
const sideSchema = z.object({ cwd: z.string(), files: filesSchema }).strict();
const compatibilitySchema = z.object({
  runner: z.enum(["local", "docker"]),
  platform: z.array(z.string()).min(1),
  arch: z.array(z.string()).min(1),
  node_version: z.string().min(1),
  docker_shell_image_digest: imageReference.optional(),
  docker_http_image_digest: imageReference.optional(),
}).strict();
const planSchema = z.object({
  version: z.literal(1),
  finding: findingSchema.optional(),
  finding_path: z.string().min(1).optional(),
  vulnerable_root: z.string().min(1),
  patched_root: z.string().min(1),
  files: z.object({
    vulnerable: z.array(z.string().min(1)).min(1),
    patched: z.array(z.string().min(1)).min(1),
  }).strict(),
  runner: z.enum(["local", "docker"]),
  docker_shell_image: imageReference.optional(),
  docker_http_image: imageReference.optional(),
}).strict().refine((p) => (p.finding !== undefined) !== (p.finding_path !== undefined),
  "exactly one of finding or finding_path is required");
const manifestSchema = z.object({
  version: z.literal(1),
  created_at: z.string().datetime(),
  engine_version: z.string().min(1),
  finding: findingSchema,
  vulnerable: sideSchema,
  patched: sideSchema,
  runner_compatibility: compatibilitySchema,
}).strict();

export type BundlePlan = z.infer<typeof planSchema>;
export type BundleManifest = z.infer<typeof manifestSchema>;
export type BundleSideManifest = z.infer<typeof sideSchema>;
export type RunnerCompatibility = z.infer<typeof compatibilitySchema>;
export interface ReproductionBundleResult {
  status: "confirmed" | "not_reproduced" | "inconclusive" | "error";
  exitCode: number;
  vulnerable: VerificationResult;
  patched: VerificationResult;
  summary: string;
  results_dir?: string;
}

export function validateBundlePlan(raw: unknown): BundlePlan {
  return planSchema.parse(raw);
}

function relativePath(path: string, allowDot = false): void {
  if (allowDot && path === ".") return;
  if (!path || /[\\:\0]/.test(path) || path.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error(`unsafe relative bundle path: ${path}`);
  }
}

/** Check every component, not just the final file; directory symlinks escape roots. */
function noSymlinks(path: string): void {
  const absolute = resolve(path);
  let current = parse(absolute).root;
  for (const part of absolute.slice(current.length).split(sep).filter(Boolean)) {
    current = join(current, part);
    const stat = lstatSync(current, { throwIfNoEntry: false });
    if (stat?.isSymbolicLink()) throw new Error(`symlink is not allowed: ${current}`);
  }
}

function readRegular(path: string, limit: number): Buffer {
  noSymlinks(path);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.size > limit) throw new Error(`not a regular file within the size limit: ${path}`);
  const bytes = readFileSync(path);
  if (bytes.length > limit) throw new Error(`file exceeds size limit: ${path}`);
  return bytes;
}

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function overlaps(a: string, b: string): boolean {
  return a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
}

function freshDirectory(path: string): void {
  noSymlinks(path);
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat && (!stat.isDirectory() || readdirSync(path).length !== 0)) {
    throw new Error(`output directory must be empty: ${path}`);
  }
  mkdirSync(path, { recursive: true, mode: 0o700 });
}

function validateSteps(finding: Finding, compatibility: RunnerCompatibility): void {
  const steps = finding.pocSteps ?? [];
  if (!steps.length || !steps.some((step) => step.expect)) throw new Error("bundle requires executable PoC steps and assertions");
  const ids = new Set<string>();
  for (const step of steps) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(step.id) || ids.has(step.id)) throw new Error("PoC step ids must be unique, safe filenames");
    ids.add(step.id);
    if (step.action.type === "note" || (compatibility.runner === "local" && step.action.type !== "shell")) {
      throw new Error(`runner ${compatibility.runner} cannot execute ${step.action.type} steps`);
    }
    if (step.action.type === "shell") {
      relativePath(step.action.cwd ?? ".", true);
      if (compatibility.runner === "docker" && !compatibility.docker_shell_image_digest) throw new Error("docker shell steps require a digest-pinned docker_shell_image");
    }
    if (step.action.type === "http" && !compatibility.docker_http_image_digest) throw new Error("docker HTTP steps require a digest-pinned docker_http_image");
    if (step.action.type === "docker") imageReference.parse(step.action.image);
    if (step.expect?.type === "file-exists") relativePath(step.expect.path);
    if (step.expect?.type === "body-matches") new RegExp(step.expect.pattern);
  }
}

/** Package only explicitly allowlisted files. This phase never executes PoC code. */
export async function createReproductionBundle(planPath: string, outputPath: string): Promise<{ manifest: BundleManifest; bundleDir: string }> {
  const planFile = resolve(planPath);
  const planDir = dirname(planFile);
  const plan = validateBundlePlan(JSON.parse(readRegular(planFile, MAX_MANIFEST_BYTES).toString("utf8")));
  const findingFile = plan.finding_path ? resolve(planDir, plan.finding_path) : undefined;
  const finding = plan.finding ?? findingSchema.parse(JSON.parse(readRegular(findingFile!, MAX_MANIFEST_BYTES).toString("utf8")));
  const bundleDir = resolve(outputPath);
  const roots = { vulnerable: resolve(planDir, plan.vulnerable_root), patched: resolve(planDir, plan.patched_root) };
  for (const path of [planFile, ...(findingFile ? [findingFile] : []), ...Object.values(roots)]) {
    noSymlinks(path);
    if (overlaps(path, bundleDir)) throw new Error("bundle output overlaps a source root or input file");
  }
  const compatibility: RunnerCompatibility = {
    runner: plan.runner, platform: [process.platform], arch: [process.arch], node_version: process.version,
    ...(plan.docker_shell_image ? { docker_shell_image_digest: plan.docker_shell_image } : {}),
    ...(plan.docker_http_image ? { docker_http_image_digest: plan.docker_http_image } : {}),
  };
  validateSteps(finding as Finding, compatibility);
  const snapshots = new Map<string, Buffer>();
  let totalBytes = 0;
  function snapshot(side: "vulnerable" | "patched"): BundleSideManifest {
    if (!lstatSync(roots[side]).isDirectory()) throw new Error(`${side}_root is not a directory`);
    const files: BundleSideManifest["files"] = Object.create(null);
    for (const path of plan.files[side]) {
      relativePath(path);
      if (Object.hasOwn(files, path)) throw new Error(`duplicate allowlist entry: ${path}`);
      const absolute = join(roots[side], path);
      const bytes = readRegular(absolute, MAX_SNAPSHOT_BYTES - totalBytes);
      const sha256 = digest(bytes);
      if (!snapshots.has(sha256)) { snapshots.set(sha256, bytes); totalBytes += bytes.length; }
      files[path] = { sha256, size: bytes.length, mode: lstatSync(absolute).mode & 0o777 };
    }
    return { cwd: side, files };
  }
  const manifest: BundleManifest = {
    version: 1, created_at: new Date().toISOString(), engine_version: VERSION, finding,
    vulnerable: snapshot("vulnerable"), patched: snapshot("patched"), runner_compatibility: compatibility,
  };
  // Validate everything before creating output; refuse reuse rather than mixing snapshots.
  freshDirectory(bundleDir);
  try {
    mkdirSync(join(bundleDir, "files"), { mode: 0o700 });
    for (const [sha, bytes] of snapshots) writeFileSync(join(bundleDir, "files", sha), bytes, { flag: "wx", mode: 0o400 });
    writeFileSync(join(bundleDir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  } catch (error) {
    rmSync(bundleDir, { recursive: true, force: true });
    throw error;
  }
  return { manifest, bundleDir };
}

/** Explicit runner choice is consent to execute trusted PoC code, not an authenticity check. */
export async function runReproductionBundle(opts: {
  bundleDir: string;
  runner: "local" | "docker";
  outDir?: string;
  scope?: ScopePolicy;
  dockerNetwork?: string;
}): Promise<ReproductionBundleResult> {
  let findingId = "unknown";
  try {
    const bundleDir = resolve(opts.bundleDir);
    const manifest = manifestSchema.parse(JSON.parse(readRegular(join(bundleDir, "manifest.json"), MAX_MANIFEST_BYTES).toString("utf8")));
    findingId = manifest.finding.id;
    const compat = manifest.runner_compatibility;
    if (opts.runner !== compat.runner) throw new Error(`bundle requires runner ${compat.runner}`);
    if (!compat.platform.includes(process.platform) || !compat.arch.includes(process.arch)) throw new Error("bundle platform or architecture does not match this host");
    if (manifest.engine_version !== VERSION) throw new Error("bundle engine version does not match this verifier");
    if (opts.runner === "local" && compat.node_version !== process.version) throw new Error("bundle Node version does not match this local runtime");
    if (opts.dockerNetwork && opts.runner !== "docker") throw new Error("dockerNetwork requires the docker runner");
    const finding = manifest.finding as Finding;
    validateSteps(finding, compat);
    if (finding.pocSteps!.some((step) => step.action.type === "http") && (!opts.scope || !opts.dockerNetwork || opts.dockerNetwork === "none")) {
      throw new Error("HTTP replay requires explicit scope and docker network");
    }
    const snapshots = new Map<string, Buffer>();
    let totalBytes = 0;
    for (const side of ["vulnerable", "patched"] as const) {
      if (manifest[side].cwd !== side) throw new Error(`invalid ${side} working directory`);
      const paths = Object.keys(manifest[side].files).sort();
      for (let i = 0; i < paths.length; i++) {
        const path = paths[i]!;
        relativePath(path);
        if (paths[i + 1]?.startsWith(path + "/")) throw new Error("bundle contains overlapping file paths");
        const entry = manifest[side].files[path]!;
        let bytes = snapshots.get(entry.sha256);
        if (!bytes) {
          bytes = readRegular(join(bundleDir, "files", entry.sha256), MAX_SNAPSHOT_BYTES - totalBytes);
          if (digest(bytes) !== entry.sha256) throw new Error(`snapshot digest mismatch: ${path}`);
          snapshots.set(entry.sha256, bytes);
          totalBytes += bytes.length;
        }
        if (bytes.length !== entry.size) throw new Error(`snapshot size mismatch: ${path}`);
      }
    }
    const resultsDir = opts.outDir ? resolve(opts.outDir) : mkdtempSync(join(tmpdir(), "0sec-repro-"));
    if (overlaps(bundleDir, resultsDir)) throw new Error("replay output overlaps the bundle");
    freshDirectory(resultsDir);
    async function replay(side: "vulnerable" | "patched"): Promise<VerificationResult> {
      // Materialize the control only after the vulnerable run exits, from the
      // already-validated cached bytes. Never reuse files produced by a replay.
      const runDir = join(resultsDir, side);
      noSymlinks(runDir);
      mkdirSync(runDir, { mode: 0o700 });
      for (const [path, entry] of Object.entries(manifest[side].files)) {
        const destination = join(resultsDir, side, path);
        mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
        writeFileSync(destination, snapshots.get(entry.sha256)!, { flag: "wx", mode: 0o600 });
        chmodSync(destination, 0o600 | (entry.mode & 0o111));
      }
      const delegate = opts.runner === "local" ? new LocalShellRunner() : new DockerRunner({
        shellImage: compat.docker_shell_image_digest, httpImage: compat.docker_http_image_digest, network: opts.dockerNetwork,
      });
      const runner: ReplayRunner = {
        kind: delegate.kind,
        async exec(step, context) {
          if (step.action.type === "shell") noSymlinks(resolve(runDir, step.action.cwd ?? "."));
          const result = await delegate.exec(step, context);
          // A failed process is not evidence that a patch blocked an exploit.
          // Stop on setup errors too; later marker output cannot redeem them.
          if (result.timedOut || result.exitCode !== 0) result.launchError ??= `PoC step ${step.id} did not complete successfully (exit ${result.exitCode})`;
          if (step.expect?.type === "file-exists") noSymlinks(step.expect.path);
          return result;
        },
      };
      const scopedFinding: Finding = { ...finding, pocSteps: finding.pocSteps!.map((step) => ({
        ...step, expect: step.expect?.type === "file-exists" ? { ...step.expect, path: join(runDir, step.expect.path) } : step.expect,
      })) };
      const { result } = await runDeterministicReplay(scopedFinding, { runner, runDir, scope: opts.scope, engineVersion: VERSION });
      writeFileSync(join(resultsDir, `${side}.json`), JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
      return result;
    }
    const vulnerable = await replay("vulnerable");
    const patched = await replay("patched");
    const healthy = (result: VerificationResult) => result.status !== "error" && result.status !== "skipped" && result.assertions.length > 0;
    const status: ReproductionBundleResult["status"] = !healthy(vulnerable) || !healthy(patched) ? "error"
      : vulnerable.status !== "reproduced" ? "not_reproduced"
      : patched.status === "reproduced" ? "inconclusive" : "confirmed";
    const summary = { confirmed: "Vulnerable reproduced; patched completed successfully without reproducing.",
      inconclusive: "PoC reproduces on both sides; the negative control failed.",
      not_reproduced: "The vulnerable snapshot did not reproduce the finding.",
      error: "A replay failed to execute or evaluate assertions; no negative control established." }[status];
    const result = { status, exitCode: status === "confirmed" ? 0 : status === "error" ? 3 : 1, vulnerable, patched, summary, results_dir: resultsDir };
    writeFileSync(join(resultsDir, "result.json"), JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
    return result;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    const now = new Date().toISOString();
    const failure: VerificationResult = {
      status: "error", mode: "deterministic_replay", finding_id: findingId, engine_version: VERSION,
      started_at: now, completed_at: now, duration_ms: 0, commands: [], assertions: [], evidence_artifacts: [],
      engine_metadata: { os: process.platform, arch: process.arch, runner: opts.runner }, error_reason: reason, summary: reason,
    };
    return { status: "error", exitCode: 3, vulnerable: failure, patched: failure, summary: reason };
  }
}
