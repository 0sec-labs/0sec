import { createHash, randomUUID } from "node:crypto";
import {
  constants as fsConst,
  copyFileSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
  closeSync,
} from "node:fs";
import { open, readFile, writeFile, mkdir, readdir, readlink, stat, unlink, rmdir, copyFile, chmod } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";

import { canonicalEvolutionJson, parseEvolutionConfig } from "./config.js";
import { acquireEvolutionController, EvolutionControllerBusyError } from "./controller-lock.js";
import {
  ensureEvolutionDirectory,
  publishEvolutionArtifact,
  readEvolutionArtifact,
} from "./artifacts.js";
import type {
  EvolutionArtifactKind,
  EvolutionConfig,
  EvolutionEdit,
  EvolutionEvaluation,
  EvolutionFile,
  EvolutionProposal,
  EvolutionRegistry,
  EvolutionRegistryEvent,
  EvolutionSnapshot,
  EvolutionVersion,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MAX_PATH_COMPONENT = 4096;

/** Extensions allowed for non-source artifact kinds. */
const SKILL_EXTENSIONS: Record<string, true> = { ".yaml": true, ".yml": true };
const ROUTER_EXTENSIONS: Record<string, true> = { ".json": true };
const LENS_EXTENSIONS: Record<string, true> = { ".json": true };

/** File-name patterns automatically rejected as secrets/credentials. */
const SECRET_PATTERNS = [
  /^\.env/i,
  /\.auth$/i,
  /(?:^|[_.-])keys?(?:$|[_.-])/i,
  /(?:^|[_.-])secrets?(?:$|[_.-])/i,
  /(?:^|[_.-])tokens?(?:$|[_.-])/i,
  /(?:^|[_.-])credentials?(?:$|[_.-])/i,
  /(?:^|[_-])pem(?:$|[_.-])/i,
  /(?:^|[_-])cert(?:$|[_.-])/i,
  /\.pem$/i,
  /\.key$/i,
];

type ExtensionMap = Record<string, true>;

function allowedExtensionsForKind(kind: EvolutionArtifactKind): ExtensionMap | null {
  if (kind === "source") return null;
  switch (kind) {
    case "skill": return SKILL_EXTENSIONS;
    case "router": return ROUTER_EXTENSIONS;
    case "lens": return LENS_EXTENSIONS;
  }
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

/** Content-address any evolution value with canonical JSON + SHA-256. */
export function evolutionDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalEvolutionJson(value)).digest("hex")}`;
}

function isSha256Digest(value: string): boolean {
  return /^sha256:[a-f0-9]{64}$/i.test(value);
}

// ---------------------------------------------------------------------------
// Store path helpers — layout contract
// ---------------------------------------------------------------------------

function snapshotsDir(storePath: string): string { return join(storePath, "snapshots"); }
export function snapshotDir(storePath: string, id: string): string { return join(snapshotsDir(storePath), id); }
export function receiptsDir(storePath: string): string { return join(storePath, "receipts"); }
export function configsDir(storePath: string): string { return join(storePath, "configs"); }
function registryPath(storePath: string): string { return join(storePath, "registry.json"); }
function lockDir(storePath: string): string { return join(storePath, ".lock"); }
function pinsDir(storePath: string): string { return join(storePath, "pins"); }

// ---------------------------------------------------------------------------
// Receipt I/O (via Main artifacts.ts)
// ---------------------------------------------------------------------------

/**
 * Load and verify an evaluation receipt from the store. Returns the parsed
 * receipt, or null if the receipt file does not exist.
 */
export function loadEvolutionReceipt(storePath: string, versionId: string, canaryTrial?: number): EvolutionEvaluation | null {
  if (canaryTrial !== undefined && (!Number.isSafeInteger(canaryTrial) || canaryTrial < 0 || canaryTrial >= 20)) {
    throw new Error("invalid canary trial index");
  }
  const filename = canaryTrial === undefined ? versionId : `${versionId}.canary-${canaryTrial}`;
  const rp = join(receiptsDir(storePath), `${filename}.json`);
  if (!existsSync(rp)) return null;
  try {
    const raw = readEvolutionArtifact(rp) as EvolutionEvaluation;
    if (raw.candidateId !== versionId) {
      throw new Error(`receipt candidateId mismatch: expected ${versionId}, got ${raw.candidateId}`);
    }
    if (!isSha256Digest(raw.receiptDigest)) {
      throw new Error(`invalid receipt digest format: ${raw.receiptDigest}`);
    }
    const { receiptDigest: _rd, ...unsigned } = raw;
    const expected = evolutionDigest(unsigned);
    if (raw.receiptDigest !== expected) {
      throw new Error(`receipt digest mismatch for ${versionId}: stored ${raw.receiptDigest}, computed ${expected}`);
    }
    return raw;
  } catch (err) {
    if ((err as Error).message.includes("unsafe evolution artifact")) {
      throw new Error(`tampered or unsafe evolution receipt: ${rp}`);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// File-level hash + safety validation
// ---------------------------------------------------------------------------

function fileDigest(absPath: string): string {
  const buf = readFileSync(absPath);
  return `sha256:${createHash("sha256").update(buf).digest("hex")}`;
}

function validateSnapshotPath(absPath: string, sourceRoot: string, storePath: string | null, maxBytes: number): void {
  const st = lstatSync(absPath);
  if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) {
    throw new Error(`snapshot source path is not a regular file: ${absPath}`);
  }
  if (st.size > maxBytes) {
    throw new Error(`snapshot source file exceeds maxSourceBytes: ${absPath} (${st.size} > ${maxBytes})`);
  }
  if (st.isFIFO() || st.isSocket() || st.isCharacterDevice() || st.isBlockDevice()) {
    throw new Error(`snapshot source path is a special file: ${absPath}`);
  }

  // Detect symlinks in ancestor dirs
  const real = realpathSync(absPath);
  if (real !== absPath) {
    throw new Error(`snapshot source path resolves differently via symlink: ${absPath} -> ${real}`);
  }
  // Path traversal
  if (!real.startsWith(sourceRoot + sep) && real !== sourceRoot) {
    throw new Error(`snapshot source path escapes source root: ${absPath}`);
  }
  // Must not overlap with store
  if (storePath !== null && (real.startsWith(storePath + sep) || real === storePath)) {
    throw new Error(`snapshot source path is inside evolution store: ${absPath}`);
  }
  // Reject credential/secret files
  const fileName = basename(absPath);
  if (SECRET_PATTERNS.some((p) => p.test(fileName))) {
    throw new Error(`snapshot source path appears to be a credential/secret file: ${absPath}`);
  }
}

function validateEditPath(editPath: string, config: EvolutionConfig): void {
  if (isAbsolute(editPath) || editPath.includes("..") || editPath.includes("\0")) {
    throw new Error(`edit path is absolute, has traversal or null byte: ${editPath}`);
  }
  const normalized = normalize(editPath);
  if (normalized.startsWith("..")) {
    throw new Error(`edit path escapes via parent traversal: ${editPath}`);
  }

  const withinEditable = config.editablePaths.some((a) => normalized === a || normalized.startsWith(`${a}/`));
  if (!withinEditable) {
    throw new Error(`edit path is not within configured editablePaths: ${editPath}`);
  }

  const extSet = allowedExtensionsForKind(config.kind);
  if (extSet !== null) {
    const ext = normalized.slice(normalized.lastIndexOf(".")).toLowerCase();
    if (!extSet[ext]) {
      throw new Error(`edit path extension "${ext}" is not allowed for kind "${config.kind}": ${editPath}`);
    }
    if (basename(normalized) === "package.json") {
      throw new Error(`non-source kind "${config.kind}" cannot edit package.json (potential executable change): ${editPath}`);
    }
  }

  // Protected code paths
  const lower = `/${normalized.toLowerCase()}`;
  const protectedPatterns = [
    /[/\\]improvement[/\\]evaluation\./,
    /[/\\]improvement[/\\]registry\./,
    /[/\\]improvement[/\\]loop\./,
    /[/\\]improvement[/\\]config\./,
    /[/\\]bench[/\\]improvement-promotion\./,
    /[/\\]bench[/\\]improvement\./,
    /[/\\]bench[/\\]oracle\./,
    /[/\\]bench[/\\]runner\./,
    /[/\\]bench[/\\]scorecard\./,
    /scope[/\\]/,
    /auth/i,
    /authorization/i,
    /credential/i,
    /\.test\.(ts|js|mjs)$/,
    /\.spec\.(ts|js|mjs)$/,
    /[/\\](?:test|spec)\.[cm]?[jt]s$/,
    /__tests__[/\\]/,
  ];
  for (const p of protectedPatterns) {
    if (p.test(lower)) throw new Error(`edit path targets protected code area: ${editPath}`);
  }
}

// ---------------------------------------------------------------------------
// Process-safe directory lock
// ---------------------------------------------------------------------------

const LOCK_RETRY_MS = 50;
const LOCK_MAX_RETRIES = 200; // 10 seconds

async function acquireLock(storePath: string, signal?: AbortSignal): Promise<() => void> {
  for (let attempt = 0; attempt < LOCK_MAX_RETRIES; attempt++) {
    signal?.throwIfAborted();
    try {
      return acquireEvolutionController(lockDir(storePath));
    } catch (error) {
      if (!(error instanceof EvolutionControllerBusyError)) throw error;
    }
    await new Promise<void>((done) => setTimeout(done, LOCK_RETRY_MS));
  }
  throw new Error(`could not acquire evolution registry lock at ${storePath}`);
}

// ---------------------------------------------------------------------------
// Registry I/O — atomic mutable state via temp-in-store + rename
// ---------------------------------------------------------------------------

function saveRegistryRaw(storePath: string, registry: EvolutionRegistry): void {
  const rp = registryPath(storePath);
  const tmp = join(storePath, `.registry-${randomUUID()}.tmp`);
  const fd = openSync(tmp, fsConst.O_WRONLY | fsConst.O_CREAT | fsConst.O_EXCL, 0o600);
  try {
    writeFileSync(fd, JSON.stringify(registry, null, 2), "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, rp);
  // fsync parent directory
  try {
    const dirFd = openSync(storePath, fsConst.O_RDONLY);
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  } catch { /* best-effort */ }
}

/** Replay lifecycle transitions; mutable pointers and statuses must agree exactly. */
function deriveVersionStates(registry: EvolutionRegistry): {
  activeId: string | null; canaryId: string | null; statuses: Map<string, EvolutionVersion["status"]>;
} {
  const versions = new Map(registry.versions.map((version) => [version.id, version]));
  const statuses = new Map<string, EvolutionVersion["status"]>();
  let activeId: string | null = null;
  let canaryId: string | null = null;
  for (const event of registry.events) {
    const version = versions.get(event.versionId);
    if (!version) throw new Error(`event references unknown version ${event.versionId}`);
    if (event.type === "recorded") {
      if (statuses.has(version.id)) throw new Error(`duplicate recorded event for ${version.id}`);
      if (version.parentId === null) {
        if (statuses.size !== 0 || version.receiptDigest !== null) throw new Error("invalid baseline recording");
        statuses.set(version.id, "baseline");
        activeId = version.id;
      } else {
        if (!statuses.has(version.parentId)) throw new Error("candidate parent was not recorded");
        statuses.set(version.id, "candidate");
      }
    } else if (event.type === "canary_started") {
      if (canaryId !== null || statuses.get(version.id) !== "candidate" || version.parentId !== activeId) {
        throw new Error("invalid canary transition in registry");
      }
      statuses.set(version.id, "canary");
      canaryId = version.id;
    } else if (event.type === "promoted") {
      if (canaryId !== version.id || version.parentId !== activeId) throw new Error("invalid promotion transition in registry");
      if (activeId !== null) statuses.set(activeId, "retired");
      statuses.set(version.id, "active");
      activeId = version.id;
      canaryId = null;
    } else {
      if (version.id !== canaryId && (version.id !== activeId || canaryId !== null)) {
        throw new Error("invalid rollback transition in registry");
      }
      statuses.set(version.id, "retired");
      if (version.parentId !== null) statuses.set(version.parentId, "active");
      activeId = version.parentId;
      canaryId = null;
    }
  }
  return { activeId, canaryId, statuses };
}

function loadRegistryRaw(storePath: string): EvolutionRegistry {
  const rp = registryPath(storePath);
  if (!existsSync(rp)) {
    return { schemaVersion: 1, activeId: null, canaryId: null, versions: [], events: [] };
  }

  let parsed: unknown;
  try { parsed = readEvolutionArtifact(rp); } catch (err) {
    throw new Error(`evolution registry is not readable: ${rp}: ${(err as Error).message}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error(`evolution registry must be a JSON object: ${rp}`);
  }
  const reg = parsed as Record<string, unknown>;
  if (reg.schemaVersion !== 1) {
    throw new Error(`unknown evolution registry schema version: ${rp}`);
  }

  const registry = reg as unknown as EvolutionRegistry;

  // Validate versions array
  if (!Array.isArray(registry.versions)) {
    throw new Error(`evolution registry has no versions array: ${rp}`);
  }
  const seenIds = new Set<string>();
  for (const v of registry.versions) {
    if (typeof v.id !== "string" || v.id.length === 0) {
      throw new Error(`version with empty or non-string id in registry: ${rp}`);
    }
    if (seenIds.has(v.id)) throw new Error(`duplicate version id in registry: ${v.id}`);
    if (v.alternativeParentId !== undefined
      && (typeof v.alternativeParentId !== "string" || !seenIds.has(v.alternativeParentId))) {
      throw new Error(`alternative parent must reference an earlier retained version: ${v.id}`);
    }
    seenIds.add(v.id);
    if (!["baseline", "candidate", "canary", "active", "retired"].includes(v.status)) {
      throw new Error(`invalid version status "${v.status}" for ${v.id}`);
    }
  }

  // Validate events array and hash chain
  if (!Array.isArray(registry.events)) {
    throw new Error(`evolution registry has no events array: ${rp}`);
  }
  let previousDigest: string | null = null;
  for (const [seq, evt] of registry.events.entries()) {
    if (evt.sequence !== seq) {
      throw new Error(`registry event sequence mismatch at ${seq}: expected ${seq}, got ${evt.sequence}`);
    }
    if (typeof evt.digest !== "string" || !isSha256Digest(evt.digest)) {
      throw new Error(`invalid digest in registry event at sequence ${seq}`);
    }
    if (evt.previousDigest !== previousDigest) {
      throw new Error(`broken hash chain in registry at sequence ${seq}`);
    }
    if (!["recorded", "canary_started", "promoted", "rolled_back"].includes(evt.type)) {
      throw new Error(`invalid event type "${evt.type}" at sequence ${seq}`);
    }
    const unsigned = { sequence: evt.sequence, at: evt.at, type: evt.type, versionId: evt.versionId, reason: evt.reason, previousDigest: evt.previousDigest };
    const expected = evolutionDigest(unsigned);
    if (evt.digest !== expected) {
      throw new Error(`tampered registry event at sequence ${seq}: digest mismatch`);
    }
    previousDigest = evt.digest;
  }

  const derived = deriveVersionStates(registry);
  if (registry.activeId !== derived.activeId || registry.canaryId !== derived.canaryId) {
    throw new Error("registry activeId/canaryId disagree with event chain");
  }
  for (const version of registry.versions) {
    if (version.status !== derived.statuses.get(version.id)) throw new Error(`version ${version.id} status disagrees with event chain`);
  }

  return registry;
}

function makeRegistryEvent(
  registry: EvolutionRegistry,
  type: EvolutionRegistryEvent["type"],
  versionId: string,
  reason: string,
): EvolutionRegistryEvent {
  const previousDigest = registry.events.length === 0 ? null : registry.events[registry.events.length - 1]!.digest;
  const unsigned = { sequence: registry.events.length, at: new Date().toISOString(), type, versionId, reason, previousDigest };
  return { ...unsigned, digest: evolutionDigest(unsigned) };
}

// ---------------------------------------------------------------------------
// Snapshot files computation
// ---------------------------------------------------------------------------

function* resolveSourceFiles(
  sourceRoot: string,
  relPath: string,
  storePath: string | null,
  maxBytes: number,
): Generator<string> {
  const absPath = resolve(sourceRoot, relPath);
  const st = lstatSync(absPath);
  if (!st.isDirectory()) {
    validateSnapshotPath(absPath, sourceRoot, storePath, maxBytes);
    yield absPath;
    return;
  }
  const entries = readdirSync(absPath, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (entry.name === "." || entry.name === "..") continue;
    const child = join(absPath, entry.name);
    const childRel = relative(sourceRoot, child);
    try {
      if (entry.isDirectory()) {
        yield* resolveSourceFiles(sourceRoot, childRel, storePath, maxBytes);
      } else if (entry.isFile() && !entry.isSymbolicLink()) {
        validateSnapshotPath(child, sourceRoot, storePath, maxBytes);
        yield child;
      } else {
        throw new Error(`snapshot source contains a symlink or special file: ${child}`);
      }
    } catch (err) {
      throw new Error(`snapshot source path error at ${childRel}: ${(err as Error).message}`);
    }
  }
}

interface IndexedFiles { sourceAbsPaths: string[]; files: EvolutionFile[] }

function indexSourceFiles(sourceRoot: string, sourcePaths: string[], storePath: string, maxSourceBytes: number): IndexedFiles {
  const absPaths: string[] = [];
  const files: EvolutionFile[] = [];
  const seen = new Set<string>();
  let totalBytes = 0;
  for (const relPath of sourcePaths) {
    for (const absPath of resolveSourceFiles(sourceRoot, relPath, storePath, maxSourceBytes)) {
      if (seen.has(absPath)) continue;
      seen.add(absPath);
      const st = statSync(absPath);
      totalBytes += st.size;
      if (totalBytes > maxSourceBytes) throw new Error(`total snapshot source exceeds maxSourceBytes (${totalBytes} > ${maxSourceBytes})`);
      absPaths.push(absPath);
      files.push({ path: relative(sourceRoot, absPath), digest: fileDigest(absPath), bytes: st.size });
    }
  }
  return { sourceAbsPaths: absPaths, files };
}

function computeSnapshotDigest(files: EvolutionFile[]): string {
  return evolutionDigest(files);
}

/** Seal all snapshot subtree entries: dirs 0555 (world-traversable), files 0444. */
async function sealSnapshotDir(storePath: string, id: string): Promise<void> {
  const snapRoot = snapshotDir(storePath, id);
  async function seal(absDir: string): Promise<void> {
    for (const entry of await readdir(absDir, { withFileTypes: true })) {
      const child = join(absDir, entry.name);
      if (entry.isDirectory()) { await seal(child); await chmod(child, 0o555); }
      else if (entry.isFile()) { await chmod(child, 0o444); }
    }
  }
  await seal(snapRoot);
  await chmod(snapRoot, 0o555);
}

async function copySnapshotFiles(sourceRoot: string, absPaths: string[], storePath: string, id: string): Promise<void> {
  const destDir = snapshotDir(storePath, id);
  await mkdir(destDir, { recursive: true });
  for (const absPath of absPaths) {
    const rel = relative(sourceRoot, absPath);
    const dest = join(destDir, rel);
    await mkdir(dirname(dest), { recursive: true });
    await copyFile(absPath, dest, fsConst.COPYFILE_FICLONE);
  }
  await sealSnapshotDir(storePath, id);
  // Restore execute bits for originally-executable files
  for (const absPath of absPaths) {
    const rel = relative(sourceRoot, absPath);
    const dest = join(destDir, rel);
    if ((statSync(absPath).mode & 0o111) !== 0) {
      await chmod(dest, 0o555);
    }
  }
}

// ---------------------------------------------------------------------------
// Edit application helpers
// ---------------------------------------------------------------------------

function applyEdits(base: EvolutionSnapshot, edits: EvolutionEdit[], config: EvolutionConfig): { files: EvolutionFile[] } {
  const baseFiles = new Map<string, EvolutionFile>();
  for (const f of base.files) baseFiles.set(f.path, f);
  const seen = new Set<string>();
  let totalChangedBytes = 0;
  const addedFiles: EvolutionFile[] = [];

  for (const edit of edits) {
    validateEditPath(edit.path, config);
    if (seen.has(edit.path)) throw new Error(`duplicate edit path: ${edit.path}`);
    seen.add(edit.path);

    const baseEntry = baseFiles.get(edit.path);
    if (edit.content === null) {
      if (!baseEntry) throw new Error(`edit deletes non-existent file: ${edit.path}`);
      if (edit.beforeDigest !== baseEntry.digest) throw new Error(`beforeDigest mismatch for deletion of ${edit.path}: expected ${baseEntry.digest}, got ${edit.beforeDigest}`);
      baseFiles.delete(edit.path);
      totalChangedBytes += baseEntry.bytes;
    } else if (baseEntry) {
      if (edit.beforeDigest !== baseEntry.digest) throw new Error(`beforeDigest mismatch for ${edit.path}: expected ${baseEntry.digest}, got ${edit.beforeDigest}`);
      const cb = Buffer.byteLength(edit.content, "utf8");
      totalChangedBytes += cb > baseEntry.bytes ? cb : baseEntry.bytes;
      baseFiles.set(edit.path, { path: edit.path, digest: `sha256:${createHash("sha256").update(edit.content, "utf8").digest("hex")}`, bytes: cb });
    } else {
      if (edit.beforeDigest !== null) throw new Error(`beforeDigest must be null for new file ${edit.path}: got ${edit.beforeDigest}`);
      const extSet = allowedExtensionsForKind(config.kind);
      if (extSet !== null) {
        const ext = edit.path.slice(edit.path.lastIndexOf(".")).toLowerCase();
        if (!extSet[ext]) throw new Error(`new file extension "${ext}" not allowed for kind "${config.kind}": ${edit.path}`);
      }
      const cb = Buffer.byteLength(edit.content, "utf8");
      totalChangedBytes += cb;
      addedFiles.push({ path: edit.path, digest: `sha256:${createHash("sha256").update(edit.content, "utf8").digest("hex")}`, bytes: cb });
    }
  }
  if (totalChangedBytes > config.maxChangedBytes) throw new Error(`total changed bytes ${totalChangedBytes} exceeds maxChangedBytes ${config.maxChangedBytes}`);
  const finalFiles = [...baseFiles.values(), ...addedFiles];
  finalFiles.sort((a, b) => a.path.localeCompare(b.path));
  return { files: finalFiles };
}

async function writeSnapshotFiles(snapshotId: string, base: EvolutionSnapshot, edits: EvolutionEdit[], storePath: string): Promise<void> {
  const destDir = snapshotDir(storePath, snapshotId);
  await mkdir(destDir, { recursive: true });

  // Phase 1: copy base files — they arrive read-only from the sealed base
  const origExecutable = new Set<string>();
  for (const f of base.files) {
    const src = join(base.root, f.path);
    const dest = join(destDir, f.path);
    await mkdir(dirname(dest), { recursive: true });
    if (existsSync(src)) {
      const wasExec = (statSync(src).mode & 0o111) !== 0;
      if (wasExec) origExecutable.add(f.path);
      // Copy then make writable for staging
      await copyFile(src, dest, fsConst.COPYFILE_FICLONE);
      await chmod(dest, 0o600);
    }
  }

  // Phase 2: apply edits (staging — writable)
  for (const edit of edits) {
    const dest = join(destDir, edit.path);
    if (edit.content === null) {
      if (existsSync(dest)) await unlink(dest);
    } else {
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, edit.content, "utf8");
      // New model-written files start writable; sealed below
    }
  }

  // Phase 3: seal read-only, preserve execute bits from original base
  await sealSnapshotDir(storePath, snapshotId);
  for (const f of base.files) {
    if (origExecutable.has(f.path)) {
      const dest = join(destDir, f.path);
      if (existsSync(dest)) await chmod(dest, 0o555);
    }
  }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/** Hash bytes, verify content integrity against stored snapshot metadata. */
export function verifyEvolutionSnapshot(snapshot: EvolutionSnapshot): void {
  if (typeof snapshot.id !== "string" || snapshot.id.length === 0) throw new Error("snapshot id must be a non-empty string");
  if (typeof snapshot.root !== "string" || snapshot.root.length === 0) throw new Error("snapshot root must be a non-empty string");
  if (!isSha256Digest(snapshot.digest)) throw new Error(`invalid snapshot digest format: ${snapshot.digest}`);
  if (!Array.isArray(snapshot.files) || snapshot.files.length === 0) throw new Error("snapshot must contain at least one file");

  const resolvedRoot = resolve(snapshot.root);
  if (realpathSync(resolvedRoot) !== resolvedRoot) throw new Error("snapshot root resolves through a symlink");
  const indexedPaths = new Set<string>();
  for (const f of snapshot.files) {
    if (typeof f.path !== "string" || f.path.length === 0) throw new Error(`invalid file path: ${JSON.stringify(f.path)}`);
    if (indexedPaths.has(f.path)) throw new Error(`duplicate snapshot path: ${f.path}`);
    indexedPaths.add(f.path);
    if (!isSha256Digest(f.digest)) throw new Error(`invalid file digest format for ${f.path}: ${f.digest}`);
    if (!Number.isSafeInteger(f.bytes) || f.bytes < 0) throw new Error(`invalid file size for ${f.path}`);

    const absPath = resolve(snapshot.root, f.path);
    if (!absPath.startsWith(resolvedRoot + sep) && absPath !== resolvedRoot) {
      throw new Error(`file path escapes snapshot root: ${f.path}`);
    }
    if (!existsSync(absPath)) throw new Error(`snapshot file missing: ${absPath}`);
    validateSnapshotPath(absPath, resolvedRoot, null, f.bytes);
    const actualDigest = fileDigest(absPath);
    if (actualDigest !== f.digest) throw new Error(`snapshot file ${f.path} digest mismatch: expected ${f.digest}, got ${actualDigest}`);
    const st = statSync(absPath);
    if (!st.isFile()) throw new Error(`snapshot file is not a regular file: ${absPath}`);
    if (st.size !== f.bytes) throw new Error(`snapshot file ${f.path} size mismatch: expected ${f.bytes}, got ${st.size}`);
  }
  let actualFiles = 0;
  for (const path of resolveSourceFiles(resolvedRoot, ".", null, Number.MAX_SAFE_INTEGER)) {
    if (!indexedPaths.has(relative(resolvedRoot, path))) throw new Error(`unindexed file in snapshot: ${path}`);
    actualFiles++;
  }
  if (actualFiles !== snapshot.files.length) throw new Error("snapshot file index is incomplete");
  const expectedDigest = computeSnapshotDigest(snapshot.files);
  if (expectedDigest !== snapshot.digest) throw new Error(`snapshot digest mismatch: expected ${snapshot.digest}, computed ${expectedDigest}`);
}

/** Strip `sha256:` prefix for filesystem-safe hex-only filenames. */
function configHexDigest(digest: string): string {
  return digest.replace(/^sha256:/, "");
}

// ---------------------------------------------------------------------------
// Shared receipt / provenance validator
// ---------------------------------------------------------------------------

/** Comprehensive receipt validation. Returns the validated receipt on success,
 * throws on any integrity or semantic mismatch. Used by canary, promotion, and
 * external consumers (LearningPromotion).
 *
 * @param storePath - evolution store root
 * @param versionId - candidate/version id in the receipt
 * @param version - the registry EvolutionVersion to cross-check against (nullable for baseline-only checks)
 * @param expectedBaselineDigest - optional expected baseline snapshot digest
 */
export function verifyEvolutionReceipt(
  storePath: string,
  versionId: string,
  version?: EvolutionVersion,
  expectedBaselineDigest?: string,
  canaryTrial?: number,
): EvolutionEvaluation {
  const receipt = loadEvolutionReceipt(storePath, versionId, canaryTrial);
  if (!receipt) throw new Error(`receipt not found for ${versionId}`);

  // candidateId identity
  if (receipt.candidateId !== versionId) {
    throw new Error(`receipt candidateId ${receipt.candidateId} does not match expected ${versionId}`);
  }

  // receiptDigest integrity already verified by loadEvolutionReceipt

  assertPromotableReceipt(receipt, versionId);
  if (version && canaryTrial === undefined && receipt.receiptDigest !== version.receiptDigest) {
    throw new Error(`receipt digest does not match recorded version ${versionId}`);
  }

  // configDigest must match version
  if (version && receipt.configDigest !== version.configDigest) {
    throw new Error(`receipt configDigest ${receipt.configDigest} does not match version configDigest ${version.configDigest}`);
  }

  // candidateDigest must match version snapshot digest
  if (version && receipt.candidateDigest !== version.snapshot.digest) {
    throw new Error(`receipt candidateDigest ${receipt.candidateDigest} does not match version snapshot digest ${version.snapshot.digest}`);
  }

  // baselineDigest check
  if (expectedBaselineDigest !== undefined && receipt.baselineDigest !== expectedBaselineDigest) {
    throw new Error(`receipt baselineDigest ${receipt.baselineDigest} does not match expected ${expectedBaselineDigest}`);
  }

  return receipt;
}

function assertPromotableReceipt(receipt: EvolutionEvaluation, versionId: string): void {
  if (receipt.decision?.candidateId !== versionId
    || !["eligible_for_canary", "requires_human_approval"].includes(receipt.decision.status)
    || !Array.isArray(receipt.decision.checks) || receipt.decision.checks.length === 0
    || receipt.decision.checks.some((check) => check.passed !== true)) {
    throw new Error(`receipt for ${versionId} is rejected or has incomplete promotion checks`);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Copy explicitly selected sourcePaths into a store-owned immutable content-addressed directory. */
export async function snapshotEvolutionSource(config: Pick<EvolutionConfig, "sourceRoot" | "storePath" | "sourcePaths" | "maxSourceBytes">): Promise<EvolutionSnapshot> {
  const { sourceRoot, storePath, sourcePaths, maxSourceBytes } = config;
  for (const d of [snapshotsDir(storePath), receiptsDir(storePath), configsDir(storePath)]) {
    ensureEvolutionDirectory(d);
  }
  const id = randomUUID();
  const { sourceAbsPaths, files } = indexSourceFiles(sourceRoot, sourcePaths, storePath, maxSourceBytes);
  await copySnapshotFiles(sourceRoot, sourceAbsPaths, storePath, id);
  const digest = computeSnapshotDigest(files);
  const snapshot: EvolutionSnapshot = { id, root: snapshotDir(storePath, id), digest, files };
  verifyEvolutionSnapshot(snapshot);
  return snapshot;
}

/** Apply model file edits to a COPY of the baseline snapshot, creating a new candidate. */
export async function createEvolutionCandidate(
  base: EvolutionSnapshot, proposal: EvolutionProposal, config: EvolutionConfig,
): Promise<EvolutionSnapshot> {
  verifyEvolutionSnapshot(base);
  const id = randomUUID();
  const { files } = applyEdits(base, proposal.edits, config);
  const digest = computeSnapshotDigest(files);
  const snapshot: EvolutionSnapshot = { id, root: snapshotDir(config.storePath, id), digest, files };
  await mkdir(snapshotDir(config.storePath, id), { recursive: true });
  await writeSnapshotFiles(id, base, proposal.edits, config.storePath);
  verifyEvolutionSnapshot(snapshot);
  return snapshot;
}

/** Load and validate a registry from disk. Fails closed on tamper/drift. */
export function loadEvolutionRegistry(storePath: string): EvolutionRegistry {
  return loadRegistryRaw(storePath);
}

/**
 * Record a version in the registry with atomic + serialized process-safe lock.
 * Config and evaluation receipt are published via Main artifacts.ts.
 */
export async function recordEvolutionVersion(
  storePath: string, version: EvolutionVersion,
  config?: EvolutionConfig, evaluation?: EvolutionEvaluation, signal?: AbortSignal,
): Promise<void> {
  const unlock = await acquireLock(storePath, signal);
  try {
    const registry = loadRegistryRaw(storePath);
    if (typeof version.id !== "string" || version.id.length === 0) throw new Error("version id must be a non-empty string");
    if (registry.versions.some((v) => v.id === version.id)) throw new Error(`version already exists in registry: ${version.id}`);
    if (version.status !== "baseline" && version.status !== "candidate") throw new Error("new versions must be baseline or candidate");
    if (version.status === "baseline") {
      if (registry.versions.length !== 0 || version.parentId !== null || version.receiptDigest !== null) throw new Error("only the initial version may be a baseline");
    } else if (version.parentId === null || !registry.versions.some((parent) => parent.id === version.parentId)) {
      throw new Error("candidate must reference an existing parent");
    }
    if (version.alternativeParentId !== undefined
      && !registry.versions.some(parent => parent.id === version.alternativeParentId && parent.kind === version.kind)) {
      throw new Error("alternative parent must reference an existing version of the same artifact kind");
    }
    if (config && evolutionDigest(config) !== version.configDigest) throw new Error("recorded config digest mismatch");
    if (evaluation && (evaluation.receiptDigest !== version.receiptDigest || evaluation.candidateId !== version.id
      || evaluation.candidateDigest !== version.snapshot.digest || evaluation.configDigest !== version.configDigest)) {
      throw new Error("recorded evaluation identity mismatch");
    }

    // Publish config via Main's write-once artifact API (hex digest filename)
    if (config) {
      publishEvolutionArtifact(join(configsDir(storePath), `${configHexDigest(version.configDigest)}.json`), config);
    }

    // Publish evaluation receipt via Main's write-once artifact API
    if (evaluation && version.receiptDigest !== null) {
      publishEvolutionArtifact(join(receiptsDir(storePath), `${version.id}.json`), evaluation);
    }

    registry.versions.push(version);
    registry.events.push(makeRegistryEvent(registry, "recorded", version.id, `Recorded version ${version.id} with status ${version.status}`));
    if (registry.activeId === null && version.status === "baseline") {
      registry.activeId = version.id;
    }
    saveRegistryRaw(storePath, registry);
  } finally { unlock(); }
}

/** Start a canary trial. Uses CAS on expectedActiveId. Requires evaluation receipt. */
export async function startEvolutionCanary(
  storePath: string, id: string, expectedActiveId: string | null, signal?: AbortSignal,
): Promise<void> {
  const unlock = await acquireLock(storePath, signal);
  try {
    const registry = loadRegistryRaw(storePath);
    if (registry.activeId !== expectedActiveId) {
      throw new Error(`CAS mismatch for canary start: expected active ${expectedActiveId}, actual ${registry.activeId}`);
    }
    const version = registry.versions.find((v) => v.id === id);
    if (!version) throw new Error(`version not found for canary: ${id}`);
    if (version.status !== "candidate" || registry.canaryId !== null || version.parentId !== registry.activeId) {
      throw new Error(`version ${id} has status ${version.status}; expected candidate or baseline for canary`);
    }
    const baselineId = version.parentId;

    // Comprehensive receipt validation (baseline digest from registry)
    const baselineVersion = baselineId ? registry.versions.find((v) => v.id === baselineId) : undefined;
    verifyEvolutionReceipt(storePath, id, version, baselineVersion?.snapshot.digest);

    // Reject altered code before exposing it as a canary.
    verifyEvolutionSnapshot(version.snapshot);

    const idx = registry.versions.indexOf(version);
    registry.versions[idx] = { ...version, status: "canary" };
    registry.canaryId = id;
    registry.events.push(makeRegistryEvent(registry, "canary_started", id, "Canary trial started"));
    saveRegistryRaw(storePath, registry);
  } finally { unlock(); }
}

/**
 * Promote a canary version to active. Uses CAS on expectedActiveId.
 * canaryTrials is derived from the immutable stored config.
 * Retires the previous active version.
 */
export async function promoteEvolutionVersion(
  storePath: string, id: string, expectedActiveId: string | null, signal?: AbortSignal,
): Promise<void> {
  const unlock = await acquireLock(storePath, signal);
  try {
    const registry = loadRegistryRaw(storePath);
    if (registry.activeId !== expectedActiveId) {
      throw new Error(`CAS mismatch for promotion: expected active ${expectedActiveId}, actual ${registry.activeId}`);
    }
    const version = registry.versions.find((v) => v.id === id);
    if (!version) throw new Error(`version not found for promotion: ${id}`);
    if (version.status !== "canary" || registry.canaryId !== id || version.parentId !== registry.activeId) {
      throw new Error(`version ${id} must be the current canary against the active baseline`);
    }
    const baselineId = version.parentId;

    // Comprehensive receipt validation with baseline digest from registry
    const baselineVersion = baselineId ? registry.versions.find((v) => v.id === baselineId) : undefined;
    verifyEvolutionReceipt(storePath, id, version, baselineVersion?.snapshot.digest);

    // Load config to derive canaryTrials (immutable stored config; fail closed if missing or mismatched)
    const configHex = configHexDigest(version.configDigest);
    const configPath = join(configsDir(storePath), `${configHex}.json`);
    let storedConfig: EvolutionConfig;
    try {
      storedConfig = readEvolutionArtifact(configPath) as EvolutionConfig;
    } catch (err) {
      throw new Error(`cannot promote ${id}: stored config not found or unreadable at ${configPath}: ${(err as Error).message}`);
    }
    const loadedConfigDigest = evolutionDigest(storedConfig);
    if (loadedConfigDigest !== version.configDigest) {
      throw new Error(`stored config digest mismatch for ${id}: loaded ${loadedConfigDigest}, expected ${version.configDigest}`);
    }
    const validatedConfig = parseEvolutionConfig(storedConfig);
    if (validatedConfig.kind !== version.kind || evolutionDigest(validatedConfig) !== version.configDigest) throw new Error("stored config is not the canonical version contract");
    const canaryTrials = validatedConfig.canaryTrials;

    // Verify all canary trial proofs exist and are valid
    for (let i = 0; i < canaryTrials; i++) {
      verifyEvolutionReceipt(storePath, id, version, baselineVersion?.snapshot.digest, i);
    }
    verifyEvolutionSnapshot(version.snapshot);

    // Retire previous active
    const prevActive = registry.versions.find((v) => v.id === registry.activeId);
    if (prevActive && prevActive.id !== version.id) {
      const prevIdx = registry.versions.indexOf(prevActive);
      registry.versions[prevIdx] = { ...prevActive, status: "retired" };
    }

    const idx = registry.versions.indexOf(version);
    registry.versions[idx] = { ...version, status: "active" };
    registry.activeId = id;
    registry.canaryId = null;
    registry.events.push(makeRegistryEvent(registry, "promoted", id, "Promoted to active"));
    saveRegistryRaw(storePath, registry);
  } finally { unlock(); }
}

/** Rollback a version (retire it) and restore parent as active. */
export async function rollbackEvolutionVersion(
  storePath: string, id: string, reason: string, signal?: AbortSignal,
): Promise<void> {
  const unlock = await acquireLock(storePath, signal);
  try {
    const registry = loadRegistryRaw(storePath);
    const version = registry.versions.find((v) => v.id === id);
    if (!version) throw new Error(`version not found for rollback: ${id}`);
    if (version.status !== "active" && version.status !== "canary") {
      throw new Error(`version ${id} has status ${version.status}; expected active or canary for rollback`);
    }
    if (registry.canaryId !== id && (registry.activeId !== id || registry.canaryId !== null)) {
      throw new Error("rollback must retire the current canary, or the active version with no pending canary");
    }
    const rollbackTargetId = version.parentId;
    if (rollbackTargetId !== null && !registry.versions.some((v) => v.id === rollbackTargetId)) {
      throw new Error(`rollback target version ${rollbackTargetId} not found for rollback of ${id}`);
    }

    const idx = registry.versions.indexOf(version);
    registry.versions[idx] = { ...version, status: "retired" };

    if (rollbackTargetId !== null) {
      const parentEntry = registry.versions.find((v) => v.id === rollbackTargetId)!;
      verifyEvolutionSnapshot(parentEntry.snapshot);
      const pIdx = registry.versions.indexOf(parentEntry);
      registry.versions[pIdx] = { ...parentEntry, status: "active" };
      registry.activeId = rollbackTargetId;
    } else {
      registry.activeId = null;
    }
    if (registry.canaryId === id) registry.canaryId = null;

    registry.events.push(makeRegistryEvent(registry, "rolled_back", id, reason));
    saveRegistryRaw(storePath, registry);
  } finally { unlock(); }
}

function readPinnedEvolutionVersion(storePath: string, runId: string): {
  version: EvolutionVersion; parentRunId?: string;
} {
  const pin = readEvolutionArtifact(join(pinsDir(storePath), `${runId}.json`)) as {
    runId: string; versionId: string; versionDigest: string; parentRunId?: string;
  };
  if (!pin || pin.runId !== runId) throw new Error("pin file runId mismatch");
  if (pin.parentRunId !== undefined && (typeof pin.parentRunId !== "string"
    || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(pin.parentRunId))) throw new Error("invalid stored parent run id");
  const registry = loadRegistryRaw(storePath);
  const version = registry.versions.find((entry) => entry.id === pin.versionId);
  if (!version) throw new Error(`pinned version ${pin.versionId} not found in registry`);
  if (pin.versionDigest !== version.snapshot.digest) throw new Error("pinned version digest changed");
  if (version.parentId !== null && !registry.events.some((event) => event.type === "promoted" && event.versionId === version.id)) {
    throw new Error("worker pins cannot authorize a version that was never active");
  }
  if (!existsSync(snapshotDir(storePath, version.id))) throw new Error(`snapshot directory missing for pinned version ${version.id}`);
  verifyEvolutionSnapshot(version.snapshot);
  if (version.receiptDigest !== null) {
    const parent = registry.versions.find((entry) => entry.id === version.parentId);
    verifyEvolutionReceipt(storePath, version.id, version, parent?.snapshot.digest);
  }
  return { version, ...(pin.parentRunId !== undefined ? { parentRunId: pin.parentRunId } : {}) };
}

/**
 * Pin the active version, or derive a child from an already-existing parent pin.
 * A parent is never created implicitly and cannot select an unpromoted version.
 * Existing bindings remain immutable across promotion, rollback, and replay.
 */
export async function pinEvolutionVersion(
  storePath: string, runId: string, signal?: AbortSignal, parentRunId?: string,
): Promise<EvolutionVersion> {
  signal?.throwIfAborted();
  if (typeof runId !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(runId)) {
    throw new Error(`invalid runId: ${runId}`);
  }
  if (parentRunId !== undefined && (typeof parentRunId !== "string"
    || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(parentRunId) || parentRunId === runId)) {
    throw new Error("invalid parent run id");
  }
  const pinDir = pinsDir(storePath);
  ensureEvolutionDirectory(pinDir);
  const pinPath = join(pinDir, `${runId}.json`);
  if (!existsSync(pinPath)) {
    const unlock = await acquireLock(storePath, signal);
    try {
      if (!existsSync(pinPath)) {
        const registry = loadRegistryRaw(storePath);
        const parent = parentRunId !== undefined ? readPinnedEvolutionVersion(storePath, parentRunId) : undefined;
        const versionId = parent?.version.id ?? registry.activeId;
        if (versionId === null) throw new Error(`no active version to pin for runId ${runId}`);
        const version = registry.versions.find((entry) => entry.id === versionId);
        if (!version) throw new Error("selected pinned version is absent from the registry");
        verifyEvolutionSnapshot(version.snapshot);
        publishEvolutionArtifact(pinPath, {
          runId, versionId, pinnedAt: new Date().toISOString(), versionDigest: version.snapshot.digest,
          ...(parentRunId !== undefined ? { parentRunId } : {}),
        });
      }
    } finally { unlock(); }
  }
  const pinned = readPinnedEvolutionVersion(storePath, runId);
  if (parentRunId !== undefined) {
    const parent = readPinnedEvolutionVersion(storePath, parentRunId);
    if (pinned.parentRunId !== parentRunId || pinned.version.id !== parent.version.id) {
      throw new Error("child run is already bound to a different parent engagement");
    }
  }
  return { ...pinned.version };
}