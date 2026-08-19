import {
  closeSync,
  copyFileSync,
  createReadStream,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeSync,
  fsyncSync,
} from "node:fs";
import { readFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import {
  DEFAULT_JOURNAL_SIDECAR_THRESHOLD_BYTES,
  JOURNAL_SCHEMA_VERSION,
  type JournalArtifact,
  type JournalArtifactInput,
  type JournalArtifactInline,
  type JournalArtifactRef,
  type JournalEntry,
  type JournalEntryInput,
  type JournalPaths,
} from "./types.js";
import { migrateJournalEntry } from "./migrate.js";

export interface JournalWriterOptions {
  runId: string;
  rootDir?: string;
  runDir?: string;
  sidecarThresholdBytes?: number;
  now?: () => Date;
  idFactory?: () => string;
}

export interface JournalLoadOptions {
  runId: string;
  rootDir?: string;
  runDir?: string;
  migrate?: (raw: unknown) => JournalEntry;
}

export interface JournalReplayOptions {
  /** Optional run directory override; defaults to `dirname(path)`. */
  runDir?: string;
  /** Custom migration hook applied before sidecar resolution. */
  migrate?: (raw: unknown) => JournalEntry;
  /**
   * Skip rehydrating sidecar (`ref`) artifacts into inline ones. When true the
   * returned entries are byte-identical to the on-disk journal; sidecar files
   * are not opened. Defaults to false.
   */
  preserveRefs?: boolean;
}

export interface JournalWriter {
  readonly paths: JournalPaths;
  append(entry: JournalEntryInput): JournalEntry;
  load(): JournalEntry[];
}

export function defaultJournalRootDir(): string {
  return join(homedir(), ".pwnkit", "runs");
}

export function resolveJournalPaths(options: { runId: string; rootDir?: string; runDir?: string }): JournalPaths {
  const runDir = options.runDir ?? join(options.rootDir ?? defaultJournalRootDir(), options.runId);
  return {
    runDir,
    journalPath: join(runDir, "journal.jsonl"),
    artifactsDir: join(runDir, "artifacts"),
  };
}

export interface BranchJournalOptions {
  /** Run ID of the source journal to branch from. */
  runId: string;
  /**
   * Zero-based index of the last entry to include in the branch. Entries
   * 0..fromEntry (inclusive) are copied; entries after fromEntry are omitted.
   */
  fromEntry: number;
  /** Optional human-readable label baked into the new run ID. */
  label?: string;
  /** Override the runs root directory (default: `~/.pwnkit/runs`). */
  rootDir?: string;
}

export interface BranchJournalResult {
  /** Newly created run ID. */
  newRunId: string;
  /** Resolved paths for the new branch run directory. */
  paths: JournalPaths;
  /** Number of journal entries copied. */
  entriesCopied: number;
  /** Number of sidecar artifact files copied. */
  artifactsCopied: number;
}

/**
 * Branch a journal: copy entries 0..fromEntry (inclusive) from an existing run
 * into a brand-new run directory. Sidecar artifacts referenced by the copied
 * entries are duplicated into the new run's `artifacts/` directory so the two
 * runs share no mutable state.
 *
 * The parent journal is never modified.
 */
export function branchJournal(options: BranchJournalOptions): BranchJournalResult {
  const { runId, fromEntry, label, rootDir } = options;
  const effectiveRootDir = rootDir ?? defaultJournalRootDir();

  // Resolve source paths and load entries.
  const srcPaths = resolveJournalPaths({ runId, rootDir: effectiveRootDir });
  if (!existsSync(srcPaths.journalPath)) {
    throw new Error(`Source journal not found: ${srcPaths.journalPath}`);
  }
  const allEntries = loadJournalSync({ runId, rootDir: effectiveRootDir });
  if (allEntries.length === 0) {
    throw new Error(`Source journal is empty: ${srcPaths.journalPath}`);
  }
  if (fromEntry < 0 || fromEntry >= allEntries.length) {
    throw new Error(
      `fromEntry ${fromEntry} is out of range; journal has ${allEntries.length} entries (valid: 0..${allEntries.length - 1})`,
    );
  }

  // Generate a new run ID.
  const suffix = label ? `-${label}` : "";
  const newRunId = `${runId}-branch${suffix}-${randomUUID().slice(0, 8)}`;

  // Set up destination directories.
  const dstPaths = resolveJournalPaths({ runId: newRunId, rootDir: effectiveRootDir });
  mkdirSync(dstPaths.runDir, { recursive: true, mode: 0o700 });
  mkdirSync(dstPaths.artifactsDir, { recursive: true, mode: 0o700 });

  // Copy entries 0..fromEntry (inclusive) to the new journal.
  const entriesToCopy = allEntries.slice(0, fromEntry + 1);
  // Rewrite runId in each entry so the branch journal is self-consistent.
  const rewrittenEntries = entriesToCopy.map((entry) => ({
    ...entry,
    runId: newRunId,
  }));

  // Write all entries to the new journal.
  const lines = rewrittenEntries.map((entry) => JSON.stringify(entry)).join("\n") + "\n";
  const fd = openSync(dstPaths.journalPath, "w", 0o600);
  try {
    writeSync(fd, Buffer.from(lines, "utf8"));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }

  // Collect sidecar artifact refs from the copied entries and copy them.
  const refsToCopy = new Set<string>();
  for (const entry of entriesToCopy) {
    if (!entry.artifacts) continue;
    for (const artifact of entry.artifacts) {
      if (artifact.kind === "ref") {
        refsToCopy.add(artifact.ref);
      }
    }
  }

  let artifactsCopied = 0;
  for (const ref of refsToCopy) {
    const srcPath = join(srcPaths.runDir, ref);
    const dstPath = join(dstPaths.runDir, ref);
    if (existsSync(srcPath)) {
      mkdirSync(dirname(dstPath), { recursive: true, mode: 0o700 });
      copyFileSync(srcPath, dstPath);
      artifactsCopied += 1;
    }
  }

  fsyncDir(dirname(dstPaths.runDir));

  return {
    newRunId,
    paths: dstPaths,
    entriesCopied: entriesToCopy.length,
    artifactsCopied,
  };
}

export function createJournalWriter(options: JournalWriterOptions): JournalWriter {
  return new FileJournalWriter(options);
}

/**
 * Read a journal from a JSONL file on disk and rehydrate sidecar artifact
 * references into inline artifacts so callers see complete `JournalEntry`s.
 *
 * Round-trip semantics: the returned entries are equivalent to what the
 * writer materialized (small artifacts kept inline, large ones spilled to
 * `<runDir>/artifacts/` and stored as `ref` entries). Pass `preserveRefs` to
 * skip sidecar loading and get the on-disk shape verbatim.
 */
export function loadJournal(path: string, options?: JournalReplayOptions): Promise<JournalEntry[]>;
/**
 * Read a journal by run id from the standard runs root (or an override).
 * Returns entries synchronously without resolving sidecar artifacts.
 */
export function loadJournal(options: JournalLoadOptions): JournalEntry[];
export function loadJournal(
  pathOrOptions: string | JournalLoadOptions,
  pathOptions?: JournalReplayOptions,
): JournalEntry[] | Promise<JournalEntry[]> {
  if (typeof pathOrOptions === "string") {
    return loadJournalFromPath(pathOrOptions, pathOptions);
  }
  return loadJournalSync(pathOrOptions);
}

export async function* streamJournal(
  path: string,
  options: JournalReplayOptions = {},
): AsyncGenerator<JournalEntry> {
  if (!existsSync(path)) return;

  const migrate = options.migrate ?? migrateJournalEntry;
  const runDir = options.runDir ?? dirname(path);
  const stream = createReadStream(path, { encoding: "utf8" });
  let buffer = "";
  let lineNumber = 0;

  try {
    for await (const chunk of stream) {
      buffer += String(chunk);

      let newline = buffer.indexOf("\n");
      while (newline !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        lineNumber += 1;

        const entry = parseCompleteJournalLine(line, lineNumber, migrate);
        if (entry) {
          yield options.preserveRefs ? entry : await rehydrateEntryArtifacts(entry, runDir);
        }

        newline = buffer.indexOf("\n");
      }
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    if (code === "ENOENT" && lineNumber === 0 && !buffer) return;
    throw err;
  }

  if (!buffer.trim()) return;

  try {
    const entry = migrate(JSON.parse(buffer));
    yield options.preserveRefs ? entry : await rehydrateEntryArtifacts(entry, runDir);
  } catch {
    // Ignore the final unterminated line so a crash mid-write does not make
    // replay unusable. Complete malformed lines still throw above.
  }
}

function loadJournalSync(options: JournalLoadOptions): JournalEntry[] {
  const paths = resolveJournalPaths(options);
  if (!existsSync(paths.journalPath)) return [];

  const text = readFileSync(paths.journalPath, "utf8");
  return parseJournalText(text, options.migrate ?? migrateJournalEntry);
}

async function loadJournalFromPath(
  path: string,
  options: JournalReplayOptions = {},
): Promise<JournalEntry[]> {
  const entries: JournalEntry[] = [];
  for await (const entry of streamJournal(path, options)) {
    entries.push(entry);
  }
  return entries;
}

function parseJournalText(
  text: string,
  migrate: (raw: unknown) => JournalEntry,
): JournalEntry[] {
  const lines = text.split("\n");
  const entries: JournalEntry[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;

    try {
      entries.push(migrate(JSON.parse(line)));
    } catch (err) {
      const isTrailingLine = lines.slice(index + 1).every((rest) => rest.trim() === "");
      const lineWasTerminated = index < lines.length - 1;
      if (isTrailingLine && !lineWasTerminated) break;
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Invalid journal line ${index + 1}: ${msg}`);
    }
  }

  return entries;
}

function parseCompleteJournalLine(
  line: string,
  lineNumber: number,
  migrate: (raw: unknown) => JournalEntry,
): JournalEntry | undefined {
  if (!line.trim()) return undefined;

  try {
    return migrate(JSON.parse(line));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid journal line ${lineNumber}: ${msg}`);
  }
}

async function rehydrateEntryArtifacts(entry: JournalEntry, runDir: string): Promise<JournalEntry> {
  const artifacts = entry.artifacts;
  if (!artifacts || artifacts.length === 0) return entry;

  const resolved = await Promise.all(
    artifacts.map((artifact) =>
      artifact.kind === "ref" ? rehydrateRefArtifact(artifact, runDir) : artifact,
    ),
  );

  return { ...entry, artifacts: resolved } as JournalEntry;
}

async function rehydrateRefArtifact(
  artifact: JournalArtifactRef,
  runDir: string,
): Promise<JournalArtifactInline> {
  const sidecarPath = resolveSidecarPath(runDir, artifact.ref);
  let bytes: Buffer;
  try {
    bytes = await readFile(sidecarPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    if (code === "ENOENT") {
      throw new Error(`Journal sidecar artifact missing: ${artifact.ref}`);
    }
    throw err;
  }

  const encoding: JournalArtifactInline["encoding"] =
    artifact.mediaType && !artifact.mediaType.startsWith("text/") && !artifact.mediaType.includes("json")
      ? "base64"
      : "utf8";

  const inline: JournalArtifactInline = {
    kind: "inline",
    ...(artifact.name ? { name: artifact.name } : {}),
    ...(artifact.mediaType ? { mediaType: artifact.mediaType } : {}),
    content: encoding === "base64" ? bytes.toString("base64") : bytes.toString("utf8"),
    encoding,
    sha256: artifact.sha256,
    size: artifact.size,
  };
  return inline;
}

function resolveSidecarPath(runDir: string, ref: string): string {
  const root = resolve(runDir);
  const resolved = resolve(root, ref);
  if (resolved !== root && !resolved.startsWith(`${root}${sep}`)) {
    throw new Error(`Journal artifact ref escapes run directory: ${ref}`);
  }
  return resolved;
}

class FileJournalWriter implements JournalWriter {
  readonly paths: JournalPaths;
  private readonly runId: string;
  private readonly sidecarThresholdBytes: number;
  private readonly now: () => Date;
  private readonly idFactory: () => string;
  /** Next monotonic seq to assign. Seeded from any pre-existing journal so
   *  resumed / branched runs continue the numbering rather than restarting. */
  private nextSeq: number;

  constructor(options: JournalWriterOptions) {
    this.runId = options.runId;
    this.paths = resolveJournalPaths(options);
    this.sidecarThresholdBytes = options.sidecarThresholdBytes ?? DEFAULT_JOURNAL_SIDECAR_THRESHOLD_BYTES;
    this.now = options.now ?? (() => new Date());
    this.idFactory = options.idFactory ?? randomUUID;
    mkdirSync(this.paths.runDir, { recursive: true, mode: 0o700 });
    mkdirSync(this.paths.artifactsDir, { recursive: true, mode: 0o700 });
    fsyncDir(dirname(this.paths.runDir));
    this.nextSeq = seedNextSeq(this.paths.journalPath);
  }

  append(input: JournalEntryInput): JournalEntry {
    const id = input.id ?? this.idFactory();
    const timestamp = input.timestamp ?? this.now().toISOString();
    const artifacts = input.artifacts
      ? materializeArtifacts(this.paths, input.artifacts, this.sidecarThresholdBytes)
      : undefined;
    // Honour a caller-supplied seq (replay/branch tooling) but never let it
    // move the counter backwards; otherwise assign the next monotonic value.
    const seq = input.seq ?? this.nextSeq;
    this.nextSeq = Math.max(this.nextSeq, seq) + 1;

    const { artifacts: _inputArtifacts, id: _inputId, timestamp: _inputTimestamp, seq: _inputSeq, ...rest } = input;
    const entry = {
      schemaVersion: JOURNAL_SCHEMA_VERSION,
      id,
      runId: this.runId,
      seq,
      timestamp,
      ...rest,
      ...(artifacts && artifacts.length > 0 ? { artifacts } : {}),
    } as JournalEntry;

    atomicAppendJsonLine(this.paths.journalPath, entry);
    return entry;
  }

  load(): JournalEntry[] {
    return loadJournal({ runId: this.runId, runDir: this.paths.runDir });
  }
}

/**
 * Determine the next monotonic seq for a (possibly pre-existing) journal so a
 * resumed or branched run continues numbering rather than colliding with
 * already-written entries.
 *
 * - No file / empty file → 0.
 * - Entries carrying `seq` → max(seq) + 1.
 * - Legacy v1 entries without `seq` → entry count (file order is the order),
 *   which is also the seq the writer would have assigned had it been present.
 *
 * Best-effort: a corrupt/half-written journal must not crash writer
 * construction, so any parse failure falls back to a line count.
 */
function seedNextSeq(journalPath: string): number {
  if (!existsSync(journalPath)) return 0;
  let text: string;
  try {
    text = readFileSync(journalPath, "utf8");
  } catch {
    return 0;
  }
  const lines = text.split("\n").filter((line) => line.trim() !== "");
  if (lines.length === 0) return 0;

  let maxSeq = -1;
  let sawSeq = false;
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as { seq?: unknown };
      if (typeof parsed.seq === "number" && Number.isFinite(parsed.seq)) {
        sawSeq = true;
        if (parsed.seq > maxSeq) maxSeq = parsed.seq;
      }
    } catch {
      // Ignore unparseable (e.g. trailing half-written) lines; they still
      // occupy a slot so the line-count fallback below stays monotonic.
    }
  }

  return sawSeq ? maxSeq + 1 : lines.length;
}

function materializeArtifacts(
  paths: JournalPaths,
  artifacts: JournalArtifactInput[],
  thresholdBytes: number,
): JournalArtifact[] {
  return artifacts.map((artifact) => {
    const bytes = artifact.content instanceof Uint8Array
      ? Buffer.from(artifact.content)
      : Buffer.from(artifact.content, "utf8");
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const size = bytes.byteLength;

    if (artifact.forceSidecar || size > thresholdBytes) {
      const ext = sanitizeExtension(artifact.ext ?? inferExtension(artifact));
      const filename = `${sha256}.${ext}`;
      const absPath = join(paths.artifactsDir, filename);
      atomicWriteFile(absPath, bytes);
      const ref: JournalArtifactRef = {
        kind: "ref",
        ...(artifact.name ? { name: artifact.name } : {}),
        ...(artifact.mediaType ? { mediaType: artifact.mediaType } : {}),
        ref: `artifacts/${filename}`,
        sha256,
        size,
      };
      return ref;
    }

    const binary = artifact.content instanceof Uint8Array;
    const inline: JournalArtifactInline = {
      kind: "inline",
      ...(artifact.name ? { name: artifact.name } : {}),
      ...(artifact.mediaType ? { mediaType: artifact.mediaType } : {}),
      content: binary ? bytes.toString("base64") : bytes.toString("utf8"),
      encoding: binary ? "base64" : "utf8",
      sha256,
      size,
    };
    return inline;
  });
}

function inferExtension(artifact: JournalArtifactInput): string {
  if (artifact.mediaType?.includes("json")) return "json";
  if (artifact.mediaType?.startsWith("text/")) return "txt";
  return typeof artifact.content === "string" ? "txt" : "bin";
}

function sanitizeExtension(ext: string): string {
  const cleaned = ext.replace(/^\.+/, "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 16);
  return cleaned || "bin";
}

// Linux PIPE_BUF — the threshold below which POSIX guarantees `write(2)` on
// an `O_APPEND` fd is atomic against concurrent writers. macOS uses a much
// smaller 512-byte PIPE_BUF, but pwnkit agents run primarily on Linux, and
// the test target for concurrent journal correctness is Linux. We warn at
// the Linux ceiling so operators notice when a line crosses into "not
// atomic anywhere" territory.
const LINUX_PIPE_BUF = 4096;

/**
 * Append a JSONL entry using `O_APPEND` + `fsync`. Linear (O(N)) cumulative
 * I/O versus the prior read-concat-temp-rename scheme that was O(N²) in
 * journal length (closes #415).
 *
 * Atomicity: POSIX guarantees `write(2)` on an `O_APPEND` fd is atomic for
 * payloads up to `PIPE_BUF` (4096 on Linux, 512 on macOS). Concurrent writers
 * cannot interleave bytes within a single line below that threshold.
 *
 * Large artifact payloads cannot trip this because the writer sidecars
 * anything over `sidecarThresholdBytes` (32 KiB default) into `artifacts/`,
 * leaving only a small `ref` in the journal line. The metadata-only line we
 * emit here is comfortably below 4 KiB in practice; we still emit a
 * `process.emitWarning` if a line crosses the Linux PIPE_BUF threshold so
 * operators investigating unexpected payload growth get a clear signal.
 */
function atomicAppendJsonLine(path: string, entry: JournalEntry): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const line = JSON.stringify(entry) + "\n";
  const bytes = Buffer.from(line, "utf8");

  if (bytes.byteLength > LINUX_PIPE_BUF) {
    process.emitWarning(
      `journal line ${bytes.byteLength}B exceeds PIPE_BUF (${LINUX_PIPE_BUF}B); ` +
        `concurrent writers may interleave. Consider forcing the artifact to a sidecar.`,
      { code: "PWNKIT_JOURNAL_LINE_TOO_LARGE", type: "Warning" },
    );
  }

  const fd = openSync(path, "a", 0o600);
  try {
    writeSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function atomicWriteFile(path: string, data: string | Uint8Array): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.${Date.now()}-${randomUUID()}.tmp`);
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  fsyncDir(dir);
}

function fsyncDir(dir: string): void {
  try {
    if (!existsSync(dir) || !statSync(dir).isDirectory()) return;
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    // Some platforms/filesystems do not support directory fsync. The file
    // itself is still fsynced; directory fsync is a best-effort durability bump.
  }
}
