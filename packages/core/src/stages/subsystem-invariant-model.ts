/**
 * Cold-start whole-subsystem invariant modeling — pwnkit's THIRD discovery axis
 * (the SEEDLESS one). Variant-hunt needs a fix diff to chase; invariant-candidates
 * (its sibling) fuses model-build and violation-hunt into ONE LLM turn, so the
 * "where's the bug" step is still the model guessing. This axis SPLITS those two
 * steps on purpose, and that split is the whole point:
 *
 *   subsystem source ──LLM (ONCE)──▶ InvariantModel {per-object lock/refcount/
 *                                      lifecycle/init-order}  ──stored as JSON──┐
 *                                                                               │ durable,
 *                                                                               │ re-checkable
 *                                    ┌──────────────────────────────────────────┘
 *                                    ▼
 *              InvariantModel ──DETERMINISTIC checker (NO LLM)──▶ InvariantViolation[]
 *                    (tree-sitter-c AST + intra-procedural lock-set / reaching-free
 *                     dataflow over a per-function CFG — see {@link ./c-dataflow.ts})
 *                                    │
 *                                    ▼  map to sites
 *              HuntCandidate[] ──runHuntScan(composeGate(skeptic, prover, [oracle]))──▶ confirmed, ranked
 *
 * WHY the split matters (the compounding property): the model is a STORED ARTIFACT.
 * Build it once for a subsystem; re-run the deterministic checker against every new
 * revision of that subsystem for free (no LLM). A new commit that starts touching a
 * guarded field without its lock is caught by re-checking the SAME model — the model
 * is the reusable asset, the checker is a pure function. Contrast the sibling
 * invariant-candidates path, where every hunt re-pays the full LLM reasoning cost and
 * nothing is stored to re-check.
 *
 * HONEST SCOPE (read this before trusting a violation): the deterministic checker is
 * REAL intra-procedural dataflow ({@link findViolationsDataflow} in `c-dataflow.ts`):
 * a tree-sitter-c AST, a per-function basic-block CFG, a lock-set MUST-analysis
 * (meet = intersection) that knows "is L held AT the program point where F is read"
 * (not "somewhere in the body"), and a reaching-free MAY-analysis (meet = union) that
 * makes UAF path-sensitive (a free on a returning error branch does NOT reach a use
 * on the success branch). Locks resolve to the STRUCT FIELD (receiver expression +
 * field), so cross-function variable naming does not break the check. It is still
 * INTRA-procedural: a caller-held lock or a get/put split across helpers is NOT
 * resolved (no call graph), and it has no points-to/alias analysis (two names for the
 * same object are distinct). Those residual cases still surface as candidates the
 * downstream skeptic+prover gate confirms — but at a FRACTION of the old token-level
 * finder's false-positive volume. The legacy token-level checker is retained as
 * {@link findInvariantViolationsTokenLevel} for A/B comparison. It only emits a
 * violation it can point at a concrete `file:line` for.
 */

import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, posix, relative, resolve, sep, win32 } from "node:path";
import type { RuntimeMode } from "@pwnkit/shared";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import { findViolationsDataflow } from "./c-dataflow.js";
import {
  composeGate,
  makeSkepticVerifier,
  runHuntScan,
  type HuntBrief,
  type HuntCandidate,
  type HuntScanResult,
  type HuntVerifier,
} from "./hunt-scan.js";

// ── The stored invariant model (the compounding, re-checkable artifact) ────────

/** Current model schema version — bumped when the shape changes so a stored model can be migrated / rejected. */
export const INVARIANT_MODEL_VERSION = 1 as const;

/**
 * Lock discipline for one object: which lock guards which fields, and the
 * acquire-call tokens that count as "holding" it. `lock` is the token as it
 * appears at the acquire SITE (e.g. `"llcp_devices_lock"`, `"local->sockets.lock"`,
 * `"sk->sk_lock.slock"`) — the checker looks for `<acquireFn>(&?<lock>)` in a
 * function body to decide the lock is held there.
 */
export interface LockRule {
  /** The lock token as written at the acquire site (with or without a leading `&`). */
  lock: string;
  /** Struct-field accessors this lock guards, as written after `->`/`.` (e.g. `["state", "remote_miu"]`). */
  guardedFields: string[];
  /**
   * Acquire-call function tokens that establish this lock is held (e.g.
   * `["spin_lock", "spin_lock_bh", "mutex_lock"]`). Optional — when omitted the
   * checker falls back to {@link DEFAULT_ACQUIRE_FNS}.
   */
  acquireFns?: string[];
}

/** Refcount balance for one object: the get/put call tokens that must pair. */
export interface RefcountRule {
  /** Human name of the refcount (e.g. `"nfc_llcp_local ref"`). */
  name: string;
  /** The acquire/get call token (e.g. `"nfc_llcp_local_get"`, `"sock_hold"`). */
  getFn: string;
  /** The release/put call token (e.g. `"nfc_llcp_local_put"`, `"sock_put"`). */
  putFn: string;
}

/** Lifetime rule: a free/release call after which the object variable must not be used. */
export interface LifecycleRule {
  /**
   * The free/release call token after which use is illegal (e.g. `"kfree"`,
   * `"nfc_llcp_local_put"`, `"sock_put"`). The checker reads the FIRST argument
   * of the call as the freed variable and flags later uses of that same
   * identifier in the same function.
   */
  freeFn: string;
  /** Human note on what this frees (provenance only). */
  note?: string;
}

/** The invariant model for one key object in the subsystem. */
export interface InvariantObjectModel {
  /** The struct/object this models (e.g. `"struct nfc_llcp_local"`). */
  object: string;
  /** Where it's allocated (function name; provenance only). */
  allocSite?: string;
  /** Where it's freed (function name; provenance only). */
  freeSite?: string;
  /** Lock discipline: which lock guards which fields. */
  lockRules: LockRule[];
  /** Refcount balance: get/put pairings. */
  refcountRules: RefcountRule[];
  /** Lifetime rules: free tokens after which use is illegal. */
  lifecycleRules: LifecycleRule[];
  /** Init-order requirements: fields that must be set before first use (provenance/notes). */
  initOrder?: string[];
}

/**
 * The durable, re-checkable invariant model for a subsystem. Serialized to a JSON
 * artifact ({@link storeInvariantModel}) so the deterministic checker can be re-run
 * against future revisions of the same subsystem without another LLM call.
 */
export interface InvariantModel {
  /** Schema version — {@link INVARIANT_MODEL_VERSION} at build time. */
  modelVersion: number;
  /** Subsystem label (e.g. `"net/nfc/llcp"`). */
  subsystem: string;
  /** The repo-relative files this model was built from. */
  subsystemFiles: string[];
  /** The per-object invariant models. */
  objects: InvariantObjectModel[];
  /** ISO timestamp of the model build (provenance / staleness). */
  builtAt: string;
  /** Free-form notes from the model build (provenance). */
  notes?: string;
}

// ── Deterministic violation output ─────────────────────────────────────────────

export type ViolationKind =
  /** A guarded field is accessed in a function that never acquires its guarding lock. */
  | "unlocked-field-access"
  /** A variable is used AFTER it is passed to a free/release call, in the same function. */
  | "use-after-free-order"
  /** A function calls a put/release with no matching get/acquire (double-put/underflow smell). */
  | "refcount-imbalance";

/** One deterministically-found candidate violation of the stored model. */
export interface InvariantViolation {
  kind: ViolationKind;
  /** The modeled object whose invariant this violates. */
  object: string;
  /** Repo-relative file the offending access lives in. */
  file: string;
  /** 1-based line of the offending access. */
  line: number;
  /** The enclosing function (best-effort, from the brace-scoped splitter). */
  functionName: string;
  /** A concrete restatement of the specific invariant this violates. */
  invariant: string;
  /** Human-readable detail citing the model rule + the code evidence. */
  detail: string;
}

// ── Model-build (LLM, once) ────────────────────────────────────────────────────

export interface BuildModelInput {
  /** Local source tree the subsystem files live under. */
  sourceRoot: string;
  /** Subsystem label for the stored artifact (e.g. `"net/nfc/llcp"`). */
  subsystem: string;
  /** The subsystem's key source files (canonical repo-relative paths under `sourceRoot`). */
  subsystemFiles: string[];
  runtime: RuntimeMode;
  model?: string;
  /** Chars of source sent to the model per file (default 24000; clipped with a marker). */
  maxCharsPerFile?: number;
  log?: (msg: string) => void;
}

const clip = (s: string, n: number) =>
  s.length > n ? s.slice(0, n) + `\n...[truncated ${s.length - n} chars]` : s;

function pathIsWithin(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Resolve an existing, canonical repo-relative path beneath sourceRoot.
 * Both lexical traversal and symlink escapes are rejected. Backslashes are
 * treated as separators on every host so a path cannot become unsafe only when
 * the same scan runs on Windows.
 */
export function resolveContainedSourcePath(sourceRoot: string, relativePath: string): string | null {
  const normalized = relativePath.replaceAll("\\", "/");
  if (
    !normalized ||
    normalized.includes("\0") ||
    posix.isAbsolute(normalized) ||
    win32.isAbsolute(normalized) ||
    /^[A-Za-z]:/.test(normalized)
  ) return null;
  const parts = normalized.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) return null;

  try {
    const rootAbs = resolve(sourceRoot);
    const candidateAbs = resolve(rootAbs, ...parts);
    if (!pathIsWithin(rootAbs, candidateAbs)) return null;
    const rootReal = realpathSync(rootAbs);
    const candidateReal = realpathSync(candidateAbs);
    return pathIsWithin(rootReal, candidateReal) ? candidateReal : null;
  } catch {
    return null;
  }
}

function readSource(sourceRoot: string, file: string): string | null {
  const path = resolveContainedSourcePath(sourceRoot, file);
  if (!path) return null;
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

const MODEL_TOOL = {
  name: "emit_invariant_model",
  description:
    "Emit the EXPLICIT, STRUCTURED invariant model for each key object in the subsystem: lock discipline, refcount balance, lifetime rules, init-order. This is a MODEL, not a bug report — do not hunt bugs here; describe the rules the code is SUPPOSED to uphold so a separate deterministic checker can find violations.",
  input_schema: {
    type: "object",
    properties: {
      objects: {
        type: "array",
        description: "One model per key heap object / state machine in the subsystem.",
        items: {
          type: "object",
          properties: {
            object: { type: "string", description: "The struct/object, e.g. 'struct nfc_llcp_local'." },
            allocSite: { type: "string", description: "Function where it's allocated (provenance)." },
            freeSite: { type: "string", description: "Function where it's freed (provenance)." },
            lockRules: {
              type: "array",
              description: "Which lock guards which fields.",
              items: {
                type: "object",
                properties: {
                  lock: { type: "string", description: "The lock token as written at the acquire site, e.g. 'local->sockets.lock' or 'llcp_devices_lock'." },
                  guardedFields: { type: "array", items: { type: "string" }, description: "Field names (as written after -> or .) this lock protects from concurrent mutation." },
                  acquireFns: { type: "array", items: { type: "string" }, description: "Acquire-call tokens, e.g. ['spin_lock','spin_lock_bh','mutex_lock']. Omit for the common defaults." },
                },
                required: ["lock", "guardedFields"],
              },
            },
            refcountRules: {
              type: "array",
              description: "get/put pairings that must balance.",
              items: {
                type: "object",
                properties: {
                  name: { type: "string", description: "Human name, e.g. 'nfc_llcp_local ref'." },
                  getFn: { type: "string", description: "The acquire/get call token, e.g. 'nfc_llcp_local_get' or 'sock_hold'." },
                  putFn: { type: "string", description: "The release/put call token, e.g. 'nfc_llcp_local_put' or 'sock_put'." },
                },
                required: ["name", "getFn", "putFn"],
              },
            },
            lifecycleRules: {
              type: "array",
              description: "Free/release calls after which the freed variable must not be used.",
              items: {
                type: "object",
                properties: {
                  freeFn: { type: "string", description: "The free/release call token, e.g. 'kfree', 'nfc_llcp_local_put', 'sock_put'." },
                  note: { type: "string", description: "What it frees (provenance)." },
                },
                required: ["freeFn"],
              },
            },
            initOrder: { type: "array", items: { type: "string" }, description: "Fields that must be initialized before first use (notes)." },
          },
          required: ["object", "lockRules", "refcountRules", "lifecycleRules"],
        },
      },
      notes: { type: "string", description: "Free-form provenance notes about the model." },
    },
    required: ["objects"],
  },
};

const MODEL_SYSTEM =
  "You are a kernel subsystem analyst building a REUSABLE INVARIANT MODEL of a subsystem's key objects. You are given " +
  "the source. Your job is NOT to find bugs — it is to describe, per key heap object / state machine, the RULES the " +
  "code is supposed to uphold, so a separate deterministic checker can later find code that violates them.\n\n" +
  "For each key object emit:\n" +
  "  - LOCK DISCIPLINE: which lock (spinlock/mutex/rwlock/seqlock) guards which FIELDS. Give the lock token EXACTLY as " +
  "it is written at the acquire site (e.g. 'local->sockets.lock', 'llcp_devices_lock', 'sk->sk_lock.slock'), and the " +
  "field names exactly as written after '->' or '.'. If a nonstandard acquire wrapper is used, list it in acquireFns.\n" +
  "  - REFCOUNT BALANCE: the get/put (or hold/put, kref_get/kref_put) call-token PAIRS that must balance.\n" +
  "  - LIFETIME: the free/release call tokens (kfree, *_put, *_free) after which the object must NOT be used.\n" +
  "  - INIT-ORDER: fields that must be initialized before first use.\n\n" +
  "Be precise about TOKENS — the downstream checker matches your tokens literally against the source, so a lock token or " +
  "field name that doesn't appear verbatim in the code is useless. Prefer the objects reachable from UNPRIVILEGED " +
  "syscalls. Emit the model via emit_invariant_model.";

interface ModelFromLlm {
  objects: InvariantObjectModel[];
  notes?: string;
}

/**
 * MODEL-BUILD (LLM, once). Reads the subsystem source and produces the explicit,
 * structured {@link InvariantModel}. This is the ONLY LLM call in the pipeline —
 * everything downstream (violation-finding) is deterministic and re-runs against
 * the stored model for free.
 */
export async function buildInvariantModel(input: BuildModelInput): Promise<InvariantModel> {
  const log = input.log ?? (() => {});
  const maxCharsPerFile = input.maxCharsPerFile ?? 24_000;
  if (!input.subsystemFiles || input.subsystemFiles.length === 0) {
    throw new Error("invariant model build needs at least one subsystemFile");
  }

  const sources: Array<{ file: string; text: string }> = [];
  for (const file of input.subsystemFiles) {
    const text = readSource(input.sourceRoot, file);
    if (text == null) {
      log(`[invariant-model] could not read ${file}`);
      continue;
    }
    sources.push({ file, text });
  }
  if (sources.length === 0) {
    throw new Error("invariant model build could not read any subsystemFile under sourceRoot");
  }

  const sourceBlocks = sources
    .map((s) => `### FILE: ${s.file}\n\`\`\`c\n${clip(s.text, maxCharsPerFile)}\n\`\`\``)
    .join("\n\n");
  const messages = [{ role: "user", content: [{ type: "text", text: `## Subsystem source\n\n${sourceBlocks}` }] }];

  const rt = new LlmApiRuntime({ type: "api", ...(input.model ? { model: input.model } : {}), timeout: 300_000 });
  let modelOut: ModelFromLlm | null = null;
  try {
    const res = (await rt.executeNative(MODEL_SYSTEM, messages as never, [MODEL_TOOL] as never, {
      onThinking() {}, onDelta() {}, onText() {}, onUsage() {},
    } as never)) as { content?: Array<Record<string, unknown>> };
    const call = (res.content ?? []).find(
      (b) => (b as { type?: string; name?: string }).type === "tool_use" && (b as { name?: string }).name === "emit_invariant_model",
    ) as { input?: ModelFromLlm } | undefined;
    if (call?.input) modelOut = call.input;
  } catch (e) {
    throw new Error(`invariant-model LLM call failed: ${String(e).slice(0, 200)}`);
  }

  const objects = Array.isArray(modelOut?.objects) ? modelOut!.objects : [];
  if (objects.length === 0) throw new Error("model build emitted no objects");

  // Normalize: ensure every object has the three rule arrays (the checker indexes them).
  const normalized: InvariantObjectModel[] = objects
    .filter((o) => o && typeof o.object === "string")
    .map((o) => ({
      object: o.object,
      ...(o.allocSite ? { allocSite: o.allocSite } : {}),
      ...(o.freeSite ? { freeSite: o.freeSite } : {}),
      lockRules: Array.isArray(o.lockRules) ? o.lockRules.filter((r) => r && typeof r.lock === "string" && Array.isArray(r.guardedFields)) : [],
      refcountRules: Array.isArray(o.refcountRules) ? o.refcountRules.filter((r) => r && typeof r.getFn === "string" && typeof r.putFn === "string") : [],
      lifecycleRules: Array.isArray(o.lifecycleRules) ? o.lifecycleRules.filter((r) => r && typeof r.freeFn === "string") : [],
      ...(Array.isArray(o.initOrder) ? { initOrder: o.initOrder } : {}),
    }));
  if (normalized.length === 0) throw new Error("model build emitted no well-formed objects");

  log(`[invariant-model] built model for ${normalized.length} object(s) in ${input.subsystem}`);
  return {
    modelVersion: INVARIANT_MODEL_VERSION,
    subsystem: input.subsystem,
    subsystemFiles: sources.map((s) => s.file),
    objects: normalized,
    builtAt: new Date().toISOString(),
    ...(modelOut?.notes ? { notes: modelOut.notes } : {}),
  };
}

// ── Durable artifact (the compounding property) ────────────────────────────────

/** Serialize a model to a JSON artifact (creating parent dirs). Returns the path written. */
export function storeInvariantModel(model: InvariantModel, path: string): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(model, null, 2) + "\n", "utf8");
  return path;
}

/** Load + validate a stored model. Throws on a version mismatch (re-build required). */
export function loadInvariantModel(path: string): InvariantModel {
  const model = JSON.parse(readFileSync(path, "utf8")) as InvariantModel;
  if (model.modelVersion !== INVARIANT_MODEL_VERSION) {
    throw new Error(
      `stored model is schema v${model.modelVersion}, checker is v${INVARIANT_MODEL_VERSION} — rebuild the model`,
    );
  }
  if (!Array.isArray(model.objects)) throw new Error("stored model has no objects array");
  return model;
}

// ── Deterministic C-function splitter (brace-scoped, comment/string aware) ──────

/** One top-level C function body recovered from a file. */
export interface CFunction {
  name: string;
  /** 1-based line the signature starts on. */
  startLine: number;
  /** 1-based line the closing brace is on. */
  endLine: number;
  /** The full text from the signature to the closing brace. */
  text: string;
  /** File char offset the body text begins at (used to map inner offsets to lines). */
  startOffset: number;
}

// Control keywords that precede a `(...) {` but are NOT function definitions.
const CONTROL_KEYWORDS = new Set([
  "if", "for", "while", "switch", "do", "else", "return", "sizeof", "typeof",
  "__attribute__", "case", "default", "goto", "asm", "__asm__", "static_assert",
]);

/**
 * Strip C comments and string/char literals to spaces (preserving newlines and
 * length) so brace/paren scanning and token matching never trip on braces or
 * identifiers inside comments or strings. Length- and line-preserving so offsets
 * map 1:1 back to the original file.
 */
export function blankCommentsAndStrings(src: string): string {
  const out = src.split("");
  let i = 0;
  const n = src.length;
  const blank = (a: number, b: number) => {
    for (let k = a; k < b && k < n; k++) if (out[k] !== "\n") out[k] = " ";
  };
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === "/" && c2 === "/") {
      let j = i + 2;
      while (j < n && src[j] !== "\n") j++;
      blank(i, j);
      i = j;
    } else if (c === "/" && c2 === "*") {
      let j = i + 2;
      while (j < n && !(src[j] === "*" && src[j + 1] === "/")) j++;
      j = Math.min(n, j + 2);
      blank(i, j);
      i = j;
    } else if (c === '"' || c === "'") {
      const quote = c;
      let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === quote) { j++; break; }
        if (src[j] === "\n") break; // unterminated — stop at line end
        j++;
      }
      blank(i, j);
      i = j;
    } else {
      i++;
    }
  }
  return out.join("");
}

/** Count 1-based line number of `offset` in `src` (newline count + 1). */
function lineAt(src: string, offset: number): number {
  let line = 1;
  for (let k = 0; k < offset && k < src.length; k++) if (src[k] === "\n") line++;
  return line;
}

const IDENT_RE = /[A-Za-z_][A-Za-z0-9_]*/;

/**
 * Split a C source file into its top-level function bodies. Deterministic: uses a
 * comment/string-blanked copy for structural scanning, finds each `{` at brace
 * depth 0, walks back to the `identifier(...)` signature, and captures to the
 * matching `}`. Heuristic (no real parser): skips control-keyword blocks and
 * struct/enum initializers, and can miss K&R-style or macro-obscured definitions.
 * Good enough to scope the token checks below to a function; imprecision here just
 * means a check runs over a slightly-off body, which the downstream gate absorbs.
 */
export function splitCFunctions(src: string): CFunction[] {
  const blanked = blankCommentsAndStrings(src);
  const fns: CFunction[] = [];
  let depth = 0;
  const n = blanked.length;
  for (let i = 0; i < n; i++) {
    const ch = blanked[i];
    if (ch === "{") {
      if (depth === 0) {
        // Candidate function open-brace. Walk back over whitespace to find `)`.
        let j = i - 1;
        while (j >= 0 && /\s/.test(blanked[j])) j--;
        if (j >= 0 && blanked[j] === ")") {
          // Match the paren group back to its `(`.
          let pd = 0;
          let k = j;
          for (; k >= 0; k--) {
            if (blanked[k] === ")") pd++;
            else if (blanked[k] === "(") { pd--; if (pd === 0) break; }
          }
          if (k >= 0) {
            // The identifier immediately before `(` is the function name.
            let m = k - 1;
            while (m >= 0 && /\s/.test(blanked[m])) m--;
            let e = m;
            while (e >= 0 && /[A-Za-z0-9_]/.test(blanked[e])) e--;
            const name = blanked.slice(e + 1, m + 1).trim();
            if (name && IDENT_RE.test(name) && !CONTROL_KEYWORDS.has(name)) {
              // Capture to the matching close brace.
              let bd = 0;
              let end = i;
              for (; end < n; end++) {
                if (blanked[end] === "{") bd++;
                else if (blanked[end] === "}") { bd--; if (bd === 0) break; }
              }
              // Signature start = beginning of the line the identifier is on.
              let sigStart = e + 1;
              while (sigStart > 0 && blanked[sigStart - 1] !== "\n") sigStart--;
              fns.push({
                name,
                startLine: lineAt(src, sigStart),
                endLine: lineAt(src, end),
                text: src.slice(sigStart, Math.min(n, end + 1)),
                startOffset: sigStart,
              });
              depth = 0;
              i = end; // resume after the function
              continue;
            }
          }
        }
      }
      depth++;
    } else if (ch === "}") {
      if (depth > 0) depth--;
    }
  }
  return fns;
}

// ── Deterministic violation finder (NO LLM) ────────────────────────────────────

/** Default acquire-call tokens that count as "holding" a lock when a rule lists none. */
export const DEFAULT_ACQUIRE_FNS: readonly string[] = [
  "spin_lock", "spin_lock_bh", "spin_lock_irq", "spin_lock_irqsave", "spin_trylock",
  "raw_spin_lock", "raw_spin_lock_bh", "raw_spin_lock_irqsave",
  "mutex_lock", "mutex_lock_interruptible", "mutex_trylock",
  "read_lock", "read_lock_bh", "write_lock", "write_lock_bh",
  "down", "down_read", "down_write", "down_interruptible",
];

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** True if a blanked function body acquires `lock` via any of `acquireFns` (`fn(&?lock)`). */
function bodyHoldsLock(blankedBody: string, lock: string, acquireFns: readonly string[]): boolean {
  const lockRe = escapeRe(lock);
  for (const fn of acquireFns) {
    // fn ( optional-&  lock  — allow whitespace; lock may itself contain -> or . which escapeRe preserved.
    const re = new RegExp(`\\b${escapeRe(fn)}\\s*\\(\\s*&?\\s*${lockRe}\\b`);
    if (re.test(blankedBody)) return true;
  }
  return false;
}

/** Find each 1-based line in a blanked body where `->field` or `.field` is accessed. */
function fieldAccessLines(blankedBody: string, bodyStartLine: number, field: string): number[] {
  const re = new RegExp(`(->|\\.)\\s*${escapeRe(field)}\\b`, "g");
  const lines: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(blankedBody)) !== null) {
    lines.push(bodyStartLine + countNewlines(blankedBody, m.index));
  }
  return lines;
}

function countNewlines(s: string, upto: number): number {
  let c = 0;
  for (let k = 0; k < upto && k < s.length; k++) if (s[k] === "\n") c++;
  return c;
}

/**
 * Read the first-argument identifier of a `fn(...)` call at `callIndex` in a
 * blanked body, plus the offset just past the call's closing paren (so the
 * caller resumes scanning AFTER the whole call, not inside its own arg list).
 */
function parseFreeCall(
  blankedBody: string,
  callIndex: number,
  fn: string,
): { freedVar: string; callEnd: number } | null {
  const open = blankedBody.indexOf("(", callIndex + fn.length);
  if (open === -1) return null;
  // First arg = up to the first top-level comma or the closing paren.
  let depth = 0;
  let firstArgEnd = -1;
  let callEnd = -1;
  for (let end = open + 1; end < blankedBody.length; end++) {
    const ch = blankedBody[end];
    if (ch === "(") depth++;
    else if (ch === ")") {
      if (depth === 0) { callEnd = end + 1; if (firstArgEnd === -1) firstArgEnd = end; break; }
      depth--;
    } else if (ch === "," && depth === 0 && firstArgEnd === -1) {
      firstArgEnd = end;
    }
  }
  if (firstArgEnd === -1 || callEnd === -1) return null;
  const arg = blankedBody.slice(open + 1, firstArgEnd).trim();
  // Strip a leading `&`; take the leading identifier chain's base variable.
  const m = /^&?\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(arg);
  return m ? { freedVar: m[1], callEnd } : null;
}

export interface FindViolationsOptions {
  /** Cap emitted violations (default 40). */
  maxViolations?: number;
  /**
   * Include the refcount-imbalance check. Default true. It is the WEAKEST /
   * noisiest check (a single-function put with no get is legitimately common —
   * the get lives in a caller), so callers hunting only the strong signals can
   * turn it off.
   */
  refcountCheck?: boolean;
  log?: (msg: string) => void;
}

/**
 * DETERMINISTIC violation finder — the seedless candidate generator. Given the
 * stored {@link InvariantModel} and the subsystem sources, mechanically finds code
 * that violates the model. NO LLM.
 *
 * Backed by REAL intra-procedural dataflow ({@link findViolationsDataflow} in
 * `c-dataflow.ts`): a tree-sitter-c AST, a per-function CFG, a lock-set MUST-analysis
 * for `unlocked-field-access` (lock held AT the access point, resolved to the struct
 * field), a reaching-free MAY-analysis for `use-after-free-order` (path-sensitive),
 * and a per-function get/put heuristic for `refcount-imbalance` (weakest; opt-out via
 * {@link FindViolationsOptions.refcountCheck}). See that module's header for the exact
 * lattices and the honest residual scope (still intra-procedural; no points-to).
 *
 * `sources` maps repo-relative file → its full text (the SAME files the model was
 * built from, or a newer revision of them — that re-check is the whole point).
 */
export function findInvariantViolations(
  model: InvariantModel,
  sources: Array<{ file: string; text: string }>,
  opts: FindViolationsOptions = {},
): InvariantViolation[] {
  return findViolationsDataflow(model, sources, {
    ...(opts.maxViolations !== undefined ? { maxViolations: opts.maxViolations } : {}),
    ...(opts.refcountCheck !== undefined ? { refcountCheck: opts.refcountCheck } : {}),
    ...(opts.log ? { log: opts.log } : {}),
  });
}

/**
 * LEGACY token-level finder — retained ONLY for A/B comparison against the real
 * dataflow finder ({@link findInvariantViolations}). This is the original
 * over-approximation: brace-scoped function splitting + "does the body acquire the
 * lock ANYWHERE" / "textual use after a textual free" / "pure put". It over-reports
 * (caller-held locks, frees on dead branches, single-function puts) — the very
 * false positives the dataflow finder eliminates. Do not use it in production; use
 * {@link findInvariantViolations}.
 */
export function findInvariantViolationsTokenLevel(
  model: InvariantModel,
  sources: Array<{ file: string; text: string }>,
  opts: FindViolationsOptions = {},
): InvariantViolation[] {
  const log = opts.log ?? (() => {});
  const maxViolations = opts.maxViolations ?? 40;
  const refcountCheck = opts.refcountCheck ?? true;
  const violations: InvariantViolation[] = [];

  for (const { file, text } of sources) {
    const blanked = blankCommentsAndStrings(text);
    const fns = splitCFunctions(text);
    // Build a blanked view per function aligned to file offsets (slice the same range).
    for (const fn of fns) {
      const bStart = fn.startOffset;
      const bEnd = bStart + fn.text.length;
      const blankedBody = blanked.slice(bStart, bEnd);
      const bodyStartLine = fn.startLine;

      for (const obj of model.objects) {
        // (1) unlocked-field-access
        for (const rule of obj.lockRules) {
          const acquireFns = rule.acquireFns && rule.acquireFns.length > 0 ? rule.acquireFns : DEFAULT_ACQUIRE_FNS;
          const holds = bodyHoldsLock(blankedBody, rule.lock, acquireFns);
          if (holds) continue; // lock acquired somewhere in this body → not a candidate
          for (const field of rule.guardedFields) {
            const lines = fieldAccessLines(blankedBody, bodyStartLine, field);
            if (lines.length === 0) continue;
            // One violation per (function, field) at the FIRST access line.
            violations.push({
              kind: "unlocked-field-access",
              object: obj.object,
              file,
              line: lines[0],
              functionName: fn.name,
              invariant: `field '${field}' of ${obj.object} must only be accessed while holding ${rule.lock}`,
              detail:
                `${fn.name}() accesses ->${field} (line ${lines[0]}${lines.length > 1 ? `, +${lines.length - 1} more` : ""}) ` +
                `but never acquires ${rule.lock} in this function body. Confirm the lock isn't held by a caller ` +
                `(intra-procedural check — caller-held locks are a false positive).`,
            });
          }
        }

        // (2) use-after-free-order
        for (const rule of obj.lifecycleRules) {
          const callRe = new RegExp(`\\b${escapeRe(rule.freeFn)}\\s*\\(`, "g");
          let cm: RegExpExecArray | null;
          while ((cm = callRe.exec(blankedBody)) !== null) {
            const parsed = parseFreeCall(blankedBody, cm.index, rule.freeFn);
            if (!parsed) continue;
            const { freedVar, callEnd } = parsed;
            const freeLine = bodyStartLine + countNewlines(blankedBody, cm.index);
            // Look for a later use of freedVar: `var->`, `var[`, or `var` as a call arg / rvalue,
            // that is not an assignment `var =` (a reassignment clears the danger). Scan starts
            // AFTER the free call's own closing paren so its own argument isn't counted as a use.
            const useRe = new RegExp(`\\b${escapeRe(freedVar)}\\b`, "g");
            useRe.lastIndex = callEnd;
            let um: RegExpExecArray | null;
            while ((um = useRe.exec(blankedBody)) !== null) {
              const after = blankedBody.slice(um.index + freedVar.length);
              // Reassignment `var =` (but not `==`, `!=`, `<=`, `>=`) resets the object — stop scanning.
              if (/^\s*=[^=]/.test(after)) break;
              const isDeref = /^\s*(->|\[)/.test(after);
              const isCallArg = /^\s*[,)]/.test(after);
              if (isDeref || isCallArg) {
                const useLine = bodyStartLine + countNewlines(blankedBody, um.index);
                violations.push({
                  kind: "use-after-free-order",
                  object: obj.object,
                  file,
                  line: useLine,
                  functionName: fn.name,
                  invariant: `'${freedVar}' must not be used after ${rule.freeFn}() releases it`,
                  detail:
                    `${fn.name}() calls ${rule.freeFn}(${freedVar}) at line ${freeLine}, then uses ${freedVar} again ` +
                    `at line ${useLine}. Confirm this isn't a different-object reassignment or a path where the free ` +
                    `didn't run (intra-procedural, path-insensitive check).`,
                });
                break; // one violation per free site is enough to flag the function
              }
            }
          }
        }

        // (3) refcount-imbalance (weakest; opt-out)
        if (refcountCheck) {
          for (const rule of obj.refcountRules) {
            const getCount = (blankedBody.match(new RegExp(`\\b${escapeRe(rule.getFn)}\\s*\\(`, "g")) ?? []).length;
            const putM = new RegExp(`\\b${escapeRe(rule.putFn)}\\s*\\(`, "g").exec(blankedBody);
            const putCount = (blankedBody.match(new RegExp(`\\b${escapeRe(rule.putFn)}\\s*\\(`, "g")) ?? []).length;
            if (putCount > 0 && getCount === 0 && putM) {
              const putLine = bodyStartLine + countNewlines(blankedBody, putM.index);
              violations.push({
                kind: "refcount-imbalance",
                object: obj.object,
                file,
                line: putLine,
                functionName: fn.name,
                invariant: `${rule.name}: every ${rule.putFn}() must be balanced by a prior ${rule.getFn}()`,
                detail:
                  `${fn.name}() calls ${rule.putFn}() (${putCount}x) but no ${rule.getFn}() — possible double-put / ` +
                  `underflow if the ref wasn't held on entry. WEAK signal: the get is often legitimately in a caller.`,
              });
            }
          }
        }
      }
    }
  }

  violations.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  const capped = violations.slice(0, maxViolations);
  log(`[invariant-check] ${violations.length} violation candidate(s)${capped.length < violations.length ? ` (capped to ${capped.length})` : ""}`);
  return capped;
}

// ── Emit HuntCandidates + compose with runHuntScan ─────────────────────────────

/** Human-readable kind labels for hints. */
const KIND_LABEL: Record<ViolationKind, string> = {
  "unlocked-field-access": "UNLOCKED FIELD ACCESS",
  "use-after-free-order": "USE-AFTER-FREE ORDER",
  "refcount-imbalance": "REFCOUNT IMBALANCE",
};

export interface InvariantHuntPlan {
  /** The stored model this hunt derives from. */
  model: InvariantModel;
  /** The deterministic violations found. */
  violations: InvariantViolation[];
  /** One `runHuntScan` brief describing the seedless invariant bug class. */
  brief: HuntBrief;
  /** `runHuntScan` candidate sites (one per file, merged per-site hints). */
  candidates: HuntCandidate[];
}

/**
 * Turn deterministic violations into a {@link HuntCandidate}[] + {@link HuntBrief}
 * that plug straight into `runHuntScan`. Violations are grouped per file (one
 * candidate per file, merged hints) so the finder re-reads the whole file with
 * every located violation as guidance — the finder + skeptic + prover gate then
 * kill the over-approximation FPs.
 */
export function violationsToHuntPlan(model: InvariantModel, violations: InvariantViolation[]): InvariantHuntPlan {
  const bySite = new Map<string, HuntCandidate>();
  for (const v of violations) {
    const hint =
      `${KIND_LABEL[v.kind]} candidate (deterministic, from stored invariant model). ` +
      `Invariant: ${v.invariant}. Site: ${v.file}:${v.line} in ${v.functionName}(). ${v.detail}`;
    const existing = bySite.get(v.file);
    if (existing) existing.hint = `${existing.hint}\n---\n${hint}`;
    else bySite.set(v.file, { path: v.file, hint });
  }
  const kinds = [...new Set(violations.map((v) => v.kind))].map((k) => KIND_LABEL[k]).join(", ");
  const brief: HuntBrief = {
    bugClass: `invariant-model violation (seedless): ${kinds || "lock/refcount/lifetime discipline"}`,
    pattern:
      `A key object in ${model.subsystem} violates its modeled invariant — a guarded field touched without its lock, ` +
      `a variable used after free, or an unbalanced refcount put. The candidate sites below were found by a deterministic ` +
      `checker against the stored invariant model; verify each is a real, reachable violation and not a caller-held-lock / ` +
      `path-insensitive false positive.`,
    fixReference: undefined,
  };
  return { model, violations, brief, candidates: [...bySite.values()] };
}

// ── End-to-end orchestration (seedless → candidate → verified → ranked) ─────────

export interface SubsystemInvariantHuntInput {
  /** Local source tree the subsystem files live under. */
  sourceRoot: string;
  /** Subsystem label (e.g. `"net/nfc/llcp"`). */
  subsystem: string;
  /** The subsystem's key source files (canonical repo-relative paths under `sourceRoot`). */
  subsystemFiles: string[];
  runtime: RuntimeMode;
  /**
   * Where the durable model JSON lives. When it exists and `rebuildModel` is
   * falsy, the model is LOADED (no LLM call) and the deterministic checker re-runs
   * against the current source — the compounding, re-checkable property. When
   * absent (or `rebuildModel`), the model is built by one LLM call and stored here.
   */
  modelPath: string;
  /** Force a fresh LLM model build even if `modelPath` exists. */
  rebuildModel?: boolean;
  /** Model-build LLM override. */
  model?: string;
  /** Violation-finder options (cap, refcount opt-out). */
  findOptions?: FindViolationsOptions;
  /**
   * The skeptic+prover gate for `runHuntScan`. When omitted, a default
   * {@link makeSkepticVerifier} (adversarial re-read) is used as the skeptic; a
   * caller with a kernel-VM prover should pass `composeGate(skeptic, prover)`.
   */
  verify?: HuntVerifier;
  /**
   * OPTIONAL PROVE stage — the exploitability→root oracle
   * (`makeKernelVmExploitabilityGate`), composed as the terminal gate in
   * `runHuntScan` so confirmed candidates are ranked by real weaponizability.
   */
  exploitability?: HuntVerifier;
  /** Finder model diversity for `runHuntScan`. */
  finderModels?: string[];
  /** Skip `runHuntScan` and return just the model + violations + plan (candidate gen only). */
  skipHunt?: boolean;
  log?: (msg: string) => void;
}

export interface SubsystemInvariantHuntResult {
  /** The invariant model used (built fresh or loaded from `modelPath`). */
  model: InvariantModel;
  /** Where the model artifact is stored. */
  modelPath: string;
  /** Whether the model was loaded from disk (true) or freshly built by the LLM (false). */
  modelLoaded: boolean;
  /** The deterministically-found violations (seedless candidates). */
  violations: InvariantViolation[];
  /** The `runHuntScan` plan (brief + candidates). */
  plan: InvariantHuntPlan;
  /** The `runHuntScan` result — undefined when `skipHunt`. */
  hunt?: HuntScanResult;
}

/**
 * Full seedless pipeline: (build or load) the stored invariant model → run the
 * DETERMINISTIC violation checker → map to `runHuntScan` candidates → verify +
 * rank through `composeGate(skeptic, prover, [exploitability])`. No seed patch,
 * no known CVE — the model + checker generate candidates from cold.
 */
export async function runSubsystemInvariantHunt(
  input: SubsystemInvariantHuntInput,
): Promise<SubsystemInvariantHuntResult> {
  const log = input.log ?? (() => {});

  // 1. Build (LLM, once) OR load (free re-check) the durable model.
  let model: InvariantModel;
  let modelLoaded = false;
  if (!input.rebuildModel) {
    try {
      model = loadInvariantModel(input.modelPath);
      modelLoaded = true;
      log(`[invariant] loaded stored model ${input.modelPath} (${model.objects.length} object(s)) — no LLM call`);
    } catch {
      model = await buildInvariantModel(input);
      storeInvariantModel(model, input.modelPath);
      log(`[invariant] built + stored model ${input.modelPath}`);
    }
  } else {
    model = await buildInvariantModel(input);
    storeInvariantModel(model, input.modelPath);
    log(`[invariant] rebuilt + stored model ${input.modelPath}`);
  }

  // 2. Read the CURRENT subsystem source (model files, or a newer revision).
  const sources: Array<{ file: string; text: string }> = [];
  for (const file of input.subsystemFiles) {
    const text = readSource(input.sourceRoot, file);
    if (text != null) sources.push({ file, text });
  }
  if (sources.length === 0) throw new Error("invariant hunt could not read any subsystemFile under sourceRoot");

  // 3. DETERMINISTIC violation finder (NO LLM).
  const violations = findInvariantViolations(model, sources, { ...input.findOptions, log });
  const plan = violationsToHuntPlan(model, violations);

  if (input.skipHunt || plan.candidates.length === 0) {
    return { model, modelPath: input.modelPath, modelLoaded, violations, plan };
  }

  // 4. Verify + rank through the skeptic+prover gate (and the exploitability oracle
  //    when wired). Seedless candidates now flow through the SAME gate variant-hunt
  //    candidates do — LLM-verify kills the over-approximation FPs, the oracle ranks
  //    survivors by weaponizability.
  const verify =
    input.verify ?? makeSkepticVerifier({ sourceRoot: input.sourceRoot, runtime: input.runtime });

  const hunt = await runHuntScan({
    sourceRoot: input.sourceRoot,
    candidates: plan.candidates,
    brief: plan.brief,
    runtime: input.runtime,
    ...(input.finderModels && input.finderModels.length > 0 ? { models: input.finderModels } : {}),
    verify,
    ...(input.exploitability ? { exploitability: input.exploitability } : {}),
    log,
  });

  return { model, modelPath: input.modelPath, modelLoaded, violations, plan, hunt };
}

// Re-export the gate helpers a caller composes the verify pipeline from, so a
// consumer wiring the exploitability oracle imports everything from one module.
export { composeGate, makeSkepticVerifier };
