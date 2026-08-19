/**
 * Unsafe-deserialization source-audit detector — deterministic static-pattern
 * oracles for insecure deserialization / dynamic-code-execution sinks in
 * JS/TS and Python source.
 *
 * Motivation: the `unsafe-deserialization` and `code-injection` categories are
 * recognized by the audit pipeline (see `analysis-prompts.ts` and
 * `remediation.ts`), but they were detected LLM-only — there was no
 * deterministic oracle. Insecure deserialization is reliably disclosure-worthy
 * and provable by inspection (the sink itself is the bug — `pickle.loads` /
 * `yaml.load` on external bytes is RCE-by-construction), which means low
 * inconclusive rate and high precision. This mirrors the deterministic
 * `crypto-misuse-detector.ts` / `malicious-detector.ts` model: a pure static
 * pass that runs BEFORE the LLM agent and emits `Finding` objects.
 *
 * Detectors (each precision-gated to genuinely dangerous usage so we do NOT
 * flood on every `JSON.parse` or safe `yaml.safeLoad`):
 *
 *   1. Python pickle/marshal/dill/shelve — `pickle.loads` / `pickle.load` /
 *      `cPickle.*` / `marshal.loads` / `dill.loads` / `shelve.open`. These
 *      deserialize arbitrary objects and are RCE-by-construction on
 *      attacker-controlled bytes. Always flagged.
 *   2. Python unsafe YAML — `yaml.load(...)` WITHOUT a `Safe*`/`Base*` loader,
 *      and `yaml.unsafe_load` / `yaml.full_load`. `yaml.safe_load` and an
 *      explicit `Loader=yaml.SafeLoader` are NOT flagged.
 *   3. Node insecure-deserialize libraries — `node-serialize` `unserialize()`,
 *      `serialize-to-js` `deserialize()`, `funcster.deepDeserialize`, and a
 *      bare `vm.runInNewContext` / `vm.runInContext` / `vm.runInThisContext`
 *      (a sandbox-escape-prone code-eval sink).
 *   4. Dynamic code execution — `eval(...)` and `new Function(...)` where the
 *      argument is NOT a pure string literal (i.e. it interpolates a variable /
 *      template / concatenation), which is the dangerous, near-always-a-bug
 *      shape. A literal `eval("1+1")` is NOT flagged.
 *
 * Every finding is deterministic and self-evidencing, so it is emitted with
 * `status: "verified"`. Categories: `unsafe-deserialization` for the
 * deserialization sinks, `code-injection` for the eval/Function sinks.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { relative } from "node:path";
import { randomUUID } from "node:crypto";
import type { AttackCategory, Finding, Severity } from "@pwnkit/shared";
import { collectScopeFiles } from "./source-files.js";

// ────────────────────────────────────────────────────────────────────
// Shared helpers
// ────────────────────────────────────────────────────────────────────

/** Source file extensions this detector understands. */
const DESER_SOURCE_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx",
  ".py",
]);

/** Per-detector finding shape, before it is turned into a {@link Finding}. */
export interface DeserHit {
  detector:
    | "python-pickle"
    | "python-unsafe-yaml"
    | "node-insecure-deserialize"
    | "dynamic-code-exec";
  templateId: string;
  title: string;
  description: string;
  severity: Severity;
  category: AttackCategory;
  /** 1-based line number in the source file. */
  line: number;
  /** The matched source line, trimmed and length-capped for evidence. */
  snippet: string;
  confidence: number;
}

/** Split a source blob into lines once; callers reuse the array. */
function toLines(source: string): string[] {
  return source.split(/\r?\n/);
}

/** Trim + cap a source line for safe inclusion in finding evidence. */
function snippetOf(line: string): string {
  const t = line.trim();
  return t.length > 200 ? `${t.slice(0, 197)}...` : t;
}

/** True for lines that are pure comments — skipped to cut comment-only FPs. */
function isCommentLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("#") || t.startsWith("/*");
}

// ────────────────────────────────────────────────────────────────────
// Detector 1 — Python pickle / marshal / dill / shelve
// ────────────────────────────────────────────────────────────────────

/**
 * Python deserializers that reconstruct arbitrary objects (and therefore
 * execute arbitrary code via `__reduce__`) from bytes. `pickle`, the legacy
 * `cPickle`, `marshal`, `dill`, and `shelve` are all RCE-by-construction on
 * attacker-controlled input.
 */
const PY_PICKLE_RX =
  /\b(?:c?Pickle|pickle|marshal|dill|_pickle)\s*\.\s*(loads|load)\s*\(|\bshelve\s*\.\s*open\s*\(/;

/**
 * Detect Python pickle/marshal/dill/shelve deserialization. Always flagged —
 * there is no safe way to deserialize untrusted bytes with these modules.
 */
export function detectPythonPickle(source: string): DeserHit[] {
  const hits: DeserHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;
    const m = PY_PICKLE_RX.exec(line);
    if (!m) continue;
    const isShelve = /\bshelve\b/.test(line);
    hits.push({
      detector: "python-pickle",
      templateId: "deser-python-pickle",
      title: isShelve
        ? "Python `shelve` opens a pickle-backed store (deserialization RCE)"
        : "Python pickle/marshal/dill deserialization of untrusted data",
      description:
        "This call reconstructs arbitrary Python objects from serialized bytes. `pickle` / `cPickle` / " +
        "`marshal` / `dill` (and `shelve`, which is pickle-backed) invoke `__reduce__` during " +
        "deserialization, so a crafted payload achieves remote code execution the moment it is loaded — " +
        "there is no safe-mode flag. If the bytes can come from a request, file upload, cache, queue, or " +
        "any untrusted source, this is RCE-by-construction. Use a data-only format (JSON, or protobuf / " +
        "MessagePack with a fixed schema) instead, and never unpickle data you did not produce yourself.",
      severity: "critical",
      category: "unsafe-deserialization",
      line: i + 1,
      snippet: snippetOf(line),
      confidence: 0.85,
    });
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Detector 2 — Python unsafe YAML
// ────────────────────────────────────────────────────────────────────

/** A `yaml.load(...)` call (PyYAML / ruamel). */
const PY_YAML_LOAD_RX = /\byaml\s*\.\s*load\s*\(/;
/** Explicitly unsafe loaders — always dangerous regardless of args. */
const PY_YAML_UNSAFE_RX = /\byaml\s*\.\s*(?:unsafe_load|full_load)\s*\(/;
/** A safe loader named on the line → `yaml.load(x, Loader=yaml.SafeLoader)` etc. */
const PY_YAML_SAFE_LOADER_RX = /\b(?:Safe|Base|CSafe)Loader\b/;

/**
 * Detect unsafe YAML deserialization in Python. PyYAML's default `Loader`
 * constructs arbitrary Python objects (`!!python/object/apply:os.system` → RCE).
 * Precision gate: `yaml.load(...)` is flagged UNLESS a `Safe*`/`Base*` loader
 * is named on the line; `yaml.safe_load` is never matched in the first place.
 * `yaml.unsafe_load` / `yaml.full_load` are always flagged.
 */
export function detectPythonUnsafeYaml(source: string): DeserHit[] {
  const hits: DeserHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    const isExplicitUnsafe = PY_YAML_UNSAFE_RX.test(line);
    const isBareLoad = PY_YAML_LOAD_RX.test(line) && !PY_YAML_SAFE_LOADER_RX.test(line);
    if (!isExplicitUnsafe && !isBareLoad) continue;

    hits.push({
      detector: "python-unsafe-yaml",
      templateId: "deser-python-unsafe-yaml",
      title: "Unsafe YAML deserialization (PyYAML default/unsafe loader)",
      description:
        "PyYAML's `yaml.load()` with the default loader (and `yaml.unsafe_load` / `yaml.full_load`) can " +
        "instantiate arbitrary Python objects from tags such as `!!python/object/apply:os.system`, which " +
        "means a malicious YAML document yields remote code execution. Use `yaml.safe_load()` (or pass " +
        "`Loader=yaml.SafeLoader`), which restricts parsing to standard scalar/sequence/mapping types.",
      severity: "high",
      category: "unsafe-deserialization",
      line: i + 1,
      snippet: snippetOf(line),
      confidence: isExplicitUnsafe ? 0.85 : 0.75,
    });
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Detector 3 — Node insecure-deserialize libraries + vm sinks
// ────────────────────────────────────────────────────────────────────

/** `node-serialize` `unserialize()`, `serialize-to-js` `deserialize()`, funcster. */
const NODE_DESER_RX =
  /\bunserialize\s*\(|\bserializeToJs\s*\.\s*deserialize\s*\(|\bfuncster\s*\.\s*deepDeserialize\s*\(/;
/** Node `vm` code-eval sinks — sandbox-escape-prone arbitrary-code execution. */
const NODE_VM_RX = /\bvm\s*\.\s*(?:runInNewContext|runInContext|runInThisContext|compileFunction)\s*\(/;

/**
 * Detect Node insecure-deserialization libraries and `vm` code-eval sinks.
 * `node-serialize.unserialize()` famously executes an embedded
 * `_$$ND_FUNC$$_` immediately-invoked function (RCE), and the `vm` module's
 * run-in-context family evaluates arbitrary code in a sandbox that is widely
 * known to be escapable. Always security-relevant.
 */
export function detectNodeInsecureDeserialize(source: string): DeserHit[] {
  const hits: DeserHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    if (NODE_DESER_RX.test(line)) {
      hits.push({
        detector: "node-insecure-deserialize",
        templateId: "deser-node-insecure-lib",
        title: "Insecure JS deserialization library (`unserialize` / funcster)",
        description:
          "This call deserializes JavaScript values from a string using a library that reconstructs " +
          "functions (`node-serialize`'s `unserialize`, `serialize-to-js`, `funcster`). `node-serialize` " +
          "immediately invokes an embedded `_$$ND_FUNC$$_` function, so a crafted payload achieves remote " +
          "code execution. Never deserialize untrusted input with a function-rehydrating serializer; use " +
          "`JSON.parse` for data, and validate the parsed shape.",
        severity: "critical",
        category: "unsafe-deserialization",
        line: i + 1,
        snippet: snippetOf(line),
        confidence: 0.8,
      });
      continue;
    }

    if (NODE_VM_RX.test(line)) {
      hits.push({
        detector: "node-insecure-deserialize",
        templateId: "deser-node-vm-eval",
        title: "Node `vm` code-evaluation sink (sandbox-escape-prone)",
        description:
          "The Node `vm` module's `runInNewContext` / `runInContext` / `runInThisContext` / `compileFunction` " +
          "execute arbitrary JavaScript. The `vm` sandbox is explicitly documented as NOT a security boundary " +
          "and is trivially escapable (`this.constructor.constructor('return process')()`), so running " +
          "untrusted code through it is remote code execution. Do not evaluate external code; if you must run " +
          "untrusted code, use an out-of-process isolate (e.g. `isolated-vm` with a hardened policy).",
        severity: "high",
        category: "code-injection",
        line: i + 1,
        snippet: snippetOf(line),
        confidence: 0.75,
      });
    }
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Detector 4 — dynamic code execution (eval / new Function on non-literals)
// ────────────────────────────────────────────────────────────────────

/** An `eval(` call (JS) — captures the parenthesized head of the argument. */
const EVAL_RX = /\beval\s*\(\s*([^)]*)/;
/** A `new Function(` call — last argument is the executed body. */
const NEW_FUNCTION_RX = /\bnew\s+Function\s*\(\s*([^)]*)/;

/**
 * True when the captured argument head is a single pure string/number literal
 * (no interpolation, concatenation, or identifier) — the benign shape we do
 * NOT flag (e.g. `eval("1 + 1")`). A template literal with `${...}`, a `+`
 * concat, or a bare identifier means the executed text is dynamic → flagged.
 */
function isStaticLiteralArg(argHead: string): boolean {
  const a = argHead.trim();
  if (a === "") return false;
  // Template literal containing an interpolation → dynamic.
  if (/`[^`]*\$\{/.test(a)) return false;
  // Pure single-/double-quoted string, plain template (no interpolation), or a
  // numeric literal — optionally followed by a trailing comma (Function arg
  // lists) — is static. Anything else (identifier, concat, member access) is
  // treated as dynamic.
  return (
    /^(['"])(?:\\.|(?!\1).)*\1\s*,?$/.test(a) ||
    /^`[^`$]*`\s*,?$/.test(a) ||
    /^[\d.]+\s*,?$/.test(a)
  );
}

/**
 * Detect dynamic code execution via `eval()` / `new Function()` where the
 * argument is NOT a pure string literal. The dangerous, near-always-a-bug shape
 * is a template/concat/variable being executed; a literal `eval("1+1")` (rare
 * but legitimate, e.g. config math) is intentionally NOT flagged so we keep the
 * FP rate down.
 */
export function detectDynamicCodeExec(source: string): DeserHit[] {
  const hits: DeserHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    const evalM = EVAL_RX.exec(line);
    if (evalM && !isStaticLiteralArg(evalM[1])) {
      hits.push({
        detector: "dynamic-code-exec",
        templateId: "deser-dynamic-eval",
        title: "Dynamic `eval()` of a non-literal expression",
        description:
          "`eval()` is called on a dynamically-built string (a template literal, concatenation, or variable) " +
          "rather than a constant. If any part of that string derives from input, an attacker controls the " +
          "executed JavaScript — arbitrary code execution. Replace `eval` with the specific operation you " +
          "need (e.g. `JSON.parse` for data, a lookup object for dispatch); there is almost never a safe " +
          "reason to `eval` a dynamic string.",
        severity: "high",
        category: "code-injection",
        line: i + 1,
        snippet: snippetOf(line),
        confidence: 0.7,
      });
      continue;
    }

    const fnM = NEW_FUNCTION_RX.exec(line);
    if (fnM && !isStaticLiteralArg(fnM[1])) {
      hits.push({
        detector: "dynamic-code-exec",
        templateId: "deser-dynamic-function",
        title: "Dynamic `new Function()` body built from a non-literal",
        description:
          "`new Function(...)` compiles a string into executable code in the global scope, equivalent to " +
          "`eval`. Here the body is built dynamically (template / concatenation / variable), so any " +
          "input-derived component is executed as JavaScript — arbitrary code execution. Use a static " +
          "function or a dispatch table instead of compiling code at runtime.",
        severity: "high",
        category: "code-injection",
        line: i + 1,
        snippet: snippetOf(line),
        confidence: 0.65,
      });
    }
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Aggregate single-source scan
// ────────────────────────────────────────────────────────────────────

/** Run every detector over one source blob and return the merged hits. */
export function scanSourceForUnsafeDeser(source: string): DeserHit[] {
  return [
    ...detectPythonPickle(source),
    ...detectPythonUnsafeYaml(source),
    ...detectNodeInsecureDeserialize(source),
    ...detectDynamicCodeExec(source),
  ];
}

// ────────────────────────────────────────────────────────────────────
// Public entry point — produce Finding[] for the audit pipeline
// ────────────────────────────────────────────────────────────────────

export interface UnsafeDeserScanOptions {
  /** Root directory of the package/repo to audit. */
  packagePath: string;
  /** Package/target name, used only to label findings. */
  packageName?: string;
  /** Max source files to scan (deterministic order). Defaults to 400. */
  maxFiles?: number;
}

const DEFAULT_DESER_MAX_FILES = 400;

/**
 * Walk the package source tree and run all unsafe-deserialization / dynamic
 * code-exec detectors, returning `Finding` objects ready to drop into
 * `AuditReport.findings`. Findings are deterministic and self-evidencing, so
 * they are emitted `status: "verified"`.
 *
 * Fail-soft: an unreadable directory / file is skipped, never thrown.
 */
export function scanForUnsafeDeser(opts: UnsafeDeserScanOptions): Finding[] {
  const { packagePath } = opts;
  if (!existsSync(packagePath)) return [];

  let files: string[];
  try {
    files = statSync(packagePath).isDirectory()
      ? collectScopeFiles(packagePath, {
          maxFiles: opts.maxFiles ?? DEFAULT_DESER_MAX_FILES,
          extensions: DESER_SOURCE_EXTS,
        })
      : [packagePath];
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  const now = Date.now();

  for (const file of files) {
    let source: string;
    try {
      source = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = (() => {
      try {
        return relative(packagePath, file) || file;
      } catch {
        return file;
      }
    })();

    for (const hit of scanSourceForUnsafeDeser(source)) {
      findings.push({
        id: randomUUID(),
        templateId: hit.templateId,
        title: hit.title,
        description: `${hit.description}\n\n**Location:** \`${rel}:${hit.line}\``,
        severity: hit.severity,
        category: hit.category,
        status: "verified",
        evidence: {
          request: `${rel}:${hit.line}`,
          response: hit.snippet,
          analysis:
            `Deterministic unsafe-deserialization oracle (detector: ${hit.detector}; no LLM, no network). ` +
            `The dangerous sink is present in the source, so the finding is provable by inspection.`,
        },
        confidence: hit.confidence,
        timestamp: now,
      });
    }
  }

  return findings;
}
