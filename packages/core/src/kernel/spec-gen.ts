/**
 * kernel/spec-gen.ts
 *
 * KernelGPT-style LLM → syzlang syscall-spec generation — the FRONT of our
 * LLM-review → spec → fuzz loop. Given a kernel subsystem and a slice of its
 * source (the same source `review/linux-kernel-profile.ts` already feeds the
 * review agent), an LLM infers a syzkaller (`syzlang`) description for the
 * syscall / ioctl entry points, we STRUCTURALLY validate the produced spec,
 * and on failure re-prompt the model with the concrete error — an
 * infer → validate → repair loop bounded to N iterations.
 *
 * Why: syzkaller's coverage is thin exactly where our research focus lives —
 * driver `ioctl` surfaces (MediaTek, the vfio/media/gpio class above). KernelGPT
 * (arXiv 2401.00563, ASPLOS'25) showed an LLM can recover these descriptions
 * from source and that the recovered specs find real bugs (24 bugs / 11 CVEs,
 * merged into syzkaller). This module is the inference + structural-validation +
 * repair core of that technique.
 *
 * Scope of THIS module (deliberately bounded — simplicity first):
 *   - We do the cheap, dependency-free half: structural validation (balanced
 *     syntax, known type/resource keywords, plausible arg shapes).
 *   - Full semantic validation — syzkaller's `syz-check` / compile + coverage —
 *     needs a syzkaller checkout and a built kernel (the `fuzzer` box). That is
 *     a FOLLOW-UP. The loop takes a pluggable {@link SyzlangValidator}, so the
 *     `syz-check` validator drops in later behind the same interface with zero
 *     churn to callers.
 *
 * Reuses the LLM via the existing {@link NativeRuntime} abstraction
 * (`executeNative`), exactly like `triage/structured-verify.ts`.
 */
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntime,
} from "../runtime/types.js";

// ── syzlang vocabulary (grounded in KernelGPT's grammar + emitted specs) ──

/**
 * Built-in syzlang type names. From the syzkaller description grammar
 * (KernelGPT `step-repair-struct.txt`). A struct/union/alias/resource NAME the
 * spec itself declares is *also* a valid type — those are collected at
 * validation time and unioned with this set.
 */
const BUILTIN_TYPES = new Set<string>([
  "const",
  "intptr",
  "int8",
  "int16",
  "int32",
  "int64",
  "int8be",
  "int16be",
  "int32be",
  "int64be",
  "flags",
  "array",
  "ptr",
  "ptr64",
  "string",
  "strconst",
  "stringnoz",
  "filename",
  "glob",
  "len",
  "bytesize",
  "bytesize2",
  "bytesize4",
  "bytesize8",
  "bitsize",
  "offsetof",
  "vma",
  "vma64",
  "proc",
  "text",
  "void",
  "fmt",
  "compressed_image",
]);

/**
 * Top-level syzlang declaration keywords. A line starting with one of these
 * (other than a syscall) introduces a named entity the rest of the spec may
 * reference as a type.
 */
const DECL_KEYWORDS = new Set<string>([
  "resource",
  "type",
  "define",
  "include",
  "incdir",
  "meta",
]);

// ── Public types ──

export interface SpecGenOptions {
  /** Max infer → validate → repair iterations. Default 4 (KernelGPT-ish). */
  maxIterations?: number;
  /**
   * Pluggable validator. Defaults to {@link structurallyValidateSyzlang}.
   * The future syz-check validator (needs a syzkaller checkout) drops in here.
   */
  validator?: SyzlangValidator;
  /** Forwarded into the prompt to bias the model toward the target surface. */
  focusHint?: string;
}

/** A single structural / semantic problem found in a candidate spec. */
export interface SyzlangValidationError {
  /** 1-based line number within the spec, or 0 for whole-spec problems. */
  line: number;
  message: string;
}

export interface SyzlangValidationResult {
  valid: boolean;
  errors: SyzlangValidationError[];
}

/**
 * The validator contract. Structural today; `syz-check` tomorrow — same shape,
 * so the loop never changes. Async because a real `syz-check` shells out.
 */
export type SyzlangValidator = (
  spec: string,
) => SyzlangValidationResult | Promise<SyzlangValidationResult>;

export interface SpecGenResult {
  /** True iff a candidate passed validation within the iteration budget. */
  ok: boolean;
  /** Last candidate produced (valid if `ok`, else the best-effort attempt). */
  spec: string;
  /** Number of LLM calls made (initial inference + repairs). */
  iterations: number;
  /** Validation errors from the final attempt (empty when `ok`). */
  errors: SyzlangValidationError[];
}

// ── Structural validator ──

/**
 * Strip an inline `# comment` and trailing whitespace from a syzlang line.
 * A `#` inside a `"..."` string literal (e.g. `string["/dev/gpiochip#"]`) is
 * NOT a comment — only a `#` outside quotes starts one.
 */
function stripComment(line: string): string {
  let inStr = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i - 1] !== "\\") inStr = !inStr;
    else if (ch === "#" && !inStr) return line.slice(0, i).replace(/\s+$/, "");
  }
  return line.replace(/\s+$/, "");
}

/**
 * Collect every type name the spec *declares* — struct/union headers, `resource`
 * and `type` aliases — so references to them validate. A struct header is
 * `name {`, a union header is `name [` (at column 0, i.e. not indented field
 * lines). `resource NAME[...]` / `type NAME ...` declare the leading NAME.
 */
function collectDeclaredTypes(lines: string[]): Set<string> {
  const declared = new Set<string>();
  for (const raw of lines) {
    const line = stripComment(raw);
    if (!line.trim()) continue;

    // Indented lines are struct/union fields, not declarations.
    if (/^\s/.test(line)) continue;

    const firstWord = line.trim().split(/[\s({[]/)[0];
    if (firstWord === "resource" || firstWord === "type") {
      const name = line.trim().split(/\s+/)[1]?.split(/[[\s]/)[0];
      if (name) declared.add(name);
      continue;
    }

    // `structname {` or `unionname [` header.
    const header = line.match(/^([A-Za-z_]\w*)\s*[{[]\s*$/);
    if (header) declared.add(header[1]);
  }
  return declared;
}

/**
 * Verify `(){}[]` nesting is balanced across the whole spec and that no line
 * closes more than it opens up to that point. Returns the 1-based line of the
 * first imbalance, or 0 if balanced.
 */
function findBracketImbalance(lines: string[]): number {
  const pairs: Record<string, string> = { ")": "(", "}": "{", "]": "[" };
  const stack: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i]);
    let inStr = false;
    for (let j = 0; j < line.length; j++) {
      const ch = line[j];
      if (ch === '"' && line[j - 1] !== "\\") inStr = !inStr;
      if (inStr) continue;
      if (ch === "(" || ch === "{" || ch === "[") {
        stack.push(ch);
      } else if (ch === ")" || ch === "}" || ch === "]") {
        if (stack.pop() !== pairs[ch]) return i + 1;
      }
    }
  }
  return stack.length > 0 ? lines.length : 0;
}

/** Replace `"..."` string literals with spaces so they can't yield spurious tokens. */
function maskStrings(expr: string): string {
  return expr.replace(/"(?:[^"\\]|\\.)*"/g, (m) => " ".repeat(m.length));
}

/** ptr direction keywords — these are not type references. */
const PTR_DIRS = new Set(["in", "out", "inout"]);

/**
 * Pull type-name references out of a type expression. We enforce two
 * low-false-positive forms:
 *   - `typename[` — a parametrised type (`array[...]`, `flags[...]`, `ptr[...]`);
 *   - the element type of `ptr[dir, T]` and `array[T, ...]` — the one bare
 *     positional slot that is unambiguously a type.
 *
 * Bare flag/const values elsewhere are left alone (they need semantic info to
 * classify — that's the syz-check follow-up), keeping this conservative.
 */
function referencedTypeNames(rawExpr: string): string[] {
  const expr = maskStrings(rawExpr);
  const names: string[] = [];

  // `typename[`
  const head = /([A-Za-z_]\w*)\s*\[/g;
  let m: RegExpExecArray | null;
  while ((m = head.exec(expr)) !== null) names.push(m[1]);

  // `ptr[dir, T]` → T
  const ptr = /\bptr\d*\s*\[\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)/g;
  while ((m = ptr.exec(expr)) !== null) {
    if (PTR_DIRS.has(m[1])) names.push(m[2]);
  }

  // `array[T` / `array[T,` → T (first positional slot is the element type)
  const arr = /\barray\s*\[\s*([A-Za-z_]\w*)/g;
  while ((m = arr.exec(expr)) !== null) names.push(m[1]);

  return names;
}

/**
 * Structurally validate a syzlang spec without a syzkaller checkout.
 *
 * Checks, in order of bluntness:
 *   1. non-empty;
 *   2. balanced `(){}[]`;
 *   3. at least one syscall declaration (`name(...)`);
 *   4. each syscall's parenthesised arg list parses as `argname type[,…]`;
 *   5. every `typename[` reference resolves to a builtin or a declared type.
 *
 * This is intentionally conservative — it rejects the malformed shapes the LLM
 * actually produces (unbalanced brackets, unknown type keywords, arg-less
 * syscalls, dangling type refs) while not pretending to be `syz-check`.
 */
export function structurallyValidateSyzlang(
  spec: string,
): SyzlangValidationResult {
  const errors: SyzlangValidationError[] = [];
  if (!spec.trim()) {
    return { valid: false, errors: [{ line: 0, message: "empty spec" }] };
  }

  const lines = spec.split("\n");

  const imbalance = findBracketImbalance(lines);
  if (imbalance > 0) {
    errors.push({ line: imbalance, message: "unbalanced brackets ()/{}/[]" });
    // Bracket parsing below is unreliable once nesting is broken; report and stop.
    return { valid: false, errors };
  }

  const declared = collectDeclaredTypes(lines);
  const known = new Set<string>([...BUILTIN_TYPES, ...declared]);

  let syscallCount = 0;
  let inBlock = false; // inside a struct/union body

  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i]);
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Track struct/union bodies so we don't treat field lines as syscalls.
    if (/^[A-Za-z_]\w*\s*[{[]\s*$/.test(trimmed)) {
      inBlock = true;
      continue;
    }
    if (inBlock) {
      if (/^[}\]]/.test(trimmed)) inBlock = false;
      // (Field type refs are validated below via referencedTypeNames too.)
    }

    const firstWord = trimmed.split(/[\s({[]/)[0];

    // Top-level declaration line — validate its referenced types, skip syscall rules.
    if (DECL_KEYWORDS.has(firstWord)) {
      for (const name of referencedTypeNames(trimmed)) {
        if (!known.has(name)) {
          errors.push({ line: i + 1, message: `unknown type \`${name}\`` });
        }
      }
      continue;
    }

    // Syscall declaration: `name(...args...) [ret]`.
    const call = trimmed.match(/^([A-Za-z_]\w*(?:\$[A-Za-z_]\w*)?)\s*\((.*)\)/);
    if (!inBlock && call) {
      syscallCount++;
      const argList = call[2].trim();
      if (argList) {
        for (const arg of splitArgs(argList)) {
          // Each arg must be `argname type…`.
          const parts = arg.trim().split(/\s+/);
          if (parts.length < 2) {
            errors.push({
              line: i + 1,
              message: `malformed arg \`${arg.trim()}\` (expected \`name type\`)`,
            });
          }
        }
      }
    }

    // Validate `typename[` references on every non-declaration line.
    for (const name of referencedTypeNames(trimmed)) {
      if (!known.has(name)) {
        errors.push({ line: i + 1, message: `unknown type \`${name}\`` });
      }
    }
  }

  if (syscallCount === 0) {
    errors.push({
      line: 0,
      message: "no syscall declaration found (expected `name(...) ...`)",
    });
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Split a syscall's arg list on top-level commas only — commas inside
 * `[...]`/`{...}`/`(...)` (e.g. `ptr[in, foo]`, `flags[bar, int32]`) belong to a
 * nested type and must not split the arg.
 */
function splitArgs(argList: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of argList) {
    if (ch === "[" || ch === "{" || ch === "(") depth++;
    else if (ch === "]" || ch === "}" || ch === ")") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push(cur);
  return out;
}

// ── Prompting ──

const SYSTEM_PROMPT = [
  "You are a syzkaller specification generator and Linux kernel source analyzer.",
  "Given kernel source for a subsystem, infer a syzkaller (syzlang) description",
  "for its syscall/ioctl entry points so a fuzzer can reach them.",
  "",
  "Rules:",
  "- Output ONLY the syzlang spec inside a single ```syzlang fenced block.",
  "- Declare resources you reference (e.g. `resource fd_foo[fd]`).",
  "- Use real ioctl command names and concrete struct field types from the source.",
  "- Prefer `syz_open_dev$NAME(...) fd_foo` for /dev/foo# style devices, `openat` for constant paths.",
  "- ptr args take a direction: `ptr[in, T]`, `ptr[out, T]`, or `ptr[inout, T]`.",
  "- Keep brackets `()[]{}` balanced; every `name[` type must be a builtin or one you declared.",
].join("\n");

function buildInitialPrompt(
  subsystem: string,
  sourceSlice: string,
  focusHint?: string,
): string {
  const hint = focusHint
    ? `\nFocus: ${focusHint}\n`
    : "";
  return [
    `# Subsystem: ${subsystem}`,
    hint,
    "Infer the syzkaller (syzlang) description for the syscall/ioctl entry points",
    "in the following kernel source. Emit a single ```syzlang fenced block.",
    "",
    "## Source",
    "```c",
    sourceSlice,
    "```",
  ].join("\n");
}

function buildRepairPrompt(
  candidate: string,
  errors: SyzlangValidationError[],
): string {
  const errorList = errors
    .map((e) => (e.line > 0 ? `- line ${e.line}: ${e.message}` : `- ${e.message}`))
    .join("\n");
  return [
    "The syzlang spec you produced failed structural validation.",
    "Fix ONLY the reported problems and re-emit the COMPLETE corrected spec",
    "inside a single ```syzlang fenced block. Do not add commentary.",
    "",
    "## Your spec",
    "```",
    candidate,
    "```",
    "",
    "## Validation errors",
    errorList,
  ].join("\n");
}

/**
 * Extract the syzlang body from a model response: prefer a fenced
 * ```syzlang / ``` block, fall back to any fenced block, else the raw text.
 */
export function extractSyzlang(response: string): string {
  const fenced =
    response.match(/```(?:syzlang|syz)?\s*\n([\s\S]*?)```/i) ??
    response.match(/```\s*\n([\s\S]*?)```/);
  return (fenced ? fenced[1] : response).trim();
}

function responseText(content: NativeContentBlock[]): string {
  return content
    .filter((b): b is NativeContentBlock & { type: "text" } => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}

// ── Main loop ──

/**
 * Generate a syzlang syscall/ioctl spec for `subsystem` from `sourceSlice` via
 * an infer → validate → repair loop over `llm` (a {@link NativeRuntime}).
 *
 * The loop: infer a candidate, validate it; if invalid and budget remains,
 * re-prompt with the concrete errors and try again. Returns the first valid
 * candidate (`ok: true`) or the last attempt with its errors (`ok: false`).
 */
export async function generateSyzlangSpec(
  subsystem: string,
  sourceSlice: string,
  llm: NativeRuntime,
  opts: SpecGenOptions = {},
): Promise<SpecGenResult> {
  const maxIterations = Math.max(1, opts.maxIterations ?? 4);
  const validate = opts.validator ?? structurallyValidateSyzlang;

  let prompt = buildInitialPrompt(subsystem, sourceSlice, opts.focusHint);
  let candidate = "";
  let errors: SyzlangValidationError[] = [];

  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    const message: NativeMessage = {
      role: "user",
      content: [{ type: "text", text: prompt }],
    };
    const result = await llm.executeNative(SYSTEM_PROMPT, [message], []);
    candidate = extractSyzlang(responseText(result.content));

    const verdict = await validate(candidate);
    if (verdict.valid) {
      return { ok: true, spec: candidate, iterations: iteration, errors: [] };
    }

    errors = verdict.errors;
    prompt = buildRepairPrompt(candidate, errors);
  }

  return { ok: false, spec: candidate, iterations: maxIterations, errors };
}
