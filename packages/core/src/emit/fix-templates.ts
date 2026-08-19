// Fix-template registry for the `--emit pr` flow (0sec#377).
//
// A fix template is a deterministic, *conservative* mapping from a finding to
// a unified diff that a human reviewer can accept or reject. Templates do NOT
// try to be clever: they encode the smallest, safest patch shape we are
// willing to ship as a starter suggestion. Anything ambitious belongs in a
// follow-up PR, not in the auto-emitted starter.
//
// The registry is keyed on `Finding.category`. Multiple AttackCategory values
// can map to the same template (e.g. `missing-validation` and the seed-finding
// shape both share the input-validation guard template). Unknown categories
// return null and the emitter falls back to a repro-only PR.
//
// Templates produce a `UnifiedDiff` value: a header pair and a sequence of
// hunks, ready to be persisted to a file or printed to stdout. The shape is
// intentionally serialisable (no functions, no closures) so it can be logged
// and asserted on in tests.

import type { Finding, AttackCategory } from "@0sec/shared";

/** A single hunk of a unified diff. Line counts are recomputed at render time. */
export interface UnifiedDiffHunk {
  /** Old-file starting line (1-indexed). */
  oldStart: number;
  /** New-file starting line (1-indexed). */
  newStart: number;
  /**
   * Mixed `+`/`-`/` ` lines (no leading-space sentinel — render adds it).
   * Each entry is one logical line of the hunk body, without the trailing
   * newline.
   */
  lines: Array<{ kind: "add" | "del" | "ctx"; text: string }>;
}

export interface UnifiedDiff {
  /** Repo-relative path, used for both `---` and `+++` headers. */
  filePath: string;
  /** Optional language hint, useful for downstream syntax highlighting. */
  language?: string;
  /**
   * One-line summary of what the template did — used in commit messages and
   * PR body. Phrase it as an imperative: "Replace literal secret with
   * process.env lookup".
   */
  summary: string;
  hunks: UnifiedDiffHunk[];
}

/** Render a {@link UnifiedDiff} to canonical unified-diff text. */
export function renderUnifiedDiff(diff: UnifiedDiff): string {
  const lines: string[] = [];
  lines.push(`--- a/${diff.filePath}`);
  lines.push(`+++ b/${diff.filePath}`);
  for (const hunk of diff.hunks) {
    const oldLen = hunk.lines.filter((l) => l.kind !== "add").length;
    const newLen = hunk.lines.filter((l) => l.kind !== "del").length;
    lines.push(`@@ -${hunk.oldStart},${oldLen} +${hunk.newStart},${newLen} @@`);
    for (const ln of hunk.lines) {
      const prefix = ln.kind === "add" ? "+" : ln.kind === "del" ? "-" : " ";
      lines.push(`${prefix}${ln.text}`);
    }
  }
  return lines.join("\n") + "\n";
}

/**
 * A fix template: deterministic function from a finding to a suggested patch.
 * Returning `null` means "no safe starter patch for this finding" — the
 * emitter then ships a repro-only PR instead.
 */
export type FixTemplate = (finding: Finding) => UnifiedDiff | null;

/**
 * Registry mapping logical template id → template function. The emitter
 * looks up a finding's category in {@link CATEGORY_TO_TEMPLATE} to pick the
 * template id. Tests can register custom templates by constructing a new
 * registry, so the production registry stays a const.
 */
export class FixTemplateRegistry {
  private readonly templates = new Map<string, FixTemplate>();

  register(id: string, template: FixTemplate): this {
    this.templates.set(id, template);
    return this;
  }

  get(id: string): FixTemplate | undefined {
    return this.templates.get(id);
  }

  /**
   * Resolve a finding to a diff, if any. Returns null when no template is
   * registered for the finding's category OR when the template returns null
   * (e.g. it could not locate a confident hint in `evidence`).
   */
  apply(finding: Finding): UnifiedDiff | null {
    const id = templateIdForCategory(finding.category);
    if (!id) return null;
    const tpl = this.templates.get(id);
    if (!tpl) return null;
    return tpl(finding);
  }

  /** All registered template ids (stable order). */
  ids(): string[] {
    return [...this.templates.keys()];
  }
}

/**
 * Map a finding's category to the logical template id we ship for it.
 * Unknown categories return null. Only the three starter templates from
 * #377 are wired here; future categories belong in follow-up PRs.
 */
export function templateIdForCategory(category: AttackCategory): string | null {
  switch (category) {
    case "information-disclosure":
      // Hard-coded-secret findings live under the broader
      // information-disclosure umbrella in the schema today.
      return "hard_coded_secret";
    case "missing-validation":
      return "missing_input_validation";
    case "integer-truncation":
    case "integer-overflow":
      return "integer_truncation_guard";
    default:
      return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — small, well-tested string utilities the three starter templates
// reuse. Pulled out of the template bodies so the per-category logic stays
// readable.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Pull a file-path hint out of a finding. Templates prefer, in order:
 *   1. `finding.evidence.analysis` matching `<path>:<line>` shape
 *   2. The first `<path>:<line>` in the description
 *   3. null — caller must bail out to a repro-only PR
 */
function inferFilePath(finding: Finding): { file: string; line: number } | null {
  const candidates = [
    finding.evidence?.analysis ?? "",
    finding.description ?? "",
    finding.evidence?.request ?? "",
  ];
  for (const text of candidates) {
    const m = text.match(/([A-Za-z0-9_./\-]+\.[A-Za-z0-9]+):(\d+)/);
    if (m) {
      const line = Number.parseInt(m[2]!, 10);
      if (Number.isFinite(line) && line > 0) {
        return { file: m[1]!, line };
      }
    }
  }
  return null;
}

/** Infer language from file extension. */
function inferLanguage(path: string): string | undefined {
  const ext = path.split(".").pop()?.toLowerCase();
  switch (ext) {
    case "ts":
    case "tsx":
      return "typescript";
    case "js":
    case "jsx":
    case "mjs":
    case "cjs":
      return "javascript";
    case "py":
      return "python";
    case "c":
    case "h":
      return "c";
    case "cc":
    case "cpp":
    case "cxx":
    case "hpp":
      return "cpp";
    case "go":
      return "go";
    case "rs":
      return "rust";
    default:
      return undefined;
  }
}

/**
 * Convert an arbitrary identifier hint (the variable a literal was assigned
 * to, the key in a config object, etc.) to a SCREAMING_SNAKE env-var name.
 * Falls back to `0SEC_SECRET` so we never produce an unnamed env lookup.
 */
function toEnvVarName(hint: string | undefined): string {
  if (!hint) return "0SEC_SECRET";
  const cleaned = hint
    .replace(/[^A-Za-z0-9_]/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
  if (!cleaned) return "0SEC_SECRET";
  // If it doesn't already end in a "secret-shaped" suffix, leave it as-is —
  // we don't want to invent a name that's wrong.
  return cleaned;
}

// ─────────────────────────────────────────────────────────────────────────────
// Starter templates — three categories per #377 spec.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Replace a literal secret with `process.env.<NAME>`. Conservative: we don't
 * try to parse the surrounding TS/JS; we drop a one-line suggested diff that
 * the reviewer can adapt. The line-number anchor comes from
 * `inferFilePath` — if we have no anchor we return null so the emitter ships
 * a repro-only PR.
 */
export const hardCodedSecretTemplate: FixTemplate = (finding) => {
  const anchor = inferFilePath(finding);
  if (!anchor) return null;
  const lang = inferLanguage(anchor.file);

  // The "secret literal" is what the agent placed in evidence.response if
  // it followed the convention, otherwise we use a placeholder. The actual
  // value is intentionally NEVER copied into the diff — reviewers should
  // never have the literal value land in a public PR. We mark the line as
  // a comment-removed sentinel and add the env replacement.
  const envName = toEnvVarName(extractIdentifierHint(finding));

  const isPy = lang === "python";
  const oldLine = isPy
    ? `# TODO: secret literal removed by 0sec; original at ${anchor.file}:${anchor.line}`
    : `// TODO: secret literal removed by 0sec; original at ${anchor.file}:${anchor.line}`;
  const newLine = isPy
    ? `import os  # 0sec#377 starter patch`
    : `// 0sec#377 starter patch — replace with process.env.${envName}`;
  const envExpr = isPy
    ? `value = os.environ["${envName}"]`
    : `const value = process.env.${envName};`;

  return {
    filePath: anchor.file,
    language: lang,
    summary: `Replace hard-coded secret with environment lookup (\`${envName}\`)`,
    hunks: [
      {
        oldStart: anchor.line,
        newStart: anchor.line,
        lines: [
          { kind: "del", text: oldLine },
          { kind: "add", text: newLine },
          { kind: "add", text: envExpr },
        ],
      },
    ],
  };
};

/** Lift the most-likely variable name out of the finding. Best-effort. */
function extractIdentifierHint(finding: Finding): string | undefined {
  const text = `${finding.title} ${finding.description} ${finding.evidence?.analysis ?? ""}`;
  // `apiKey = "..."` or `const FOO = "..."` shapes.
  const assign = text.match(/\b([A-Z][A-Z0-9_]{2,}|[a-z][A-Za-z0-9_]*(?:Key|Token|Secret|Password)\b)/);
  if (assign) return assign[1]!;
  return undefined;
}

/**
 * Insert a runtime input-validation guard at the start of the function the
 * finding points at. We pick the cheap shape: a single `if (typeof x !==
 * "string") return;` because zod-or-similar adoption can't be assumed. The
 * emitter notes in the PR body that the reviewer should swap in the project's
 * preferred validator (zod / yup / valibot / pydantic).
 */
export const missingInputValidationTemplate: FixTemplate = (finding) => {
  const anchor = inferFilePath(finding);
  if (!anchor) return null;
  const lang = inferLanguage(anchor.file);
  const isPy = lang === "python";

  // We assume the line the finding points at is the *entry-point* of the
  // unvalidated path (e.g. the handler signature). Insert the guard
  // immediately after it. The reviewer can move it if the anchor was off
  // by a couple of lines; that's a normal PR-review interaction.
  const inputName = extractInputHint(finding) ?? "input";
  const guard = isPy
    ? `    if not isinstance(${inputName}, str):  # 0sec#377 starter guard\n        raise TypeError("${inputName} must be str")`
    : `  if (typeof ${inputName} !== "string") {  // 0sec#377 starter guard\n    throw new TypeError("${inputName} must be a string");\n  }`;

  // Split the guard back into lines for the diff body.
  const guardLines = guard.split("\n").map((text) => ({ kind: "add" as const, text }));

  return {
    filePath: anchor.file,
    language: lang,
    summary: `Add runtime guard on \`${inputName}\` at entry of ${anchor.file}:${anchor.line}`,
    hunks: [
      {
        oldStart: anchor.line + 1,
        newStart: anchor.line + 1,
        lines: guardLines,
      },
    ],
  };
};

function extractInputHint(finding: Finding): string | undefined {
  const text = `${finding.title} ${finding.description}`;
  // Match `parameter <name>` or `argument <name>` or `\`<name>\``
  const named = text.match(/(?:parameter|argument|input|field)\s+`?([a-zA-Z_][a-zA-Z0-9_]*)`?/i);
  if (named) return named[1]!;
  const backticked = text.match(/`([a-zA-Z_][a-zA-Z0-9_]*)`/);
  if (backticked) return backticked[1]!;
  return undefined;
}

/**
 * Insert an explicit upper-bound check before an allocation, for the
 * integer-truncation / integer-overflow category. The shape is the
 * conservative C/C++ idiom:
 *
 *   if (x > MAX_FOO) return -EINVAL;
 *
 * We don't know the right `MAX_FOO` constant, so we wire the diff to use
 * `SIZE_MAX / sizeof(*ptr)` as a sentinel and a comment that asks the
 * reviewer to pick the real bound. Better than emitting nothing — the
 * reviewer at least sees the right *shape* and can refine.
 */
export const integerTruncationGuardTemplate: FixTemplate = (finding) => {
  const anchor = inferFilePath(finding);
  if (!anchor) return null;
  const lang = inferLanguage(anchor.file);
  // We require a C-family language for this guard; punting on other langs.
  if (lang !== "c" && lang !== "cpp") return null;

  const var_ = extractInputHint(finding) ?? "size";
  const guard = [
    `    /* 0sec#377 starter guard — replace SIZE_MAX/sizeof bound with the`,
    `     * real maximum for this allocation (and -EINVAL with the project's`,
    `     * preferred error code). */`,
    `    if (${var_} > SIZE_MAX / sizeof(*ptr)) {`,
    `        return -EINVAL;`,
    `    }`,
  ];

  return {
    filePath: anchor.file,
    language: lang,
    summary: `Guard against integer truncation in \`${var_}\` before allocation at ${anchor.file}:${anchor.line}`,
    hunks: [
      {
        oldStart: anchor.line,
        newStart: anchor.line,
        lines: guard.map((text) => ({ kind: "add" as const, text })),
      },
    ],
  };
};

/** Build the default registry shipped with #377 — three starter templates. */
export function createDefaultFixTemplateRegistry(): FixTemplateRegistry {
  return new FixTemplateRegistry()
    .register("hard_coded_secret", hardCodedSecretTemplate)
    .register("missing_input_validation", missingInputValidationTemplate)
    .register("integer_truncation_guard", integerTruncationGuardTemplate);
}
