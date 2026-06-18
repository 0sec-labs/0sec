/**
 * protocol/conformance-gen.ts — LLM infer → validate → repair loop that turns
 * (authoritative spec excerpt + implementation source excerpt) into a validated
 * set of {@link ConformanceRule}s and ranked {@link DivergenceHypothesis}es.
 *
 * This is a direct clone of `kernel/spec-gen.ts`'s scaffold
 * (`generateSyzlangSpec`, :462-493), re-pointed:
 *   - spec-gen.ts infers a syzlang spec FROM kernel source and validates its
 *     syntax with a pluggable `SyzlangValidator` (:125-127);
 *   - this module infers conformance RULES + DIVERGENCE HYPOTHESES from a spec
 *     excerpt + impl excerpt and validates the model's JSON against a Zod
 *     schema, re-prompting with the concrete errors on a mismatch.
 *
 * Same loop shape: infer a candidate, validate it; if invalid and budget
 * remains, re-prompt with the concrete error and try again (bounded to N
 * iterations). Same pluggable-validator seam so a richer semantic validator can
 * drop in later behind one interface with zero churn to callers.
 *
 * Reuses the LLM via the existing {@link NativeRuntime} abstraction
 * (`executeNative`) — the SAME unified-service entry point spec-gen.ts uses. No
 * raw vendor fetch/keys (per repo rule). The model decides nothing about
 * confirmed/refuted here — that is the deterministic oracle's job
 * (`oracle-http.ts`). This step only proposes hypotheses.
 *
 * Scope of THIS slice (#972, deliberately bounded):
 *   - The spec excerpt is RFC/ABNF prose passed in as a STRING. No
 *     RFC-fetching/ingestion infra (that is the `spec-ingest.ts` gap).
 *   - HTTP/text-protocol shaped only.
 */
import { z } from "zod";
import type {
  NativeMessage,
  NativeContentBlock,
  NativeRuntime,
} from "../runtime/types.js";
import type {
  ConformanceRule,
  DivergenceHypothesis,
  ProtocolModel,
} from "./model.js";

// ── Zod structural validator (the SyzlangValidator drop-in analogue) ──

const REQUIREMENT_LEVELS = [
  "MUST",
  "MUST NOT",
  "SHOULD",
  "SHOULD NOT",
  "MAY",
] as const;

const HTTP_SURFACES = ["method", "header", "status"] as const;

const httpExerciseSchema = z
  .object({
    method: z.string().min(1),
    path: z.string().optional(),
    headers: z.record(z.string()).optional(),
    body: z.string().optional(),
  })
  .strict();

const conformanceRuleSchema = z
  .object({
    id: z.string().min(1),
    specCitation: z.string().min(1),
    level: z.enum(REQUIREMENT_LEVELS),
    surface: z.enum(HTTP_SURFACES),
    mandate: z.string().min(1),
    exercise: httpExerciseSchema,
  })
  .strict();

const predictionSchema = z
  .object({
    surface: z.enum(HTTP_SURFACES),
    expectedStatusIn: z.array(z.number().int()).optional(),
    forbiddenStatusIn: z.array(z.number().int()).optional(),
    requiredHeader: z.string().optional(),
    forbiddenHeader: z.string().optional(),
  })
  .strict()
  // A prediction is useless to the oracle unless it carries at least one
  // matcher. Reject the empty shell so the model self-corrects.
  .refine(
    (p) =>
      (p.expectedStatusIn && p.expectedStatusIn.length > 0) ||
      (p.forbiddenStatusIn && p.forbiddenStatusIn.length > 0) ||
      Boolean(p.requiredHeader) ||
      Boolean(p.forbiddenHeader),
    { message: "predictedObservable carries no matcher (status set or header)" },
  );

const divergenceHypothesisSchema = z
  .object({
    ruleId: z.string().min(1),
    specCitation: z.string().min(1),
    level: z.enum(REQUIREMENT_LEVELS),
    implLocation: z.string().min(1),
    rationale: z.string().min(1),
    predictedObservable: predictionSchema,
    exercise: httpExerciseSchema,
    confidence: z.number().min(0).max(1),
  })
  .strict();

const conformanceModelSchema = z
  .object({
    rules: z.array(conformanceRuleSchema).min(1),
    hypotheses: z.array(divergenceHypothesisSchema),
  })
  .strict()
  // Every hypothesis must reference a rule that actually exists — a dangling
  // ruleId means the model invented a citation the oracle can't ground.
  .superRefine((model, ctx) => {
    const ruleIds = new Set(model.rules.map((r) => r.id));
    model.hypotheses.forEach((h, i) => {
      if (!ruleIds.has(h.ruleId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["hypotheses", i, "ruleId"],
          message: `hypothesis references unknown ruleId \`${h.ruleId}\``,
        });
      }
    });
  });

/** Parsed, validated conformance model: rules + ranked hypotheses. */
export interface ConformanceModel {
  rules: ConformanceRule[];
  hypotheses: DivergenceHypothesis[];
}

/** A single structural problem found in a candidate model (mirrors `SyzlangValidationError`). */
export interface ConformanceValidationError {
  /** Dotted JSON path to the offending field, or "" for whole-model problems. */
  path: string;
  message: string;
}

export interface ConformanceValidationResult {
  valid: boolean;
  /** The parsed model when `valid`; undefined otherwise. */
  model?: ConformanceModel;
  errors: ConformanceValidationError[];
}

/**
 * The validator contract — structural (Zod) today; a richer semantic validator
 * tomorrow, same shape, so the loop never changes. Mirrors `SyzlangValidator`
 * (`kernel/spec-gen.ts:125-127`). Sync today; typed async-capable for a future
 * validator that shells out.
 */
export type ConformanceValidator = (
  candidate: unknown,
) => ConformanceValidationResult | Promise<ConformanceValidationResult>;

/**
 * Default structural validator: parse the candidate against the Zod schema and
 * flatten any issues into `{ path, message }` (the shape the repair prompt
 * renders). Intentionally conservative — it rejects the malformed shapes a
 * model actually emits (missing fields, unknown enum values, matcher-less
 * predictions, dangling ruleIds) without pretending to be a semantic checker.
 */
export function structurallyValidateConformanceModel(
  candidate: unknown,
): ConformanceValidationResult {
  const parsed = conformanceModelSchema.safeParse(candidate);
  if (parsed.success) {
    return { valid: true, model: parsed.data, errors: [] };
  }
  const errors = parsed.error.issues.map((issue) => ({
    path: issue.path.join("."),
    message: issue.message,
  }));
  return { valid: false, errors };
}

// ── Options + result (mirror SpecGenOptions / SpecGenResult) ──

export interface ConformanceGenOptions {
  /** Max infer → validate → repair iterations. Default 4 (spec-gen-ish). */
  maxIterations?: number;
  /** Pluggable validator. Defaults to {@link structurallyValidateConformanceModel}. */
  validator?: ConformanceValidator;
  /** Forwarded into the prompt to bias the model toward a surface (e.g. "method handling"). */
  focusHint?: string;
}

export interface ConformanceGenResult {
  /** True iff a candidate passed validation within the iteration budget. */
  ok: boolean;
  /** The validated model, when `ok`. */
  model?: ConformanceModel;
  /** Raw last candidate text the model produced (for debugging a failed run). */
  rawCandidate: string;
  /** Number of LLM calls made (initial inference + repairs). */
  iterations: number;
  /** Validation errors from the final attempt (empty when `ok`). */
  errors: ConformanceValidationError[];
}

// ── Prompting (mirrors spec-gen.ts's SYSTEM_PROMPT / build*Prompt / extract) ──

const SYSTEM_PROMPT = [
  "You are a protocol-conformance analyst. Given (a) an authoritative protocol",
  "specification excerpt and (b) a slice of an implementation's source, you",
  "extract the spec's testable requirements and hypothesize where the",
  "implementation diverges from them.",
  "",
  "Rules:",
  "- Output ONLY a single ```json fenced block — no prose outside it.",
  "- The JSON has exactly two top-level keys: `rules` and `hypotheses`.",
  "- A rule is { id, specCitation, level, surface, mandate, exercise }.",
  "  - `level` is one of MUST, MUST NOT, SHOULD, SHOULD NOT, MAY (RFC 2119).",
  "  - `surface` is one of method, header, status (Tier-1 is HTTP/text only).",
  "  - `exercise` is the HTTP request that exercises the rule:",
  "    { method, path?, headers?, body? }.",
  "- A hypothesis is { ruleId, specCitation, level, implLocation, rationale,",
  "  predictedObservable, exercise, confidence }.",
  "  - `ruleId` MUST reference one of the rules you emitted.",
  "  - `predictedObservable` is the deterministic, machine-checkable shape a",
  "    CONFORMANT response must have: { surface, expectedStatusIn?,",
  "    forbiddenStatusIn?, requiredHeader?, forbiddenHeader? }. It MUST carry at",
  "    least one matcher. Use `forbiddenStatusIn` for codes that CONCRETELY",
  "    prove a violation (e.g. a 2xx to a method the spec says MUST be rejected).",
  "  - `confidence` is your prior plausibility (0–1) that the impl diverges. It",
  "    is NOT a verdict — a deterministic oracle decides confirmed/refuted.",
  "- Prefer MUST/MUST NOT rules: only those can be confirmed by the oracle.",
  "  SHOULD-level divergences are advisory and cannot be confirmed, so do not",
  "  over-invest hypotheses in them.",
].join("\n");

function buildInitialPrompt(
  model: ProtocolModel,
  implExcerpt: string,
  focusHint?: string,
): string {
  const hint = focusHint ? `\nFocus: ${focusHint}\n` : "";
  return [
    `# Protocol: ${model.name} (${model.version}, ${model.specRef})`,
    hint,
    "Extract the testable conformance requirements from the specification",
    "excerpt below, then hypothesize where the implementation source diverges",
    "from them. Emit a single ```json fenced block with `rules` and",
    "`hypotheses`.",
    "",
    "## Specification excerpt",
    "```",
    model.specExcerpt ?? "",
    "```",
    "",
    "## Implementation source excerpt",
    "```",
    implExcerpt,
    "```",
  ].join("\n");
}

function buildRepairPrompt(
  rawCandidate: string,
  errors: ConformanceValidationError[],
): string {
  const errorList = errors
    .map((e) => (e.path ? `- ${e.path}: ${e.message}` : `- ${e.message}`))
    .join("\n");
  return [
    "The JSON you produced failed structural validation.",
    "Fix ONLY the reported problems and re-emit the COMPLETE corrected JSON",
    "inside a single ```json fenced block. Do not add commentary.",
    "",
    "## Your output",
    "```",
    rawCandidate,
    "```",
    "",
    "## Validation errors",
    errorList,
  ].join("\n");
}

/**
 * Extract the JSON body from a model response: prefer a fenced ```json / ```
 * block, fall back to any fenced block, else the raw text. Mirrors
 * `extractSyzlang` in spec-gen.ts.
 */
export function extractJsonBlock(response: string): string {
  const fenced =
    response.match(/```(?:json)?\s*\n([\s\S]*?)```/i) ??
    response.match(/```\s*\n([\s\S]*?)```/);
  return (fenced ? fenced[1] : response).trim();
}

function responseText(content: NativeContentBlock[]): string {
  return content
    .filter((b): b is NativeContentBlock & { type: "text" } => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}

/**
 * Parse the model's JSON text into a candidate object. A parse failure is
 * itself a validation error (whole-model `path: ""`) so the loop re-prompts
 * with it rather than throwing — same self-correcting shape as spec-gen.ts.
 */
function parseCandidate(
  raw: string,
): { ok: true; value: unknown } | { ok: false; error: string } {
  try {
    return { ok: true, value: JSON.parse(raw) };
  } catch (err) {
    return {
      ok: false,
      error: `not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

// ── Main loop (clone of generateSyzlangSpec) ──

/**
 * Infer + validate + repair a {@link ConformanceModel} for `model` from
 * `implExcerpt` via an infer → validate → repair loop over `llm` (a
 * {@link NativeRuntime}). The spec text rides on `model.specExcerpt`.
 *
 * The loop: infer a candidate, parse + validate it; if invalid and budget
 * remains, re-prompt with the concrete errors and try again. Returns the first
 * valid candidate (`ok: true`) or the last attempt with its errors
 * (`ok: false`). Byte-for-byte the same control flow as
 * `generateSyzlangSpec` (`kernel/spec-gen.ts:462-493`).
 */
export async function generateConformanceModel(
  model: ProtocolModel,
  implExcerpt: string,
  llm: NativeRuntime,
  opts: ConformanceGenOptions = {},
): Promise<ConformanceGenResult> {
  const maxIterations = Math.max(1, opts.maxIterations ?? 4);
  const validate = opts.validator ?? structurallyValidateConformanceModel;

  let prompt = buildInitialPrompt(model, implExcerpt, opts.focusHint);
  let rawCandidate = "";
  let errors: ConformanceValidationError[] = [];

  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    const message: NativeMessage = {
      role: "user",
      content: [{ type: "text", text: prompt }],
    };
    const result = await llm.executeNative(SYSTEM_PROMPT, [message], []);
    rawCandidate = extractJsonBlock(responseText(result.content));

    const parsed = parseCandidate(rawCandidate);
    if (!parsed.ok) {
      errors = [{ path: "", message: parsed.error }];
      prompt = buildRepairPrompt(rawCandidate, errors);
      continue;
    }

    const verdict = await validate(parsed.value);
    if (verdict.valid && verdict.model) {
      return {
        ok: true,
        model: verdict.model,
        rawCandidate,
        iterations: iteration,
        errors: [],
      };
    }

    errors = verdict.errors;
    prompt = buildRepairPrompt(rawCandidate, errors);
  }

  return { ok: false, rawCandidate, iterations: maxIterations, errors };
}
