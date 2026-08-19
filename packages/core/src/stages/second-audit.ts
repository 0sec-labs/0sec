/**
 * Second-audit stage — the "treat every crash as SHALLOW-by-default" step.
 *
 * This is the winner move that separates an $82k kernelCTF-class submission from
 * a first-order crash report. A raw crash / KASAN report / candidate almost
 * always names a SYMPTOM (the sink that faulted), not the ROOT. The people who
 * win do a second audit BEFORE they burn a verify budget:
 *
 *   1. Is the obvious root-cause the REAL bug, or a shallow symptom of a deeper
 *      one? (e.g. a UAF read that faults is a symptom; the deeper bug is the
 *      lifetime/refcount rule that let the object die early — fixing the read
 *      site leaves the deeper bug live and re-triggerable elsewhere.)
 *   2. If there is already an upstream fix for the obvious bug, is that fix
 *      COMPLETE or BYPASSABLE? A patch that guards ONE call-site / ONE
 *      precondition frequently misses a sibling path — the highest-EV variant.
 *   3. Emit a REFINED candidate: {deeper_root_cause, fix_bypass_hypothesis,
 *      confidence} — or "first-order is the real bug" when the audit confirms
 *      the obvious cause is genuinely the root and any fix is complete.
 *
 * It sits in front of the skeptic+prover gate as a candidate-REFINEMENT step:
 * DEEPEN first, then verify. It does not itself confirm anything (it is a model
 * reading code, so it only proposes) — the refined candidate is what the gate
 * then tries to reproduce.
 *
 * The LLM is INJECTED (a `SecondAuditModel`) so prod wires the real engine
 * runtime (LlmApiRuntime) and tests stub it with a fake — no network, no keys.
 */

import type { Finding, RuntimeMode } from "@0sec/shared";
import type {
  NativeMessage,
  NativeRuntimeResult,
  NativeToolDef,
} from "../runtime/types.js";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import type { HuntBrief, HuntCandidate } from "./hunt-scan.js";

// ── Input contract ───────────────────────────────────────────────────────────

/**
 * A crash / candidate to second-audit. One of these shapes describes the
 * first-order observation; `source` is the surrounding code the auditor reads.
 */
export interface SecondAuditInput {
  /**
   * The first-order observation. Exactly the raw thing a fuzzer / prior stage
   * handed you — a KASAN/KCSAN report string, a syzbot title + report, or a
   * HuntBrief bug class. `title` names the obvious bug; `report` is the raw
   * detail (stack trace, race annotation, diff, etc).
   */
  observation: {
    /** The obvious bug as first reported, e.g. "slab-use-after-free in tipc_conn_close". */
    title: string;
    /** Raw report detail: KASAN/KCSAN dump, stack trace, race annotation, or brief prose. */
    report: string;
    /** Optional: a HuntBrief this originated from (keeps the bug-class context). */
    brief?: HuntBrief;
  };
  /**
   * The surrounding source the auditor reads to reason about depth. Keep it to
   * the sink + the functions on the reaching/lifetime path — enough to judge
   * root cause, not the whole tree.
   */
  source: string;
  /**
   * OPTIONAL existing upstream fix for the obvious bug. When present, the audit
   * ALSO judges whether that fix is complete or bypassable. Omit when no fix
   * exists (then the audit only does the shallow-vs-deep split).
   */
  existingFix?: {
    /** The fix diff / patch text. */
    diff: string;
    /** Optional provenance (commit hash, CVE, list message-id). */
    reference?: string;
  };
  runtime: RuntimeMode;
  /** Optional engine model override (diversity / cost). */
  model?: string;
  log?: (msg: string) => void;
}

// ── Output contract ──────────────────────────────────────────────────────────

/**
 * The refined candidate the audit emits. This is what feeds the gate next.
 */
export interface SecondAuditResult {
  /**
   * The audit verdict on depth:
   *  - "deeper-root-cause": the obvious bug is a SYMPTOM; `deeperRootCause`
   *    names the real bug to chase instead.
   *  - "first-order": the audit genuinely could not find a deeper cause — the
   *    obvious bug IS the root. (Not a default; only after actually looking.)
   */
  verdict: "deeper-root-cause" | "first-order";
  /**
   * The deeper root cause to chase, when `verdict === "deeper-root-cause"`.
   * Names the real invariant that is violated (a lifetime/locking/refcount/
   * bounds-provenance rule), NOT the fault site. Empty for "first-order".
   */
  deeperRootCause: string;
  /**
   * A concrete fix-bypass hypothesis, when an `existingFix` was supplied AND the
   * audit judges it incomplete: the sibling path / missed precondition the patch
   * did not cover, phrased as something the gate can try to reproduce. Empty
   * when no fix was supplied or the fix is judged complete.
   */
  fixBypassHypothesis: string;
  /** Whether the supplied fix is judged bypassable. `false` when no fix supplied. */
  fixIsBypassable: boolean;
  /** 0..1 self-reported confidence in the refined candidate. */
  confidence: number;
  /** One-paragraph rationale (why deeper / why the fix leaks / why first-order). */
  rationale: string;
  /**
   * The refined `HuntCandidate` to hand the gate next, when the audit produced a
   * new place to look (a deeper cause or a bypass path). `undefined` for a
   * "first-order" verdict with no fix bypass — the original candidate stands.
   */
  refinedCandidate?: HuntCandidate;
  warnings: string[];
}

// ── Injectable model ─────────────────────────────────────────────────────────

/**
 * The one LLM call this stage makes, as an injectable function. Prod passes the
 * default {@link defaultSecondAuditModel} (real engine runtime); tests pass a
 * fake that returns a canned tool_use block. Mirrors the native-runtime shape so
 * the default is a thin adapter over LlmApiRuntime.executeNative.
 */
export type SecondAuditModel = (
  system: string,
  messages: NativeMessage[],
  tools: NativeToolDef[],
) => Promise<NativeRuntimeResult>;

/** The default model: routes through the engine LLM runtime (no raw keys). */
export function defaultSecondAuditModel(opts: { model?: string }): SecondAuditModel {
  return async (system, messages, tools) => {
    const rt = new LlmApiRuntime({
      type: "api",
      ...(opts.model ? { model: opts.model } : {}),
      timeout: 240_000,
    });
    return rt.executeNative(system, messages, tools, {
      onThinking() {},
      onDelta() {},
      onUsage() {},
    });
  };
}

// ── Prompt ───────────────────────────────────────────────────────────────────

const AUDIT_TOOL: NativeToolDef = {
  name: "emit_second_audit",
  description:
    "Emit the second-audit verdict: whether the obvious bug is shallow or the " +
    "root, whether any supplied upstream fix is bypassable, and the refined candidate.",
  input_schema: {
    type: "object",
    properties: {
      verdict: {
        type: "string",
        enum: ["deeper-root-cause", "first-order"],
        description:
          "'deeper-root-cause' if the obvious bug is a SYMPTOM of a deeper one; " +
          "'first-order' ONLY if, after genuinely looking, the obvious bug is the real root.",
      },
      deeperRootCause: {
        type: "string",
        description:
          "When deeper: the real invariant violated (lifetime/locking/refcount/" +
          "bounds-provenance rule) and WHERE, not the fault site. Empty for first-order.",
      },
      fixIsBypassable: {
        type: "boolean",
        description:
          "Only meaningful if an existing fix was supplied: true if the fix guards " +
          "ONE path/precondition but a sibling path or missed precondition still reaches " +
          "the bug. false if no fix supplied or the fix is complete.",
      },
      fixBypassHypothesis: {
        type: "string",
        description:
          "When fixIsBypassable: the concrete sibling path / missed precondition the " +
          "patch did not cover, phrased so it can be reproduced (which entry, which " +
          "condition, which sink). Empty otherwise.",
      },
      refinedTargetPath: {
        type: "string",
        description:
          "file[:line] the gate should re-audit next — where the deeper cause or the " +
          "bypass path lives. Empty if the original candidate still stands.",
      },
      confidence: {
        type: "number",
        description: "0..1 confidence in this refined candidate.",
      },
      rationale: {
        type: "string",
        description: "One paragraph: why deeper / why the fix leaks / why first-order.",
      },
    },
    required: ["verdict", "fixIsBypassable", "confidence", "rationale"],
  },
};

const SYSTEM =
  "You are a SECOND-AUDIT analyst for a novel-vulnerability engine. A prior stage handed you a crash / " +
  "candidate. Treat it as SHALLOW BY DEFAULT: a raw crash almost always names a SYMPTOM (the sink that " +
  "faulted), not the ROOT cause. Winners chase the deeper bug BEFORE spending a verify budget.\n\n" +
  "Do TWO things:\n" +
  "1. SHALLOW-vs-DEEP: is the obvious root cause the REAL bug, or a symptom of a deeper one? A UAF READ " +
  "that faults is a symptom — the deeper bug is the lifetime/refcount rule that let the object die early; " +
  "fixing the read site leaves the deeper bug live and re-triggerable from a sibling site. An OOB read at " +
  "one index is a symptom — the deeper bug is the missing bound on the length/provenance that produced the " +
  "index. Name the INVARIANT that is violated (lifetime / locking / refcount / bounds-provenance), and the " +
  "site that violates it — not the fault site.\n" +
  "2. FIX-COMPLETENESS (only if an existing fix is supplied): is the patch COMPLETE or BYPASSABLE? Patches " +
  "routinely guard ONE call-site or ONE precondition and miss a SIBLING path — a second entry into the same " +
  "sink, a race the added lock does not cover, a precondition the check assumes but does not enforce. If a " +
  "sibling path or missed precondition still reaches the bug, the fix is BYPASSABLE — give the concrete path.\n\n" +
  "Be honest: only return 'first-order' if you actually looked for a deeper cause and there genuinely is " +
  "none. Only claim a bypass you can point to a concrete path for. Call emit_second_audit once.";

const clip = (s: string, n: number): string =>
  s.length > n ? s.slice(0, n) + `\n...[truncated ${s.length - n} chars]` : s;

interface RawAudit {
  verdict?: string;
  deeperRootCause?: string;
  fixIsBypassable?: boolean;
  fixBypassHypothesis?: string;
  refinedTargetPath?: string;
  confidence?: number;
  rationale?: string;
}

/**
 * Run the second audit on one crash/candidate. Deterministic, single LLM call,
 * injectable model. Never throws on a malformed model reply — degrades to a
 * conservative "first-order" with a warning so the gate still gets a candidate.
 */
export async function runSecondAudit(
  input: SecondAuditInput,
  model?: SecondAuditModel,
): Promise<SecondAuditResult> {
  const log = input.log ?? (() => {});
  const warnings: string[] = [];
  const runModel = model ?? defaultSecondAuditModel({ model: input.model });

  const userParts: string[] = [
    `## Obvious bug (first-order)\n${input.observation.title}`,
    `## Raw report\n${clip(input.observation.report, 12_000)}`,
  ];
  if (input.observation.brief) {
    userParts.push(
      `## Originating bug-class brief\nclass: ${input.observation.brief.bugClass}\npattern: ${input.observation.brief.pattern}`,
    );
  }
  userParts.push(`## Surrounding source\n${clip(input.source, 24_000)}`);
  if (input.existingFix) {
    userParts.push(
      `## Existing upstream fix (judge complete vs bypassable)\n` +
        (input.existingFix.reference ? `ref: ${input.existingFix.reference}\n` : "") +
        clip(input.existingFix.diff, 16_000),
    );
  } else {
    userParts.push(
      "## Existing upstream fix\n(none supplied — only do the shallow-vs-deep split; set fixIsBypassable=false)",
    );
  }
  const messages: NativeMessage[] = [
    { role: "user", content: [{ type: "text", text: userParts.join("\n\n") }] },
  ];

  let raw: RawAudit | null = null;
  try {
    const res = await runModel(SYSTEM, messages, [AUDIT_TOOL]);
    const call = res.content.find(
      (b): b is Extract<typeof b, { type: "tool_use" }> =>
        b.type === "tool_use" && b.name === "emit_second_audit",
    );
    if (call) raw = call.input as RawAudit;
    else warnings.push("second-audit: model did not call emit_second_audit");
  } catch (e) {
    warnings.push(`second-audit: model call failed: ${String(e).slice(0, 160)}`);
  }

  // Degrade safely: a missing/garbled reply must NOT invent a deeper bug. Fall
  // back to "first-order, original candidate stands" — the gate is unaffected.
  if (!raw) {
    return {
      verdict: "first-order",
      deeperRootCause: "",
      fixBypassHypothesis: "",
      fixIsBypassable: false,
      confidence: 0,
      rationale: "second audit produced no usable verdict; treating first-order as-is",
      refinedCandidate: undefined,
      warnings,
    };
  }

  const verdict: SecondAuditResult["verdict"] =
    raw.verdict === "deeper-root-cause" ? "deeper-root-cause" : "first-order";
  const deeperRootCause = verdict === "deeper-root-cause" ? String(raw.deeperRootCause ?? "").trim() : "";
  // A bypass claim only counts when a fix was actually supplied to judge.
  const fixIsBypassable = Boolean(input.existingFix) && raw.fixIsBypassable === true;
  const fixBypassHypothesis = fixIsBypassable ? String(raw.fixBypassHypothesis ?? "").trim() : "";
  const confidence = clamp01(raw.confidence);
  const rationale = String(raw.rationale ?? "").trim();

  // Build the refined candidate the gate should chase next, if the audit found a
  // new place to look. A "deeper-root-cause" verdict OR a fix bypass both give
  // one; a plain "first-order" with no bypass leaves the original candidate.
  let refinedCandidate: HuntCandidate | undefined;
  const path = String(raw.refinedTargetPath ?? "").trim();
  if (verdict === "deeper-root-cause" || fixIsBypassable) {
    const hintBits: string[] = [];
    if (deeperRootCause) hintBits.push(`Deeper root cause (chase THIS, not the fault site): ${deeperRootCause}.`);
    if (fixBypassHypothesis) hintBits.push(`Fix-bypass hypothesis: ${fixBypassHypothesis}.`);
    hintBits.push(`Original first-order symptom was: ${input.observation.title}.`);
    // Fall back to the source-derived path only when the model named none. When
    // it named none and we have nothing, keep it undefined rather than fabricate.
    if (path) {
      refinedCandidate = { path, hint: hintBits.join(" ") };
    } else {
      warnings.push("second-audit: no refined target path emitted; gate should reuse the original candidate path");
    }
  }

  log(
    `[second-audit] verdict=${verdict} bypassable=${fixIsBypassable} conf=${confidence.toFixed(2)}` +
      (deeperRootCause ? ` deeper="${deeperRootCause.slice(0, 80)}"` : ""),
  );

  return {
    verdict,
    deeperRootCause,
    fixBypassHypothesis,
    fixIsBypassable,
    confidence,
    rationale,
    refinedCandidate,
    warnings,
  };
}

function clamp01(n: unknown): number {
  const v = typeof n === "number" && Number.isFinite(n) ? n : 0;
  return v < 0 ? 0 : v > 1 ? 1 : v;
}

// ── runHuntScan adapter ──────────────────────────────────────────────────────

/**
 * Adapt {@link runSecondAudit} into the `refine` hook `runHuntScan` expects:
 * `(finding, candidate) => Promise<HuntCandidate>`. For each surfaced finding it
 * runs the second audit and returns the DEEPENED candidate (root-cause / fix-
 * bypass path) when the audit found one, else the original candidate unchanged —
 * so the gate then verifies the deeper candidate. Deepen, then verify.
 *
 * `loadSource` fetches the surrounding code for a candidate (prod: read the file
 * under sourceRoot; tests: return a fixture). `existingFixFor` optionally
 * supplies a known upstream fix to judge for bypassability. Both are injected so
 * this module stays free of filesystem / lore-mirror coupling.
 */
export function makeSecondAuditRefiner(opts: {
  runtime: RuntimeMode;
  loadSource: (candidate: HuntCandidate) => Promise<string>;
  existingFixFor?: (finding: Finding, candidate: HuntCandidate) => Promise<SecondAuditInput["existingFix"] | undefined>;
  model?: SecondAuditModel;
  modelName?: string;
  /** Skip audits below this confidence when refining (default 0 — always take a produced candidate). */
  minConfidence?: number;
  log?: (msg: string) => void;
}): (finding: Finding, candidate: HuntCandidate) => Promise<HuntCandidate> {
  const minConf = opts.minConfidence ?? 0;
  return async (finding, candidate) => {
    const source = await opts.loadSource(candidate);
    const existingFix = opts.existingFixFor ? await opts.existingFixFor(finding, candidate) : undefined;
    const result = await runSecondAudit(
      {
        observation: { title: finding.title, report: finding.description ?? "" },
        source,
        existingFix,
        runtime: opts.runtime,
        model: opts.modelName,
        log: opts.log,
      },
      opts.model,
    );
    if (result.refinedCandidate && result.confidence >= minConf) {
      // Preserve the original path when the audit named none.
      return { path: result.refinedCandidate.path || candidate.path, hint: result.refinedCandidate.hint };
    }
    return candidate;
  };
}
