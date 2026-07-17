/**
 * Invariant-checker candidate generation — pwnkit's kernelCTF Pipeline #2.
 *
 * A sibling of `generateVariantCandidates` (variant-candidates.ts). Variant hunt
 * chases a KNOWN fix's bug class to OTHER call-sites; this hunts a DIFFERENT
 * class entirely — CONCURRENCY bugs in a subsystem's state machine, where no
 * fix seeds the search. The move that works for concurrency is not "grep for a
 * sink shape" (there is none) but "recover the invariant the locking is supposed
 * to uphold, then find where a concurrent unprivileged caller can violate it":
 *
 *   subsystem source ──LLM──▶ InvariantSpec {lock, guarded_fields, refcount, states}
 *                                   │
 *                                   ▼ (same LLM turn, spec-first-then-violate)
 *                       InvariantCandidate[] {invariant, racing syscall pair, field, primitive}
 *                                   │  map to sites
 *                                   ▼
 *                       runHuntScan(brief, candidates)   ── and ──▶ race-poc-synth.ts
 *
 * Same shape/interface as variant-candidates (returns a `brief` + `HuntCandidate[]`)
 * so it drops straight into `runHuntScan`; it additionally returns the structured
 * spec + the rich race candidates, which the 2-thread race-PoC synthesizer
 * (race-poc-synth.ts) consumes.
 *
 * The LLM does the one thing a grep can't: read a lock/refcount/state machine and
 * reason about which interleaving of two *unprivileged* entrypoints tears an
 * invariant. It is a HYPOTHESIS generator — every candidate still goes through
 * the skeptic+prover gate in `runHuntScan` (and, eventually, a real race PoC)
 * before it is believed. No self-grading here.
 */

import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { RuntimeMode } from "@pwnkit/shared";
import type { HuntBrief, HuntCandidate } from "./hunt-scan.js";
import { extractInvariantSpec } from "./invariant-spec-builder.js";

export interface InvariantHuntInput {
  /** Local source tree the subsystem files live under. */
  sourceRoot: string;
  /**
   * The subsystem's concurrent-state-machine source files (repo-relative or
   * absolute), e.g. `["net/unix/garbage.c", "net/unix/af_unix.c"]`. These
   * define the lock discipline / refcount balance / state transitions the
   * model extracts an invariant spec from.
   */
  subsystemFiles: string[];
  runtime: RuntimeMode;
  model?: string;
  /** Cap the emitted candidate sites (default 20). */
  maxCandidates?: number;
  /** Chars of source sent to the model per file (default 24000; clipped with a marker). */
  maxCharsPerFile?: number;
  log?: (msg: string) => void;
}

/**
 * The structured invariant the subsystem's locking is meant to uphold — the
 * thing a concurrency bug violates. Recovered from source by the model.
 */
export interface InvariantSpec {
  /** The lock / serializing mechanism (e.g. "unix_gc_lock", "u->lock", "RCU + refcount"). */
  lock: string;
  /** The fields that lock is supposed to protect from concurrent mutation. */
  guardedFields: string[];
  /** The refcount acquire/release balance invariant (e.g. "each skb queued holds one ref on the peer sk; GC drops exactly the queued refs"). */
  refcountBalance: string;
  /** The legal state transitions of the machine (e.g. "UNIX_GC_CANDIDATE -> scanned -> collectible"). */
  stateTransitions: string[];
}

/** One hypothesized concurrency bug: an interleaving that violates the invariant. */
export interface InvariantCandidate {
  /** The specific invariant this candidate violates (a concrete restatement from the spec). */
  invariant: string;
  /** The two UNPRIVILEGED entrypoints whose concurrent execution tears the invariant. */
  racingSyscallPair: { A: string; B: string };
  /** The field/object left in a torn/inconsistent state by the race. */
  field: string;
  /** The primitive the tear yields (e.g. "UAF on sk", "refcount underflow -> double free", "OOB"). */
  hypothesizedPrimitive: string;
  /** Where the racy access lives — repo-relative `file` or `file:line` (used as the hunt site). */
  site?: string;
}

export interface InvariantHuntPlan {
  /** Plugs straight into `runHuntScan` — the bug-class/pattern brief. */
  brief: HuntBrief;
  /** The recovered invariant spec (provenance + the race-synth input). */
  spec: InvariantSpec;
  /** The `runHuntScan` candidate sites (file + per-site hint) — one per race candidate. */
  candidates: HuntCandidate[];
  /** The rich structured race candidates (what race-poc-synth.ts consumes). */
  invariantCandidates: InvariantCandidate[];
  warnings: string[];
}

interface AnalysisFromModel {
  spec: InvariantSpec;
  candidates: InvariantCandidate[];
}

/** Read a subsystem file (repo-relative under sourceRoot, or absolute). Returns null on failure. */
function readSource(sourceRoot: string, file: string): string | null {
  const path = isAbsolute(file) ? file : join(sourceRoot, file);
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Normalize `file:line` / `file` to the repo-relative file part for site matching. */
function siteFile(site: string | undefined): string | undefined {
  if (!site) return undefined;
  const trimmed = site.trim().replace(/^\.\//, "");
  const noLine = trimmed.replace(/:\d+(?::\d+)?$/, "");
  return noLine || undefined;
}

const ANALYSIS_TOOL = {
  name: "emit_invariant_analysis",
  description: "Emit the recovered invariant spec and the concurrency-bug candidates that violate it.",
  input_schema: {
    type: "object",
    properties: {
      spec: {
        type: "object",
        description: "The invariant the subsystem's locking upholds.",
        properties: {
          lock: { type: "string", description: "The lock / serializing mechanism guarding the state machine." },
          guardedFields: { type: "array", items: { type: "string" }, description: "Fields that lock protects from concurrent mutation." },
          refcountBalance: { type: "string", description: "The refcount acquire/release balance invariant." },
          stateTransitions: { type: "array", items: { type: "string" }, description: "Legal state transitions of the machine." },
        },
        required: ["lock", "guardedFields", "refcountBalance", "stateTransitions"],
      },
      candidates: {
        type: "array",
        description: "Concurrency-bug hypotheses: interleavings of two UNPRIVILEGED entrypoints that violate the invariant.",
        items: {
          type: "object",
          properties: {
            invariant: { type: "string", description: "The specific invariant violated (a concrete restatement)." },
            racingSyscallPair: {
              type: "object",
              description: "The two unprivileged entrypoints (syscall/ioctl/handler names) that race.",
              properties: { A: { type: "string" }, B: { type: "string" } },
              required: ["A", "B"],
            },
            field: { type: "string", description: "The field/object left torn by the race." },
            hypothesizedPrimitive: { type: "string", description: "The primitive the tear yields (UAF/double-free/OOB/underflow)." },
            site: { type: "string", description: "Where the racy access lives: repo-relative file or file:line." },
          },
          required: ["invariant", "racingSyscallPair", "field", "hypothesizedPrimitive"],
        },
      },
    },
    required: ["spec", "candidates"],
  },
};

const SYSTEM =
  "You are a kernel CONCURRENCY analyst hunting race conditions in a subsystem's state machine. You are given the " +
  "source of a subsystem that maintains shared state across concurrent syscalls. Do TWO things, in order.\n\n" +
  "STEP 1 — recover the INVARIANT SPEC the locking is meant to uphold. Read the code and extract: the lock/serializing " +
  "mechanism (spinlock, mutex, RCU, seqlock, refcount as a lock); the exact FIELDS that lock is supposed to protect; " +
  "the REFCOUNT BALANCE invariant (who takes a ref, who drops it, and the equality that must hold); and the legal " +
  "STATE TRANSITIONS of the machine.\n\n" +
  "STEP 2 — hunt VIOLATIONS. Find interleavings where two concurrently-runnable, UNPRIVILEGED entrypoints (syscalls, " +
  "ioctls, netlink/socket handlers reachable without CAP_*) violate that invariant: a field mutated without the lock " +
  "held on one side; a refcount dropped twice or observed at zero mid-transition; a state read in one transition while " +
  "another transition is mid-flight. For each, name the RACING PAIR (the two entrypoints, A and B), the FIELD left torn, " +
  "the PRIMITIVE it yields (UAF / double-free / refcount underflow / OOB), and the SITE (file or file:line) of the racy " +
  "access.\n\n" +
  "Be concrete and grounded — every candidate must point at real code in the provided source, not a generic 'maybe there " +
  "is a race'. Both sides of the pair must be unprivileged and concurrently reachable; if one side needs a privilege or " +
  "can never run concurrently with the other, it is NOT a candidate. Rank the strongest (clearest lock/refcount/state " +
  "violation with a plausible primitive) first. Emit 3-8 candidates via emit_invariant_analysis.";

export async function generateInvariantCandidates(input: InvariantHuntInput): Promise<InvariantHuntPlan> {
  const log = input.log ?? (() => {});
  const warnings: string[] = [];
  const maxCandidates = input.maxCandidates ?? 20;

  if (!input.subsystemFiles || input.subsystemFiles.length === 0) {
    throw new Error("invariant hunt needs at least one subsystemFile");
  }

  // 1. Read the subsystem source.
  const sources: Array<{ file: string; text: string }> = [];
  for (const file of input.subsystemFiles) {
    const text = readSource(input.sourceRoot, file);
    if (text == null) {
      warnings.push(`could not read subsystem file: ${file}`);
      continue;
    }
    sources.push({ file, text });
  }
  if (sources.length === 0) {
    throw new Error("invariant hunt could not read any subsystemFile under sourceRoot");
  }

  // 2. LLM: recover the invariant spec, then hunt violations (one tool call,
  //    spec-first-then-violate) via the SHARED extraction primitive. The model is
  //    a HYPOTHESIS generator — the verify gate downstream, not this, decides truth.
  //    Unlike the durable-model builder, this fuses spec + candidates in one turn
  //    and consumes them inline (no stored artifact).
  const analysis = await extractInvariantSpec<AnalysisFromModel>({
    sources,
    system: SYSTEM,
    tool: ANALYSIS_TOOL,
    ...(input.model ? { model: input.model } : {}),
    ...(input.maxCharsPerFile !== undefined ? { maxCharsPerFile: input.maxCharsPerFile } : {}),
    errorLabel: "invariant-analysis",
  });

  const spec = analysis?.spec;
  if (!spec || typeof spec.lock !== "string" || !Array.isArray(spec.guardedFields)) {
    throw new Error("model did not emit a usable invariant spec");
  }
  const rawCandidates = Array.isArray(analysis?.candidates) ? analysis!.candidates : [];
  if (rawCandidates.length === 0) throw new Error("model emitted a spec but no invariant candidates");

  log(`[invariant] lock: ${spec.lock}; ${spec.guardedFields.length} guarded field(s); ${rawCandidates.length} candidate(s)`);

  // 3. Keep only well-formed candidates (both racing sides + a primitive).
  const valid = rawCandidates.filter(
    (c) =>
      c && c.racingSyscallPair && typeof c.racingSyscallPair.A === "string" && typeof c.racingSyscallPair.B === "string" &&
      typeof c.field === "string" && typeof c.hypothesizedPrimitive === "string",
  );
  if (valid.length < rawCandidates.length) {
    warnings.push(`dropped ${rawCandidates.length - valid.length} malformed candidate(s) (missing racing pair/field/primitive)`);
  }

  const invariantCandidates = valid.slice(0, maxCandidates);
  if (valid.length > maxCandidates) {
    warnings.push(`capped candidates ${valid.length} -> ${maxCandidates} (raise maxCandidates to widen)`);
  }

  // 4. Map each race candidate to a runHuntScan site. Prefer the model's `site`
  //    when it names one of the provided files; else fall back to the first
  //    subsystem file (still a real, readable path under sourceRoot).
  const knownFiles = new Set(sources.map((s) => s.file));
  const fallbackFile = sources[0].file;
  const bySite = new Map<string, HuntCandidate>(); // dedupe multiple candidates onto the same site
  for (const c of invariantCandidates) {
    const sf = siteFile(c.site);
    const path = sf && knownFiles.has(sf) ? sf : fallbackFile;
    const hint =
      `CONCURRENCY hunt. Invariant: ${c.invariant}. Race the pair ${c.racingSyscallPair.A} vs ${c.racingSyscallPair.B} ` +
      `on field '${c.field}' — hypothesized ${c.hypothesizedPrimitive}. Confirm the field is mutated/observed WITHOUT ` +
      `holding ${spec.lock} on at least one side, and that both entrypoints are unprivileged + concurrently reachable.`;
    const existing = bySite.get(path);
    if (existing) existing.hint = `${existing.hint}\n---\n${hint}`;
    else bySite.set(path, { path, hint });
  }
  const candidates = [...bySite.values()];
  log(`[invariant] ${invariantCandidates.length} race candidate(s) across ${candidates.length} site(s)`);

  const brief: HuntBrief = {
    bugClass: `concurrency: invariant violation guarded by ${spec.lock}`,
    pattern: `A field in {${spec.guardedFields.join(", ")}} is mutated or observed torn when two unprivileged entrypoints race without ${spec.lock} held on both sides. Refcount invariant: ${spec.refcountBalance}.`,
    fixReference: undefined,
  };

  return { brief, spec, candidates, invariantCandidates, warnings };
}
