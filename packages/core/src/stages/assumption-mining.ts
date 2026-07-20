/**
 * ASSUMPTION-MINING — pwnkit's FOURTH seedless discovery axis, and the first one
 * that reasons like an auditor instead of pointing a fixed-shape checker at code.
 *
 * WHY THIS EXISTS (the gap the other three seedless stages structurally cannot
 * close). subsystem-invariant-model / interproc-refcount / concurrency-race all
 * ask the SAME question — "is THIS access correctly guarded?" — i.e. a LOCAL
 * violation of a FIXED invariant shape (a lock held at a field touch, a get/put
 * balanced, a lockset consistent). The deepest historical LPEs are a DIFFERENT
 * shape and no fixed schema can represent them:
 *
 *   a function RELIES ON a precondition it does NOT itself establish, and a
 *   reachable context reaches the same object WITHOUT establishing it.
 *
 *   DirtyPipe   — splice relies on "PIPE_BUF_FLAG_CAN_MERGE reflects THIS write";
 *                 a reused pipe_buffer reaches the merge path with the flag stale.
 *   AF_UNIX GC  — the GC relies on "in-flight count == real graph reachability";
 *                 an SCM_RIGHTS send reaches the same skb without re-establishing it.
 *   DirtyCred   — a consumer relies on "this file/cred is the one I validated";
 *                 a UAF swaps a same-cache object the validation never covered.
 *   io_uring    — completion relies on "the fd/creds validated AT SUBMIT still hold";
 *                 async handoff reaches it after the establishing context is gone.
 *
 * Our old schema has no field for "ptr validated by caller V" / "fd resolved once" /
 * "state S unreachable here", so we could not hunt their violation. This stage
 * represents exactly that: it MINES the implicit relied-on assumptions each function
 * makes, then adversarially hunts REACHABLE contexts that violate them.
 *
 *   subsystem source ──LLM (ONCE)──▶ AssumptionModel {per-fn relied-on preconditions
 *                                     + the TOKEN a caller/lock/API uses to establish
 *                                     each}  ──stored as JSON──┐  durable, re-checkable
 *                                                              │
 *      ┌───────────────────────────────────────────────────────┘
 *      ▼
 *  STAGE 1b  enforced-vs-relied cross-check (DETERMINISTIC, no LLM — the primary FP
 *            bound): drop prose-only / non-mechanizable establishers; verify each
 *            "enforced-local" claim against the body and reclassify when the token is
 *            absent; keep only genuinely relied-on, security-relevant assumptions.
 *      ▼
 *  CALLER-SCAN enumerator (DETERMINISTIC, no LLM — the v0 mechanism): generalizes
 *            concurrency-race's MUST lock-set + computePropagatedLocks from "lock K
 *            held on the path" to "establisherToken present on the path". An
 *            establisher-propagation fixpoint (a caller that INHERITS the establisher
 *            from ITS callers is NOT a violation — the proven FP-killer) leaves only
 *            callers that reach the subject WITHOUT establishing the precondition.
 *      ▼
 *  assumptionsToHuntPlan ──runHuntScan(composeGate(skeptic, …))──▶ confirmed, ranked
 *
 * HONEST SCOPE — read before trusting a context. This is a CANDIDATE generator; a
 * surviving context is an assumption to DISPROVE, not a bug:
 *   • The mine is one LLM turn — assumption extraction precision is the input-quality
 *     bound; 1b removes the mechanically-uncheckable ones but cannot fix a wrong
 *     relied-on claim.
 *   • The caller-scan is NAME-BASED (buildCallGraph): indirect / fn-pointer / macro
 *     call edges are invisible, so a subject reached only through a fn pointer looks
 *     caller-less (no contexts). "Establisher present" is coarse MUST — a caller that
 *     calls the establisher ANYWHERE in its body counts as establishing (conservative:
 *     it SUPPRESSES more, trading recall for a lower FP rate — the point of v0).
 *   • Propagation is the FP-killer but under-suppresses on exported/entry functions
 *     (external callers unknown → treated as not-establishing → kept).
 * Every surviving context flows through the SAME skeptic+prover gate the other stages
 * use; the gate, not this file, adjudicates.
 */

import { readFileSync } from "node:fs";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import type { RuntimeMode } from "@pwnkit/shared";
import { buildCallGraph, type CallGraph, type FnDef } from "./interproc-refcount.js";
import {
  composeGate,
  makeSkepticVerifier,
  runHuntScan,
  type HuntBrief,
  type HuntCandidate,
  type HuntScanResult,
  type HuntVerifier,
} from "./hunt-scan.js";
import { extractInvariantSpec } from "./invariant-spec-builder.js";
import { resolveContainedSourcePath } from "./subsystem-invariant-model.js";
import { witnessDualViewContexts, type DynamicWitnessDeps, type WitnessDualViewResult } from "./dynamic-witness.js";
import { scoreGeometry } from "../kernel/geometry-score.js";
import type { Finding } from "@pwnkit/shared";

// ── The stored assumption model (durable, versioned like InvariantModel) ────────

/** Current schema version — bump when the shape changes so a stored model migrates/rejects. */
export const ASSUMPTION_MODEL_VERSION = 1 as const;

/**
 * The KIND of relied-on precondition. Each maps to a shape whose violation is a
 * classic deep bug: `revalidated`/`state-precondition` = double-fetch / TOCTOU;
 * `called-once` = re-entrant free/init; `ownership-exclusive` = dual-view /
 * DirtyCred; `refcount-positive`/`non-null` = UAF; `size-consistent` = split
 * accounting (Baron Samedit-style).
 */
export type AssumptionKind =
  | "non-null"
  | "validated-range"
  | "revalidated"
  | "state-precondition"
  | "called-once"
  | "refcount-positive"
  | "lock-held"
  | "field-initialized"
  | "ownership-exclusive"
  | "size-consistent";

/**
 * WHERE the precondition is supposed to be established. Only the `relied-on-*`
 * classes are huntable by this stage (the function does NOT establish it itself,
 * so a reachable context can skip it). `enforced-local` is verified + demoted by
 * stage 1b — a function that truly enforces its own precondition has no external
 * violator.
 */
export type AssumptionProvenance =
  | "enforced-local"
  | "relied-on-caller"
  | "relied-on-subsystem"
  | "relied-on-cross-api"
  | "relied-on-concurrency";

/** Security dimension the assumption protects. 1b keeps only the first four. */
export type SecurityRelevance = "lifetime" | "bounds" | "authz" | "type" | "other";

/**
 * How a violating context is MECHANICALLY detected. `establisherToken` is the
 * load-bearing field: the token whose ABSENCE on a reaching path == a violation.
 */
export interface ViolationOracle {
  /** The detection mechanism (provenance/among-what — free-form but small vocabulary). */
  mechanism:
    | "establisher-absent-on-path"
    | "state-not-established"
    | "revalidation-absent"
    | "establisher-absent-cross-api";
  /** The object/expression the assumption is about (`sk`, `skb->len`, `pipe->bufs`). */
  target: string;
  /**
   * The token whose ABSENCE on a path reaching the subject == a violation — a
   * CALL token a caller/lock/API uses to establish the precondition
   * (`mutex_lock`, `sock_hold`, `fdget`, a validator `nla_parse`, a guard helper).
   * Must be mechanizable (an identifier the checker can grep for) or 1b drops it.
   */
  establisherToken: string;
  /** Alternate establisher tokens that also satisfy the precondition. */
  establisherAliases?: string[];
}

/** One mined, relied-on precondition. */
export interface Assumption {
  /** Stable id (`<subject>#<n>`), assigned at mine time. */
  id: string;
  kind: AssumptionKind;
  /** The object the precondition constrains (optional; also in oracle.target). */
  object?: string;
  /** The function that RELIES on the precondition. */
  subject: string;
  /** Human statement of the precondition the subject relies on but does not establish. */
  predicate: string;
  /** Where the reliance lives (file:line or function). */
  location: string;
  provenance: AssumptionProvenance;
  /** Who normally establishes it (a caller / lock / API name) — provenance note. */
  establishedBy?: string;
  oracle: ViolationOracle;
  securityRelevance: SecurityRelevance;
}

/** The durable, re-checkable assumption model for a subsystem. */
export interface AssumptionModel {
  modelVersion: number;
  subsystem: string;
  subsystemFiles: string[];
  assumptions: Assumption[];
  builtAt: string;
  notes?: string;
}

// ── Mine (LLM, once) ────────────────────────────────────────────────────────────

/**
 * Few-shot archetypes steering extraction toward BUG-RICH relied-on predicates,
 * encoded from the deep-LPE taxonomy (A1-A12). These are EXAMPLES of the shape to
 * emit, not patterns to match — they teach the model to state a precondition +
 * name its establisher token, biased to the classes that have actually produced
 * deep LPEs.
 */
const ASSUMPTION_ARCHETYPE_FEWSHOTS = [
  // A9 dual-view / DirtyCred — a consumer relies on the object being the one it validated.
  `dual-view / DirtyCred (ownership-exclusive): a function uses a file/cred/sk it looked up EARLIER, ` +
    `relying that no concurrent path swapped a same-type object underneath it. subject=the consumer; ` +
    `predicate="'file' is still the same object validated at lookup"; establisherToken=the lookup/get ` +
    `that pins it (fget/fdget/get_file/sock_hold); kind=ownership-exclusive; securityRelevance=lifetime.`,
  // A6/err-path double-put — a cleanup relies on the ref not already having been released.
  `err-path double-put (refcount-positive): a release relies on the ref being HELD at that point, but ` +
    `an error path already released it. subject=the releasing fn; predicate="'sk' still holds a ref here"; ` +
    `establisherToken=the get that must dominate the put (sock_hold/get_pid/kref_get); kind=refcount-positive; ` +
    `securityRelevance=lifetime.`,
  // A1/double-fetch — a use relies on a value not having changed since it was validated.
  `double-fetch / revalidate (revalidated): a function validates a length/index, then RE-READS the same ` +
    `user/shared value at use, relying it did not change. subject=the using fn; predicate="'len' at use ` +
    `equals the validated 'len'"; establisherToken=the bounds check/copy that must re-run (copy_from_user/ ` +
    `check_add_overflow/a *_ok validator); kind=revalidated; securityRelevance=bounds.`,
  // A2/called-once — an init/free relies on running exactly once per object.
  `called-once (called-once): an init/free/attach relies on running EXACTLY ONCE for an object, but a ` +
    `reachable re-entry runs it twice. subject=the once-fn; predicate="this runs once per object"; ` +
    `establisherToken=the guard/state flag that must gate re-entry (test_and_set_bit/a state== check/ ` +
    `a WAS_INIT flag); kind=called-once; securityRelevance=lifetime.`,
  // A11/A12 authz sibling / incomplete-fix — a handler relies on a cap check a sibling path skips.
  `authz sibling / incomplete-fix (state-precondition): a handler relies on a capability/permission ` +
    `having been checked by the dispatcher, but a sibling entry reaches it without the check. subject=the ` +
    `handler; predicate="caller verified CAP_NET_ADMIN in the target netns"; establisherToken=the check a ` +
    `caller must perform (ns_capable/capable/netlink_capable); kind=state-precondition; securityRelevance=authz.`,
  // A9' cross-api dual-view (THE high-value shape) — request/submit phase vs reply/completion/release phase.
  `cross-api dual-view / cross-phase (relied-on-cross-api): a REQUEST/SUBMIT/CREATE phase sets up a long-lived ` +
    `object (a fuse_req, an io_uring registered fd/creds, a dma_buf, a reused pipe_buffer) and a SECOND, ` +
    `userspace-/IRQ-/completion-driven phase (the REPLY/COMPLETION/RELEASE view) reaches the SAME object via a ` +
    `DISTINCT entry. subject=the phase that RELIES on stability; object='struct fuse_req' (name the STRUCT TYPE, ` +
    `it is the dual-view join); predicate="req fields validated at request time are not mutated by the reply path"; ` +
    `establisherToken=the flag/lock/state the setup phase sets that the second phase must honor (a *_INIT/*_LOCKED ` +
    `flag, req->state==, a held lock); kind=ownership-exclusive or state-precondition; provenance=relied-on-cross-api; ` +
    `securityRelevance=lifetime or type.`,
  // fd-install / SCM_RIGHTS dual-view — installer establishes a type/validity the consumer trusts.
  `fd-install dual-view (relied-on-cross-api): one API INSTALLS an fd/file into a receiver (SCM_RIGHTS, fd ` +
    `passing) whose type/validity the CONSUMER assumes was checked at install. subject=the receiver/consumer; ` +
    `object='struct file'; predicate="the installed file was type-checked to the expected f_op/proto_ops"; ` +
    `establisherToken=the validating check the install path must perform (an f_op== compare, a proto check, a ` +
    `security_ hook); kind=ownership-exclusive; provenance=relied-on-cross-api; securityRelevance=type.`,
];

const MINE_TOOL = {
  name: "emit_assumption_set",
  description:
    "Emit the set of implicit RELIED-ON preconditions in the subsystem. Do NOT hunt bugs. For each key " +
    "function, state a precondition it DEPENDS ON but does NOT itself establish, and name the exact TOKEN " +
    "(a call / lock / validator identifier) that a caller, a lock, or another API uses to establish it — " +
    "that token's ABSENCE on a path is what a separate deterministic checker will hunt.",
  input_schema: {
    type: "object",
    properties: {
      assumptions: {
        type: "array",
        description: "One entry per relied-on precondition. Prefer preconditions on objects reachable from unprivileged syscalls.",
        items: {
          type: "object",
          properties: {
            kind: {
              type: "string",
              enum: [
                "non-null", "validated-range", "revalidated", "state-precondition", "called-once",
                "refcount-positive", "lock-held", "field-initialized", "ownership-exclusive", "size-consistent",
              ],
              description: "The precondition shape (see the archetypes in the system prompt).",
            },
            object: { type: "string", description: "The object/struct the precondition constrains, e.g. 'struct sock'." },
            subject: { type: "string", description: "The function that RELIES on the precondition (exact name as defined)." },
            predicate: { type: "string", description: "The precondition, e.g. \"'other' still holds an sk ref here\"." },
            location: { type: "string", description: "Where the reliance is, as file:line or function name." },
            provenance: {
              type: "string",
              enum: ["enforced-local", "relied-on-caller", "relied-on-subsystem", "relied-on-cross-api", "relied-on-concurrency"],
              description: "Where the precondition is supposed to be established. Use enforced-local ONLY if the subject itself establishes it.",
            },
            establishedBy: { type: "string", description: "Who normally establishes it (a caller / lock / API name)." },
            oracle: {
              type: "object",
              properties: {
                mechanism: {
                  type: "string",
                  enum: ["establisher-absent-on-path", "state-not-established", "revalidation-absent", "establisher-absent-cross-api"],
                },
                target: { type: "string", description: "The object/expression checked, e.g. 'other' or 'skb->len'." },
                establisherToken: {
                  type: "string",
                  description: "The SINGLE call/lock/validator identifier that establishes the precondition, verbatim as it appears in code (e.g. 'sock_hold', 'mutex_lock', 'ns_capable'). The checker greps this literally — a prose phrase is useless.",
                },
                establisherAliases: { type: "array", items: { type: "string" }, description: "Other tokens that also establish it." },
              },
              required: ["mechanism", "target", "establisherToken"],
            },
            securityRelevance: {
              type: "string",
              enum: ["lifetime", "bounds", "authz", "type", "other"],
              description: "Which security dimension the precondition protects.",
            },
          },
          required: ["kind", "subject", "predicate", "provenance", "oracle", "securityRelevance"],
        },
      },
      notes: { type: "string", description: "Free-form provenance notes." },
    },
    required: ["assumptions"],
  },
};

const MINE_SYSTEM =
  "You are a world-class kernel auditor performing ASSUMPTION MINING. You are given a subsystem's source. " +
  "Your job is NOT to find bugs — it is to make the code's IMPLICIT contract EXPLICIT: for each key function, " +
  "state a precondition it RELIES ON but does NOT itself establish, and name the exact TOKEN a caller, a lock, " +
  "or another API uses to establish that precondition. A separate deterministic checker will then hunt reachable " +
  "contexts where that token is ABSENT.\n\n" +
  "Think about the deepest bug classes and state the assumption whose violation WOULD be one — these archetypes " +
  "are the shape to emit (not patterns to grep):\n  - " +
  ASSUMPTION_ARCHETYPE_FEWSHOTS.join("\n  - ") +
  "\n\nRULES:\n" +
  "  1. establisherToken MUST be a real identifier that appears verbatim in the source (a function/macro call, a " +
  "lock acquire, a validator). NEVER a prose phrase — the checker matches it literally.\n" +
  "  2. Use provenance 'enforced-local' ONLY when the subject establishes the precondition itself; otherwise pick " +
  "the relied-on-* class that says WHO establishes it (caller / subsystem / cross-api / concurrency).\n" +
  "  3. Prefer preconditions on objects reachable from UNPRIVILEGED syscalls, and prefer lifetime / bounds / authz " +
  "/ type relevance (a race on a lifetime pointer, a skipped bounds/authz check) over cosmetic ones.\n" +
  "  4. 'subject' must be an exact function name as defined in the source.\n" +
  "  5. establisherAliases — CRITICAL for precision. When the precondition can be established through a FAMILY of " +
  "tokens (sibling macros like CMSG_LEN/CMSG_SPACE/CMSG_ALIGN, a helper that WRAPS the raw primitive such as " +
  "unix_table_double_lock() wrapping spin_lock(), or several equivalent validators), put the establisherToken as the " +
  "one you consider primary and list EVERY other token that also establishes it in establisherAliases. The " +
  "deterministic checker treats a caller that uses the token OR any alias (directly or through a wrapper) as having " +
  "established the precondition — a missing alias/wrapper is the #1 false-positive source, so be generous here.\n" +
  "  6. Prefer the WRAPPER identifier the surrounding code actually calls (e.g. unix_state_lock, unix_table_double_lock) " +
  "as the establisherToken when one exists, and list the raw primitive it bottoms out in as an alias.\n" +
  "  7. HIGHEST PRIORITY — DUAL-VIEW / CROSS-PHASE seams. The deepest LPEs (DirtyPipe, DirtyCred, fuse " +
  "request-vs-reply, io_uring submit-vs-completion, SCM_RIGHTS install-vs-consume) are NOT single-caller " +
  "preconditions — they are one LONG-LIVED OBJECT reached by TWO DISTINCT APIs/phases where the second phase does " +
  "not re-establish what the first set up. When you see an object that OUTLIVES a single call and is reached from " +
  "MULTIPLE entry points or lifecycle phases (create/open vs release; request/submit vs reply/completion; " +
  "install vs consume), EMIT a relied-on-cross-api assumption for it: set provenance='relied-on-cross-api' (or " +
  "'relied-on-concurrency' for a race), name the STRUCT TYPE in 'object' verbatim (e.g. 'struct fuse_req' — the " +
  "type name is the mechanical join the dual-view checker greps), and pick kind ownership-exclusive / " +
  "state-precondition / called-once / field-initialized / revalidated. Prefer these cross-phase assumptions over " +
  "plain caller-precondition ones. Emit via emit_assumption_set.";

interface MineFromLlm {
  assumptions: Array<Omit<Assumption, "id">>;
  notes?: string;
}

export interface MineAssumptionsInput {
  /** Local source tree the subsystem files live under. */
  sourceRoot: string;
  /** Subsystem label for the stored artifact (e.g. `"net/unix"`). */
  subsystem: string;
  /** The subsystem's key source files (canonical repo-relative paths under `sourceRoot`). */
  subsystemFiles: string[];
  model?: string;
  /** Chars of source sent to the model per file (default from extractInvariantSpec). */
  maxCharsPerFile?: number;
  log?: (msg: string) => void;
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

/**
 * MINE (LLM, once). Reads the subsystem source and produces the explicit
 * {@link AssumptionModel} — the relied-on preconditions + their establisher
 * tokens. The ONLY LLM call in the pipeline; 1b + the caller-scan downstream are
 * deterministic and re-run against the stored model for free.
 */
export async function mineAssumptions(input: MineAssumptionsInput): Promise<AssumptionModel> {
  const log = input.log ?? (() => {});
  if (!input.subsystemFiles || input.subsystemFiles.length === 0) {
    throw new Error("assumption mining needs at least one subsystemFile");
  }
  const sources: Array<{ file: string; text: string }> = [];
  for (const file of input.subsystemFiles) {
    const text = readSource(input.sourceRoot, file);
    if (text == null) {
      log(`[assumption-mine] could not read ${file}`);
      continue;
    }
    sources.push({ file, text });
  }
  if (sources.length === 0) throw new Error("assumption mining could not read any subsystemFile under sourceRoot");

  const out = await extractInvariantSpec<MineFromLlm>({
    sources,
    system: MINE_SYSTEM,
    tool: MINE_TOOL,
    ...(input.model ? { model: input.model } : {}),
    ...(input.maxCharsPerFile !== undefined ? { maxCharsPerFile: input.maxCharsPerFile } : {}),
    errorLabel: "assumption-mine",
  });

  const raw = Array.isArray(out?.assumptions) ? out!.assumptions : [];
  const assumptions = normalizeAssumptions(raw);
  if (assumptions.length === 0) throw new Error("assumption mine emitted no well-formed assumptions");
  log(`[assumption-mine] mined ${assumptions.length} relied-on assumption(s) in ${input.subsystem}`);
  return {
    modelVersion: ASSUMPTION_MODEL_VERSION,
    subsystem: input.subsystem,
    subsystemFiles: sources.map((s) => s.file),
    assumptions,
    builtAt: new Date().toISOString(),
    ...(out?.notes ? { notes: out.notes } : {}),
  };
}

/** Validate + id-stamp the raw LLM assumptions (drops malformed ones). */
export function normalizeAssumptions(raw: Array<Omit<Assumption, "id">>): Assumption[] {
  const perSubject = new Map<string, number>();
  const out: Assumption[] = [];
  for (const a of raw) {
    if (!a || typeof a.subject !== "string" || !a.subject) continue;
    if (!a.oracle || typeof a.oracle.establisherToken !== "string" || !a.oracle.establisherToken) continue;
    if (typeof a.predicate !== "string" || !a.predicate) continue;
    const n = (perSubject.get(a.subject) ?? 0) + 1;
    perSubject.set(a.subject, n);
    out.push({
      id: `${a.subject}#${n}`,
      kind: a.kind,
      ...(a.object ? { object: a.object } : {}),
      subject: a.subject,
      predicate: a.predicate,
      location: typeof a.location === "string" ? a.location : a.subject,
      provenance: a.provenance,
      ...(a.establishedBy ? { establishedBy: a.establishedBy } : {}),
      oracle: {
        mechanism: a.oracle.mechanism,
        target: typeof a.oracle.target === "string" && a.oracle.target ? a.oracle.target : a.subject,
        establisherToken: a.oracle.establisherToken,
        ...(Array.isArray(a.oracle.establisherAliases) ? { establisherAliases: a.oracle.establisherAliases } : {}),
      },
      securityRelevance: a.securityRelevance,
    });
  }
  return out;
}

// ── Durable artifact ────────────────────────────────────────────────────────────

/** Serialize an assumption model to JSON (creating parent dirs). Returns the path. */
export function storeAssumptionModel(model: AssumptionModel, path: string): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(model, null, 2) + "\n", "utf8");
  return path;
}

/** Load + validate a stored assumption model. Throws on a version mismatch. */
export function loadAssumptionModel(path: string): AssumptionModel {
  const model = JSON.parse(readFileSync(path, "utf8")) as AssumptionModel;
  if (model.modelVersion !== ASSUMPTION_MODEL_VERSION) {
    throw new Error(`stored assumption model is v${model.modelVersion}, checker is v${ASSUMPTION_MODEL_VERSION} — re-mine`);
  }
  if (!Array.isArray(model.assumptions)) throw new Error("stored assumption model has no assumptions array");
  return model;
}

// ── STAGE 1b: enforced-vs-relied cross-check (deterministic, no LLM) ─────────────

/** A dropped assumption + why (for the honest funnel). */
export interface DroppedAssumption {
  assumption: Assumption;
  reason: string;
}

export interface CrossCheckResult {
  /** Assumptions that survived: genuinely relied-on, mechanizable, security-relevant. */
  kept: Assumption[];
  /** Assumptions dropped, with the reason (prose-only / enforced / off-scope relevance). */
  dropped: DroppedAssumption[];
  /** Assumptions reclassified enforced-local → relied-on-caller (establisher absent in body). */
  reclassified: Assumption[];
}

/** The security dimensions 1b keeps (drops "other"). */
const KEEP_RELEVANCE = new Set<SecurityRelevance>(["lifetime", "bounds", "authz", "type"]);

/** Common English / prose tokens an establisher must not be (a phrase, not a call). */
const NON_MECHANIZABLE = new Set<string>([
  "n/a", "na", "none", "the", "a", "caller", "user", "userspace", "unknown", "somewhere",
  "before", "after", "valid", "check", "checked", "the_caller", "todo", "tbd",
]);

/**
 * True when `token` is a mechanizable establisher — a single identifier the
 * checker can grep as a call (`sock_hold`, `mutex_lock`, `ns_capable`). Rejects
 * empty / multi-word prose / punctuation / the stopword list. Length >= 3 keeps
 * incidental one/two-char noise out without excluding real short kernel calls.
 */
export function isMechanizableEstablisher(token: string): boolean {
  const t = (token ?? "").trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(t)) return false;
  if (t.length < 3) return false;
  if (NON_MECHANIZABLE.has(t.toLowerCase())) return false;
  return true;
}

/** Best-effort: does `fnBody` contain a call to `token` (i.e. `token(`)? */
function bodyCallsToken(fnBody: string, token: string): boolean {
  const esc = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`\\b${esc}\\s*\\(`).test(fnBody);
}

/** Leading identifier of an expression (`req->args.x` → `req`, `sk` → `sk`). */
function leadingIdent(expr: string): string {
  const m = (expr ?? "").trim().match(/^([A-Za-z_]\w*)/);
  return m ? m[1] : "";
}

/** Trailing identifier of an expression (`req->state` → `state`, `mode` → `mode`). */
function trailingIdent(expr: string): string {
  const m = (expr ?? "").trim().match(/([A-Za-z_]\w*)\s*$/);
  return m ? m[1] : "";
}

/** Every balanced `if (...)` / `while (...)` condition text in a function body. */
function guardConditions(body: string): string[] {
  const out: string[] = [];
  const re = /\b(?:if|while)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) {
    let i = m.index + m[0].length - 1; // at the opening '('
    let depth = 0;
    const start = i + 1;
    for (; i < body.length; i++) {
      if (body[i] === "(") depth++;
      else if (body[i] === ")") { depth--; if (depth === 0) break; }
    }
    out.push(body.slice(start, i));
    re.lastIndex = i + 1;
  }
  return out;
}

/** Argument text of the FIRST call to `name` in `body` (balanced parens), or null. */
function callArgsOf(body: string, name: string): string | null {
  const re = new RegExp(`\\b${escapeReStr(name)}\\s*\\(`);
  const m = re.exec(body);
  if (!m) return null;
  let i = m.index + m[0].length - 1;
  let depth = 0;
  const start = i + 1;
  for (; i < body.length; i++) {
    if (body[i] === "(") depth++;
    else if (body[i] === ")") { depth--; if (depth === 0) break; }
  }
  return body.slice(start, i);
}

/** Local escape helper (mirror of the module `escapeRe`, hoisted for the 1b helpers). */
function escapeReStr(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Assert/WARN-family self-enforcement calls a subject uses to assert its OWN contract. */
const SELF_ASSERT_FAMILY = ["lockdep_assert_held", "assert_spin_locked", "WARN_ON_ONCE", "WARN_ON", "BUG_ON", "VM_BUG_ON_PAGE", "VM_BUG_ON"];

/**
 * PRECISION FIX (v2) — recognize a SELF-ENFORCING subject. v1's surviving class-A/C
 * false positives were assumptions whose SUBJECT actually establishes / asserts the
 * token itself, in a form 1b's call-only `bodyCallsToken` check could not see:
 *   • a flag-test guard — `if (x & FLAG)` / `if (!(mode & FMODE_*))` on the object;
 *   • a `lockdep_assert_held` / `*_assert_held` / `assert_spin_locked` on the lock
 *     (the subject ASSERTS the caller established the contract — a violating caller
 *     trips a WARN, so it is not a latent bug; the assert IS the enforcement);
 *   • a `WARN_ON`/`BUG_ON`/`VM_BUG_ON` whose condition names the object/establisher.
 * When any of these reference the assumption's object/establisher, the subject is
 * self-enforcing (or asserts an external contract) and has NO silent violator to
 * hunt — drop it. Targeted to the assumption's own tokens so an unrelated guard in
 * the body does not over-drop. Returns a drop reason, or null when not self-enforcing.
 */
export function subjectSelfEnforces(body: string, a: Assumption): string | null {
  const tokens = [a.oracle.establisherToken, ...(a.oracle.establisherAliases ?? [])].filter(isMechanizableEstablisher);
  const target = a.oracle.target || a.object || "";
  const tvar = leadingIdent(target);
  const tfield = trailingIdent(target);
  const refs = [tvar, tfield, ...tokens].filter((r) => r && r.length >= 2);
  const wordIn = (hay: string, w: string): boolean => new RegExp(`\\b${escapeReStr(w)}\\b`).test(hay);

  // (a) lock-held: a lockdep/spinlock assert IS the enforcement of a caller-held lock.
  if (a.kind === "lock-held" && /\b(?:lockdep_assert_held|\w*_assert_held|assert_spin_locked)\s*\(/.test(body)) {
    return "subject asserts its lock is caller-held (lockdep_assert_held/*_assert_held) — self-enforcing (external contract asserted, not a silent violator)";
  }
  // (b) WARN_ON/BUG_ON/VM_BUG_ON guarding the establisher or object → the subject checks the contract.
  for (const fam of SELF_ASSERT_FAMILY) {
    const arg = callArgsOf(body, fam);
    if (arg && refs.some((r) => wordIn(arg, r))) {
      return `subject guards its contract with ${fam}(…${refs.find((r) => wordIn(arg, r))}…) — self-enforcing`;
    }
  }
  // (c) a guard condition that TESTS the establisher token, or flag-tests the object.
  for (const cond of guardConditions(body)) {
    const tokHit = tokens.find((t) => wordIn(cond, t));
    if (tokHit) return `subject tests establisher '${tokHit}' in an if/while guard — self-enforcing`;
    for (const v of [tvar, tfield].filter((x) => x && x.length >= 2)) {
      // `<obj> & FLAG` / `!(<obj> & FLAG)` — a bitmask flag-test on the object the assumption is about.
      if (new RegExp(`\\b${escapeReStr(v)}\\b[^;{}]*&\\s*[A-Z_][A-Z0-9_]{2,}`).test(cond)) {
        return `subject flag-tests '${v}' against a FLAG in a guard — self-enforcing`;
      }
    }
  }
  return null;
}

/**
 * STAGE 1b — the primary FALSE-POSITIVE BOUND (deterministic, NO LLM). Three
 * deterministic filters over the mined model, using each subject's body text
 * (`bodies`: name → body, from {@link buildFunctionBodyIndex}):
 *   1. DROP any assumption whose establisherToken is non-mechanizable (prose-only)
 *      — the checker cannot grep a phrase, so it can never find its absence.
 *   2. For each `enforced-local` claim, VERIFY the establisher token is actually in
 *      the subject's body; if ABSENT, reclassify to `relied-on-caller` (the subject
 *      does not in fact enforce it, so a caller must — and can skip it).
 *   3. KEEP only relied-on-* assumptions with securityRelevance in
 *      {lifetime, bounds, authz, type}.
 * An `enforced-local` claim VERIFIED in (2) is dropped: a function that truly
 * establishes its own precondition has no external violator to hunt. An
 * `enforced-local` claim whose subject body is UNREADABLE (not in `bodies`) is
 * dropped too — we cannot confirm a violator, the safe under-approximation.
 */
export function crossCheckAssumptions(model: AssumptionModel, bodies: Map<string, string>): CrossCheckResult {
  const kept: Assumption[] = [];
  const dropped: DroppedAssumption[] = [];
  const reclassified: Assumption[] = [];

  for (const a of model.assumptions) {
    // Filter 1: mechanizable establisher.
    if (!isMechanizableEstablisher(a.oracle.establisherToken)) {
      dropped.push({ assumption: a, reason: `non-mechanizable establisher token "${a.oracle.establisherToken}" (prose-only)` });
      continue;
    }

    // Filter 1b (v2 precision fix): drop a SELF-ENFORCING subject — one whose body
    // establishes/asserts the token in a NON-CALL form 1b's call-check misses (a
    // flag-test guard, a lockdep_assert_held, a WARN_ON of the contract). Kills the
    // v1 class-A/C FPs (the guard is present, asserted by the subject itself). Runs
    // for ALL provenances; only fires when the guard names THIS assumption's tokens.
    const sbody = bodies.get(a.subject);
    if (sbody != null) {
      const selfReason = subjectSelfEnforces(sbody, a);
      if (selfReason) {
        dropped.push({ assumption: a, reason: selfReason });
        continue;
      }
    }

    // Filter 2: verify enforced-local, else reclassify (only when we can read the body).
    let effective = a;
    if (a.provenance === "enforced-local") {
      const body = bodies.get(a.subject);
      if (body == null) {
        dropped.push({ assumption: a, reason: `enforced-local but ${a.subject}() body unreadable — cannot confirm a violator (safe drop)` });
        continue;
      }
      const establishes =
        bodyCallsToken(body, a.oracle.establisherToken) ||
        (a.oracle.establisherAliases ?? []).some((alias) => isMechanizableEstablisher(alias) && bodyCallsToken(body, alias));
      if (establishes) {
        dropped.push({ assumption: a, reason: `enforced-local verified — ${a.subject}() establishes ${a.oracle.establisherToken} itself (no external violator)` });
        continue;
      }
      effective = { ...a, provenance: "relied-on-caller" };
      reclassified.push(effective);
    }

    // Filter 3: security-relevance.
    if (!KEEP_RELEVANCE.has(effective.securityRelevance)) {
      dropped.push({ assumption: a, reason: `securityRelevance '${effective.securityRelevance}' not in {lifetime,bounds,authz,type}` });
      continue;
    }
    kept.push(effective);
  }
  return { kept, dropped, reclassified };
}

/** Build a name→body-text index from the subsystem sources (top-level C functions). */
export function buildFunctionBodyIndex(sources: Array<{ file: string; text: string }>): Map<string, string> {
  const out = new Map<string, string>();
  for (const { text } of sources) {
    for (const fn of splitTopLevelFunctions(text)) {
      if (!out.has(fn.name)) out.set(fn.name, fn.text);
    }
  }
  return out;
}

/**
 * Minimal brace-scoped top-level function splitter (comment/string aware), local
 * to this stage so 1b can read a subject's body without depending on the invariant
 * model's internals. Mirrors subsystem-invariant-model's splitter shape but stays
 * self-contained (only name + text are needed here).
 */
function splitTopLevelFunctions(src: string): Array<{ name: string; text: string }> {
  const blanked = blankCommentsAndStrings(src);
  const out: Array<{ name: string; text: string }> = [];
  const n = blanked.length;
  let depth = 0;
  const CONTROL = new Set(["if", "for", "while", "switch", "do", "else", "return", "sizeof", "typeof", "__attribute__", "case", "default", "goto", "asm", "__asm__", "static_assert"]);
  for (let i = 0; i < n; i++) {
    const ch = blanked[i];
    if (ch === "{") {
      if (depth === 0) {
        let j = i - 1;
        while (j >= 0 && /\s/.test(blanked[j])) j--;
        if (j >= 0 && blanked[j] === ")") {
          let pd = 0;
          let k = j;
          for (; k >= 0; k--) {
            if (blanked[k] === ")") pd++;
            else if (blanked[k] === "(") { pd--; if (pd === 0) break; }
          }
          if (k >= 0) {
            let m = k - 1;
            while (m >= 0 && /\s/.test(blanked[m])) m--;
            let e = m;
            while (e >= 0 && /[A-Za-z0-9_]/.test(blanked[e])) e--;
            const name = blanked.slice(e + 1, m + 1).trim();
            if (name && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && !CONTROL.has(name)) {
              let bd = 0;
              let end = i;
              for (; end < n; end++) {
                if (blanked[end] === "{") bd++;
                else if (blanked[end] === "}") { bd--; if (bd === 0) break; }
              }
              let sigStart = e + 1;
              while (sigStart > 0 && blanked[sigStart - 1] !== "\n") sigStart--;
              out.push({ name, text: src.slice(sigStart, Math.min(n, end + 1)) });
              i = end;
              depth = 0;
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
  return out;
}

/** Blank comments + string/char literals to spaces (length/line preserving). */
function blankCommentsAndStrings(src: string): string {
  const out = src.split("");
  let i = 0;
  const n = src.length;
  const blank = (a: number, b: number) => { for (let k = a; k < b && k < n; k++) if (out[k] !== "\n") out[k] = " "; };
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === "/" && c2 === "/") { let j = i + 2; while (j < n && src[j] !== "\n") j++; blank(i, j); i = j; }
    else if (c === "/" && c2 === "*") { let j = i + 2; while (j < n && !(src[j] === "*" && src[j + 1] === "/")) j++; j = Math.min(n, j + 2); blank(i, j); i = j; }
    else if (c === '"' || c === "'") {
      const q = c; let j = i + 1;
      while (j < n) { if (src[j] === "\\") { j += 2; continue; } if (src[j] === q) { j++; break; } if (src[j] === "\n") break; j++; }
      blank(i, j); i = j;
    } else i++;
  }
  return out.join("");
}

// ── CALLER-SCAN enumerator (deterministic, no LLM — the v0 mechanism) ────────────
//
// Generalizes concurrency-race's MUST lock-set + computePropagatedLocks from
// "lock K held on the path" to "establisherToken present on the path":
//   • local(F)  = establisher tokens F calls anywhere in its body (coarse MUST).
//   • establisherSet(F) fixpoint = local(F) ∪ { E : F has >=1 in-subsystem caller AND
//     EVERY caller has E in ITS establisherSet } — the propagation lift that makes a
//     caller INHERITING E from its own callers NOT a violation (the proven FP-killer).
//   • For assumption (subject S, token E): each in-subsystem caller C of S with
//     E ∉ establisherSet(C) reaches S WITHOUT establishing E → a ViolatingContext.
// Exported/entry functions have unknown external callers, so they never inherit
// (kept as not-establishing) — conservative: we would rather keep a candidate than
// wrongly suppress a genuinely lock-free external entry.

/** One caller that reaches a subject without establishing its precondition. */
export interface ViolatingContext {
  assumptionId: string;
  /** The relied-on subject the caller reaches. */
  subject: string;
  /** The caller that reaches `subject` without establishing the precondition. */
  caller: string;
  callerFile: string;
  /** 1-based line of the call to `subject` in `caller` (best-effort). */
  callLine: number;
  /** The establisher token that is absent on this path. */
  establisherToken: string;
  /** True when the caller is an unprivileged syscall/ioctl-style entry (ranked highest). */
  unprivEntry: boolean;
  detail: string;
  /** v2 DUAL-VIEW: true when this context is a cross-api/cross-phase pair, not a caller-scan hit. */
  dualView?: boolean;
  /**
   * v2 DUAL-VIEW: the SIBLING entry that DOES establish the guarantee (`entryA`), paired
   * against `caller` (`entryB`, the phase that reaches the same object WITHOUT it).
   */
  pairedEntry?: string;
  /** v2 DUAL-VIEW: the object TYPE token both entries operate on (`fuse_req`, `dma_buf`). */
  object?: string;
  /** DUAL-VIEW field-granular: the shared struct MEMBER both phases contend on (the seam key). */
  field?: string;
}

/** Names that read as an unprivileged syscall / ioctl / socket-op entry point. */
const UNPRIV_ENTRY_RE =
  /(^__?sys_|^__do_sys_|_ioctl$|_recvmsg$|_sendmsg$|_recvmmsg$|_sendmmsg$|_setsockopt$|_getsockopt$|_read$|_write$|_poll$|_mmap$|_release$|_connect$|_bind$|_listen$|_accept)/;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * ESTABLISHER-WRAPPER resolution — the v1 precision fix (kills the dominant v0 FP
 * class). v0's `local(F)` counted a token established ONLY when F calls the raw
 * establisher token itself. But the deepest guards are reached through a HELPER:
 * `unix_table_double_lock()` acquires the bucket `spin_lock`; a `CMSG_*` family
 * macro; a `validate_*` wrapper. A caller that establishes the precondition THROUGH
 * such a helper is NOT a violation — but v0's name-based scan can't see the guard
 * under the wrapper's name, so it flagged every one (all 15 net/unix v0 candidates
 * were this shape).
 *
 * This is the establisher analog of interproc-refcount's `resolveWrapperOps`, which
 * resolves get/put wrappers by return-ownership / param-put evidence. Establishers
 * (locks, validators, capability checks) are rarely RETURNED or called on a bare
 * PARAM — `unix_table_double_lock()` locks `&unix_table_locks[hash]` (derived from
 * its args) and returns void — so `resolveWrapperOps`'s get/put heuristics do not
 * recognize them. We therefore lift the SAME token-presence MUST v0 already applies
 * to the raw token (local(F) = "F calls E anywhere") across call hops: F establishes
 * E when F's body calls E, OR calls an in-subsystem function whose body (transitively,
 * bounded) establishes E.
 *
 * Returns fnName → the establisher tokens a call to that in-subsystem function
 * establishes. HONEST LIMIT: a MUST-ish over-approximation of "establishes" — a
 * wrapper that acquires E on only one branch still counts, so a GENERIC token (a
 * bare `spin_lock` relied on by many subjects) can over-suppress (lower recall).
 * That is the deliberate v0 precision-over-recall trade extended one layer; the
 * skeptic gate, not this map, adjudicates the survivors.
 */
export function computeEstablisherWrappers(
  cg: CallGraph,
  establisherTokens: Set<string>,
  maxRounds = 4,
): Map<string, Set<string>> {
  const defined = new Set(cg.fns.map((f) => f.name));
  // Seed: a function that DIRECTLY calls a raw establisher token establishes it.
  const establishes = new Map<string, Set<string>>();
  for (const fn of cg.fns) {
    const s = new Set<string>();
    for (const call of fn.calls) if (establisherTokens.has(call.callee)) s.add(call.callee);
    establishes.set(fn.name, s);
  }
  // Fixpoint (callee direction): a function that calls another in-subsystem
  // function establishing E (transitively) also establishes E — the wrapper lift.
  for (let round = 0; round < Math.max(1, maxRounds); round++) {
    let changed = false;
    for (const fn of cg.fns) {
      const cur = establishes.get(fn.name)!;
      for (const call of fn.calls) {
        if (!defined.has(call.callee)) continue;
        const via = establishes.get(call.callee);
        if (!via) continue;
        for (const t of via) if (!cur.has(t)) { cur.add(t); changed = true; }
      }
    }
    if (!changed) break;
  }
  return establishes;
}

/**
 * Build a name→establisher-set map to a bounded fixpoint. `establisherTokens` is
 * the union of every assumption's establisherToken + aliases (only these matter).
 * `local(F)` counts a token as established if F calls it anywhere OR reaches it
 * through a wrapper (`wrappers`, from {@link computeEstablisherWrappers} — the v1
 * fix). Propagation is the MUST-intersection over F's in-subsystem callers,
 * iterated. Exported/entry functions (no in-subsystem callers) never gain a
 * propagated token. Passing `wrappers=undefined` reproduces v0 (direct-token only)
 * — used for the FP-suppression ablation.
 */
export function computeEstablisherSets(
  cg: CallGraph,
  establisherTokens: Set<string>,
  exported: Set<string>,
  maxRounds = 8,
  wrappers?: Map<string, Set<string>>,
): Map<string, Set<string>> {
  // local(F): establisher tokens F establishes — directly (F calls the token) and,
  // when `wrappers` is supplied, through a helper F calls (the v1 wrapper lift).
  const local = new Map<string, Set<string>>();
  for (const fn of cg.fns) {
    const s = wrappers?.get(fn.name) ? new Set(wrappers.get(fn.name)) : new Set<string>();
    for (const call of fn.calls) if (establisherTokens.has(call.callee)) s.add(call.callee);
    local.set(fn.name, s);
  }
  // callee → its in-subsystem callers.
  const callersOf = new Map<string, Set<string>>();
  const defined = new Set(cg.fns.map((f) => f.name));
  for (const fn of cg.fns) {
    for (const call of fn.calls) {
      if (!defined.has(call.callee)) continue;
      const set = callersOf.get(call.callee) ?? new Set<string>();
      set.add(fn.name);
      callersOf.set(call.callee, set);
    }
  }

  const est = new Map<string, Set<string>>();
  for (const fn of cg.fns) est.set(fn.name, new Set(local.get(fn.name)));

  for (let round = 0; round < Math.max(1, maxRounds); round++) {
    let changed = false;
    for (const fn of cg.fns) {
      const callers = callersOf.get(fn.name);
      // No in-subsystem callers OR exported (unknown external callers) → no propagation.
      if (!callers || callers.size === 0 || exported.has(fn.name)) continue;
      // MUST-intersection over callers of (their current establisherSet).
      let inter: Set<string> | null = null;
      for (const c of callers) {
        const cs = est.get(c) ?? new Set<string>();
        if (inter === null) inter = new Set(cs);
        else for (const t of [...inter]) if (!cs.has(t)) inter.delete(t);
        if (inter.size === 0) break;
      }
      if (!inter || inter.size === 0) continue;
      const cur = est.get(fn.name)!;
      for (const t of inter) {
        if (!cur.has(t)) { cur.add(t); changed = true; }
      }
    }
    if (!changed) break;
  }
  return est;
}

/** Collect EXPORT_SYMBOL'd names (external, possibly establisher-free callers). */
function collectExportedSymbols(sources: Array<{ file: string; text: string }>): Set<string> {
  const out = new Set<string>();
  const re = /EXPORT_SYMBOL(?:_GPL|_NS|_NS_GPL)?\s*\(\s*([A-Za-z_]\w*)/g;
  for (const { text } of sources) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) out.add(m[1]);
  }
  return out;
}

/** Line (1-based) of the first call to `callee` inside `callerBody` text, or 0. */
function callLineInBody(callerBody: string, callerStartLine: number, callee: string): number {
  const re = new RegExp(`\\b${escapeRe(callee)}\\s*\\(`);
  const m = re.exec(callerBody);
  if (!m) return callerStartLine;
  let nl = 0;
  for (let k = 0; k < m.index; k++) if (callerBody[k] === "\n") nl++;
  return callerStartLine + nl;
}

export interface CallerScanOptions {
  maxContexts?: number;
  maxPropagationRounds?: number;
  /**
   * Resolve establisher WRAPPERS (v1, default true): count a caller that reaches
   * the establisher through a helper (`unix_table_double_lock`→`spin_lock`, a
   * `CMSG_*` family macro) as establishing it. Set false to reproduce v0's
   * direct-token-only scan (the FP-suppression ablation).
   */
  resolveWrappers?: boolean;
  /** Bounded wrapper-closure hops (default 4). */
  wrapperRounds?: number;
  log?: (msg: string) => void;
}

/**
 * The caller-scan: for every kept assumption, enumerate in-subsystem callers of
 * its subject that reach it WITHOUT establishing the precondition (and do not
 * inherit the establisher via propagation). NO LLM. `bodies` maps fn name → body
 * text (for the call-line + coarse establisher-anywhere check).
 */
export function scanViolatingContexts(
  kept: Assumption[],
  cg: CallGraph,
  sources: Array<{ file: string; text: string }>,
  bodies: Map<string, string>,
  opts: CallerScanOptions = {},
): ViolatingContext[] {
  const log = opts.log ?? (() => {});
  const maxContexts = opts.maxContexts ?? 60;

  const establisherTokens = new Set<string>();
  for (const a of kept) {
    establisherTokens.add(a.oracle.establisherToken);
    for (const alias of a.oracle.establisherAliases ?? []) if (isMechanizableEstablisher(alias)) establisherTokens.add(alias);
  }
  const exported = collectExportedSymbols(sources);
  // v1: resolve establisher wrappers (default on) so a caller that establishes the
  // precondition through a helper is not a violation — the dominant v0 FP fix.
  const wrappers =
    opts.resolveWrappers === false
      ? undefined
      : computeEstablisherWrappers(cg, establisherTokens, opts.wrapperRounds ?? 4);
  const est = computeEstablisherSets(cg, establisherTokens, exported, opts.maxPropagationRounds ?? 8, wrappers);

  // callee → in-subsystem callers (FnDef) for the enumeration.
  const callersOf = new Map<string, FnDef[]>();
  const defined = new Set(cg.fns.map((f) => f.name));
  for (const fn of cg.fns) {
    const seen = new Set<string>();
    for (const call of fn.calls) {
      if (!defined.has(call.callee) || seen.has(call.callee)) continue;
      seen.add(call.callee);
      const arr = callersOf.get(call.callee) ?? [];
      arr.push(fn);
      callersOf.set(call.callee, arr);
    }
  }

  const contexts: ViolatingContext[] = [];
  for (const a of kept) {
    const subject = a.subject;
    const token = a.oracle.establisherToken;
    const aliases = (a.oracle.establisherAliases ?? []).filter(isMechanizableEstablisher);
    const establishesToken = (fnName: string): boolean => {
      const set = est.get(fnName);
      if (!set) return false;
      if (set.has(token)) return true;
      return aliases.some((al) => set.has(al));
    };
    // The subject must itself NOT establish the token (it relies on it). If the
    // subject establishes it via propagation from ALL its callers, no caller violates.
    const callers = callersOf.get(subject);
    if (!callers || callers.length === 0) continue; // no in-subsystem caller → nothing to scan
    for (const c of callers) {
      if (c.name === subject) continue; // self-edge (recursion) — a fn is not its own violating caller
      if (establishesToken(c.name)) continue; // caller establishes or inherits it → not a violation
      const body = bodies.get(c.name) ?? "";
      const line = callLineInBody(body, c.startLine, subject);
      const unpriv = UNPRIV_ENTRY_RE.test(c.name) || !(callersOf.get(c.name)?.length);
      contexts.push({
        assumptionId: a.id,
        subject,
        caller: c.name,
        callerFile: c.file,
        callLine: line,
        establisherToken: token,
        unprivEntry: unpriv,
        detail:
          `${c.name}() calls ${subject}() at ${c.file}:${line} but never establishes ${token}` +
          `${aliases.length ? ` (nor ${aliases.join("/")})` : ""}, and does not inherit it from its callers. ` +
          `${subject}() RELIES ON: ${a.predicate} (${a.kind}, ${a.securityRelevance}). ` +
          `If this path is attacker-reachable and the precondition is genuinely required, the assumption is VIOLATED here. ` +
          `CANDIDATE to DISPROVE — coarse establisher-anywhere + name-based call graph; confirm ${token} is truly absent on THIS path.`,
      });
    }
  }

  // Rank: unpriv entries first, then by subject then caller for determinism.
  contexts.sort(
    (x, y) => Number(y.unprivEntry) - Number(x.unprivEntry) || x.subject.localeCompare(y.subject) || x.caller.localeCompare(y.caller),
  );
  const capped = contexts.slice(0, maxContexts);
  log(`[assumption-scan] ${contexts.length} violating context(s)${capped.length < contexts.length ? ` (capped to ${capped.length})` : ""}`);
  return capped;
}

// ── DUAL-API / CROSS-PHASE enumerator (v2 — the HIGH-VALUE mechanism) ────────────
//
// The caller-scan asks "which CALLER of subject S skips S's establisher?" — a
// SINGLE-view question (one call-tree, one entry). The deepest latent LPEs are
// DUAL-view: a long-lived object is set up on ONE entry/phase (request, submit,
// create, fd-install) and reached again on a DISTINCT entry/phase (reply,
// completion, release, receiver) that does NOT re-establish the guarantee the first
// phase relies on. DirtyPipe (write phase vs merge phase on a reused pipe_buffer),
// fuse (request path vs userspace-driven reply path on one fuse_req), SCM_RIGHTS
// (installer vs consumer of a file), io_uring (submit-view vs completion-view of a
// registered fd/creds) are ALL this shape. The caller-scan structurally cannot see
// it: entryB is not a caller of the subject at all.
//
// MECHANISM (deterministic, no LLM). For a cross-api/cross-phase assumption on object
// TYPE O with establisher token E:
//   • touchers(O)   = functions whose body references the type token O (`\bfuse_req\b`).
//                     The proxy for "operates on an O instance" — coarse (type-name,
//                     like the whole stage), precision-over-recall, skeptic adjudicates.
//   • establishing  = touchers whose establisher set (v1 wrapper-closed) contains E.
//   • skipping      = touchers whose establisher set does NOT contain E.
//   • a DUAL-VIEW violation is a pair (entryA ∈ establishing, entryB ∈ skipping) that
//     reach the SAME type via DISTINCT call-trees — NEITHER calls the other (if entryB
//     reached entryA it would inherit E via the establisher set; requiring mutual
//     non-reachability isolates genuinely separate phases/APIs).
//   • require establishing ≠ ∅ — E must be a guarantee the code DOES apply somewhere
//     on O (proof it is a real in-subsystem contract, not an external one 1b mined
//     out); the skipping sibling is then the latent-bug candidate.
// Emits ViolatingContext tagged dualView (caller = entryB, pairedEntry = entryA).

/** Kinds whose VIOLATION is a cross-phase/dual-view bug even absent relied-on-cross-api provenance. */
const DEFAULT_CROSS_API_KINDS = new Set<AssumptionKind>([
  "ownership-exclusive", "called-once", "field-initialized", "revalidated", "state-precondition",
]);

/**
 * Ubiquitous kernel types the type-name toucher grep CANNOT meaningfully constrain.
 * `struct file`, `struct inode`, `struct sock`, `struct cred` … are reached by
 * dozens of functions, so "an entry reaches this type without establisher E" is
 * true of nearly every function and says nothing — the DirtyCred-class instance
 * problem needs per-instance aliasing (a v3 dynamic oracle), not a static type
 * grep. Suppressing them here keeps the STATIC dual-view generator honest: it fires
 * on FOCUSED, long-lived subsystem objects (fuse_req, dma_buf, io_ring_ctx) where
 * the toucher set is a small number of lifecycle phases.
 */
const UBIQUITOUS_OBJECT_TYPES = new Set<string>([
  "file", "inode", "dentry", "page", "folio", "sk_buff", "sock", "task_struct", "mm_struct",
  "vm_area_struct", "kiocb", "address_space", "super_block", "vfsmount", "path", "kobject",
  "device", "list_head", "work_struct", "timer_list", "pid", "cred", "seq_file", "kmem_cache",
  "nameidata", "kstat", "iov_iter", "bio", "request",
]);

/** True when an assumption is a dual-view/cross-phase candidate (by provenance OR kind). */
export function isCrossApiAssumption(a: Assumption, kinds: Set<AssumptionKind> = DEFAULT_CROSS_API_KINDS): boolean {
  return a.provenance === "relied-on-cross-api" || a.provenance === "relied-on-concurrency" || kinds.has(a.kind);
}

/** The object TYPE token to grep for touchers: `struct fuse_req` → `fuse_req`; a bare type ident (len ≥ 4). */
export function objectTypeToken(a: Assumption): string | null {
  const raw = (a.object ?? a.oracle.target ?? "").trim();
  const sm = raw.match(/struct\s+([A-Za-z_]\w*)/);
  if (sm) return sm[1];
  const bm = raw.match(/^([A-Za-z_]\w*)$/);
  if (bm && bm[1].length >= 4) return bm[1];
  return null;
}

/** name → set of in-subsystem callees (for reachability). */
function buildAdjacency(cg: CallGraph): Map<string, Set<string>> {
  const defined = new Set(cg.fns.map((f) => f.name));
  const adj = new Map<string, Set<string>>();
  for (const fn of cg.fns) {
    const s = adj.get(fn.name) ?? new Set<string>();
    for (const call of fn.calls) if (defined.has(call.callee)) s.add(call.callee);
    adj.set(fn.name, s);
  }
  return adj;
}

/** BFS: does `from` transitively call `to` within `maxDepth` hops? */
function reachesFn(adj: Map<string, Set<string>>, from: string, to: string, maxDepth = 12): boolean {
  if (from === to) return true;
  const seen = new Set<string>([from]);
  let frontier = [from];
  let depth = 0;
  while (frontier.length && depth++ < maxDepth) {
    const next: string[] = [];
    for (const f of frontier) {
      for (const c of adj.get(f) ?? []) {
        if (c === to) return true;
        if (!seen.has(c)) { seen.add(c); next.push(c); }
      }
    }
    frontier = next;
  }
  return false;
}

// ── FIELD + LOCK GRANULARITY (the precision fix) ────────────────────────────────
//
// v2's dual-view enumerator paired entries that share only the STRUCT TYPE (object).
// A post-mortem of crypto/af_alg.c proved that is too coarse and burns the (small,
// expensive) dynamic-witness budget on NON-seams:
//   • af_alg_alloc_tsgl (mutates ctx->tsgl_list) ⇄ af_alg_poll (reads ctx->more /
//     ctx->used) — a DELIBERATE benign lockless scalar read of DIFFERENT fields, not a
//     lifetime seam on the same field.
//   • af_alg_alloc_tsgl ⇄ af_alg_free_resources (touches ctx->inflight / ctx->rcvused)
//     — DISJOINT fields, not tsgl_list.
// A genuine seam requires the two phases to CONTEND on the SAME field, AND that field
// not to be co-serialized by the same lock in both phases. We refine seam emission
// from (object) to (field, lock) granularity:
//   1. FIELD-MATCH (necessary): the establishing entryA and the skipping entryB must
//      access at least one COMMON struct member of the object. Disjoint fields ⇒ drop.
//   2. LOCK-COVERAGE: for every shared field, if BOTH accesses are covered by the SAME
//      lock (both under lock_sock / the same mutex / spinlock / rcu / guard), that field
//      is serialized. Emit only when some shared field has an access that is LOCKLESS in
//      at least one phase, OR the two phases hold DIFFERENT locks over it.
// DEGRADE-SAFE: when field info cannot be recovered for EITHER side (no typed var, a
// macro-hidden access), we KEEP the pair — reproducing v2's object-granular behavior
// rather than silently dropping. Suppression only ever fires on POSITIVE evidence of
// field-disjointness or same-lock coverage — that bounds the false-negative risk.

/** Paren ranges [open, close] of every recognized lock/guard call in a blanked body. */
function lockCallArgRanges(blanked: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const push = (openParen: number) => {
    let depth = 0;
    for (let i = openParen; i < blanked.length; i++) {
      if (blanked[i] === "(") depth++;
      else if (blanked[i] === ")") { depth--; if (depth === 0) { ranges.push([openParen, i]); return; } }
    }
  };
  LOCK_CALL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = LOCK_CALL_RE.exec(blanked))) push(m.index + m[0].length - 1);
  const guardRe = /\b(?:guard|scoped_guard)\s*\(/g;
  let g: RegExpExecArray | null;
  while ((g = guardRe.exec(blanked))) push(g.index + g[0].length - 1);
  return ranges;
}

/**
 * Struct member accesses of the given object TYPE in a function body: field → char
 * offsets. A `->`/`.` access that is the ARGUMENT of a lock primitive (`o->lock` inside
 * `mutex_lock(&o->lock)`) is EXCLUDED — that member is the lock handle, not a contended
 * data field, and counting it would spuriously match / mis-cover the seam.
 */
export function objectFieldAccesses(body: string, typeToken: string): Map<string, number[]> {
  const out = new Map<string, number[]>();
  if (!body || !typeToken) return out;
  const blanked = blankCommentsAndStrings(body);
  const lockRanges = lockCallArgRanges(blanked);
  const insideLockArg = (idx: number): boolean => lockRanges.some(([s, e]) => idx > s && idx < e);
  // Variables declared as (struct)? <typeToken> [*] <name> — the handles onto an object instance.
  const vars = new Set<string>();
  const declRe = new RegExp(`(?:struct\\s+)?\\b${escapeRe(typeToken)}\\b\\s*\\**\\s*([A-Za-z_]\\w*)`, "g");
  let dm: RegExpExecArray | null;
  while ((dm = declRe.exec(blanked))) {
    const name = dm[1];
    // Skip C keywords that can trail a type in odd matches; keep plain identifiers.
    if (name && name !== "struct") vars.add(name);
  }
  if (vars.size === 0) return out;
  // For each variable, record every `<var>-><field>` / `<var>.<field>` access + its offset.
  for (const v of vars) {
    const accRe = new RegExp(`\\b${escapeRe(v)}\\s*(?:->|\\.)\\s*([A-Za-z_]\\w*)`, "g");
    let am: RegExpExecArray | null;
    while ((am = accRe.exec(blanked))) {
      if (insideLockArg(am.index)) continue; // the lock handle itself, not a data field
      const field = am[1];
      const arr = out.get(field) ?? [];
      arr.push(am.index);
      out.set(field, arr);
    }
  }
  return out;
}

/** Recognized lock ACQUIRE/RELEASE primitives → a normalized lock IDENTITY string. */
const LOCK_CALL_RE =
  /\b(lock_sock_nested|lock_sock|bh_lock_sock|bh_unlock_sock|release_sock|mutex_lock_interruptible|mutex_lock_nested|mutex_lock_killable|mutex_lock|mutex_unlock|spin_lock_irqsave|spin_lock_irq|spin_lock_bh|spin_lock|spin_unlock_irqrestore|spin_unlock_irq|spin_unlock_bh|spin_unlock|read_lock_bh|read_lock|read_unlock_bh|read_unlock|write_lock_bh|write_lock|write_unlock_bh|write_unlock|rcu_read_lock|rcu_read_unlock)\s*\(/g;

/** First (top-level) argument of a call whose `(` is at `openParen`, normalized (strip &, whitespace). */
function firstCallArgNorm(body: string, openParen: number): string {
  let depth = 0;
  let i = openParen;
  const start = openParen + 1;
  let end = start;
  for (; i < body.length; i++) {
    const c = body[i];
    if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) { end = i; break; } }
    else if (c === "," && depth === 1) { end = i; break; }
  }
  return body.slice(start, end).replace(/\s+/g, "").replace(/^&/, "");
}

interface LockEvent { index: number; acquire: boolean; id: string; }

/** Ordered acquire/release events for the recognized lock primitives in a body. */
function lockEvents(body: string): LockEvent[] {
  const blanked = blankCommentsAndStrings(body);
  const events: LockEvent[] = [];
  LOCK_CALL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = LOCK_CALL_RE.exec(blanked))) {
    const name = m[1];
    const openParen = m.index + m[0].length - 1;
    const arg = firstCallArgNorm(blanked, openParen);
    let id: string;
    let acquire: boolean;
    if (name === "lock_sock" || name === "lock_sock_nested" || name === "bh_lock_sock") { id = "sock"; acquire = true; }
    else if (name === "release_sock" || name === "bh_unlock_sock") { id = "sock"; acquire = false; }
    else if (name === "rcu_read_lock") { id = "rcu"; acquire = true; }
    else if (name === "rcu_read_unlock") { id = "rcu"; acquire = false; }
    else if (name.startsWith("mutex_lock")) { id = `mutex:${arg}`; acquire = true; }
    else if (name === "mutex_unlock") { id = `mutex:${arg}`; acquire = false; }
    else if (name.startsWith("spin_lock")) { id = `spin:${arg}`; acquire = true; }
    else if (name.startsWith("spin_unlock")) { id = `spin:${arg}`; acquire = false; }
    else if (name.startsWith("read_lock") || name.startsWith("write_lock")) { id = `rw:${arg}`; acquire = true; }
    else if (name.startsWith("read_unlock") || name.startsWith("write_unlock")) { id = `rw:${arg}`; acquire = false; }
    else continue;
    events.push({ index: m.index, acquire, id });
  }
  // guard(TYPE)(&lock) / scoped_guard(TYPE, &lock) — RAII: held from here to end of scope.
  // Textual approx: treat as acquired (never released) — end-of-function is the outer scope.
  const guardRe = /\b(?:guard|scoped_guard)\s*\(\s*\w+\s*(?:\)\s*\(|,)\s*([^),]+)/g;
  let g: RegExpExecArray | null;
  while ((g = guardRe.exec(blanked))) {
    const arg = g[1].replace(/\s+/g, "").replace(/^&/, "");
    events.push({ index: g.index, acquire: true, id: `guard:${arg}` });
  }
  events.sort((a, b) => a.index - b.index);
  return events;
}

/** The set of lock IDENTITIES held at char offset `at` (textual held-lockset approximation). */
export function heldLockIdsAt(events: LockEvent[], at: number): Set<string> {
  const counts = new Map<string, number>();
  for (const e of events) {
    if (e.index >= at) break;
    const c = counts.get(e.id) ?? 0;
    counts.set(e.id, e.acquire ? c + 1 : Math.max(0, c - 1));
  }
  const held = new Set<string>();
  for (const [id, c] of counts) if (c > 0) held.add(id);
  return held;
}

/**
 * The locks that cover EVERY access at `offsets` (intersection of the held-lockset at
 * each). A field whose accesses are all under lock L returns {…,L}; a field with ANY
 * lockless access returns ∅ (a single unguarded touch means it is not fully serialized).
 */
function fieldCoveringLocks(events: LockEvent[], offsets: number[]): Set<string> {
  let inter: Set<string> | null = null;
  for (const off of offsets) {
    const held = heldLockIdsAt(events, off);
    if (inter === null) inter = new Set(held);
    else for (const id of [...inter]) if (!held.has(id)) inter.delete(id);
    if (inter.size === 0) break;
  }
  return inter ?? new Set<string>();
}

export interface SeamDecision {
  /** True = a genuine (field, lock) seam to emit; false = a non-seam to drop. */
  keep: boolean;
  reason: string;
  /** The contended shared field the decision keyed on (when a field-level verdict was reached). */
  sharedField?: string;
}

/**
 * FIELD + LOCK granular seam verdict for an establishing entryA / skipping entryB pair
 * on object TYPE `typeToken`. Keeps only genuinely suspicious pairings (see the block
 * comment above): same-field contention that is NOT co-serialized by a shared lock.
 * Degrades to KEEP when field info is unrecoverable for either side (backward-compatible
 * with v2's object-granular behavior — never silently drops on missing data).
 */
export function dualViewSeamDecision(bodyA: string, bodyB: string, typeToken: string): SeamDecision {
  const fieldsA = objectFieldAccesses(bodyA, typeToken);
  const fieldsB = objectFieldAccesses(bodyB, typeToken);
  // Degrade-safe: no recoverable field info on a side → keep (v2 object-granular behavior).
  if (fieldsA.size === 0 || fieldsB.size === 0) {
    return { keep: true, reason: "field info unavailable on a phase — degraded to object-granular (kept)" };
  }
  const shared = [...fieldsA.keys()].filter((f) => fieldsB.has(f));
  if (shared.length === 0) {
    return { keep: false, reason: `disjoint fields (A:{${[...fieldsA.keys()].join(",")}} vs B:{${[...fieldsB.keys()].join(",")}}) — not a same-field seam` };
  }
  const eventsA = lockEvents(bodyA);
  const eventsB = lockEvents(bodyB);
  for (const f of shared) {
    const covA = fieldCoveringLocks(eventsA, fieldsA.get(f)!);
    const covB = fieldCoveringLocks(eventsB, fieldsB.get(f)!);
    const common = [...covA].filter((id) => covB.has(id));
    if (common.length === 0) {
      const lockNote =
        covA.size === 0 || covB.size === 0
          ? `field '${f}' is accessed LOCKLESS in at least one phase`
          : `field '${f}' is held under DIFFERENT locks ({${[...covA].join(",")}} vs {${[...covB].join(",")}})`;
      return { keep: true, sharedField: f, reason: `same-field seam on '${f}' — ${lockNote}` };
    }
  }
  return {
    keep: false,
    reason: `all shared field(s) {${shared.join(",")}} are covered by a common lock in BOTH phases — serialized, not a seam`,
  };
}

export interface DualViewOptions {
  maxContexts?: number;
  maxPropagationRounds?: number;
  resolveWrappers?: boolean;
  wrapperRounds?: number;
  /** Bounded reachability depth for the distinctness (neither-calls-the-other) test. */
  reachDepth?: number;
  /** Override the cross-phase kind set. */
  crossApiKinds?: Set<AssumptionKind>;
  /**
   * PRECISION GATE: skip an object type touched by MORE than this many functions
   * (default 14). A focused cross-phase object is reached by a bounded set of
   * lifecycle phases; a type touched by dozens of functions is pervasive, and
   * "establisher absent" on it is meaningless (see {@link UBIQUITOUS_OBJECT_TYPES}).
   */
  maxTouchers?: number;
  /** Cap dual-view pairs emitted per (assumption, object) to bound near-duplicates (default 6). */
  maxPairsPerObject?: number;
  /** Extra object type tokens to suppress (merged with the ubiquitous-type denylist). */
  objectDenylist?: Set<string>;
  /**
   * FIELD+LOCK GRANULARITY (default true): emit a dual-view seam ONLY when the
   * establishing and skipping phases contend on the SAME struct field AND that field is
   * not co-serialized by a common lock (see {@link dualViewSeamDecision}). Set false to
   * reproduce v2's object-granular pairing (the precision ablation). Degrades to keep
   * when field info is unrecoverable, so it never drops a pair on missing data.
   */
  fieldGranular?: boolean;
  log?: (msg: string) => void;
}

// ── DUAL-VIEW WEAPONIZABILITY RANKING (replaces the alphabetical tiebreak) ────────
//
// The dual-view contexts feed the EXPENSIVE dynamic KASAN oracle under a small daily
// budget (default ~10/run). v2 ranked them by `unprivEntry` then ALPHABETICALLY by
// object/caller — so a flywheel run spent its whole witness budget on the
// alphabetically-first candidates every day, and a genuinely high-value seam that
// sorted late was NEVER witnessed. This scores each candidate by how likely its
// VIOLATION is a WEAPONIZABLE LPE (a class the KASAN oracle can actually witness), so
// the top-N — the ones witnessed — are the highest-value, not the alphabetically-first.
// Alphabetical survives only as the FINAL deterministic tiebreak.

/** securityRelevance rank: lifetime (UAF) / type (type-confusion) highest, then bounds, authz, other. */
const RELEVANCE_RANK: Record<SecurityRelevance, number> = {
  lifetime: 5,
  type: 4,
  bounds: 3,
  authz: 2,
  other: 1,
};

/**
 * kind rank: the UAF / double-free / refcount / ownership-exclusive classes — whose
 * violation is a LIFETIME bug the KASAN oracle can witness — rank above the
 * range/non-null classes (a missing bounds/null check is rarely a dual-view seam).
 */
const KIND_RANK: Record<AssumptionKind, number> = {
  "ownership-exclusive": 3,
  "refcount-positive": 3,
  "called-once": 3,
  "state-precondition": 3,
  revalidated: 2,
  "field-initialized": 2,
  "size-consistent": 2,
  "lock-held": 2,
  "validated-range": 1,
  "non-null": 1,
};

/** Geometry bonus is capped below the KIND weight (100) so it only breaks kind-ties, never overrides them. */
const GEOMETRY_BONUS_CAP = 90;

/**
 * OBJECT-ON-A-WEAPONIZABLE-SLAB hint — reuse hunt-scan's {@link scoreGeometry} on a
 * synthetic finding built from the assumption's object type + kind + predicate. It
 * only fires when the object prose names a known elastic-reclaim spray (msg_msg,
 * pipe_buffer, …), a sibling-type class (qdisc/HFSC/…), or an `_ops` fn-ptr struct —
 * i.e. the geometry that turns a UAF/OOB into root. HONEST LIMIT: a mined assumption's
 * prose is usually just a bare type name with no crash-shape, so this bonus is 0 for
 * most candidates; it is a fine tiebreak among equal relevance/kind, not a primary key.
 * Only POSITIVE geometry is credited (the DoS penalty is meaningless on assumption prose).
 */
function assumptionGeometryBonus(a: Assumption): number {
  const object = (a.object ?? a.oracle.target ?? "").trim();
  if (!object) return 0;
  const synthetic = {
    title: object,
    description: `${a.predicate} ${a.kind} ${a.securityRelevance}`,
    evidence: { analysis: `${object} ${a.oracle.target ?? ""}` },
    category: "",
  } as unknown as Finding;
  const g = scoreGeometry(synthetic);
  return g.geometryScore > 0 ? Math.min(g.geometryScore, GEOMETRY_BONUS_CAP) : 0;
}

export interface DualViewScore {
  /** Higher = more likely a weaponizable dual-view LPE. */
  score: number;
  rationale: string[];
}

/**
 * Score an assumption's dual-view WEAPONIZABILITY: securityRelevance (dominant) →
 * kind → object-on-a-weaponizable-slab geometry bonus. The three tiers are separated
 * (relevance ×1000, kind ×100, geometry 0–90) so a higher-relevance candidate ALWAYS
 * outranks a lower-relevance one regardless of kind/geometry, and geometry only breaks
 * kind-ties. Deterministic + pure — no I/O, no LLM.
 */
export function scoreDualViewWeaponizability(a: Assumption): DualViewScore {
  const rel = RELEVANCE_RANK[a.securityRelevance] ?? 0;
  const kind = KIND_RANK[a.kind] ?? 0;
  const geom = assumptionGeometryBonus(a);
  const score = rel * 1000 + kind * 100 + geom;
  const rationale = [
    `securityRelevance=${a.securityRelevance} (rank ${rel}/5)`,
    `kind=${a.kind} (rank ${kind}/3)`,
    ...(geom > 0 ? [`+${geom} object-on-weaponizable-slab geometry ('${a.object ?? a.oracle.target}')`] : []),
  ];
  return { score, rationale };
}

/**
 * The DUAL-API / CROSS-PHASE enumerator. For every cross-api/cross-phase assumption
 * (see {@link isCrossApiAssumption}), find distinct entry pairs reaching the same
 * object type where one establishes the guarantee and the sibling does not. NO LLM.
 * `bodies` maps fn name → body text (for the type-name toucher grep + the reporting
 * line). Emits dual-view {@link ViolatingContext}[] — materially different candidates
 * than the caller-scan (the sibling entryB is NOT a caller of the subject).
 */
export function scanDualViewContexts(
  kept: Assumption[],
  cg: CallGraph,
  sources: Array<{ file: string; text: string }>,
  bodies: Map<string, string>,
  opts: DualViewOptions = {},
): ViolatingContext[] {
  const log = opts.log ?? (() => {});
  const maxContexts = opts.maxContexts ?? 60;
  const kinds = opts.crossApiKinds ?? DEFAULT_CROSS_API_KINDS;
  const reachDepth = opts.reachDepth ?? 12;
  // maxTouchers is an OPT-IN safety valve, not a default gate: a focused dual-view
  // object like fuse_req is legitimately touched by many functions (it is the central
  // request object), so suppressing by toucher-count kills the very signal we want.
  // The emitted-pair explosion is instead bounded by maxPairsPerObject + the denylist.
  const maxTouchers = opts.maxTouchers ?? Infinity;
  const maxPairsPerObject = opts.maxPairsPerObject ?? 6;
  const denylist = opts.objectDenylist ?? UBIQUITOUS_OBJECT_TYPES;
  const fieldGranular = opts.fieldGranular !== false;

  const crossApi = kept.filter((a) => isCrossApiAssumption(a, kinds) && objectTypeToken(a));
  if (crossApi.length === 0) {
    log("[dual-view] no cross-api/cross-phase assumptions with a typed object to enumerate");
    return [];
  }

  const establisherTokens = new Set<string>();
  for (const a of crossApi) {
    establisherTokens.add(a.oracle.establisherToken);
    for (const alias of a.oracle.establisherAliases ?? []) if (isMechanizableEstablisher(alias)) establisherTokens.add(alias);
  }
  const exported = collectExportedSymbols(sources);
  const wrappers =
    opts.resolveWrappers === false ? undefined : computeEstablisherWrappers(cg, establisherTokens, opts.wrapperRounds ?? 4);
  const est = computeEstablisherSets(cg, establisherTokens, exported, opts.maxPropagationRounds ?? 8, wrappers);
  const adj = buildAdjacency(cg);

  const defined = new Set(cg.fns.map((f) => f.name));
  const hasInternalCaller = new Set<string>();
  for (const fn of cg.fns) for (const call of fn.calls) if (defined.has(call.callee)) hasInternalCaller.add(call.callee);
  const isEntry = (n: string): boolean => UNPRIV_ENTRY_RE.test(n) || exported.has(n) || !hasInternalCaller.has(n);

  const contexts: ViolatingContext[] = [];
  const seenPair = new Set<string>();

  const suppressed = new Map<string, string>();
  for (const a of crossApi) {
    const type = objectTypeToken(a)!;
    // PRECISION GATE 1: a pervasive/ubiquitous type cannot be constrained by a
    // type-name grep (the instance problem — needs per-object aliasing, not names).
    if (denylist.has(type)) { suppressed.set(type, "ubiquitous type (needs per-instance aliasing, not a static type grep)"); continue; }
    const token = a.oracle.establisherToken;
    const aliases = (a.oracle.establisherAliases ?? []).filter(isMechanizableEstablisher);
    const establishesE = (fn: string): boolean => {
      const s = est.get(fn);
      return !!s && (s.has(token) || aliases.some((al) => s.has(al)));
    };
    const typeRe = new RegExp(`\\b${escapeRe(type)}\\b`);
    const touchers = cg.fns.filter((f) => { const b = bodies.get(f.name); return b != null && typeRe.test(b); }).map((f) => f.name);
    if (touchers.length < 2) continue;
    // PRECISION GATE 2: a type touched by more than maxTouchers functions is pervasive
    // in THIS subsystem — not a focused cross-phase seam. Suppress (honest recall trade).
    if (touchers.length > maxTouchers) { suppressed.set(type, `${touchers.length} touchers > ${maxTouchers} (pervasive in-subsystem type, not a focused seam)`); continue; }
    const establishing = touchers.filter(establishesE);
    const skipping = touchers.filter((t) => !establishesE(t));
    // Need BOTH a phase that establishes E on O and a distinct phase that skips it.
    if (establishing.length === 0 || skipping.length === 0) continue;

    let emittedForObject = 0;
    for (const tB of skipping) {
      if (emittedForObject >= maxPairsPerObject) break;
      // A distinct establishing sibling tA: neither calls the other (genuinely separate
      // phases). PRECISION FIX: also require a genuine (field, lock)-granular SEAM with tB —
      // the pair must contend on the SAME field, not co-serialized by a common lock (see
      // dualViewSeamDecision). This kills the af_alg poll/free_resources non-seams. Field
      // granularity is on by default; opts.fieldGranular=false reproduces v2 object-granular.
      let tA: string | undefined;
      let seam: SeamDecision | undefined;
      for (const x of establishing) {
        if (x === tB || reachesFn(adj, x, tB, reachDepth) || reachesFn(adj, tB, x, reachDepth)) continue;
        if (fieldGranular) {
          const d = dualViewSeamDecision(bodies.get(x) ?? "", bodies.get(tB) ?? "", type);
          if (!d.keep) { seam = seam ?? d; continue; } // remember the last drop reason for logging
          tA = x;
          seam = d;
          break;
        }
        tA = x;
        break;
      }
      if (!tA) {
        if (fieldGranular && seam) log(`[dual-view] dropped ${tB}() on 'struct ${type}': ${seam.reason}`);
        continue;
      }
      const key = `${a.id}|${tA}|${tB}`;
      if (seenPair.has(key)) continue;
      seenPair.add(key);
      const sharedField = seam?.sharedField;

      const fnB = cg.byName.get(tB)!;
      const b = bodies.get(tB) ?? "";
      const mm = typeRe.exec(b);
      let line = fnB.startLine;
      if (mm) { let nl = 0; for (let k = 0; k < mm.index; k++) if (b[k] === "\n") nl++; line = fnB.startLine + nl; }

      contexts.push({
        assumptionId: a.id,
        subject: a.subject,
        caller: tB,
        callerFile: fnB.file,
        callLine: line,
        establisherToken: token,
        unprivEntry: isEntry(tB),
        dualView: true,
        pairedEntry: tA,
        object: type,
        ...(sharedField ? { field: sharedField } : {}),
        detail:
          `DUAL-VIEW (cross-api/cross-phase): ${tA}() and ${tB}() both operate on 'struct ${type}'` +
          `${sharedField ? `.${sharedField}` : ""}, reached via ` +
          `DISTINCT call-trees (neither calls the other). ${tA}() ESTABLISHES ${token}` +
          `${aliases.length ? `/${aliases.join("/")}` : ""} on the object; ${tB}() reaches the SAME object type WITHOUT it. ` +
          `${sharedField ? `Both contend on field '${sharedField}' (${seam?.reason}). ` : ""}` +
          `${a.subject}() RELIES ON: ${a.predicate} (${a.kind}, ${a.securityRelevance}). If ${tB}() can run on the SAME ` +
          `${type} INSTANCE concurrently with, or after, ${tA}()'s guarantee, the cross-api assumption is VIOLATED. ` +
          `CANDIDATE to DISPROVE — type-name toucher grep + field-match + name-based establisher set: confirm (1) both paths reach the ` +
          `SAME instance (aliasing / a shared table / an fd), and (2) ${token} is genuinely absent on ${tB}()'s path.`,
      });
      emittedForObject++;
    }
  }

  if (suppressed.size > 0) {
    log(`[dual-view] suppressed ${suppressed.size} pervasive object type(s): ${[...suppressed.entries()].map(([t, r]) => `${t} (${r})`).join("; ")}`);
  }
  // RANK by WEAPONIZABILITY (not alphabet): unprivEntry first (keep), then the
  // per-assumption weaponizability score (relevance → kind → object-slab geometry), so
  // the top-N (the ones the expensive KASAN oracle witnesses) are the highest-value.
  // Alphabetical (object, caller) survives only as the FINAL deterministic tiebreak.
  const scoreById = new Map<string, number>();
  for (const a of kept) scoreById.set(a.id, scoreDualViewWeaponizability(a).score);
  contexts.sort(
    (x, y) =>
      Number(y.unprivEntry) - Number(x.unprivEntry) ||
      (scoreById.get(y.assumptionId) ?? 0) - (scoreById.get(x.assumptionId) ?? 0) ||
      (x.object ?? "").localeCompare(y.object ?? "") ||
      x.caller.localeCompare(y.caller),
  );
  const capped = contexts.slice(0, maxContexts);
  log(`[dual-view] ${contexts.length} dual-view context(s)${capped.length < contexts.length ? ` (capped to ${capped.length})` : ""}`);
  return capped;
}

// ── assumptionsToHuntPlan (mirror violationsToHuntPlan) ─────────────────────────

export interface AssumptionHuntPlan {
  model: AssumptionModel;
  kept: Assumption[];
  contexts: ViolatingContext[];
  brief: HuntBrief;
  candidates: HuntCandidate[];
}

/**
 * Turn violating contexts into a {@link HuntCandidate}[] + {@link HuntBrief} that
 * plug straight into `runHuntScan`. Grouped per file (the file the violating caller
 * lives in), hints merged — so the finder + skeptic gate confirm or kill each
 * assumption-violation candidate against the real code.
 */
export function assumptionsToHuntPlan(
  model: AssumptionModel,
  kept: Assumption[],
  contexts: ViolatingContext[],
): AssumptionHuntPlan {
  const bySite = new Map<string, HuntCandidate>();
  for (const ctx of contexts) {
    const hint =
      `ASSUMPTION-VIOLATION candidate (seedless, from mined assumption model). ` +
      `Subject ${ctx.subject}() relies on an establisher (${ctx.establisherToken}) that caller ${ctx.caller}() ` +
      `reaches it without. ${ctx.detail}`;
    const existing = bySite.get(ctx.callerFile);
    if (existing) existing.hint = `${existing.hint}\n---\n${hint}`;
    else bySite.set(ctx.callerFile, { path: ctx.callerFile, hint });
  }
  const kinds = [...new Set(kept.map((a) => a.kind))].join(", ");
  const brief: HuntBrief = {
    bugClass: `relied-on-assumption violation (seedless, assumption-mining): ${kinds || "precondition not established on a reachable path"}`,
    pattern:
      `A function in ${model.subsystem} RELIES ON a precondition it does not itself establish (a validated ref, a ` +
      `held lock, a re-checked value, a once-only init, an exclusive owner, a caller-side capability check), and a ` +
      `reachable context reaches the same object/function WITHOUT establishing it. The candidate sites below are ` +
      `callers found (deterministically) to reach the relied-on subject without the establisher token and without ` +
      `inheriting it from their own callers. Verify each is a real, attacker-reachable violation — confirm the ` +
      `establisher is genuinely absent on THIS path (not present under a different name, not established by an ` +
      `unfollowed indirect caller) before trusting it.`,
    fixReference: undefined,
  };
  return { model, kept, contexts, brief, candidates: [...bySite.values()] };
}

/**
 * FINDER-TARGETING (v1) — hand the finder/skeptic the specific violating FUNCTION
 * (+ its relied-on subjects) as a small excerpt file, NOT the whole subsystem file.
 * v0 pointed `HuntCandidate.path` at the raw caller file; on kernel-scale sources
 * (af_unix.c is ~3800 lines) `agenticScan` timed out at 300s just reading it. This
 * writes one excerpt per violating caller — the caller body + each relied-on
 * subject body it reaches, with a provenance header mapping back to the real
 * file:line — under `excerptDir`, and points the candidate there. The finder then
 * reasons over ~tens-to-hundreds of lines instead of thousands.
 *
 * A caller whose body is not in `bodies` (unreadable / macro-defined) is SKIPPED
 * here; the caller (`runAssumptionHunt`) falls back to the per-file candidate for
 * those so no context is silently lost.
 */
export function buildFocusedCandidates(
  kept: Assumption[],
  contexts: ViolatingContext[],
  bodies: Map<string, string>,
  excerptDir: string,
): { candidates: HuntCandidate[]; missedCallers: string[] } {
  const predById = new Map(kept.map((a) => [a.id, a.predicate]));
  const byCaller = new Map<string, ViolatingContext[]>();
  for (const ctx of contexts) {
    const arr = byCaller.get(ctx.caller) ?? [];
    arr.push(ctx);
    byCaller.set(ctx.caller, arr);
  }
  const candidates: HuntCandidate[] = [];
  const missedCallers: string[] = [];
  let wrote = false;
  for (const [caller, ctxs] of byCaller) {
    const callerBody = bodies.get(caller);
    if (!callerBody) {
      missedCallers.push(caller);
      continue;
    }
    if (!wrote) {
      mkdirSync(excerptDir, { recursive: true });
      wrote = true;
    }
    const subjects = [...new Set(ctxs.map((c) => c.subject))];
    const header =
      `/* FOCUSED EXCERPT — seedless assumption-violation candidate(s) to DISPROVE.\n` +
      ` * Caller ${caller}() at ${ctxs[0].callerFile}:${ctxs[0].callLine} reaches, WITHOUT establishing the precondition:\n` +
      ctxs
        .map(
          (c) =>
            ` *   ${c.subject}()  — relies on establisher '${c.establisherToken}': ${predById.get(c.assumptionId) ?? ""}`,
        )
        .join("\n") +
      `\n * Confirm the establisher is GENUINELY ABSENT on the reachable path: not present under a\n` +
      ` * wrapper/alias, not established by an unfollowed indirect (fn-pointer/macro) caller. If it is\n` +
      ` * present under any name, this is a FALSE POSITIVE. Original tree lines are in the headers below. */\n`;
    const label = ctxs.some((c) => c.dualView) ? "skipping view (entryB)" : "violating caller";
    const parts = [header, `/* --- ${label}: ${caller}() (${ctxs[0].callerFile}) --- */\n${callerBody}\n`];
    // v2 dual-view: also include the paired ESTABLISHING view(s) so the finder can DIFF
    // the phase that sets the guarantee against the phase that skips it.
    const pairedEntries = [...new Set(ctxs.map((c) => c.pairedEntry).filter((p): p is string => !!p))];
    for (const p of pairedEntries) {
      const b = bodies.get(p);
      if (b) parts.push(`/* --- paired establishing view (entryA): ${p}() --- */\n${b}\n`);
    }
    for (const s of subjects) {
      if (pairedEntries.includes(s)) continue;
      const b = bodies.get(s);
      if (b) parts.push(`/* --- relied-on subject: ${s}() --- */\n${b}\n`);
    }
    const safe = caller.replace(/[^A-Za-z0-9_]/g, "_") || "caller";
    const path = join(excerptDir, `${safe}.c`);
    writeFileSync(path, parts.join("\n"), "utf8");
    const hint =
      `ASSUMPTION-VIOLATION candidate (focused excerpt: ${caller}() + its relied-on subject(s)). ` +
      ctxs.map((c) => c.detail).join("\n---\n");
    candidates.push({ path, hint });
  }
  return { candidates, missedCallers };
}

// ── End-to-end orchestration (mine → 1b → caller-scan → hunt-gate) ──────────────

export interface AssumptionHuntInput {
  sourceRoot: string;
  subsystem: string;
  subsystemFiles: string[];
  runtime: RuntimeMode;
  /** Where the durable assumption model JSON lives (mine-once, re-check-free). */
  modelPath: string;
  /** Force a fresh LLM mine even if `modelPath` exists. */
  remine?: boolean;
  /** Mining LLM override. */
  model?: string;
  /** Caller-scan options (cap, propagation rounds). */
  scanOptions?: CallerScanOptions;
  /** The skeptic+prover gate for runHuntScan. Default: makeSkepticVerifier. */
  verify?: HuntVerifier;
  /** Optional terminal exploitability gate (composed after verify by runHuntScan). */
  exploitability?: HuntVerifier;
  /** Finder model diversity. */
  finderModels?: string[];
  /** Skip runHuntScan; return just model + kept + contexts + plan (candidate-gen only). */
  skipHunt?: boolean;
  /**
   * FINDER-TARGETING (v1, default true): feed the finder a focused excerpt of the
   * violating function(s) instead of the whole subsystem file — avoids the
   * kernel-scale finder timeout. Set false to hunt the raw per-file candidates.
   */
  finderTargeting?: boolean;
  /** Where excerpts are written (default: an os-tmpdir subdir). */
  excerptDir?: string;
  /**
   * v2 DUAL-VIEW enumerator (default true): additionally run the cross-api/cross-phase
   * scan (distinct entries reaching the same object, one establishing the guarantee and
   * the sibling skipping it) and feed its contexts to the same hunt gate. Set false to
   * run the caller-scan only (the v1 behavior / ablation).
   */
  dualView?: boolean;
  /** Dual-view enumerator options (cap, reach depth, kind set). */
  dualViewOptions?: DualViewOptions;
  /**
   * v3 DYNAMIC WITNESS — the dynamic oracle for the dual-view class. When set, the
   * dual-view contexts are routed DIRECTLY to the KASAN synthesize→boot→witness
   * oracle (BYPASSING the static skeptic, which v2 proved refutes them all), and
   * the object-bound-splat verdicts land in {@link AssumptionHuntResult.witness}.
   * The caller-scan (single-view) contexts still flow through the static gate.
   */
  dynamicWitness?: {
    /** Cap the dual-view candidates run through the (expensive) oracle. Default 10. */
    maxCandidates?: number;
    /**
     * CROSS-RUN ROTATION state path (e.g. `<model-dir>/.witnessed-candidates.json`).
     * When set, candidates witnessed within the TTL are skipped so consecutive runs
     * cover fresh candidates. Omit to disable rotation.
     */
    rotationStatePath?: string;
    /** Clock injection for deterministic rotation tests. */
    now?: number;
  } & DynamicWitnessDeps;
  log?: (msg: string) => void;
}

export interface AssumptionHuntResult {
  model: AssumptionModel;
  modelPath: string;
  modelLoaded: boolean;
  crossCheck: CrossCheckResult;
  /** Caller-scan violating contexts (v1 single-view mechanism). */
  contexts: ViolatingContext[];
  /** v2 dual-api/cross-phase violating contexts (distinct-entry pairs). */
  dualViewContexts: ViolatingContext[];
  plan: AssumptionHuntPlan;
  hunt?: HuntScanResult;
  /** v3 dynamic-witness verdicts over the dual-view class (when the oracle ran). */
  witness?: WitnessDualViewResult;
}

/**
 * Full seedless pipeline: (mine or load) the stored assumption model → 1b
 * enforced/relied cross-check → caller-scan for violating contexts → map to
 * runHuntScan candidates → verify + rank through composeGate(skeptic, …). No seed,
 * no CVE — the mine + deterministic scan generate candidates from cold.
 */
export async function runAssumptionHunt(input: AssumptionHuntInput): Promise<AssumptionHuntResult> {
  const log = input.log ?? (() => {});

  // 1. Mine (LLM, once) OR load (free re-check) the durable model.
  let model: AssumptionModel;
  let modelLoaded = false;
  if (!input.remine) {
    try {
      model = loadAssumptionModel(input.modelPath);
      modelLoaded = true;
      log(`[assumption] loaded stored model ${input.modelPath} (${model.assumptions.length} assumption(s)) — no LLM call`);
    } catch {
      model = await mineAssumptions(input);
      storeAssumptionModel(model, input.modelPath);
      log(`[assumption] mined + stored model ${input.modelPath}`);
    }
  } else {
    model = await mineAssumptions(input);
    storeAssumptionModel(model, input.modelPath);
    log(`[assumption] re-mined + stored model ${input.modelPath}`);
  }

  // 2. Read current sources; build the call graph + body index.
  const sources: Array<{ file: string; text: string }> = [];
  for (const file of input.subsystemFiles) {
    const text = readSource(input.sourceRoot, file);
    if (text != null) sources.push({ file, text });
  }
  if (sources.length === 0) throw new Error("assumption hunt could not read any subsystemFile under sourceRoot");
  const cg = buildCallGraph(sources);
  const bodies = buildFunctionBodyIndex(sources);

  // 3. STAGE 1b cross-check (deterministic) over the real per-function body index.
  const crossCheck = crossCheckAssumptions(model, bodies);
  log(
    `[assumption] 1b: ${crossCheck.kept.length} kept, ${crossCheck.dropped.length} dropped, ` +
      `${crossCheck.reclassified.length} reclassified enforced→relied`,
  );

  // 4. Caller-scan (deterministic, v1 single-view).
  const contexts = scanViolatingContexts(crossCheck.kept, cg, sources, bodies, { ...input.scanOptions, log });

  // 4b. DUAL-VIEW / cross-phase enumerator (v2, default on) — the high-value mechanism
  // for the DirtyPipe/fuse/SCM_RIGHTS/io_uring class the caller-scan structurally
  // cannot see. Merged into the SAME hunt plan + skeptic gate as the caller-scan hits.
  const dualViewContexts =
    input.dualView === false
      ? []
      : scanDualViewContexts(crossCheck.kept, cg, sources, bodies, { ...input.dualViewOptions, log });

  const allContexts = [...contexts, ...dualViewContexts];
  const plan = assumptionsToHuntPlan(model, crossCheck.kept, allContexts);

  // 4c. v3 DYNAMIC WITNESS — route the dual-view class DIRECTLY to the KASAN
  // synthesize→boot→witness oracle, bypassing the static skeptic (v2 proved it
  // refutes them all). The caller-scan contexts keep the static gate below.
  let witness: WitnessDualViewResult | undefined;
  if (input.dynamicWitness && dualViewContexts.length > 0) {
    const { maxCandidates, rotationStatePath, now, ...deps } = input.dynamicWitness;
    witness = await witnessDualViewContexts({
      contexts: dualViewContexts,
      kept: crossCheck.kept,
      bodies,
      subsystem: input.subsystem,
      ...(maxCandidates !== undefined ? { maxCandidates } : {}),
      ...(rotationStatePath !== undefined ? { rotationStatePath } : {}),
      ...(now !== undefined ? { now } : {}),
      deps: deps as DynamicWitnessDeps,
      log,
    });
    log(
      `[assumption] dynamic-witness: ${witness.confirmed.length} confirmed, ` +
        `${witness.refuted.length} refuted, ${witness.inconclusive.length} inconclusive`,
    );
  }

  if (input.skipHunt || plan.candidates.length === 0) {
    return { model, modelPath: input.modelPath, modelLoaded, crossCheck, contexts, dualViewContexts, plan, ...(witness ? { witness } : {}) };
  }

  // 4b. FINDER-TARGETING (v1, default on): hunt focused per-function excerpts
  // instead of the whole subsystem file (kernel-scale finder-timeout fix). Any
  // caller whose body we could not excerpt falls back to its per-file candidate.
  let candidates = plan.candidates;
  if (input.finderTargeting !== false) {
    const excerptDir = input.excerptDir ?? join(tmpdir(), `pwnkit-assumption-excerpts-${process.pid}`);
    const focused = buildFocusedCandidates(crossCheck.kept, allContexts, bodies, excerptDir);
    const missed = new Set(focused.missedCallers);
    const fallback = plan.candidates.filter((c) =>
      allContexts.some((ctx) => missed.has(ctx.caller) && ctx.callerFile === c.path),
    );
    candidates = [...focused.candidates, ...fallback];
    log(
      `[assumption] finder-targeting: ${focused.candidates.length} focused excerpt(s) in ${excerptDir}` +
        `${fallback.length ? ` + ${fallback.length} per-file fallback (unreadable caller bodies)` : ""}`,
    );
  }

  // 5. Verify + rank through the skeptic+prover gate.
  const verify = input.verify ?? makeSkepticVerifier({ sourceRoot: input.sourceRoot, runtime: input.runtime });
  const hunt = await runHuntScan({
    sourceRoot: input.sourceRoot,
    candidates,
    brief: plan.brief,
    runtime: input.runtime,
    ...(input.finderModels && input.finderModels.length > 0 ? { models: input.finderModels } : {}),
    verify,
    ...(input.exploitability ? { exploitability: input.exploitability } : {}),
    log,
  });

  return { model, modelPath: input.modelPath, modelLoaded, crossCheck, contexts, dualViewContexts, plan, hunt, ...(witness ? { witness } : {}) };
}

export { composeGate, makeSkepticVerifier };
