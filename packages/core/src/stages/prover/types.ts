/**
 * Prover plugins — the executable half of the craft stage's format knowledge.
 *
 * ## Why this module exists
 *
 * Microsoft's published failure breakdown for MDASH across the 52 CyberGym
 * tasks it missed splits as **Scan 15.4% / Validate 19.2% / Prove 65.4%**. Two
 * thirds of the misses happen AFTER the bug has been correctly identified and
 * correctly validated as real. The wall is *proving* it: turning "this integer
 * overflows if the tile count exceeds N" into a byte-exact file that a real
 * parser will accept, walk, and crash on. Our own craft-stage history names the
 * same wall from the other side — `craft-scan.ts` had to grow a hard gate that
 * REFUSES a graded submit until a free self-test shows a crash, precisely
 * because the agent kept spending its one graded attempt on inputs that never
 * reached the vulnerable function.
 *
 * MDASH's answer was a per-domain proving plugin. Their description of the CLFS
 * one is worth quoting because it is the whole specification of this interface:
 * the plugin *"knows how to construct triggering logs given a candidate
 * finding: it understands the on-disk container layout, the block-validation
 * sequence, and the in-memory state machine well enough to drive a candidate
 * path to its sink."*
 *
 * We already have `stages/format-knowledge.ts`, whose own header cites the same
 * reference class. But it is **prose**. It tells the model what a PNG header
 * looks like; it cannot build one, and — the part that actually costs graded
 * submits — it cannot tell the model whether the bytes the model just built are
 * well-formed enough to reach the parser. A primer that says "many readers
 * validate CRC — compute it (zlib.crc32 over type+data)" still leaves the model
 * to compute the CRC, over the right byte range, at the right offset, for every
 * chunk. That is the step it gets wrong.
 *
 * A `ProverPlugin` closes that gap by being executable:
 *
 *   - {@link ProverPlugin.matches} — is this plugin's domain the target's?
 *   - {@link ProverPlugin.construct} — build a structurally valid container, or
 *     repair the framing of one the agent already has.
 *   - {@link ProverPlugin.validate} — statically decide whether a candidate is
 *     well-formed enough that a real parser will walk it, so a malformed input
 *     is caught for free instead of burning a graded submission.
 *
 * ## The framing / semantics line — the load-bearing design rule
 *
 * The obvious way to build this is also wrong. A naive "make this file valid"
 * repairer destroys the PoC, because in a proof-of-concept the triggering value
 * IS an invalid field. If the bug is "a chunk whose declared length exceeds the
 * remaining buffer", a repairer that clamps the length has just deleted the
 * vulnerability and handed the agent a clean file that proves nothing.
 *
 * So every prover plugin splits the fields of its format in two:
 *
 *   - **Framing invariants** — magic bytes, container checksums, directory
 *     offsets, block chaining. These are *not* attacker levers in the usual
 *     case: a parser rejects the file at the front door if they are wrong, and
 *     the bug never gets a chance to fire. Plugins compute and repair these,
 *     and report every change so the agent learns what it got wrong.
 *   - **Semantic fields** — dimensions, counts, sizes, indices, type tags.
 *     These are where the bug lives. Plugins pass them through **verbatim**.
 *     They are never "fixed", never clamped, never defaulted away when the
 *     caller supplied them.
 *
 * A plugin that cannot honour that split for a given defect must REFUSE (return
 * `ok: false` with an explanation) rather than guess, because a silent semantic
 * edit is indistinguishable, from the agent's side, from a plugin bug.
 *
 * The same rule shapes {@link ValidationReport}: a `fatal` defect means the
 * parser will bail out before reaching any interesting code, whereas a
 * `warning` means "this is malformed, and that may well be the point". A PoC is
 * *expected* to carry warnings. It must carry no fatals.
 *
 * ## Purity and the I/O seam
 *
 * `construct` and `validate` are pure functions over bytes. This is deliberate
 * and it is what makes the plugins testable to a byte: the tests in this
 * directory assert real CRC values and real offsets, not that a mock was
 * called. Determinism also means the craft agent can re-derive the same PoC
 * inside its own python generator once the plugin has shown it the bytes.
 *
 * A future plugin may genuinely need I/O — reading a seed corpus off disk,
 * shelling out to a format-specific muxer, querying a build. That is
 * accommodated the same way `craft-scan.ts` accommodates its oracle: via
 * injection, not ambient access. A plugin declares what it needs in
 * {@link ProverPlugin.requiresServices} and receives it through
 * {@link ProverServices} on the call. The registry never fabricates services;
 * a plugin that requires one it was not given is not selected. Both plugins
 * shipped today declare nothing and touch nothing.
 */

/**
 * What the craft agent knows about its target at the moment it asks for prover
 * help. Every field is optional because the agent's knowledge is genuinely
 * partial — early in a run it may have only the fuzzer's name; later it may
 * have a corpus seed's first bytes.
 */
export interface ProverContext {
  /**
   * Free-text format, fuzzer or target name, e.g. `"png"`,
   * `"libpng_read_fuzzer"`, `"zip"`. This is the same string space
   * `lookupFormatPrimer` matches on, so a hint that resolves to a primer should
   * resolve to a plugin when one exists for that format.
   */
  hint?: string;
  /**
   * Bytes of a candidate or corpus seed the agent already holds. Magic-byte
   * evidence is far stronger than a name hint — a fuzzer called
   * `image_fuzzer` says almost nothing, while the eight bytes
   * `89 50 4E 47 0D 0A 1A 0A` are conclusive — and {@link ProverMatch.score}
   * is expected to reflect that difference so the registry can rank.
   */
  sample?: Uint8Array;
  /** Optional harness / subsystem label, when it differs from `hint`. */
  harness?: string;
}

/**
 * A plugin's claim on a context. A score rather than a boolean because more
 * than one plugin can legitimately claim the same bytes — a PNG embedded in a
 * ZIP, a font inside a WOFF wrapper — and the registry needs a deterministic,
 * explainable winner instead of "whichever was registered first".
 */
export interface ProverMatch {
  /**
   * Confidence in `[0, 1]`. `0` means "not my format" and suppresses selection
   * entirely. By convention: `1.0` = magic bytes confirmed, `~0.7` = a name
   * hint matched an alias, below `0.5` = weak circumstantial evidence.
   */
  score: number;
  /** Why, in one line. Surfaced to the agent so a mis-selection is debuggable. */
  reason: string;
}

/**
 * A single framing change `construct` made while repairing a candidate.
 *
 * This exists for the agent, not for logs. When the plugin fixes a CRC the
 * agent got wrong, the agent needs to know *which* CRC, *where*, and *why* —
 * otherwise its next generator emits the same wrong bytes and the plugin has
 * taught it nothing. The craft loop is a learning loop; silent repairs break
 * it.
 */
export interface RepairRecord {
  /** Byte offset of the field that changed. */
  offset: number;
  /** Field name in the format's own vocabulary, e.g. `"IHDR.crc"`. */
  field: string;
  /** Previous value, rendered for humans (hex for checksums, decimal for counts). */
  from: string;
  /** Value written. */
  to: string;
  /** Why this is framing and not semantics — i.e. why repairing it is safe. */
  why: string;
}

/**
 * A request to build a new container from scratch (`base` omitted) or to repair
 * the framing of an existing one (`base` supplied).
 */
export interface ConstructRequest {
  /**
   * Bytes to repair. When present the plugin preserves every semantic field it
   * finds and rewrites only framing. When absent the plugin emits a minimal
   * valid skeleton parameterised by `params`.
   */
  base?: Uint8Array;
  /**
   * Format-specific structural knobs. Each plugin documents its own keys in
   * {@link ProverPlugin.paramsHelp} and **rejects unknown keys** rather than
   * ignoring them: a silently-ignored typo (`with` for `width`) produces a file
   * that looks built-to-spec and is not, which is the most expensive possible
   * failure mode here — it costs a graded submit and gives no signal.
   */
  params?: Record<string, unknown>;
}

/** Successful construction: the bytes, what was repaired, and what to know. */
export interface ConstructOk {
  ok: true;
  bytes: Uint8Array;
  /** Framing fields rewritten during a repair. Empty when building from scratch. */
  repairs: RepairRecord[];
  /**
   * Structural observations worth telling the agent — e.g. "added the PLTE
   * chunk required by colour type 3", "entry data stored uncompressed so the
   * CRC is exact". Not warnings; these are things a competent operator would
   * mention.
   */
  notes: string[];
}

/** Refusal. `construct` never guesses; it explains and stops. */
export interface ConstructErr {
  ok: false;
  /** Actionable message, fed verbatim back to the agent as tool output. */
  error: string;
}

export type ConstructResult = ConstructOk | ConstructErr;

/**
 * One structural problem found by {@link ProverPlugin.validate}.
 *
 * The `severity` split is the whole point of the type — see the framing /
 * semantics discussion in the module header.
 */
export interface ValidationDefect {
  /**
   * `fatal` — a real parser rejects or cannot walk the file, so the vulnerable
   * code is unreachable and submitting this input is a wasted attempt.
   *
   * `warning` — malformed, but the parser will still reach the code under test.
   * In a PoC this is frequently intentional and must not be "fixed".
   */
  severity: "fatal" | "warning";
  /** Byte offset, when the defect has one. */
  offset?: number;
  /** Field name in the format's vocabulary. */
  field: string;
  /** What is wrong, concretely, with the observed and expected values. */
  message: string;
  /**
   * Whether `construct({ base })` can repair this defect without touching
   * semantics. `false` here plus `fatal` severity means the agent must
   * regenerate the input, not patch it.
   */
  repairable: boolean;
}

/**
 * The verdict on a candidate's structure.
 *
 * NOTE the deliberately narrow claim: `wellFormed` means "a parser for this
 * format will accept the framing and walk into the content". It is **necessary,
 * not sufficient** for the PoC to trigger anything. Nothing in this module
 * grades a PoC — that stays the injected oracle's job, exactly as
 * `craft-scan.ts` documents ("Never self-grade"). A prover plugin's entire
 * contribution is removing the *structural* reason a good hypothesis fails.
 */
export interface ValidationReport {
  /** True iff there are no `fatal` defects. */
  wellFormed: boolean;
  defects: ValidationDefect[];
  /**
   * Human-readable structural walk — the chunk list, the entry table, the box
   * tree. This is what lets the agent see that its 4-byte length field made the
   * parser skip the chunk it cared about.
   */
  structure: string[];
}

/**
 * Injected side-effect capabilities. Empty today by construction: both shipped
 * plugins are pure. It exists so that the first plugin that genuinely needs I/O
 * gets it through the same injection seam `craft-scan.ts` already uses for its
 * oracle (`CraftPocEvaluator`) rather than reaching for `node:fs` inline and
 * quietly making the whole registry untestable.
 */
export interface ProverServices {
  /** Read a file the caller has authorised. Absent when the caller grants no I/O. */
  readFile?(path: string): Uint8Array | undefined;
  /** Diagnostic sink. */
  note?(msg: string): void;
}

/**
 * A domain expert, expressed as code.
 *
 * Implementations live one-per-file in this directory and are listed in
 * `registry.ts` — the same extension-point idiom as
 * `stages/npm-detectors/registry.ts` and `triage/router/layer-registry.ts`: a
 * frozen array plus an id map, with the shared discipline enforced outside the
 * registry so registering a plugin cannot exempt it from the rules.
 */
export interface ProverPlugin {
  /** Stable kebab-case id, e.g. `png`. Must be unique in the registry. */
  readonly id: string;
  /** One-line human description, surfaced in the tool description. */
  readonly title: string;
  /**
   * Format aliases this plugin answers to. Kept aligned with the `match` arrays
   * in `stages/format-knowledge.ts` so a format the agent can get a primer for
   * is a format it can also get a prover for, under the same name.
   */
  readonly aliases: readonly string[];
  /**
   * Services this plugin cannot work without. A plugin whose requirements are
   * not satisfied by the caller's {@link ProverServices} is skipped during
   * selection instead of failing at call time. Empty ⇒ pure.
   */
  readonly requiresServices?: readonly (keyof ProverServices)[];
  /** Documentation for the `params` this plugin accepts, shown to the agent on error. */
  readonly paramsHelp: string;

  /** Does this plugin's domain cover the target? See {@link ProverMatch}. */
  matches(ctx: ProverContext): ProverMatch;

  /**
   * Build a structurally valid container, or repair the framing of `req.base`.
   * Semantic fields are preserved verbatim; every framing change is reported in
   * {@link ConstructOk.repairs}.
   */
  construct(req: ConstructRequest, services?: ProverServices): ConstructResult;

  /**
   * Statically decide whether `bytes` is well-formed enough to reach the
   * parser. Never executes anything; never grades whether the bug triggers.
   */
  validate(bytes: Uint8Array, services?: ProverServices): ValidationReport;
}
