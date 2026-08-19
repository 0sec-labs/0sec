/**
 * Task-drift detection — is the agent still working the thing it said it was
 * working on?
 *
 * The engine already had two things that look adjacent and are not:
 *
 * - `LoopDetector` (`agent/native-loop.ts`) catches an agent REPEATING itself
 *   (same fingerprint 3× in a row, or A-B-A-B). That is stuckness, not drift.
 *   A drifting agent is the opposite shape: it is doing something new every
 *   turn, none of it related to the objective, so every loop-detector signature
 *   is unique and it never fires.
 * - The percentage-keyed prompts (`buildContinuePrompt`, 30/50/70/85%) and the
 *   Strix budget warnings are keyed on BUDGET CONSUMED, not on content. They
 *   fire on a perfectly focused run and a completely derailed one identically,
 *   because neither one looks at what the agent is actually doing.
 *
 * Nothing measured divergence from the assigned objective. This does.
 *
 * ## The signal, and why it is deterministic rather than an LLM call
 *
 * Per turn, we compute lexical **anchor contact**: does this turn's activity
 * share any content term with the objective plus the currently OPEN plan tasks?
 * Drift is declared when contact has been absent for `streakThreshold`
 * consecutive scored turns.
 *
 *   ambient  = tokens(target) ∪ NOISE_TERMS
 *   anchor   = (tokens(objective) ∪ tokens(open plan tasks)) − ambient
 *   activity = tokens(tool names + tool arguments this turn) − ambient
 *   contact  = |anchor ∩ activity| >= 1
 *
 * Subtracting `ambient` is the part that makes this work at all. `config.target`
 * appears verbatim in essentially every `http_request` / `crawl` / `bash` call
 * an agent makes, so leaving the target host in the anchor set would make
 * contact permanently true and the detector permanently silent — a
 * false-NEGATIVE machine. Hitting the target is what the agent does by
 * definition; it carries no information about whether it is on-task. The same
 * reasoning removes HTTP/JSON boilerplate (`method`, `headers`, `true`, `json`,
 * …), which is present in every tool call regardless of intent.
 *
 * An LLM-judged alternative ("ask a cheap model each turn whether this is still
 * on-task") was rejected. The comparison that matters is not accuracy in the
 * abstract, it is accuracy per dollar per turn in a loop that already re-sends
 * the whole transcript every turn:
 *
 * - **Cost.** A per-turn judge call on a 40-turn run is 40 extra model calls
 *   per agent, and the engine fans agents out (specialists, EGATS branches,
 *   the verify wave). Measured verify-call cost in this codebase runs ~$0.55
 *   per LLM verification pass; even at a tenth of that, a per-turn judge is a
 *   double-digit-percent tax on scan cost to police a failure mode that does
 *   not occur on most runs. The token cost of THIS detector is zero — it never
 *   touches the network.
 * - **Latency.** It sits on the critical path of every turn.
 *   `Set.prototype.has` does not.
 * - **Determinism.** A judge that itself hallucinates drift injects a
 *   re-anchoring message into a healthy run, and it does so nonreproducibly,
 *   which makes the feature impossible to A/B honestly. This detector is a pure
 *   function of the trajectory: same run in, same warnings out, every time.
 * - **Circularity.** The judge would be the same model family that is drifting,
 *   asked to notice that it is drifting, from the same context that caused it.
 *
 * The honest summary is that the deterministic signal is a coarser instrument
 * bought at ~1/1000th the cost, and coarseness is affordable here because the
 * intervention is a short advisory message rather than a hard stop.
 *
 * ## What this signal genuinely cannot see (read this before trusting it)
 *
 * 1. **Lexically-disguised drift.** An agent that abandons the objective but
 *    keeps using the objective's vocabulary — endlessly re-probing an already-
 *    proven SQLi while the plan says "move to the auth bypass" — stays in
 *    contact on every turn and never trips. This is probably the most common
 *    real drift mode, and this detector misses it. Catching it needs semantics.
 * 2. **Legitimate pivots read as drift.** Discovering a new host, a new
 *    subdomain, or an unplanned CVE lead produces genuinely novel vocabulary
 *    with zero anchor overlap. This is the primary false-positive source and it
 *    is not a bug in the tokenizer — a real pivot and a real derail are
 *    lexically indistinguishable. The mitigations are structural, not clever:
 *    the streak requirement (a single exploratory turn never fires), the
 *    `plan`/`save_finding` reset (an agent recording progress is by definition
 *    on-task, whatever the words say), and an intervention that is advisory —
 *    the message explicitly tells the agent that if the new direction is right,
 *    the correct response is to ADD it to the plan, not to abandon it. A false
 *    positive therefore costs one short message and produces a useful side
 *    effect (the plan gets updated) rather than derailing the run.
 *
 *    The sharpest instance of this, and the one to keep in mind before turning
 *    the flag on for white-box work: **an agent reading unfamiliar code in
 *    order to REACH the objective.** A `read_file` / `grep` walk through a
 *    codebase it has never seen produces filenames, symbols and framework
 *    vocabulary that match nothing in the plan, even though the reading is
 *    exactly the right thing to be doing. The streak requirement is what makes
 *    this survivable — four consecutive turns of source navigation with no
 *    contact at all is genuinely a lot, and orientation reading normally
 *    touches an anchored term as soon as it opens a file belonging to the
 *    subsystem the plan names. It is nevertheless the case that a long
 *    orientation pass on a large unfamiliar tree WILL trip this detector, and
 *    that is an accepted false positive rather than a solved problem. Two
 *    tests below pin both halves of the behavior. If this proves noisy on
 *    audit/review roles, raise `streakThreshold` for those roles rather than
 *    widening the noise list, which would cost real signal.
 * 3. **An empty or generic plan.** With fewer than `minAnchorTerms` distinct
 *    anchor terms the detector disables itself entirely rather than guessing.
 *    A run whose objective is "find vulnerabilities" and whose plan is empty
 *    has nothing to drift FROM, and firing there would be noise by
 *    construction.
 *
 * **No false-positive rate is claimed.** Quantifying it requires labelled
 * trajectories — replaying stored XBOW/CyberGym runs through the monitor and
 * having a human mark which fires were genuine derails — and that corpus does
 * not exist yet. Until it does, this ships behind a default-OFF flag. The
 * structural claim being made is narrower and testable from the code: the
 * detector cannot fire on a run that maintains anchor contact, cannot fire more
 * than `maxWarnings` times, and cannot fire on a run with a thin anchor set.
 */

/**
 * Tokens too common to carry intent. Anything here appears across on-task and
 * off-task turns alike, so counting it as contact would only manufacture
 * false negatives. Kept deliberately short — the `ambient` subtraction of the
 * target string does most of the real work, and an over-long stoplist starts
 * removing genuine signal (`admin`, `token`, `upload` are all noise-adjacent
 * and all meaningful).
 */
const NOISE_TERMS = new Set([
  // HTTP / tooling boilerplate present in nearly every tool call
  "http", "https", "www", "com", "net", "org", "url", "uri", "host", "port",
  "get", "post", "put", "patch", "head", "method", "header", "headers",
  "body", "data", "json", "xml", "html", "text", "content", "type", "length",
  "accept", "agent", "user", "curl", "wget", "bash", "sh", "cmd", "command",
  "true", "false", "null", "undefined", "none", "nan",
  // generic English connectives that survive a 3-char filter
  "the", "and", "for", "with", "from", "this", "that", "into", "onto", "via",
  "any", "all", "not", "but", "its", "was", "are", "has", "have", "can",
  "try", "use", "using", "then", "when", "what", "which", "should", "would",
  // engine vocabulary the agent is told to use, so it says nothing about focus
  "target", "scan", "test", "check", "find", "look", "run", "step", "task",
  "tool", "call", "result", "output", "input", "value", "name", "file", "path",
]);

/**
 * Tool calls that are DIRECT evidence of on-task behavior. A turn containing
 * any of these resets the streak unconditionally, without looking at
 * vocabulary. Rationale: an agent that just recorded a finding or updated its
 * plan is by definition still engaged with the objective, and no lexical
 * heuristic should be allowed to overrule that. This removes a large class of
 * false positives at essentially no cost in false negatives — a truly derailed
 * agent is not saving findings.
 */
const PROGRESS_TOOLS = new Set([
  "plan",
  "save_finding",
  "update_finding",
  "done",
]);

/**
 * Read-only bookkeeping tools. They are neither evidence of focus nor of
 * drift, so a turn made up solely of these is skipped: it neither advances nor
 * resets the streak. Scoring them would let an agent mask drift by polling
 * `query_findings`, and counting them as drift would punish legitimate lookup.
 */
const NEUTRAL_TOOLS = new Set([
  "query_findings",
  "use_loot",
  "list_skills",
  "load_skill",
  "oast_poll",
]);

/** Tokens shorter than this are dropped. 3 keeps `xss`, `lfi`, `jwt`, `ssh`. */
const MIN_TERM_LEN = 3;

/**
 * Split text into content terms. Lowercased, split on any non-alphanumeric run
 * (so URLs, snake_case, camel boundaries via punctuation, and JSON all shred
 * into words), pure-numeric tokens dropped — a status code or an incrementing
 * IDOR id says nothing about topic.
 */
export function contentTerms(text: string): Set<string> {
  const out = new Set<string>();
  if (!text) return out;
  for (const raw of text.toLowerCase().split(/[^a-z0-9]+/)) {
    if (raw.length < MIN_TERM_LEN) continue;
    if (/^\d+$/.test(raw)) continue;
    if (NOISE_TERMS.has(raw)) continue;
    out.add(raw);
  }
  return out;
}

export interface DriftMonitorOptions {
  /**
   * The assigned objective in prose — typically the role + task line of the
   * system prompt. Contributes anchor terms so the detector still works before
   * the agent has written any plan.
   */
  objective: string;
  /**
   * The scan target. Its tokens are subtracted from BOTH the anchor and the
   * activity sets (see the module doc) — every tool call contains the target,
   * so it is pure ambient signal.
   */
  target: string;
  /**
   * Consecutive no-contact scored turns before drift fires. Default 4.
   *
   * This default is derived STRUCTURALLY, not empirically, and the distinction
   * matters enough to record: the repo contains no stored agent trajectories to
   * calibrate against (`packages/benchmark/results/*.jsonl` are per-task
   * outcome and triage-label datasets, not turn-by-turn tool-call traces), so
   * there was nothing to fit a threshold to. It is bracketed by two existing
   * constants instead:
   *
   * - The `LoopDetector` in `native-loop.ts` intervenes at 3 identical calls or
   *   2 full A-B cycles (4 entries). That is this codebase's established view
   *   of how much repetition justifies interrupting the model, and drift should
   *   not be twitchier than the detector that already ships.
   * - The budget checkpoints fire at 30/50/70/85%, i.e. every 6-12 turns on a
   *   typical 20-40 turn run. A drift warning firing more often than those
   *   would be perceived as noise regardless of accuracy.
   *
   * 4 sits between them. Treat it as a starting point to be replaced the first
   * time real labelled trajectories exist — that measurement, not this
   * reasoning, is what should set it.
   */
  streakThreshold?: number;
  /** Below this many anchor terms the monitor stays inert. Default 3. */
  minAnchorTerms?: number;
  /** Hard cap on warnings per run, so this can never become a nag. Default 3. */
  maxWarnings?: number;
}

/** Snapshot of the monitor's internal state, for events and tests. */
export interface DriftState {
  /** Consecutive scored turns with no anchor contact. */
  streak: number;
  /** Number of anchor terms currently in play. */
  anchorSize: number;
  /** Warnings issued so far this run. */
  warningsIssued: number;
}

/**
 * Tracks anchor contact across turns and emits a re-anchoring message when
 * contact has been absent long enough to look like drift rather than
 * exploration.
 *
 * Shaped after `LoopDetector` on purpose — `record()` then `detect()`, called
 * back to back from the same place in the loop, with a fired-latch so one
 * episode produces one warning instead of one per turn.
 */
export class DriftMonitor {
  private readonly objectiveTerms: Set<string>;
  private readonly ambient: Set<string>;
  private readonly streakThreshold: number;
  private readonly minAnchorTerms: number;
  private readonly maxWarnings: number;

  private streak = 0;
  private warningsIssued = 0;
  /** Latched when a warning fires; cleared on the next contact turn. */
  private fired = false;
  /** Anchor terms as of the last `record()`, cached for `detect()`/events. */
  private lastAnchorSize = 0;
  /** Open-plan prose as of the last `record()`, used to build the message. */
  private lastPlanSummary = "";

  constructor(opts: DriftMonitorOptions) {
    this.ambient = contentTerms(opts.target);
    // Objective terms are computed once: the objective does not change
    // mid-run, and recomputing per turn would be pure waste.
    this.objectiveTerms = subtract(contentTerms(opts.objective), this.ambient);
    this.streakThreshold = opts.streakThreshold ?? 4;
    this.minAnchorTerms = opts.minAnchorTerms ?? 3;
    this.maxWarnings = opts.maxWarnings ?? 3;
  }

  get state(): DriftState {
    return {
      streak: this.streak,
      anchorSize: this.lastAnchorSize,
      warningsIssued: this.warningsIssued,
    };
  }

  /**
   * Record one turn's tool calls.
   *
   * @param calls    The tool calls the model emitted this turn.
   * @param planText Free text of the currently OPEN plan tasks
   *                 (`TaskLedger.openText()`), or `""` when there is no plan.
   *                 Passed per-turn rather than held, because the open set
   *                 changes as tasks are completed and dropped — and a
   *                 completed task must stop anchoring immediately.
   */
  record(calls: Array<{ name: string; arguments: unknown }>, planText: string): void {
    this.lastPlanSummary = planText;
    const anchor = this.buildAnchor(planText);
    this.lastAnchorSize = anchor.size;

    if (calls.length === 0) return; // a no-tool turn is not activity

    // Direct evidence of progress overrides the lexical signal entirely.
    if (calls.some((c) => PROGRESS_TOOLS.has(c.name))) {
      this.reset();
      return;
    }

    const scored = calls.filter((c) => !NEUTRAL_TOOLS.has(c.name));
    if (scored.length === 0) return; // bookkeeping-only turn: neither way

    const activity = subtract(activityTerms(scored), this.ambient);
    if (intersects(anchor, activity)) {
      this.reset();
      return;
    }
    this.streak += 1;
  }

  /**
   * Returns a re-anchoring message when drift is detected, else `null`. Safe to
   * call every turn; the fired-latch and `maxWarnings` cap guarantee at most
   * one message per drift episode and at most `maxWarnings` per run.
   */
  detect(): string | null {
    if (this.fired) return null;
    if (this.warningsIssued >= this.maxWarnings) return null;
    // Too thin an anchor to judge against — stay silent rather than guess.
    if (this.lastAnchorSize < this.minAnchorTerms) return null;
    if (this.streak < this.streakThreshold) return null;

    this.fired = true;
    this.warningsIssued += 1;
    return buildReanchorMessage(this.streak, this.lastPlanSummary);
  }

  private reset(): void {
    this.streak = 0;
    this.fired = false;
  }

  private buildAnchor(planText: string): Set<string> {
    if (!planText) return this.objectiveTerms;
    const merged = new Set(this.objectiveTerms);
    for (const t of subtract(contentTerms(planText), this.ambient)) merged.add(t);
    return merged;
  }
}

/** Terms from a turn's tool names and stringified arguments. */
function activityTerms(calls: Array<{ name: string; arguments: unknown }>): Set<string> {
  const parts: string[] = [];
  for (const c of calls) {
    parts.push(c.name);
    parts.push(
      typeof c.arguments === "string" ? c.arguments : safeStringify(c.arguments),
    );
  }
  return contentTerms(parts.join(" "));
}

/**
 * `JSON.stringify` on model-supplied arguments can throw (circular refs from a
 * malformed provider payload). Tokenization must never be the thing that ends
 * a scan, so a failure degrades to no terms — which at worst counts the turn
 * as a no-contact turn.
 */
function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value ?? "");
  } catch {
    return "";
  }
}

function subtract(set: Set<string>, remove: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const t of set) if (!remove.has(t)) out.add(t);
  return out;
}

function intersects(a: Set<string>, b: Set<string>): boolean {
  // Iterate the smaller set — anchors are usually small, activity on a
  // `bash` turn with a long script can be large.
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  for (const t of small) if (large.has(t)) return true;
  return false;
}

/**
 * The intervention. Deliberately framed as a question rather than a
 * correction, because the detector cannot tell a derail from a legitimate
 * pivot (see the module doc) and the message has to be useful in BOTH cases.
 * On a real derail it re-states the objective; on a real pivot it prompts the
 * agent to record the new direction in the plan, which is what should have
 * happened anyway and which restores anchor contact so the detector stops
 * firing.
 */
export function buildReanchorMessage(streak: number, planText: string): string {
  const planLine = planText
    ? `Your open plan is: ${planText.slice(0, 400)}`
    : "You have no open plan tasks recorded.";
  return [
    `[pwnkit drift check] Your last ${streak} turns have no apparent connection to your objective or your open plan.`,
    planLine,
    "Stop and answer, in one line, before your next tool call: which open task does this work serve?",
    "- If it serves an open task, say which one and continue.",
    "- If you have deliberately pivoted to a better lead, that is fine — but record it: call `plan` with action='add' to add the new task, then action='start' to make it current, and `drop` the tasks you have abandoned.",
    "- If you cannot connect the last few turns to anything on the plan, you have drifted. Return to the active task.",
  ].join("\n");
}
