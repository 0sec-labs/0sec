/**
 * Session objective service — the OMP-style "what am I working on" title.
 *
 * A console session gets a short, Title-Case objective (e.g.
 * "Investigate Codex Cloud Workflows") the TUI renders in a pill on the bottom
 * bar. This module OWNS deriving and refining that string; the turn engine only
 * feeds it the operator's first message and forwards the result to the event
 * bus. It lives in `console/` (not `agent/`, a lower layer) so the display
 * concern stays above the agent loop and never inverts the layering.
 *
 * Two stages, both fail-soft:
 *
 *   1. INSTANT HEURISTIC — {@link deriveObjectiveHeuristic} is a pure function
 *      that turns the first message into a clean <=48-char / ~3-6 word title
 *      immediately (collapse whitespace, drop leading filler, trim trailing
 *      punctuation, Title Case, cap on a word boundary with no mid-word cut).
 *      Zero latency, zero model calls, no throw.
 *
 *   2. OPTIONAL MODEL REFINEMENT (default on) — ONE short model call rewrites
 *      the heuristic into a crisper objective, using the session's existing
 *      runtime, with a tiny prompt, a hard timeout, and a per-session cache
 *      (computed once, never per turn). It is DEFERRED off the critical path
 *      (fire-and-forget via a timer) so it never blocks or races a turn, and on
 *      ANY error/timeout/cancel the heuristic is kept. It only ever sends the
 *      operator's own request text (capped) — never secrets, tool output, or
 *      conversation history.
 *
 * The result is DISPLAY-ONLY: it is never fed back into model-facing context.
 */

import type { NativeContentBlock, NativeMessage, NativeRuntime } from "../runtime/types.js";

/** Hard cap on the objective length; the pill has a few dozen columns at most. */
export const MAX_OBJECTIVE_CHARS = 48;

/** Word cap — a title, not a sentence. */
export const MAX_OBJECTIVE_WORDS = 6;

/** Hard timeout for the single refinement model call. */
const REFINEMENT_TIMEOUT_MS = 6_000;

/**
 * The refinement only ever summarizes the operator's OWN request, and a title
 * needs only its opening — so the text sent is capped. This bounds token spend
 * and avoids shipping a giant paste to the model for a six-word label.
 */
const REFINEMENT_MAX_INPUT_CHARS = 600;

/**
 * Leading single-word filler dropped from the front of a message before it
 * becomes a title. Articles are included so "the login bug" → "Login Bug".
 * Stripping never empties the title (see {@link stripLeadingFiller}).
 */
const LEADING_FILLER = new Set<string>([
  "also", "anyway", "anyways", "so", "well", "ok", "okay", "um", "uh", "hey",
  "hi", "hello", "please", "now", "actually", "basically", "just", "alright",
  "yeah", "yep", "yo", "and", "the", "a", "an",
]);

/**
 * Leading multi-word phrases dropped before single-word filler. Longer, more
 * specific phrases come first so "i would like you to" is consumed whole rather
 * than leaving a dangling "you to". Compared token-by-token after the same
 * punctuation-stripping normalization applied to the message.
 */
const LEADING_FILLER_PHRASES: readonly string[] = [
  "i would like you to", "i would like to", "i'd like you to", "i'd like to",
  "i want you to", "i want to", "i wanna", "i need you to", "i need to",
  "can you please", "could you please", "can you", "could you", "would you",
  "will you", "please help me", "help me with", "go ahead and", "let's", "lets",
  "let us",
];

/**
 * Articles dropped from ANYWHERE in the title (not just the front), so
 * "audit the auth flow" → "Audit Auth Flow" reads like a tab title rather than
 * a sentence. Only exact article tokens are removed, never articles embedded in
 * a larger word, and never the last remaining word.
 */
const ARTICLES = new Set<string>(["the", "a", "an"]);

/** Lowercase a token and drop everything but letters, digits and apostrophes. */
function cleanToken(token: string): string {
  return token.toLowerCase().replace(/[^a-z0-9']/g, "");
}

/**
 * Drop a leading run of filler (phrases first, then single words), but NEVER
 * reduce the message to nothing — a message that is entirely filler ("help me",
 * "please") keeps its words rather than collapsing to an empty pill. Achieved by
 * refusing any strip that would leave zero words.
 */
function stripLeadingFiller(words: string[]): string[] {
  let current = words.slice();
  for (;;) {
    if (current.length === 0) break;
    const lower = current.map(cleanToken);
    let stripped = false;

    for (const phrase of LEADING_FILLER_PHRASES) {
      const parts = phrase.split(" ").map(cleanToken);
      if (
        parts.length < current.length &&
        parts.every((part, i) => part === lower[i])
      ) {
        current = current.slice(parts.length);
        stripped = true;
        break;
      }
    }
    if (stripped) continue;

    if (current.length > 1 && LEADING_FILLER.has(lower[0])) {
      current = current.slice(1);
      stripped = true;
    }
    if (!stripped) break;
  }
  return current;
}

/**
 * Take words up to the char/word cap on a WORD BOUNDARY (never a mid-word cut,
 * never an ellipsis). If a single first word already exceeds the char cap it is
 * hard-sliced — the only case a word is split, and still without an ellipsis.
 */
function capWords(words: string[]): string[] {
  const out: string[] = [];
  let len = 0;
  for (const word of words) {
    if (out.length >= MAX_OBJECTIVE_WORDS) break;
    const add = out.length === 0 ? word.length : word.length + 1;
    if (len + add > MAX_OBJECTIVE_CHARS) break;
    out.push(word);
    len += add;
  }
  if (out.length === 0 && words.length > 0) {
    out.push(words[0].slice(0, MAX_OBJECTIVE_CHARS));
  }
  return out;
}

/**
 * Capitalize the first letter, but leave a word that ALREADY carries an
 * uppercase letter untouched — so acronyms and proper casing survive ("api" →
 * "Api" is acceptable, but "API"/"OAuth"/"Codex"/"CVE-2026" are preserved).
 */
function titleWord(word: string): string {
  if (!word) return word;
  if (/[A-Z]/.test(word)) return word;
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/**
 * Derive a clean objective title from a raw operator message. Pure and total:
 * any input yields a valid string, and an empty / whitespace-only / all-punctuation
 * message yields "" so the renderer hides the pill.
 *
 * Rules (all cheap — no spell-correction): collapse whitespace, unwrap wrapping
 * quotes/backticks, trim trailing sentence punctuation, drop leading filler,
 * Title Case (preserving existing acronym casing), and cap to
 * {@link MAX_OBJECTIVE_WORDS} words / {@link MAX_OBJECTIVE_CHARS} chars on a word
 * boundary.
 */
export function deriveObjectiveHeuristic(text: string): string {
  if (typeof text !== "string") return "";
  const flat = text.replace(/\s+/g, " ").trim();
  if (!flat) return "";
  const unwrapped = flat.replace(/^["'`\s]+/, "").replace(/["'`\s]+$/, "");
  const base = (unwrapped || flat).replace(/[.!?…]+$/g, "").trim();
  if (!base) return "";

  let words = base.split(" ").filter(Boolean);
  const stripped = stripLeadingFiller(words);
  words = stripped.length > 0 ? stripped : words;
  // Drop interior articles for a tighter title, but never empty the list.
  const deArticled = words.filter((w) => !ARTICLES.has(cleanToken(w)));
  if (deArticled.length > 0) words = deArticled;
  words = capWords(words);

  const out = words.map(titleWord).join(" ");
  return out.replace(/[\s.,;:!?\-–—]+$/g, "").trim();
}

const REFINEMENT_SYSTEM = [
  "You name a work session for a security-research operator's console in a few",
  "words, like a browser tab title. Given the operator's request, reply with a",
  "single 3-6 word Title Case label naming what they are working on.",
  "Output ONLY the label: no quotes, no trailing punctuation, no preamble, no",
  "explanation. Never include secrets, credentials, tokens or file contents.",
].join(" ");

function buildRefinementPrompt(userText: string, heuristic: string): string {
  const trimmed = userText.replace(/\s+/g, " ").trim().slice(0, REFINEMENT_MAX_INPUT_CHARS);
  return [
    `Operator request: ${trimmed}`,
    `Draft label: ${heuristic}`,
    "Return a crisp 3-6 word Title Case label naming the objective.",
  ].join("\n");
}

/**
 * Run the model output back through the SAME clamps as the heuristic so a chatty
 * or over-long model answer still yields a clean pill. A leading "Objective:"
 * style label the model sometimes prepends is stripped first.
 */
function normalizeRefined(raw: string): string {
  const delabeled = raw.replace(/^\s*(?:objective|label|title|session)\s*[:\-–—]\s*/i, "");
  return deriveObjectiveHeuristic(delabeled);
}

/**
 * Configuration for {@link createSessionObjectiveService}.
 */
export interface SessionObjectiveServiceConfig {
  /**
   * Publish the current objective. Called synchronously with the heuristic
   * first (`refined: false`), then AT MOST once more with the model-refined
   * value (`refined: true`) if refinement succeeds and produces something
   * different. Never called with an empty string. The service already guards
   * this call, so a throwing emitter cannot break a turn.
   */
  emit: (objective: string, refined: boolean) => void;
  /**
   * Runtime used for the optional one-shot refinement. When absent, the service
   * is heuristic-only. Pass the session's own runtime to reuse the existing
   * model layer.
   */
  runtime?: NativeRuntime;
  /** Master switch for the model refinement. Default `true` (on). */
  refine?: boolean;
  /** Hard timeout (ms) for the refinement model call. Default 6000. */
  refineTimeoutMs?: number;
}

/**
 * A per-session objective producer. {@link noteUserMessage} is safe to call on
 * every turn — it acts only on the FIRST message that yields a non-empty
 * objective, then caches the result for the session.
 */
export interface SessionObjectiveService {
  /**
   * Feed an operator message. On the first message that derives a non-empty
   * objective this emits the heuristic immediately and remembers that a
   * refinement is due. Cheap, synchronous, never throws, and a no-op once
   * seeded. Does NOT itself start the model call — see {@link turnEnded}.
   */
  noteUserMessage(text: string): void;
  /**
   * Mark that an operator turn has started. Must be called synchronously at the
   * top of a turn (before any await) so the refinement knows a turn is in
   * flight and never runs its model call concurrently with the turn's own.
   */
  turnStarted(): void;
  /**
   * Mark that an operator turn has finished. Once no turn is active this is what
   * lets the one-shot refinement fire — deferred to a fresh macrotask and
   * rescheduled while any turn is still running, so it can neither block nor
   * race a turn. The refinement runs at most once per session, fire-and-forget.
   */
  turnEnded(): void;
  /** The current best objective ("" until seeded). */
  current(): string;
  /** Cancel any pending / in-flight refinement (call on session teardown). */
  dispose(): void;
}

/**
 * Build a session objective service. Fail-soft by construction: the heuristic is
 * pure and cannot throw, `emit` is guarded, and the refinement is deferred off
 * the turn's critical path and swallows every error, keeping the heuristic.
 */
export function createSessionObjectiveService(
  config: SessionObjectiveServiceConfig,
): SessionObjectiveService {
  let objective = "";
  let seeded = false;
  let disposed = false;
  let activeTurns = 0;
  /** The message that seeded the objective, kept until refinement runs. */
  let pending: { text: string; heuristic: string } | undefined;
  let kickoffTimer: ReturnType<typeof setTimeout> | undefined;
  let refineController: AbortController | undefined;

  const safeEmit = (value: string, refined: boolean): void => {
    try {
      config.emit(value, refined);
    } catch {
      // Display-only: an emitter fault must never surface into the turn loop.
    }
  };

  const runRefinement = async (userText: string, heuristic: string): Promise<void> => {
    const runtime = config.runtime;
    if (!runtime) return;
    const controller = new AbortController();
    refineController = controller;
    const timeoutMs = config.refineTimeoutMs ?? REFINEMENT_TIMEOUT_MS;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const messages: NativeMessage[] = [
        { role: "user", content: [{ type: "text", text: buildRefinementPrompt(userText, heuristic) }] },
      ];
      // No tools, tiny prompt, hard-timeout signal. Any failure/timeout/cancel
      // is caught below and the heuristic stands.
      const result = await runtime.executeNative(REFINEMENT_SYSTEM, messages, [], undefined, controller.signal);
      if (disposed || result.stopReason === "error" || result.cancelled) return;
      const rawText = result.content
        .filter((b): b is Extract<NativeContentBlock, { type: "text" }> => b.type === "text")
        .map((b) => b.text)
        .join(" ");
      const refined = normalizeRefined(rawText);
      if (!refined || refined === objective) return;
      objective = refined;
      safeEmit(refined, true);
    } catch {
      // Fail-soft: keep the heuristic on any error.
    } finally {
      clearTimeout(timer);
      if (refineController === controller) refineController = undefined;
    }
  };

  const noteUserMessage = (text: string): void => {
    if (seeded || disposed) return;
    let heuristic = "";
    try {
      heuristic = deriveObjectiveHeuristic(text);
    } catch {
      heuristic = "";
    }
    // Empty message (or all filler that reduced to nothing): stay unseeded so a
    // later, meatier message can set the objective. The pill stays hidden.
    if (!heuristic) return;
    seeded = true;
    objective = heuristic;
    safeEmit(heuristic, false);
    // Remember the message so the refinement (fired once no turn is active, via
    // turnEnded) can run the model call off the critical path.
    if (config.refine !== false && config.runtime) {
      pending = { text, heuristic };
    }
  };

  // Fire the one-shot refinement, but ONLY when no turn is active. A macrotask
  // (setTimeout) — rescheduled while a turn is still running — guarantees the
  // refinement's model call never runs inside any turn's synchronous/microtask
  // window, so it can neither block nor steal a turn's own model call.
  const runKickoff = (): void => {
    kickoffTimer = undefined;
    if (disposed || !pending || !config.runtime) return;
    if (activeTurns > 0) {
      // A turn is in flight — try again on the next macrotask.
      kickoffTimer = setTimeout(runKickoff, 0);
      return;
    }
    const { text, heuristic } = pending;
    pending = undefined;
    void runRefinement(text, heuristic);
  };

  const scheduleRefinement = (): void => {
    if (disposed || !pending || !config.runtime || kickoffTimer !== undefined) return;
    kickoffTimer = setTimeout(runKickoff, 0);
  };

  const turnStarted = (): void => {
    activeTurns += 1;
  };

  const turnEnded = (): void => {
    if (activeTurns > 0) activeTurns -= 1;
    scheduleRefinement();
  };

  return {
    noteUserMessage,
    turnStarted,
    turnEnded,
    current: () => objective,
    dispose: () => {
      disposed = true;
      if (kickoffTimer !== undefined) {
        clearTimeout(kickoffTimer);
        kickoffTimer = undefined;
      }
      refineController?.abort();
    },
  };
}
