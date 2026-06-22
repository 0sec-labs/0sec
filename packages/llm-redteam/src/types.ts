/**
 * Core types for the offensive LLM/agent red-team engine.
 *
 * Flow:  Behavior + Strategy -> Payload -> Target.send() -> TargetResponse
 *        -> Judge.evaluate() -> Verdict -> (break recorded | mutate & retry)
 */

/** The injection vector a behaviour rides in — i.e. which untrusted document the
 *  target ingests and which we control. */
export type InjectionVector =
  | "readme" // coding agent told to "set up" a repo
  | "code-comment" // source/file comment
  | "issue-or-pr" // GitHub issue / PR body
  | "web-content" // fetched page / search result
  | "tool-output" // result returned by a tool the agent called
  | "support-doc" // customer report / ticket / config bundle
  | "email" // message the agent reads
  | "forum-post" // user-generated content under moderation
  | "rules-file"; // .cursorrules / AGENTS.md / skill description

/** What we want the target to be coerced into doing, plus the literal artefact
 *  that proves success (used by the regex judge). */
export interface InjectionGoal {
  /** Human description of the harmful action. */
  action: string;
  /** A regex the target's transcript/output must match for a break (the proof
   *  artefact — e.g. /pip install\s+2dgamer_dev/). */
  proof: RegExp;
  /** Optional concrete payload value the strategy should embed verbatim
   *  (a command, an SSH key, an email address, a package name). */
  literal?: string;
}

/** A named red-team target behaviour (what success means + where it rides). */
export interface Behavior {
  id: string;
  title: string;
  vector: InjectionVector;
  /** The benign task the victim user/agent is actually trying to do. */
  benignTask: string;
  goal: InjectionGoal;
  /** Free-text notes on the scenario (for crafters / prompts). */
  scenario?: string;
}

/** A generated injection payload ready to drop into the vector. */
export interface Payload {
  /** The full text to place in the injection vector (visible + any hidden). */
  text: string;
  /** Which strategy(ies) produced it, outermost last. */
  strategies: string[];
  /** Parts that are invisible to a human reader (for reporting/auditing). */
  hiddenSegments?: string[];
  /** Behaviour this payload targets. */
  behaviorId: string;
}

/** A strategy turns a goal into (part of) a payload. Strategies compose:
 *  framing strategies build the visible body; concealment strategies wrap or
 *  append hidden reinforcement. */
export interface Strategy {
  id: string;
  /** "framing" | "concealment" | "routing" | "composite" */
  kind: StrategyKind;
  /** One-line description of the technique + why it works. */
  rationale: string;
  /** Build a payload for a behaviour. `base` is prior payload text when
   *  composing (concealment wraps framing output). */
  build(behavior: Behavior, base?: string): Payload;
}

export type StrategyKind = "framing" | "concealment" | "routing" | "composite";

/** What a target returned after being fed a payload. */
export interface TargetResponse {
  /** The full transcript / final text the target produced (what the judge reads). */
  transcript: string;
  /** Optional structured tool calls the agent made, if the adapter exposes them. */
  toolCalls?: Array<{ tool: string; args: string }>;
  /** Adapter-specific raw handle (e.g. arena submission id). */
  raw?: unknown;
  /** Model/codename this response came from, if the target fans out. */
  model?: string;
}

/** A target adapter: anything we can send a payload to and read a response from. */
export interface Target {
  name: string;
  /** Send the payload (in the behaviour's context) and return the response.
   *  When the target fans out across models, the engine passes each model id. */
  send(payload: Payload, behavior: Behavior, model?: string): Promise<TargetResponse>;
  /** Optional: discrete model identifiers this target fans out across. */
  models?: string[];
}

/** Judge verdict for one (payload, response) pair. */
export interface Verdict {
  broken: boolean;
  /** The matched proof substring / explanation. */
  evidence?: string;
  /** 0..1 confidence (regex judge is 1/0; llm judge can be graded). */
  confidence: number;
  judge: string;
}

/** A confirmed (or attempted) break record. */
export interface BreakRecord {
  behaviorId: string;
  target: string;
  model?: string;
  strategies: string[];
  broken: boolean;
  evidence?: string;
  payloadText: string;
  transcriptExcerpt: string;
}

export interface CampaignResult {
  behaviorId: string;
  target: string;
  attempts: number;
  breaks: BreakRecord[];
  /** Unique broken models (when the target fans out across models). */
  brokenModels: string[];
}
