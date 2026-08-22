/**
 * Feedback capture: a local file first, and an explicitly-requested,
 * one-shot HTTPS submission second.
 *
 * ## The local file is the product; the network is an accessory
 *
 * `appendFeedback` writes to a file on the operator's own machine and is the
 * only path that runs by default. Submission is layered *on top* of that, and
 * the ordering is load-bearing: the caller must append locally first and
 * submit afterwards, so a refused, timed-out, or failed transmission can never
 * be the reason a message was lost.
 *
 * ## Why submission is hedged this heavily
 *
 * This is a pentest tool, and feedback typed mid-engagement is not neutral
 * prose. It routinely contains client hostnames, finding detail, and sometimes
 * a credential the operator pasted while complaining about it. Two separate
 * things go wrong if we are careless:
 *
 *   1. The *content* leaves the engagement boundary.
 *   2. The *connection itself* leaves the engagement boundary. An outbound
 *      request from 0sec lands in the client's egress logs, and some
 *      engagement contracts flatly forbid tooling that phones home. That
 *      second harm happens even if the body is empty.
 *
 * So the rules encoded below are:
 *
 *   - **Never automatic.** There is no "always send" setting and no retry
 *     queue. Every transmission is one explicit human action for one message.
 *   - **Previewable.** {@link buildSubmitPreview} returns the literal bytes
 *     and the literal headers that would go on the wire, so the operator can
 *     read the hostname before it leaves rather than trusting a summary.
 *   - **Nothing auto-attached.** No transcript, no findings, no scan ids, no
 *     environment, no machine id. Only the fields the caller passed. The
 *     preview *is* the payload — {@link FEEDBACK_WIRE_FIELDS} is the whole
 *     list and a test asserts the serialized body carries nothing else.
 *   - **Warn, never scrub.** {@link scanForSecrets} flags credential shapes
 *     and returns the message untouched. Partial redaction was already
 *     rejected in this codebase for transcripts, for the right reason: a
 *     scrubber advertises a guarantee it cannot keep, and an operator who
 *     believes it stops reading what they are about to send. A warning that
 *     makes a human look is worth more than a filter that makes them stop
 *     looking.
 *   - **Centrally disableable.** See {@link submissionBlockedReason} — an
 *     organization can kill egress for every operator with one env var.
 *
 * The one thing on the wire that is not in the preview is whatever default
 * `User-Agent` the Node HTTP stack attaches; we set no headers of our own
 * beyond `content-type`, and deliberately do not encode OS, arch, or version
 * detail into a header where the preview would not show it.
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export interface FeedbackEntry {
  message: string;
  /** ISO timestamp. Injected so the formatter stays deterministic. */
  timestamp: string;
  version?: string;
  model?: string;
  mode?: string;
}

export interface FeedbackResult {
  ok: boolean;
  path: string;
  error?: string;
}

export function feedbackFilePath(homeDir?: string): string {
  return join(homeDir ?? homedir(), ".0sec", "feedback.md");
}

/** Render one entry as a Markdown block. Pure, so it is unit-testable. */
export function formatFeedbackEntry(entry: FeedbackEntry): string {
  const context = [
    entry.version ? `version ${entry.version}` : null,
    entry.model ? `model ${entry.model}` : null,
    entry.mode ? `mode ${entry.mode}` : null,
  ].filter((part): part is string => part !== null);

  const lines = [`## ${entry.timestamp}`];
  if (context.length > 0) lines.push(`_${context.join(" · ")}_`);
  lines.push("", entry.message.trim(), "");
  return `${lines.join("\n")}\n`;
}

/**
 * Append an entry. Never throws — a read-only home directory must not take
 * down the console, so failure is reported through the return value.
 */
export function appendFeedback(entry: FeedbackEntry, homeDir?: string): FeedbackResult {
  const path = feedbackFilePath(homeDir);
  try {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, formatFeedbackEntry(entry), "utf8");
    return { ok: true, path };
  } catch (error) {
    return {
      ok: false,
      path,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// ---------------------------------------------------------------------------
// Opt-in submission
// ---------------------------------------------------------------------------

export type FeedbackEnv = Record<string, string | undefined>;

/** The payload shape. Structurally identical to {@link FeedbackEntry}. */
export interface FeedbackPayload {
  message: string;
  timestamp: string;
  version?: string;
  model?: string;
  mode?: string;
}

/**
 * Every key that may appear in the serialized body, in wire order. Exported
 * so the guarantee is checkable from outside rather than asserted in prose.
 */
export const FEEDBACK_WIRE_FIELDS = ["message", "timestamp", "version", "model", "mode"] as const;

export interface SubmitPreview {
  url: string;
  /** The exact bytes of the request body. Show verbatim; do not summarize. */
  body: string;
  /** The exact headers we set. Show verbatim alongside the body. */
  headers: Record<string, string>;
  warnings: string[];
}

export type SubmitSkipReason = "no-endpoint" | "opt-out" | "insecure-endpoint";

export interface SubmitResult {
  ok: boolean;
  status?: number;
  error?: string;
  skipped?: SubmitSkipReason;
}

/**
 * Default endpoint. Intentionally empty.
 *
 * TODO: confirm production endpoint. Guessing a URL here would be worse than
 * having none: an unconfirmed host either black-holes operator feedback or,
 * if someone else registers it, receives engagement data. Until a real
 * endpoint is confirmed, submission reports `no-endpoint` and the local file
 * remains the whole feature.
 */
export const DEFAULT_FEEDBACK_URL = "";

/** Env var holding the submission endpoint. */
export const FEEDBACK_URL_ENV = "0SEC_FEEDBACK_URL";

/**
 * Env vars that hard-disable submission.
 *
 * `0SEC_OFFLINE` is the pre-existing convention in this repo (see
 * `../utils/update-check.ts`, which uses it to suppress the update ping), so
 * an operator who already sets it to keep 0sec off the network gets the
 * behaviour they asked for without learning a second knob. `0SEC_NO_TELEMETRY`
 * is added as the name people reach for, and `DO_NOT_TRACK` is honoured
 * because it is the cross-tool standard.
 */
export const FEEDBACK_OPT_OUT_ENV = ["0SEC_OFFLINE", "0SEC_NO_TELEMETRY", "DO_NOT_TRACK"] as const;

/** Request timeout. Short: this is a courtesy call behind a human keystroke. */
export const FEEDBACK_TIMEOUT_MS = 5000;

/** Refuse absurd bodies rather than hanging a socket on them. */
const MAX_BODY_BYTES = 64 * 1024;

/**
 * True when `value` reads as "on".
 *
 * `update-check.ts` tests `=== "1"` exactly. This is deliberately more
 * permissive, because the two have opposite failure directions: there, a
 * missed opt-out costs a suppressed update nudge; here, a missed opt-out means
 * client data crosses a boundary someone explicitly tried to close. Someone
 * who exports `0SEC_OFFLINE=true` has unambiguously stated an intent, and
 * honouring only `1` would transmit anyway. Anything set and not explicitly
 * falsy counts as opt-out.
 */
function isOptOutSet(value: string | undefined): boolean {
  if (value === undefined) return false;
  const normalized = value.trim().toLowerCase();
  if (normalized === "") return false;
  return normalized !== "0" && normalized !== "false" && normalized !== "no";
}

/**
 * The configured endpoint, or null when none is set. Does not validate the
 * scheme — {@link submissionBlockedReason} owns that, so the UI can tell
 * "unset" apart from "set to something we refuse to use".
 */
export function feedbackEndpoint(env: FeedbackEnv = process.env): string | null {
  const configured = env[FEEDBACK_URL_ENV]?.trim();
  const url = configured && configured.length > 0 ? configured : DEFAULT_FEEDBACK_URL;
  return url.length > 0 ? url : null;
}

/**
 * Why submission cannot happen, or null if it can. Lets the UI grey out the
 * send affordance with a real reason instead of discovering it post-hoc.
 */
export function submissionBlockedReason(env: FeedbackEnv = process.env): SubmitSkipReason | null {
  // Opt-out is checked first and wins over everything, including an
  // explicitly configured endpoint. That precedence is the point: the org
  // policy must beat the individual operator's request.
  for (const name of FEEDBACK_OPT_OUT_ENV) {
    if (isOptOutSet(env[name])) return "opt-out";
  }
  const url = feedbackEndpoint(env);
  if (url === null) return "no-endpoint";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "insecure-endpoint";
  }
  // HTTPS only. Feedback bodies carry engagement context; plaintext would put
  // it in front of anything on the path, which is exactly the audience we are
  // trying to keep it away from.
  if (parsed.protocol !== "https:") return "insecure-endpoint";
  return null;
}

/** Human-readable explanation for a skip reason, for direct UI rendering. */
export function describeSkip(reason: SubmitSkipReason): string {
  switch (reason) {
    case "opt-out":
      return `Submission disabled by ${FEEDBACK_OPT_OUT_ENV.join(" / ")}. Saved locally only.`;
    case "no-endpoint":
      return `No feedback endpoint configured (set ${FEEDBACK_URL_ENV}). Saved locally only.`;
    case "insecure-endpoint":
      return `Refusing a non-HTTPS ${FEEDBACK_URL_ENV}. Saved locally only.`;
  }
}

interface SecretRule {
  label: string;
  pattern: RegExp;
}

/**
 * Credential shapes worth interrupting a human over.
 *
 * Tuned for precision rather than recall. This list is not a filter and must
 * not be read as one — it is a nudge to re-read before sending, and a nudge
 * that cries wolf gets clicked through, which is strictly worse than no nudge.
 */
const SECRET_RULES: SecretRule[] = [
  { label: "an OpenAI/Anthropic-style key (sk-…)", pattern: /\bsk-[A-Za-z0-9_-]{16,}/ },
  { label: "a GitHub token (ghp_/gho_/ghu_/ghs_/ghr_…)", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}/ },
  { label: "an AWS access key id (AKIA…/ASIA…)", pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/ },
  { label: "a Google API key (AIza…)", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: "a Slack token (xox…)", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  {
    label: "an Authorization header",
    pattern: /authorization\s*[:=]\s*(?:bearer|basic|token|digest)\s+\S+/i,
  },
  { label: "a JWT (eyJ…)", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/ },
  {
    label: "a PEM private key block",
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/,
  },
  {
    label: "a credential-shaped assignment (password=/api_key=/secret=…)",
    pattern: /\b(?:pass(?:word|wd)?|api[_-]?key|secret|token|credentials?)\s*[:=]\s*\S{6,}/i,
  },
  {
    // Long opaque runs. Requires mixed case *and* a digit so ordinary prose,
    // file paths, and hyphenated identifiers do not trip it.
    label: "a long high-entropy string (base64-ish)",
    pattern: /(?=[A-Za-z0-9+/_-]{40,})(?=[A-Za-z0-9+/_-]*[a-z])(?=[A-Za-z0-9+/_-]*[A-Z])(?=[A-Za-z0-9+/_-]*[0-9])[A-Za-z0-9+/_-]{40,}={0,2}/,
  },
];

/**
 * Report credential shapes found in `message`.
 *
 * Returns warnings only — `message` is never read back out and never
 * modified. Callers must surface these *before* the confirmation prompt, so
 * the decision to send is made with the finding in view.
 */
export function scanForSecrets(message: string): string[] {
  const warnings: string[] = [];
  for (const rule of SECRET_RULES) {
    // Only the shape's name is reported, never the matched text: the warning
    // may be rendered into a scrollback or a log the secret should not reach.
    if (rule.pattern.test(message)) warnings.push(`Message appears to contain ${rule.label}.`);
  }
  return warnings;
}

/**
 * Serialize the payload. The single place a body is constructed, so preview
 * and transmission cannot drift apart, and so the field allowlist is applied
 * exactly once. Optional fields are omitted when absent rather than sent as
 * null, keeping the wire form minimal.
 */
function serializePayload(payload: FeedbackPayload): string {
  const body: Record<string, string> = {
    message: payload.message,
    timestamp: payload.timestamp,
  };
  if (payload.version !== undefined) body.version = payload.version;
  if (payload.model !== undefined) body.model = payload.model;
  if (payload.mode !== undefined) body.mode = payload.mode;
  return JSON.stringify(body);
}

const REQUEST_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "application/json",
});

/**
 * The exact request that {@link submitFeedback} would make, or null when
 * {@link submissionBlockedReason} says it would make none.
 *
 * Render `body` and `headers` verbatim. Summarizing them defeats the purpose:
 * the operator is looking for a client hostname they did not mean to include,
 * and a summary is precisely where that hostname hides.
 */
export function buildSubmitPreview(
  payload: FeedbackPayload,
  env: FeedbackEnv = process.env,
): SubmitPreview | null {
  if (submissionBlockedReason(env) !== null) return null;
  const url = feedbackEndpoint(env);
  if (url === null) return null;
  return {
    url,
    body: serializePayload(payload),
    headers: { ...REQUEST_HEADERS },
    warnings: scanForSecrets(payload.message),
  };
}

export interface SubmitOptions {
  /** Injected transport, matching the repo's `fetchImpl` convention. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Transmit one message, once.
 *
 * Never throws, never retries, never blocks past `timeoutMs`. The caller has
 * already written the message to disk, so every failure path here is
 * cosmetic — the correct response to `ok: false` is to tell the operator the
 * local copy is still there, not to try again.
 */
export async function submitFeedback(
  payload: FeedbackPayload,
  env: FeedbackEnv = process.env,
  opts: SubmitOptions = {},
): Promise<SubmitResult> {
  const blocked = submissionBlockedReason(env);
  if (blocked !== null) return { ok: false, skipped: blocked, error: describeSkip(blocked) };

  const url = feedbackEndpoint(env);
  if (url === null) return { ok: false, skipped: "no-endpoint", error: describeSkip("no-endpoint") };

  const body = serializePayload(payload);
  if (Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES) {
    return { ok: false, error: `Message too large to submit (limit ${MAX_BODY_BYTES} bytes).` };
  }

  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? FEEDBACK_TIMEOUT_MS;
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;

  // Raced rather than relying on the abort signal alone: a transport that
  // ignores `signal` (a stub, a patched global, a future undici quirk) would
  // otherwise hang a keystroke-driven UI forever. The race makes the bound
  // ours instead of the transport's.
  const timeout = new Promise<SubmitResult>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve({ ok: false, error: `Feedback submission timed out after ${timeoutMs}ms.` });
    }, timeoutMs);
    // Do not hold the event loop open on this timer alone.
    (timer as { unref?: () => void }).unref?.();
  });

  const attempt = (async (): Promise<SubmitResult> => {
    try {
      const response = await doFetch(url, {
        method: "POST",
        headers: { ...REQUEST_HEADERS },
        body,
        signal: controller.signal,
      });
      return response.ok
        ? { ok: true, status: response.status }
        : { ok: false, status: response.status, error: `Endpoint returned ${response.status}.` };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  })();

  try {
    return await Promise.race([attempt, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
