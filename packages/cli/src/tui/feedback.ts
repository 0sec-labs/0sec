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
 * `User-Agent` the Node HTTP stack attaches. Cloud-authenticated submissions
 * also carry a Bearer token; its header name is previewed but its value is
 * deliberately redacted so credentials never enter the transcript.
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { loadCloudCredentials } from "@0sec/core";

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
 * Parsed `/feedback` subcommand. `record` deliberately remains the default so
 * an ordinary sentence never creates a network side effect.
 */
export type FeedbackCommand =
  | { kind: "record"; message: string }
  | { kind: "submit"; message: string }
  | { kind: "send" }
  | { kind: "cancel" }
  | { kind: "usage" };

/** Parse the local-only and explicitly staged feedback command forms. */
export function parseFeedbackCommand(raw: string): FeedbackCommand {
  const text = raw.trim();
  if (!text) return { kind: "usage" };

  const separator = text.search(/\s/);
  const verb = separator < 0 ? text : text.slice(0, separator);
  const rest = separator < 0 ? "" : text.slice(separator).trim();
  if (verb === "submit") return rest ? { kind: "submit", message: rest } : { kind: "usage" };
  if (verb === "send") return rest ? { kind: "usage" } : { kind: "send" };
  if (verb === "cancel") return rest ? { kind: "usage" } : { kind: "cancel" };
  return { kind: "record", message: text };
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
  /** Headers shown to the operator; authentication values are redacted. */
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
 * Explicit default endpoint. Intentionally empty: an endpoint configured by an
 * operator remains an override, while authenticated 0cloud delivery is derived
 * only from real CLI credentials below.
 */
export const DEFAULT_FEEDBACK_URL = "";

/** Env var holding the submission endpoint. */
export const FEEDBACK_URL_ENV = "0SEC_FEEDBACK_URL";

/** The authenticated 0cloud receiver behind the dashboard feedback channel. */
const CLOUD_FEEDBACK_PATH = "/api/cli-feedback";

export interface FeedbackResolveOptions {
  /**
   * Test seam for the local `0sec auth login` credential store. An explicit
   * 0SEC_FEEDBACK_URL always wins and never consumes this credential.
   */
  cloudCredentials?: () => { host: string; token: string } | null;
}

interface FeedbackTarget {
  url: string;
  authorization?: string;
}

function defaultCloudCredentials(env: FeedbackEnv): { host: string; token: string } | null {
  try {
    const credentials = loadCloudCredentials({
      env: env as NodeJS.ProcessEnv,
      warn: () => {},
    });
    return { host: credentials.host, token: credentials.token };
  } catch {
    return null;
  }
}

function cloudFeedbackUrl(host: string): string | null {
  try {
    const url = new URL(host);
    // cloud.0sec.ai is a legacy redirect. Redirecting a POST can change its
    // method, so post to the canonical dashboard host directly.
    if (url.hostname === "cloud.0sec.ai") url.hostname = "cloud.0.security";
    url.pathname = CLOUD_FEEDBACK_PATH;
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

function resolveFeedbackTarget(
  env: FeedbackEnv = process.env,
  options: FeedbackResolveOptions = {},
): FeedbackTarget | null {
  const configured = env[FEEDBACK_URL_ENV]?.trim();
  if (configured) return { url: configured };
  if (DEFAULT_FEEDBACK_URL) return { url: DEFAULT_FEEDBACK_URL };

  const credentials = (options.cloudCredentials ?? (() => defaultCloudCredentials(env)))();
  if (!credentials) return null;
  const url = cloudFeedbackUrl(credentials.host);
  return url ? { url, authorization: `Bearer ${credentials.token}` } : null;
}

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
 * The configured endpoint, or the authenticated dashboard receiver associated
 * with `0sec auth login`. Scheme validation stays in
 * {@link submissionBlockedReason}, so callers can distinguish absent from
 * refused configuration.
 */
export function feedbackEndpoint(
  env: FeedbackEnv = process.env,
  options: FeedbackResolveOptions = {},
): string | null {
  return resolveFeedbackTarget(env, options)?.url ?? null;
}

/**
 * Why submission cannot happen, or null if it can. Lets the UI grey out the
 * send affordance with a real reason instead of discovering it post-hoc.
 */
export function submissionBlockedReason(
  env: FeedbackEnv = process.env,
  options: FeedbackResolveOptions = {},
): SubmitSkipReason | null {
  // Opt-out is checked first and wins over everything, including an
  // explicitly configured endpoint. That precedence is the point: the org
  // policy must beat the individual operator's request.
  for (const name of FEEDBACK_OPT_OUT_ENV) {
    if (isOptOutSet(env[name])) return "opt-out";
  }
  const target = resolveFeedbackTarget(env, options);
  if (target === null) return "no-endpoint";
  let parsed: URL;
  try {
    parsed = new URL(target.url);
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

function requestHeaders(target: FeedbackTarget, redactAuthorization = false): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (target.authorization) {
    headers.authorization = redactAuthorization ? "Bearer <redacted>" : target.authorization;
  }
  return headers;
}

/**
 * The exact body and safe-to-display headers {@link submitFeedback} would use,
 * or null when {@link submissionBlockedReason} says it would make none.
 */
export function buildSubmitPreview(
  payload: FeedbackPayload,
  env: FeedbackEnv = process.env,
  options: FeedbackResolveOptions = {},
): SubmitPreview | null {
  if (submissionBlockedReason(env, options) !== null) return null;
  const target = resolveFeedbackTarget(env, options);
  if (target === null) return null;
  return {
    url: target.url,
    body: serializePayload(payload),
    headers: requestHeaders(target, true),
    warnings: scanForSecrets(payload.message),
  };
}

export interface SubmitOptions extends FeedbackResolveOptions {
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
  const blocked = submissionBlockedReason(env, opts);
  if (blocked !== null) return { ok: false, skipped: blocked, error: describeSkip(blocked) };

  const target = resolveFeedbackTarget(env, opts);
  if (target === null) return { ok: false, skipped: "no-endpoint", error: describeSkip("no-endpoint") };

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
      const response = await doFetch(target.url, {
        method: "POST",
        headers: requestHeaders(target),
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
