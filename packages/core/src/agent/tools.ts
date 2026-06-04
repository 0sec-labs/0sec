import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync, spawn } from "node:child_process";
import { isAbsolute, resolve } from "node:path";
import { isIP } from "node:net";
import type {
  Finding,
  AttackResult,
  PocStep,
  TargetInfo,
  VerificationSpec,
  VerificationCodePredicate,
  VerificationBehavior,
  VerificationBehaviorStep,
  NamedIdentity,
} from "@pwnkit/shared";
import { resolveIdentities, compareRoles } from "@pwnkit/shared";
import type { ToolDefinition, ToolCall, ToolResult, ToolContext, AgentRole } from "./types.js";
import type { LootKind } from "./loot.js";
import type { ScopePolicy } from "../scope/scope.js";
import { extractUrls } from "../scope/scope.js";
import type { EnforcementTracker } from "../scope/enforcement.js";
import {
  classifyResponse,
  runEvasionCampaign,
  type HttpRequestParts,
  type WafResponseLike,
} from "../scope/waf-detect.js";
import { detectScannerBinary } from "../scope/scanner-binaries.js";
import { applyAttribution, formatUserAgent } from "../scope/attribution.js";
import { sendPrompt, extractResponseText } from "../http.js";
import { buildAuthHeaders } from "./prompts.js";
import {
  runStructuralSqliProbeAsync,
  type ProbeObservation,
} from "./structural-sqli.js";
import {
  classifyPromptLayerImpact,
  type PromptLayerAsset,
} from "./playbooks.js";
import type { pwnkitDB } from "@pwnkit/db";
import { features as featureFlags } from "./features.js";
import { PtySessionManager } from "./pty-session.js";
import {
  runWpFingerprint,
  summarizeWpFingerprint,
  type FetchLike,
} from "./wp-fingerprint.js";
import {
  runScannerProcess,
  buildSqlmapArgv,
  buildNmapArgv,
  buildFfufArgv,
  buildNucleiArgv,
  parseSqlmapOutput,
  parseNmapOutput,
  parseFfufOutput,
  parseNucleiOutput,
  suggestedFindingsFor,
  summarizeScannerResult,
  type ScannerParsedResult,
  type ScannerRunStats,
} from "./scanner-tools.js";
import { validateFlagShape } from "./flag-validator.js";
import { extractPocStepsFromProse } from "./poc-steps-from-prose.js";
import { isUntrustedSourceTool } from "../untrusted-sanitizer.js";
import { computeFindingConfidence } from "./finding-confidence.js";
import {
  validateFindingDraft,
  type FindingDraft,
  type ValidationError,
} from "./finding-validator.js";
import {
  forgeObjectId,
  forgeObjectIdSequence,
  parseObjectId,
} from "./objectid-forge.js";
import {
  JSFUCK_ALERT_PAYLOAD,
  JSFUCK_XSS_PAYLOAD,
} from "./payloads.js";
import { parsePatch, applyPatchOps } from "./apply-patch.js";
import {
  normalizeFindingTitle,
  levenshtein,
  evidenceRequestPrefix,
  FUZZY_TITLE_DISTANCE_THRESHOLD,
} from "./tools-helpers.js";
import {
  listSkillSummaries,
  getSkillById,
  matchTriggers,
  loadSkillRegistry,
} from "./skills/index.js";
import { eventBus } from "../events/bus.js";
import {
  buildIntelDossier,
  lookupCve,
  searchAdvisories,
  searchSimilar,
  searchTargetHistory,
} from "../intel/index.js";

// ── Tool registry (pwnkit#611) ──
// The per-tool ToolDefinition objects now live in per-domain modules under
// ./tools/ and are assembled — in canonical order — by the ./tools/index.ts
// barrel. They are re-exported here so every existing importer of
// `./tools.js` (agent/index.ts, native-loop, egats, racing, agentic-scanner,
// the test suites) keeps resolving them, and so getToolsForRole /
// ToolExecutor below see them as local bindings. Splitting the old 600-line
// literal lets parallel feature PRs touch disjoint domain files instead of
// serializing on one merge-conflict chokepoint.
import { TOOL_DEFINITIONS, SCANNER_TOOL_NAMES } from "./tools/index.js";
export { TOOL_DEFINITIONS, SCANNER_TOOL_NAMES };

// Tool-name → handler-method-name routing table (pwnkit#614), assembled from
// per-domain `*Dispatch` maps. `ToolExecutor._dispatch` resolves the handler
// off the instance by this name, replacing the hand-written switch so adding a
// tool no longer edits a shared dispatch chokepoint.
import { TOOL_DISPATCH } from "./tools/dispatch.js";

// ── Sensitive env filtering ──

const SENSITIVE_ENV_PATTERNS = [
  "OPENROUTER_API",
  "ANTHROPIC_API",
  "OPENAI_API",
  "AZURE_OPENAI_API",
  "PWNKIT_CLOUD_TOKEN",
  "GEMINI_API",
  "MISTRAL_API",
  "XAI_API",
  "COHERE_API",
  "GROQ_API",
  "TOGETHER_API",
  "PERPLEXITY_API",
  "FIREWORKS_API",
  "AI21_API",
  "DEEPSEEK_API",
  "HUGGING_FACE_",
  "HF_TOKEN",
];

function sanitizedEnv(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) => !SENSITIVE_ENV_PATTERNS.some((p) => key.includes(p)),
    ),
  ) as Record<string, string>;
}

// ── Bash tool wallclock ceiling ──
//
// Hard upper bound on how long a single `bash` tool invocation may run before
// the subprocess (and its descendants) are forcibly reaped. This defends
// against scripts that block on network I/O without a client-side timeout —
// the canonical case being `python3 -c 'requests.post(…)'`, where `requests`
// has no default timeout and a hung remote can wedge the agent indefinitely.
//
// See https://github.com/0sec-labs/pwnkit/issues/181

const DEFAULT_BASH_WALLCLOCK_MS = 120_000;
const BASH_GRACE_MS = 2_000;

function resolveBashWallclockCeilingMs(): number {
  const raw = process.env.PWNKIT_BASH_TIMEOUT_MS?.trim();
  if (!raw) return DEFAULT_BASH_WALLCLOCK_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_BASH_WALLCLOCK_MS;
  return Math.floor(parsed);
}

type BashOutcome =
  | { kind: "exit"; exitCode: number; combined: string }
  | { kind: "timeout"; partial: string }
  | { kind: "error"; message: string };

interface BashRunOptions {
  timeoutMs: number;
  ceilingMs: number;
  env: Record<string, string>;
}

/**
 * Run a shell command with a hard wallclock ceiling. The child is its own
 * process group leader (`detached: true`); on timeout we signal the entire
 * group so any forked grandchildren (`python3 -c '…'`, `curl`, etc.) die
 * alongside the shell. SIGTERM first, then SIGKILL after a short grace.
 *
 * Exported via the module-private `runBashWithWallclock` helper so the bash
 * tool's `shellExec` can consume a typed outcome rather than wrapping the
 * raw spawn lifecycle inline.
 */
async function runBashWithWallclock(
  command: string,
  opts: BashRunOptions,
): Promise<BashOutcome> {
  return new Promise((resolvePromise) => {
    let child;
    try {
      child = spawn("/bin/bash", ["-c", command], {
        env: opts.env,
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
    } catch (err) {
      resolvePromise({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    const MAX_BUFFER = 1024 * 1024; // 1MB, matches prior execSync limit
    let stdoutLen = 0;
    let stderrLen = 0;
    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    let timedOut = false;
    let settled = false;

    child.stdout?.setEncoding("utf-8");
    child.stderr?.setEncoding("utf-8");
    child.stdout?.on("data", (chunk: string) => {
      if (stdoutLen >= MAX_BUFFER) return;
      stdoutChunks.push(chunk);
      stdoutLen += chunk.length;
    });
    child.stderr?.on("data", (chunk: string) => {
      if (stderrLen >= MAX_BUFFER) return;
      stderrChunks.push(chunk);
      stderrLen += chunk.length;
    });

    const collected = (): string =>
      (stdoutChunks.join("") + "\n" + stderrChunks.join("")).trim();

    const killGroup = (signal: NodeJS.Signals) => {
      const pid = child.pid;
      if (typeof pid !== "number") return;
      // Negative pid targets the process group (because we spawned detached).
      try {
        process.kill(-pid, signal);
      } catch {
        // Process may already be gone; fall back to per-pid kill.
        try {
          process.kill(pid, signal);
        } catch {
          /* already dead */
        }
      }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killGroup("SIGTERM");
      // Escalate after a short grace if the group ignored SIGTERM.
      setTimeout(() => {
        if (!settled) killGroup("SIGKILL");
      }, BASH_GRACE_MS).unref?.();
    }, opts.timeoutMs);
    timer.unref?.();

    const settle = (outcome: BashOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise(outcome);
    };

    child.on("error", (err: Error) => {
      settle({ kind: "error", message: err.message });
    });

    child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
      if (timedOut) {
        settle({ kind: "timeout", partial: collected() });
        return;
      }
      // Process killed by signal but not from our timer — surface as exit -1
      // with whatever output we captured. Preserves prior execSync behaviour
      // of returning combined output for non-zero exits.
      const exitCode = typeof code === "number" ? code : signal ? 1 : 0;
      settle({ kind: "exit", exitCode, combined: collected() });
    });
  });
}

// ── Tool Registry ──

// ── Tool trust level (#558) ───────────────────────────────────────────────
//
// A tool result is either TRUSTED (we constructed it — save_finding,
// query_findings, done, the intel_* summaries, …) or UNTRUSTED (its payload is
// attacker-influenced target output — http_request / crawl / read_file /
// send_prompt / submit_form / browser / any MCP tool). UNTRUSTED results are
// run through `sanitizeUntrustedToolResult` before they re-enter model context
// (see `agent/native-loop.ts`). The classification itself lives next to the
// sanitizer so the marker set and the trust set stay in one place; we re-export
// it here so the trust level is discoverable from the canonical tool registry.
export type ToolTrustLevel = "trusted" | "untrusted";

export { isUntrustedSourceTool };

/** Trust level for a tool's result content. See `isUntrustedSourceTool`. */
export function toolTrustLevel(toolName: string, isMcp = false): ToolTrustLevel {
  return isUntrustedSourceTool(toolName, isMcp) ? "untrusted" : "trusted";
}

// ── Allowed commands for run_command (safety) ──

const ALLOWED_COMMANDS = new Set([
  "grep",
  "rg",
  "find",
  "ls",
  "cat",
  "head",
  "tail",
  "wc",
  "foxguard",
  "semgrep",
  "codeql",
  "jq",
  "file",
  "stat",
  "npm",
  // Text-mangling utilities the audit agent frequently reaches for to
  // post-process grep / rg output (sort + uniq for top-N counts, sed
  // for line-trimming, awk for field extraction, cut/tr for cleanup,
  // tee for tap-points). Read-only; safe under the same no-shell-meta
  // policy the rest of the allowlist relies on.
  "sort",
  "uniq",
  "sed",
  "awk",
  "cut",
  "tr",
  "tee",
  "diff",
  // Hash + encoding helpers — useful for fingerprinting compiled
  // assets and decoding embedded blobs during source review.
  "sha256sum",
  "md5sum",
  "base64",
  "xxd",
]);

// Block dangerous shell chars. Piping is handled manually without invoking a shell.
const DISALLOWED_SHELL_CHARS = /[;&<>`$\n\r]/;
const ALLOWED_NPM_SUBCOMMANDS = new Set(["audit", "view", "ls", "list"]);

/**
 * Check whether `command` contains disallowed shell operator characters
 * OUTSIDE of single- or double-quoted strings. Characters inside quotes
 * are treated as literal data — this is safe because `run_command` never
 * invokes a shell; it tokenizes the command itself (see `tokenizeCommand`)
 * and passes arguments directly to `spawnSync`, so quoted content can
 * never be interpreted as shell metacharacters.
 *
 * This allows patterns like:
 *   rg -F 'xfs_rtgroup_put(rtg);' fs/xfs/xfs_ioctl.c
 *   grep -F "foo$bar" file.txt
 * while still blocking unquoted shell injection like:
 *   ls; rm -rf /
 *   echo $HOME
 */
export function containsUnquotedShellChars(command: string): boolean {
  let quote: "'" | '"' | null = null;
  let escaping = false;

  for (const ch of command) {
    if (escaping) {
      escaping = false;
      continue;
    }
    if (ch === "\\") {
      escaping = true;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    // Outside quotes — check for disallowed shell chars
    if (DISALLOWED_SHELL_CHARS.test(ch)) {
      return true;
    }
  }

  return false;
}

/**
 * Split a command on top-level `|` (pipe) characters, respecting
 * single + double quotes and backslash escapes. A naive
 * `command.split("|")` corrupts any \\\| or `|` that lives inside a
 * quoted regex pattern (very common in the audit agent's grep / rg
 * calls — e.g. `grep "foo\\|bar" file.js`).
 *
 * Exported for unit tests so the quote-handling invariants are
 * pinned without the surrounding {@link runCommand} machinery.
 */
export function splitOnTopLevelPipes(command: string): string[] {
  const out: string[] = [];
  let buf = "";
  let quote: "'" | '"' | null = null;
  let escaping = false;
  for (const ch of command) {
    if (escaping) {
      buf += ch;
      escaping = false;
      continue;
    }
    if (ch === "\\") {
      buf += ch;
      escaping = true;
      continue;
    }
    if (quote) {
      buf += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === "\"") {
      buf += ch;
      quote = ch;
      continue;
    }
    if (ch === "|") {
      out.push(buf);
      buf = "";
      continue;
    }
    buf += ch;
  }
  out.push(buf);
  return out;
}

// ── Auth injection in shell commands (pwnkit#282) ──────────────────
//
// Surfaced by the 2026-05-07 control-flow audit: `http_request`/`crawl`/
// `submit_form` inject auth headers automatically, but `shellExec` only
// EXPOSES `$AUTH_HEADER` / `$AUTH_VALUE` / `$AUTH_CURL_FLAG` env vars and
// trusts the agent to interpolate them. After conversation compaction
// the model loses this affordance and sends unauthenticated curls for
// 5+ turns. This is the highest-leverage code-not-prompt fix in the
// agent loop.
//
// `injectAuthIntoBashCommand` rewrites the command BEFORE exec to
// prepend the env-var indirection ($AUTH_CURL_FLAG / $AUTH_HEADER) into
// curl/wget invocations whose URL is in scope and which don't already
// include explicit auth. Python `requests`/`urllib`/`httpx` invocations
// are detected and refused with a hint pointing to `http_request`.
//
// Env-var indirection is deliberate: the actual token NEVER appears in
// the rendered command, so transcripts/logs don't leak it.

const AUTH_PRESENT_PATTERNS: RegExp[] = [
  /Authorization\s*:/i,                 // "Authorization:" header (any quoting)
  /Cookie\s*:/i,                        // "Cookie:" header
  /\B--user[\s=]/,                      // curl --user / --user=
  /\s-u\s+\S/,                          // curl -u USER:PASS
  /headers\s*=/i,                       // python requests/httpx kwarg
  /\$AUTH_CURL_FLAG\b/,                 // already injected
  /\$AUTH_HEADER\b/,                    // already injected (wget shape)
];

/**
 * Cheap heuristic: does the command already carry explicit auth? If
 * yes, the injector leaves it alone — the agent's manual auth choice
 * always wins, and we never want to double-inject (which would either
 * stomp the agent's intent or, worse, silently send two `Authorization`
 * headers, behaviour of which is server-dependent).
 */
function commandHasExplicitAuth(command: string): boolean {
  return AUTH_PRESENT_PATTERNS.some((re) => re.test(command));
}

export type AuthInjectResult =
  | { kind: "rewrite"; command: string }
  | { kind: "unchanged" }
  | { kind: "refuse"; reason: string };

/**
 * http_audit bash-egress SSRF gate (FROZEN CONTRACT). The bash subprocess
 * bypasses node's fetch — and therefore the host/path scope checks the
 * `http_request`/`crawl`/`submit_form` tools enforce. In http_audit mode we
 * must guarantee the host+path allowlist holds for ALL egress, so we refuse
 * any raw HTTP-egress command (curl/wget/python http libs) that does not
 * carry an explicit, in-scope, in-path http(s) URL we can verify up front.
 *
 * This is intentionally fail-closed: an egress command whose destination we
 * can't statically resolve (obfuscated URL, variable, base64, DNS trick) is
 * refused rather than allowed, because the whole point of http_audit is a
 * bounded, auditable egress surface. Non-egress bash (grep, jq, echo, file
 * munging) is untouched.
 *
 * Returns the list of egress-tool segments found in the command (one per
 * pipe / `&&` / `;` segment whose executable is a known HTTP client).
 */
const HTTP_EGRESS_BINARIES = new Set([
  "curl",
  "wget",
  "httpie",
  "http",
  "https",
]);

const PYTHON_HTTP_RE = /(requests\.|urllib\.|httpx\.|http\.client|aiohttp\.|socket\.)/;

export function detectHttpEgressSegments(command: string): string[] {
  const hits: string[] = [];
  // Curl/wget/httpie detection: split on top-level `;`, `&&`, and `|`
  // (quote-aware so we don't split inside a quoted arg). Each segment whose
  // executable is a known HTTP client is an egress segment.
  const segments = command.split(/\s*(?:\|\||&&|;|\|)\s*/);
  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed) continue;
    let rest = trimmed;
    let m: RegExpMatchArray | null;
    while ((m = rest.match(/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/))) {
      rest = rest.slice(m[0].length);
    }
    const exe = (rest.split(/\s+/)[0] ?? "").replace(/^.*\//, "");
    if (HTTP_EGRESS_BINARIES.has(exe)) {
      hits.push(trimmed);
    }
  }
  // python -c '…' scripts legitimately contain `;` inside the quoted body,
  // so the naive split above corrupts them. Detect a python HTTP-client
  // invocation against the WHOLE command instead and record the matched
  // python segment(s) by re-splitting only on top-level pipes (which a
  // `-c` body rarely contains unquoted).
  if (/(^|[\s;&|/])python(?:3)?(\s|$)/.test(command) && PYTHON_HTTP_RE.test(command)) {
    for (const seg of splitOnTopLevelPipes(command)) {
      const t = seg.trim();
      if (/(^|[\s;&|/])python(?:3)?(\s|$)/.test(t) && PYTHON_HTTP_RE.test(t)) {
        hits.push(t);
      }
    }
  }
  return hits;
}

/**
 * Find the index of the next URL token in a tokenized curl/wget invocation,
 * starting from `from`. Returns -1 if no URL token is present.
 *
 * We use this instead of "always insert flag at index 1" because curl
 * invocations frequently look like `curl -X POST -d '…' URL`, and we want
 * the flag to land BEFORE the URL but after the verb so the rewritten
 * command remains a syntactically valid curl call.
 */
function findUrlTokenIdx(tokens: string[], from: number): number {
  for (let i = from; i < tokens.length; i++) {
    if (/^https?:\/\//i.test(tokens[i])) return i;
  }
  return -1;
}

/**
 * Rewrite a single shell segment (one side of `|`) to inject auth into
 * a leading curl or wget invocation. Python invocations short-circuit
 * with a refusal — see `injectAuthIntoBashCommand` for the policy.
 *
 * The segment may have leading whitespace (preserved verbatim) and may
 * begin with env-var assignments like `FOO=bar curl …`; we strip those
 * to find the executable token.
 */
function rewriteSegmentForAuth(
  segment: string,
  scope: ScopePolicy | undefined,
): AuthInjectResult {
  // Skip purely-whitespace segments.
  if (!segment.trim()) return { kind: "unchanged" };

  // Tokenise on whitespace, but preserve original spacing for the
  // splice. We do the splice on the raw string by locating the
  // executable token's position so leading env-vars (`FOO=bar curl …`)
  // and the agent's whitespace pass through untouched.
  const trimmed = segment.trimStart();
  const leadingWs = segment.slice(0, segment.length - trimmed.length);

  // Skip leading `KEY=value` env-prefix tokens.
  let cursor = 0;
  while (cursor < trimmed.length) {
    const rest = trimmed.slice(cursor);
    const m = rest.match(/^[A-Za-z_][A-Za-z0-9_]*=\S+\s+/);
    if (!m) break;
    cursor += m[0].length;
  }
  const afterEnv = trimmed.slice(cursor);

  // Tokenise the post-env-prefix part.
  const tokens = afterEnv.split(/\s+/);
  const exe = tokens[0];
  if (!exe) return { kind: "unchanged" };

  // Match curl / wget / python by basename (handles /usr/bin/curl too).
  const exeBase = exe.replace(/^.*\//, "");

  if (exeBase === "curl") {
    const urlIdx = findUrlTokenIdx(tokens, 1);
    if (urlIdx < 0) return { kind: "unchanged" };
    const url = tokens[urlIdx];
    // Out-of-scope check (hard refusal already handled upstream when
    // ctx.scope is set, but if the rewriter is called in isolation we
    // still must NOT inject auth into a non-engagement target).
    if (scope && !scope.match(url).allowed) return { kind: "unchanged" };
    if (!scope) return { kind: "unchanged" }; // no scope ⇒ can't verify ⇒ don't leak
    if (commandHasExplicitAuth(segment)) return { kind: "unchanged" };

    // Splice "$AUTH_CURL_FLAG" before the URL token. We rebuild from
    // tokens because curl tolerates whitespace collapse, and this keeps
    // the splice invariant simple.
    const before = tokens.slice(0, urlIdx).join(" ");
    const after = tokens.slice(urlIdx).join(" ");
    const rewrittenAfterEnv = `${before} $AUTH_CURL_FLAG ${after}`;
    return {
      kind: "rewrite",
      command: leadingWs + trimmed.slice(0, cursor) + rewrittenAfterEnv,
    };
  }

  if (exeBase === "wget") {
    const urlIdx = findUrlTokenIdx(tokens, 1);
    if (urlIdx < 0) return { kind: "unchanged" };
    const url = tokens[urlIdx];
    if (scope && !scope.match(url).allowed) return { kind: "unchanged" };
    if (!scope) return { kind: "unchanged" };
    if (commandHasExplicitAuth(segment)) return { kind: "unchanged" };

    const before = tokens.slice(0, urlIdx).join(" ");
    const after = tokens.slice(urlIdx).join(" ");
    const rewrittenAfterEnv = `${before} --header="$AUTH_HEADER: $AUTH_VALUE" ${after}`;
    return {
      kind: "rewrite",
      command: leadingWs + trimmed.slice(0, cursor) + rewrittenAfterEnv,
    };
  }

  // Python: refuse unless the call already has `headers=` / `auth=` /
  // explicit Authorization header. Detection is cheap text-search; the
  // refusal message points the agent at `http_request` which handles
  // auth injection structurally.
  if (
    /python(?:3)?$/.test(exeBase) &&
    /(requests\.|urllib\.request\.|httpx\.)/.test(segment)
  ) {
    if (commandHasExplicitAuth(segment)) return { kind: "unchanged" };
    return {
      kind: "refuse",
      reason:
        "Python HTTP requests in shell mode must include explicit auth headers; " +
        "use the http_request tool for auto-auth, or add " +
        "`headers={'Authorization': 'Basic ...'}` to your call.",
    };
  }

  return { kind: "unchanged" };
}

/**
 * Walk every pipe / `&&` / `;` segment of the bash command and rewrite
 * each in turn. Returns either a fully-rewritten command, the original
 * (if no segment matched), or a `refuse` verdict (Python detection).
 *
 * Exported for unit tests so the rewrite invariants are pinned without
 * the surrounding `shellExec` machinery.
 */
export function injectAuthIntoBashCommand(
  command: string,
  scope: ScopePolicy | undefined,
): AuthInjectResult {
  // Python detection runs against the WHOLE command first because the
  // typical shape — `python3 -c 'import requests; requests.get(…)'` —
  // hides the `requests.` token inside a single-quoted block, and our
  // segment splitter doesn't track quoting beyond `splitOnTopLevelPipes`.
  // If the command both invokes a python interpreter and references a
  // requests-flavour HTTP call, refuse with the http_request hint —
  // unless explicit auth is already present (`headers=` / Authorization).
  if (
    /\bpython(?:3)?\b/.test(command) &&
    /(requests\.|urllib\.request\.|httpx\.)/.test(command) &&
    !commandHasExplicitAuth(command)
  ) {
    return {
      kind: "refuse",
      reason:
        "Python HTTP requests in shell mode must include explicit auth headers; " +
        "use the http_request tool for auto-auth, or add " +
        "`headers={'Authorization': 'Basic ...'}` to your call.",
    };
  }

  // Split on pipes first; then split each pipe-segment on `&&`/`||`/`;`.
  // We deliberately do NOT respect quoting beyond `splitOnTopLevelPipes`
  // — three similar branches beats an over-engineered shell parser, and
  // the worst-case (a quoted `&&` inside a curl arg) just means the
  // segment passes through to `rewriteSegmentForAuth` slightly larger
  // than necessary, which is harmless because the auth-flag splice
  // still lands in front of the URL.
  const pipeSegments = splitOnTopLevelPipes(command);

  // Track whether any segment was rewritten and rebuild the command in
  // the same shape (with the original `|` separators preserved).
  const rewritten: string[] = [];
  let anyRewrite = false;

  for (const pipeSeg of pipeSegments) {
    // Within each pipe segment, split on `&&` / `||` / `;` (top-level
    // only — we don't track quoting here, which is documented above).
    const subSegs = pipeSeg.split(/(\s*(?:&&|\|\||;)\s*)/);
    const rewrittenSubs: string[] = [];
    for (const sub of subSegs) {
      // Preserve the connector tokens verbatim.
      if (/^\s*(?:&&|\|\||;)\s*$/.test(sub)) {
        rewrittenSubs.push(sub);
        continue;
      }
      const verdict = rewriteSegmentForAuth(sub, scope);
      if (verdict.kind === "refuse") return verdict;
      if (verdict.kind === "rewrite") {
        anyRewrite = true;
        rewrittenSubs.push(verdict.command);
      } else {
        rewrittenSubs.push(sub);
      }
    }
    rewritten.push(rewrittenSubs.join(""));
  }

  if (!anyRewrite) return { kind: "unchanged" };
  return { kind: "rewrite", command: rewritten.join("|") };
}

function tokenizeCommand(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaping = false;

  for (const ch of command) {
    if (escaping) {
      current += ch;
      escaping = false;
      continue;
    }

    if (ch === "\\") {
      escaping = true;
      continue;
    }

    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }

    if (ch === "'" || ch === "\"") {
      quote = ch;
      continue;
    }

    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += ch;
  }

  if (escaping || quote) {
    throw new Error("Command contains unmatched quotes or escapes");
  }

  if (current) {
    tokens.push(current);
  }

  return tokens;
}

function isCommandAllowed(tokens: string[]): boolean {
  const executable = tokens[0];
  if (!executable || !ALLOWED_COMMANDS.has(executable)) {
    return false;
  }

  if (executable === "npm") {
    const subcommand = tokens[1];
    return !!subcommand && ALLOWED_NPM_SUBCOMMANDS.has(subcommand);
  }

  return true;
}

function validateCommandTokens(tokens: string[]): void {
  if (tokens[0] === "find") {
    const dangerousFindArgs = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
    for (const token of tokens.slice(1)) {
      if (dangerousFindArgs.has(token)) {
        throw new Error(`find subcommand ${token} is not allowed`);
      }
    }
  }
}

function executePipeline(
  segments: string[][],
  cwd: string,
  timeout: number,
): ToolResult {
  let stdin: string | Buffer | undefined;

  for (const tokens of segments) {
    const result = spawnSync(tokens[0], tokens.slice(1), {
      cwd,
      timeout,
      input: stdin,
      maxBuffer: 1024 * 1024,
      encoding: "utf-8",
    });

    if (result.error) {
      throw result.error;
    }

    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    if (result.status !== 0) {
      return {
        success: false,
        output: null,
        error: output.slice(0, 2_000) || `Command exited with status ${result.status}`,
      };
    }

    stdin = result.stdout ?? "";
  }

  return {
    success: true,
    output: typeof stdin === "string" ? stdin.slice(0, 10_000) : "",
  };
}

function resolveScopedPath(scopePath: string, inputPath: string): string {
  const root = resolve(scopePath);
  const candidate = isAbsolute(inputPath)
    ? resolve(inputPath)
    : resolve(root, inputPath);

  if (candidate !== root && !candidate.startsWith(root + "/")) {
    throw new Error(`Path escapes the allowed scope: ${inputPath}`);
  }

  return candidate;
}

function validateScopedCommand(tokens: string[], scopePath?: string): void {
  const scopeRoot = scopePath ? resolve(scopePath) : null;
  for (const token of tokens.slice(1)) {
    if (isAbsolute(token)) {
      // Allow absolute paths that resolve INSIDE the scan's scope dir
      // (e.g. /tmp/pwnkit-audit-xxxxxxxx/node_modules/lodash/lodash.js
      // when scope is /tmp/pwnkit-audit-xxxxxxxx). Without this the
      // agent kept burning turns rewriting full paths to relative ones
      // while exploring its own scratch dir — pure friction with no
      // security benefit. The scope check still rejects /etc/passwd
      // and friends.
      if (scopeRoot) {
        const resolvedToken = resolve(token);
        if (
          resolvedToken === scopeRoot ||
          resolvedToken.startsWith(scopeRoot + "/")
        ) {
          continue;
        }
      }
      throw new Error(`Absolute paths are not allowed in scoped commands: ${token}`);
    }
    if (/(^|\/)\.\.(\/|$)/.test(token)) {
      throw new Error(`Parent-path traversal is not allowed in scoped commands: ${token}`);
    }
  }
}

function normalizeLoopbackHost(hostname: string): string {
  if (hostname === "::1") return "127.0.0.1";
  return hostname.toLowerCase();
}

function isPrivateIpv4(hostname: string): boolean {
  const normalized = normalizeLoopbackHost(hostname);
  if (isIP(normalized) !== 4) return false;

  const [a, b] = normalized.split(".").map((part) => Number(part));
  return a === 10
    || a === 127
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168);
}

function isPrivateIpv6(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:");
}

function isLocalHostname(hostname: string): boolean {
  const normalized = normalizeLoopbackHost(hostname);
  return normalized === "localhost" || normalized.endsWith(".localhost");
}

function validateTargetUrl(
  baseUrl: string,
  requestedUrl: string,
  scope?: ScopePolicy,
  enforcement?: EnforcementTracker,
): string {
  const base = new URL(baseUrl);
  const candidate = new URL(requestedUrl, base);

  if (!["http:", "https:"].includes(candidate.protocol)) {
    throw new Error(`Unsupported protocol for http_request: ${candidate.protocol}`);
  }

  if (candidate.origin !== base.origin) {
    throw new Error(`Cross-origin http_request blocked: ${candidate.origin}`);
  }

  const hostname = candidate.hostname.toLowerCase();
  const baseHostname = base.hostname.toLowerCase();
  const baseIsLocal = isLocalHostname(baseHostname) || isPrivateIpv4(baseHostname) || isPrivateIpv6(baseHostname);
  const candidateIsLocal = isLocalHostname(hostname) || isPrivateIpv4(hostname) || isPrivateIpv6(hostname);

  if (candidateIsLocal && !baseIsLocal) {
    throw new Error(`Local/internal http_request blocked: ${candidate.hostname}`);
  }

  const candidateUrl = candidate.toString();

  // Programmatic scope enforcement (pwnkit#215). Additive on top of the
  // existing same-origin / private-network guards above — scope cannot
  // loosen those, only further restrict. When `scope` is undefined the
  // behaviour is identical to the pre-#215 implementation.
  if (scope) {
    const verdict = scope.match(candidateUrl);
    if (!verdict.allowed) {
      enforcement?.noteOutOfScopeBlocked();
      throw new Error(`Scope violation blocked: ${verdict.reason}`);
    }
  }

  // http_audit path-prefix allowlist (FROZEN CONTRACT). Layered on top of
  // the host scope above: a URL must pass BOTH the host check and the path
  // check. Empty path allowlist = allow all paths. Out-of-scope path is
  // counted as a blocked request, same as a host violation.
  if (enforcement) {
    const pathVerdict = enforcement.pathPolicy.match(candidateUrl);
    if (!pathVerdict.allowed) {
      enforcement.noteOutOfScopeBlocked();
      throw new Error(`Scope violation blocked: ${pathVerdict.reason}`);
    }
    enforcement.noteInScope();
  }

  return candidateUrl;
}

// ── PoC step graph helpers (pwnkit#170) ──

const POC_STEP_KINDS: ReadonlySet<string> = new Set([
  "setup",
  "auth",
  "prerequisite",
  "exploit",
  "verify",
]);
const POC_ACTION_TYPES: ReadonlySet<string> = new Set(["shell", "http", "docker", "note"]);
const POC_EXPECT_TYPES: ReadonlySet<string> = new Set([
  "exit-zero",
  "http-status",
  "body-contains",
  "body-matches",
  "file-exists",
]);

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function validatePocStep(raw: unknown): PocStep | null {
  if (!isPlainRecord(raw)) return null;
  const id = typeof raw.id === "string" && raw.id.trim().length > 0 ? raw.id.trim() : null;
  const summary =
    typeof raw.summary === "string" && raw.summary.trim().length > 0 ? raw.summary.trim() : null;
  const kind = typeof raw.kind === "string" && POC_STEP_KINDS.has(raw.kind) ? raw.kind : null;
  if (!id || !summary || !kind) return null;
  if (!isPlainRecord(raw.action)) return null;
  const actionType = raw.action.type;
  if (typeof actionType !== "string" || !POC_ACTION_TYPES.has(actionType)) return null;
  // We trust the rest of the action fields to the PocStepAction discriminated
  // union; downstream executors validate per-variant before running anything.
  const step: PocStep = {
    id,
    kind: kind as PocStep["kind"],
    summary,
    action: raw.action as PocStep["action"],
  };
  if (raw.expect != null) {
    if (
      isPlainRecord(raw.expect) &&
      typeof raw.expect.type === "string" &&
      POC_EXPECT_TYPES.has(raw.expect.type)
    ) {
      step.expect = raw.expect as PocStep["expect"];
    } else {
      // Malformed expect — drop just the predicate, keep the step. The step is
      // still useful for screenshot rendering and advisory prose even without
      // an executable predicate.
    }
  }
  return step;
}

// ── Verification spec helpers (pwnkit#193) ──
//
// Mirrors the PoC-step parser pattern above: tolerate already-parsed objects
// AND JSON strings, validate strictly, and return null on anything malformed
// so a bad payload from the LLM never blocks the finding from saving.

const VERIFICATION_PREDICATE_KINDS: ReadonlySet<string> = new Set([
  "file-contains",
  "file-missing-pattern",
  "file-exists",
  "ast-shape",
]);

const VERIFICATION_BEHAVIOR_EXPECT_LITERALS: ReadonlySet<string> = new Set([
  "success",
  "forbidden",
]);

function validateVerificationPredicate(
  raw: unknown,
): VerificationCodePredicate | null {
  if (!isPlainRecord(raw)) return null;
  const kind = raw.kind;
  if (typeof kind !== "string" || !VERIFICATION_PREDICATE_KINDS.has(kind)) {
    return null;
  }
  const file = raw.file;
  if (typeof file !== "string" || file.length === 0) return null;

  switch (kind) {
    case "file-exists":
      return { kind: "file-exists", file };
    case "file-contains": {
      const pattern = raw.pattern;
      if (typeof pattern !== "string" || pattern.length === 0) return null;
      const flags = typeof raw.flags === "string" ? raw.flags : undefined;
      return flags !== undefined
        ? { kind: "file-contains", file, pattern, flags }
        : { kind: "file-contains", file, pattern };
    }
    case "file-missing-pattern": {
      const pattern = raw.pattern;
      if (typeof pattern !== "string" || pattern.length === 0) return null;
      const flags = typeof raw.flags === "string" ? raw.flags : undefined;
      return flags !== undefined
        ? { kind: "file-missing-pattern", file, pattern, flags }
        : { kind: "file-missing-pattern", file, pattern };
    }
    case "ast-shape": {
      const query = raw.query;
      if (typeof query !== "string" || query.length === 0) return null;
      return { kind: "ast-shape", file, query };
    }
    default:
      return null;
  }
}

function validateVerificationBehaviorStep(
  raw: unknown,
): VerificationBehaviorStep | null {
  if (!isPlainRecord(raw)) return null;
  const method = raw.method;
  const path = raw.path;
  if (typeof method !== "string" || method.length === 0) return null;
  if (typeof path !== "string" || path.length === 0) return null;
  const expectRaw = raw.expect;
  let expect: VerificationBehaviorStep["expect"];
  if (typeof expectRaw === "string") {
    if (!VERIFICATION_BEHAVIOR_EXPECT_LITERALS.has(expectRaw)) return null;
    expect = expectRaw as "success" | "forbidden";
  } else if (
    isPlainRecord(expectRaw) &&
    typeof expectRaw.status === "number" &&
    Number.isInteger(expectRaw.status)
  ) {
    expect = { status: expectRaw.status };
  } else {
    return null;
  }
  const step: VerificationBehaviorStep = { method, path, expect };
  if ("body" in raw) step.body = raw.body;
  return step;
}

function validateVerificationBehavior(
  raw: unknown,
): VerificationBehavior | null {
  if (!isPlainRecord(raw)) return null;
  if (!Array.isArray(raw.steps)) return null;
  const steps: VerificationBehaviorStep[] = [];
  for (const item of raw.steps) {
    const step = validateVerificationBehaviorStep(item);
    if (step) steps.push(step);
  }
  if (steps.length === 0) return null;
  return { steps };
}

/**
 * Parse the `verification_spec` LLM tool argument into a VerificationSpec or
 * null. Same wire-shape tolerance as `parsePocStepsArg` (already-parsed
 * object OR JSON string OR garbage → null).
 *
 * Validation rules:
 *  - `code` MUST be an array (possibly empty after dropping malformed
 *    predicates). If it's missing entirely, the spec is rejected.
 *  - Each predicate is validated per-variant; malformed predicates are
 *    dropped silently (one bad predicate doesn't kill the spec).
 *  - `behavior` is optional; if present-but-malformed, the whole spec is
 *    still accepted, with `behavior` dropped.
 *
 * Exported only for unit tests; not part of the public agent surface.
 */
export function parseVerificationSpecArg(raw: unknown): VerificationSpec | null {
  if (raw == null || raw === "") return null;
  let parsed: unknown = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!isPlainRecord(parsed)) return null;
  if (!Array.isArray(parsed.code)) return null;

  const code: VerificationCodePredicate[] = [];
  for (const item of parsed.code) {
    const predicate = validateVerificationPredicate(item);
    if (predicate) code.push(predicate);
  }

  const spec: VerificationSpec = { code };
  if (parsed.behavior !== undefined) {
    const behavior = validateVerificationBehavior(parsed.behavior);
    if (behavior) spec.behavior = behavior;
  }

  // A spec with zero usable code predicates AND no behavior is effectively
  // empty — drop it so the finding doesn't carry a meaningless field.
  if (spec.code.length === 0 && !spec.behavior) return null;

  return spec;
}

/**
 * Parse the `poc_steps` LLM tool argument into a PocStep[] or null.
 *
 * Tolerates three wire shapes seen from real models:
 *   1. Already-parsed array (some runtimes auto-parse JSON-shaped strings).
 *   2. JSON-encoded string of an array.
 *   3. Anything else / malformed — returns null so the finding still saves
 *      with prose evidence only.
 *
 * Exported only for unit tests; not part of the public agent surface.
 */
export function parsePocStepsArg(raw: unknown): PocStep[] | null {
  if (raw == null || raw === "") return null;
  let parsed: unknown = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!Array.isArray(parsed)) return null;
  const out: PocStep[] = [];
  for (const item of parsed) {
    const step = validatePocStep(item);
    if (step) out.push(step);
  }
  return out.length > 0 ? out : null;
}

// ── Evidence-paths parsing & validation-failure response (pwnkit#409) ──

/**
 * Coerce the `evidence_paths` tool arg into the `FindingDraft.evidence`
 * shape the validator expects. Accepts:
 *   - JSON-encoded string of `string[]` (LLM wire format)
 *   - already-parsed `string[]`
 *   - already-shaped `Array<{path: string}>`
 *   - undefined / null / garbage → empty array
 *
 * The validator does the actual path-escape checks; this helper just
 * normalises the shape so the validator sees a uniform list.
 */
export function parseEvidencePathsArg(
  raw: unknown,
): Array<{ path: string }> {
  if (raw == null || raw === "") return [];
  let parsed: unknown = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(parsed)) return [];
  const out: Array<{ path: string }> = [];
  for (const item of parsed) {
    if (typeof item === "string") {
      out.push({ path: item });
    } else if (
      item &&
      typeof item === "object" &&
      typeof (item as { path?: unknown }).path === "string"
    ) {
      out.push({ path: (item as { path: string }).path });
    }
  }
  return out;
}

/**
 * Build the `ToolResult` returned to the agent when `validateFindingDraft`
 * rejects a finding. The shape matches the `flag-validator` convention:
 * a structured `output` object with a `kind: "validation_failed"`
 * discriminator the agent can parse, plus a human-readable `error` string
 * for runtimes that surface only the error field. Critically, this is a
 * SOFT failure — the agent should fix the offending field and re-submit.
 */
export function buildValidationFailureResult(
  errors: ValidationError[],
): ToolResult {
  const lines = errors.map((e) => {
    const hint = e.hint ? ` (hint: ${e.hint})` : "";
    return `- ${e.field}: ${e.reason}${hint}`;
  });
  return {
    success: false,
    output: {
      kind: "validation_failed",
      errors,
    },
    error:
      `save_finding rejected: ${errors.length} structural validation error(s). ` +
      `Fix the offending field(s) and re-submit:\n${lines.join("\n")}`,
  };
}

// ── `done`-tool coverage gate (#audit-laziness) ──
//
// Real-world bug: a sub-agent auditing @vercel/og emitted `done` after
// exactly one tool call (`read_file: package.json`), in 11 seconds, with
// 0 findings — the same shape repeated across @vercel/postgres,
// @vercel/kv, @vercel/blob, @vercel/edge-config, @auth0/nextjs-auth0.
// The agent's own summary said it had only looked at the manifest. We
// reject those `done` calls and tell the model to actually inspect the
// source.
//
// The gate only fires for `audit` / `review` roles — attack / discovery /
// verify sub-agents have very different shapes (network probes, not
// source reads) and would false-positive on this heuristic.

const SOURCE_FILE_RE = /\.(ts|tsx|js|mjs|cjs|jsx|py|rs|go|java|rb|php|c|h|cpp|hpp)$/i;

/**
 * Reasons a `done` call may be rejected by the coverage gate. Returned
 * to the model as a tool_result error so it knows what to do next.
 */
export interface CoverageGateInput {
  /** Distinct source files the agent has successfully read this session. */
  sourceFilesRead: number;
  /** Successful `run_command` invocations this session. */
  runCommandCount: number;
  /** Total non-`done` tool calls (success or failure) this session. */
  totalToolCalls: number;
  /** Milliseconds since the ToolExecutor was constructed. */
  elapsedMs: number;
  /** How many times `done` has already been rejected this session. */
  priorRejections: number;
}

export interface CoverageGateDecision {
  pass: boolean;
  reason?: string;
}

/**
 * Decide whether a `done` call from an audit / review sub-agent has done
 * enough work to be allowed through. Pure function so the policy is
 * unit-testable without spinning up a ToolExecutor.
 *
 * Default thresholds (override via env):
 *   - `PWNKIT_AUDIT_MIN_COVERAGE_FILES` (default 3): minimum distinct
 *     source files read.
 *   - `PWNKIT_AUDIT_DONE_GATE=0`: disable the gate entirely.
 *
 * Pass conditions (any of):
 *   1. At least N distinct source files read.
 *   2. At least one `run_command` invocation (agent ran a real shell command).
 *   3. Has been running > 60s with >= 5 tool calls (long enough that
 *      `done` likely follows a genuine investigation, not a 1-call bail).
 *   4. The agent has already been rejected twice — accept the third call
 *      so we never deadlock a legitimately-empty audit.
 */
export function evaluateDoneCoverageGate(input: CoverageGateInput, env: NodeJS.ProcessEnv = process.env): CoverageGateDecision {
  // Operator-tunable kill switch.
  if (env.PWNKIT_AUDIT_DONE_GATE === "0" || env.PWNKIT_AUDIT_DONE_GATE === "false") {
    return { pass: true };
  }

  // After two prior rejections, always pass — the agent has seen the
  // message twice and refuses to do more. Don't deadlock.
  if (input.priorRejections >= 2) {
    return { pass: true };
  }

  const minFiles = (() => {
    const raw = env.PWNKIT_AUDIT_MIN_COVERAGE_FILES;
    const n = raw === undefined ? NaN : Number.parseInt(raw, 10);
    return Number.isFinite(n) && n >= 0 ? n : 3;
  })();

  if (input.sourceFilesRead >= minFiles) return { pass: true };
  if (input.runCommandCount >= 1) return { pass: true };
  if (input.elapsedMs > 60_000 && input.totalToolCalls >= 5) return { pass: true };

  // Build a model-facing rejection that names the specific deficit.
  const parts: string[] = [];
  parts.push(
    `done rejected: only ${input.sourceFilesRead} distinct source file(s) inspected `
      + `(threshold: ${minFiles}), ${input.runCommandCount} run_command call(s), `
      + `${input.totalToolCalls} total tool calls, elapsed ${Math.round(input.elapsedMs / 1000)}s.`,
  );
  parts.push(
    "You have not actually audited the source yet — declaring the audit "
      + "complete now produces a 0-finding scan that misses real vulnerabilities. "
      + "Read more source files (try the main exports listed in package.json's "
      + "\"main\" / \"exports\", and at least src/index.* or lib/index.*), or run "
      + "a `run_command` with grep/rg against the package to map the public API. "
      + "Then call `done` again.",
  );
  return { pass: false, reason: parts.join(" ") };
}

// ── Access-control probe helpers (pwnkit#564) ──

/** A principal the access-control probe can issue requests as. */
interface ProbePrincipal {
  label: string;
  role?: string;
  /** Outbound auth + cookie headers for this principal. */
  headers: () => Record<string, string>;
  /** Capture session state (Set-Cookie / re-auth) from a response. */
  capture: (res: Response) => void;
}

/** A single response captured by the probe. */
export interface ProbeResponse {
  identity: string;
  role?: string;
  url: string;
  method: string;
  status: number;
  contentType: string;
  body: string;
}

/** Normalize a response body for similarity comparison. */
function normalizeBody(s: string): string {
  return (s ?? "").toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * Token-Jaccard similarity of two response bodies in [0, 1]. 1 = identical
 * (after whitespace/case normalization), 0 = no shared tokens. Deterministic;
 * used to decide whether a comparison identity retrieved the SAME resource as
 * the authorized baseline (the signature of broken object-level authorization).
 */
export function bodySimilarity(a: string, b: string): number {
  const na = normalizeBody(a);
  const nb = normalizeBody(b);
  if (na === "" && nb === "") return 1;
  if (na === nb) return 1;
  const ta = new Set(na.split(" ").filter(Boolean));
  const tb = new Set(nb.split(" ").filter(Boolean));
  if (ta.size === 0 && tb.size === 0) return 1;
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  const union = new Set([...ta, ...tb]).size;
  return union === 0 ? 0 : inter / union;
}

export interface AccessDiffResult {
  broken: boolean;
  verdict: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  bodySimilarity: number;
  statusMatch: boolean;
  note: string;
}

const is2xx = (s: number): boolean => s >= 200 && s < 300;

/**
 * Diff an authorized baseline response against a comparison identity's
 * response and decide whether an authorization boundary was broken.
 *
 * Logic:
 *  - comparison 401/403 → `properly_denied` (the control works).
 *  - baseline not 2xx → `inconclusive` (no authorized resource to leak).
 *  - comparison 2xx + body ~identical to baseline → broken object-level authz
 *    (BOLA/IDOR); annotated as vertical privesc when the comparison identity
 *    is lower-privileged than the baseline.
 *  - comparison 2xx + different body, but the caller said it SHOULD be denied
 *    (or it's a lower-priv identity) → broken function-level authz (BFLA).
 *  - comparison 2xx + different body otherwise → `accessible_distinct_resource`
 *    (likely its own data; flagged for manual review, not a confirmed break).
 */
export function diffAccessResponses(
  baseline: Pick<ProbeResponse, "status" | "body">,
  comparison: Pick<ProbeResponse, "status" | "body">,
  opts: { baselineRole?: string; comparisonRole?: string; expectDenied?: boolean },
): AccessDiffResult {
  const sim = bodySimilarity(baseline.body, comparison.body);
  const statusMatch = baseline.status === comparison.status;
  const vertical = compareRoles(opts.comparisonRole, opts.baselineRole) < 0;

  if (comparison.status === 401 || comparison.status === 403) {
    return {
      broken: false,
      verdict: "properly_denied",
      severity: "info",
      bodySimilarity: sim,
      statusMatch,
      note: `comparison identity was correctly denied (HTTP ${comparison.status})`,
    };
  }

  if (!is2xx(baseline.status)) {
    return {
      broken: false,
      verdict: "inconclusive",
      severity: "info",
      bodySimilarity: sim,
      statusMatch,
      note: `baseline identity did not return an authorized 2xx (HTTP ${baseline.status}); cannot establish a protected resource to leak`,
    };
  }

  if (is2xx(comparison.status)) {
    if (sim >= 0.9) {
      return {
        broken: true,
        verdict: vertical ? "vertical_privilege_escalation" : "broken_object_level_authorization",
        severity: "high",
        bodySimilarity: sim,
        statusMatch,
        note: `comparison identity retrieved the SAME resource as the baseline (body similarity ${sim.toFixed(2)}) — broken access control confirmed`,
      };
    }
    if (opts.expectDenied || vertical) {
      return {
        broken: true,
        verdict: vertical ? "vertical_privilege_escalation" : "broken_function_level_authorization",
        severity: "high",
        bodySimilarity: sim,
        statusMatch,
        note: `comparison identity reached a resource it should not access (HTTP ${comparison.status}; body differs from baseline) — likely function-level authorization break`,
      };
    }
    return {
      broken: false,
      verdict: "accessible_distinct_resource",
      severity: "info",
      bodySimilarity: sim,
      statusMatch,
      note: `comparison identity got HTTP ${comparison.status} but a distinct body — may be its OWN resource at this path; verify manually before flagging`,
    };
  }

  return {
    broken: false,
    verdict: "inconclusive",
    severity: "info",
    bodySimilarity: sim,
    statusMatch,
    note: `comparison HTTP ${comparison.status} is neither a clear allow (2xx) nor deny (401/403)`,
  };
}

/** Truncated, non-secret evidence snapshot of a probe response. */
function probeEvidence(resp: ProbeResponse): Record<string, unknown> {
  return {
    identity: resp.identity,
    role: resp.role,
    request: { url: resp.url, method: resp.method },
    response: {
      status: resp.status,
      contentType: resp.contentType,
      bodyLength: resp.body.length,
      bodyPreview: resp.body.slice(0, 1_000),
    },
  };
}

// ── Tool Executor ──

export class ToolExecutor {
  private db: pwnkitDB | null;
  private ctx: ToolContext;
  private _browser: any = null;
  private _browserPage: any = null;
  private _browserDialogs: string[] = [];
  private _browserConsole: string[] = [];
  private _playwrightAvailable: boolean | null = null;
  private _ptyManager: PtySessionManager | null = null;
  /**
   * Set of proposed flag strings that the `done` tool rejected once as
   * likely decoys. A second `done` call with the same flag passes through
   * — the anti-honeypot heuristic is a speed bump, not a hard wall.
   * See GitHub issue #82.
   */
  private _rejectedDecoyFlags: Set<string> = new Set();

  // ── Coverage-gate tracking (#audit-laziness) ──
  // Populated incrementally inside `execute()` so `markDone` can refuse
  // calls from audit / review sub-agents that haven't inspected any
  // source. See `evaluateDoneCoverageGate` above.
  private _startedAt: number = Date.now();
  private _sourceFilesRead: Set<string> = new Set();
  private _runCommandCount: number = 0;
  private _totalNonDoneToolCalls: number = 0;
  private _doneRejections: number = 0;

  constructor(ctx: ToolContext, db: pwnkitDB | null = null) {
    this.ctx = ctx;
    this.db = db;
  }

  /** Check if playwright is installed (cached). */
  async isPlaywrightAvailable(): Promise<boolean> {
    if (this._playwrightAvailable !== null) return this._playwrightAvailable;
    try {
      // @ts-ignore — playwright is an optional dependency
      await import("playwright");
      this._playwrightAvailable = true;
    } catch {
      this._playwrightAvailable = false;
    }
    return this._playwrightAvailable;
  }

  /**
   * Outbound auth headers for the CURRENTLY ACTIVE identity (pwnkit#564).
   *
   * When a stateful `SessionEngine` is wired into the context, this returns the
   * active identity's static credential merged with any cookies its jar has
   * captured this scan. With no session it falls back to the legacy stateless
   * `buildAuthHeaders(authConfig)` path — byte-identical for single-credential
   * scans. The target host keys the jar (every tool request is same-origin per
   * `validateTargetUrl`, so the target host is always the right jar key).
   */
  private activeAuthHeaders(): Record<string, string> {
    const session = this.ctx.session;
    if (session) {
      return session.headersFor(session.activeLabel, this.ctx.target);
    }
    return buildAuthHeaders(this.ctx.authConfig);
  }

  /**
   * Capture `Set-Cookie` from a response into the active identity's jar and
   * run the 401/403 re-auth handler (pwnkit#564). No-op without a session.
   */
  private captureActiveCookies(res: Response): void {
    const session = this.ctx.session;
    if (!session) return;
    session.capture(session.activeLabel, res.headers, this.ctx.target);
    session.handleAuthStatus(session.activeLabel, res.status, this.ctx.target);
  }

  /**
   * Build environment variables for auth credentials, making them available
   * to shell commands (curl, python3, etc.) via $AUTH_HEADER / $AUTH_VALUE.
   */
  private buildAuthEnvVars(): Record<string, string> {
    const auth = this.ctx.authConfig;
    if (!auth) return {};

    const headers = buildAuthHeaders(auth);
    const entries = Object.entries(headers);
    if (entries.length === 0) return {};

    const [headerName, headerValue] = entries[0];
    return {
      AUTH_HEADER: headerName,
      AUTH_VALUE: headerValue,
      // Convenience: full curl-style header flag
      AUTH_CURL_FLAG: `-H '${headerName}: ${headerValue}'`,
    };
  }

  /** Clean up browser and PTY resources. Call when the agent loop ends. */
  async cleanup(): Promise<void> {
    try {
      if (this._browserPage) {
        await this._browserPage.close().catch(() => {});
        this._browserPage = null;
      }
      if (this._browser) {
        await this._browser.close().catch(() => {});
        this._browser = null;
      }
      if (this._ptyManager) {
        this._ptyManager.cleanup();
        this._ptyManager = null;
      }
    } catch {
      // Best-effort cleanup
    }
  }

  async execute(call: ToolCall): Promise<ToolResult> {
    try {
      // Coverage-gate accounting (#audit-laziness). Counted BEFORE dispatch
      // so a tool that throws still contributes to the "total tool calls"
      // denominator — that matches the laziness-detection intent (the agent
      // tried to do something, even if it failed). `done` is excluded so
      // its own emission doesn't satisfy the gate.
      if (call.name !== "done") {
        this._totalNonDoneToolCalls += 1;
      }

      const result = await this._dispatch(call);

      // Source-file tracking — only count successful read_file calls whose
      // resolved path looks like a source file. Reading package.json,
      // README.md, LICENSE doesn't count — those are exactly the files the
      // lazy-agent bug stops on.
      if (call.name === "read_file" && result.success) {
        const path = typeof call.arguments?.path === "string" ? call.arguments.path : "";
        if (path && SOURCE_FILE_RE.test(path)) {
          this._sourceFilesRead.add(path);
        }
      }
      if (call.name === "run_command" && result.success) {
        this._runCommandCount += 1;
      }

      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  private async _dispatch(call: ToolCall): Promise<ToolResult> {
    try {
      // Resolve the handler off this instance by name. TOOL_DISPATCH (assembled
      // from the per-domain `*Dispatch` maps in tools/) is the single seam where
      // a tool name meets its still-private handler method; the cast is
      // contained here and guarded by tools/dispatch.test.ts, which pins the
      // full routing and asserts every name resolves to a real method. An
      // unmapped (or, defensively, unresolvable) name returns the same
      // "Unknown tool" result the previous switch's default did.
      const methodName = TOOL_DISPATCH[call.name];
      const handler = methodName
        ? (this as unknown as Record<
            string,
            (args: Record<string, unknown>) => ToolResult | Promise<ToolResult>
          >)[methodName]
        : undefined;
      if (typeof handler !== "function") {
        return { success: false, output: null, error: `Unknown tool: ${call.name}` };
      }
      return await handler.call(this, call.arguments);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  private async httpRequest(args: Record<string, unknown>): Promise<ToolResult> {
    const url = validateTargetUrl(this.ctx.target, args.url as string, this.ctx.scope, this.ctx.enforcement);
    const method = (args.method as string) ?? "POST";
    const body = args.body as string | undefined;
    const authHeaders = this.activeAuthHeaders();
    const headers = { ...authHeaders, ...(args.headers as Record<string, string>) ?? {} };

    // One in-scope HTTP round-trip for a given (possibly evasion-mutated)
    // request shape. Rate-limit (#214), attribution (#216), and 429-honoring
    // all live here so the baseline call AND every adaptive-evasion variant
    // (#568) pace identically and stay in-scope. Returns the response, the
    // body text, and the headers actually sent.
    const sendHttp = async (
      parts: HttpRequestParts,
    ): Promise<{ res: Response; body: string; sentHeaders: Record<string, string> }> => {
      // Re-validate the (possibly evasion-mutated) URL immediately before the
      // fetch — same-origin + scope + private-network allowlist, identical to
      // the pre-flight `validateTargetUrl` at the top. Evasion transforms only
      // rewrite query values / body / header casing, never the host or path,
      // so this always passes for legitimate variants; it is defense-in-depth
      // guaranteeing a mutated payload can never escape the validated in-scope
      // origin (and feeds an allowlisted URL into `fetch`, not a raw param).
      // `enforcement` is omitted so this re-check does NOT double-count the
      // request — the baseline was already tallied by the pre-flight call.
      const safeUrl = validateTargetUrl(this.ctx.target, parts.url, this.ctx.scope);
      // Acquire token BEFORE the network call; park the host bucket on 429
      // via `noteResponse` AFTER the response.
      if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(safeUrl);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30_000);
      try {
        const fetchInit = applyAttribution(
          safeUrl,
          {
            method: parts.method,
            headers: { "Content-Type": "application/json", ...parts.headers },
            body: parts.body ?? undefined,
            signal: controller.signal,
            redirect: "manual",
          },
          this.ctx.attribution,
          this.ctx.scope,
        )!;
        // js/no-ssrf FP: `safeUrl` is the return of validateTargetUrl() just
        // above (same-origin + scope + private-IP/localhost block + http_audit
        // path allowlist), re-validated for the baseline AND every evasion
        // variant before egress. Fetching the in-scope authorized target is
        // intended pwnkit behaviour.
        // foxguard:ignore
        const res = await fetch(safeUrl, fetchInit);
        if (this.ctx.rateLimiter) this.ctx.rateLimiter.noteResponse(safeUrl, res);
        // Persist session state (pwnkit#564): capture Set-Cookie for the active
        // identity. No-op when no SessionEngine is wired. Runs for the baseline
        // AND every evasion variant so session cookies stay current.
        this.captureActiveCookies(res);
        const text = await res.text();
        return { res, body: text, sentHeaders: fetchInit.headers as Record<string, string> };
      } finally {
        clearTimeout(timer);
      }
    };

    const baseParts: HttpRequestParts = { url, method, headers, body };
    const first = await sendHttp(baseParts);
    let chosen = first;

    // ── WAF detection + adaptive evasion (pwnkit#568) ──
    // Passive fingerprinting is cheap and ALWAYS runs, so a WAF block is
    // reported as such instead of being mistaken for "not vulnerable" (the
    // silent-false-negative gap). When a block is detected AND a WafDetector
    // is wired (authorized engagement — scope/enforcement configured), we walk
    // the evasion ladder through the SAME rate-limited / in-scope `sendHttp`
    // path, recording every attempt as evidence.
    let wafInfo: Record<string, unknown> | undefined;
    const verdict = classifyResponse({ status: first.res.status, headers: first.res.headers, body: first.body });
    if (verdict.blocked) {
      this.ctx.wafDetector?.recordBlock(url, verdict);
      wafInfo = {
        detected: true,
        blocked: true,
        vendor: verdict.fingerprint?.vendor ?? "generic",
        label: verdict.fingerprint?.label ?? "unfingerprinted WAF",
        confidence: verdict.fingerprint?.confidence ?? null,
        reason: verdict.reason,
        authorized_engagement: true,
      };

      if (this.ctx.wafDetector) {
        // Capture the underlying send for the variant that ultimately runs, so
        // a bypassing response (with its real sent-headers) becomes the result.
        let lastSend: { res: Response; body: string; sentHeaders: Record<string, string> } | null = null;
        const campaign = await runEvasionCampaign(
          baseParts,
          async (parts): Promise<WafResponseLike> => {
            const r = await sendHttp(parts);
            lastSend = r;
            return { status: r.res.status, headers: r.res.headers, body: r.body };
          },
          { jitterBaseMs: 250 },
        );
        this.ctx.wafDetector.recordEvasion(url, verdict, campaign);
        wafInfo.evasion = {
          attempts: campaign.attempts,
          bypassed: campaign.bypassed,
          bypass_strategy: campaign.bypassStrategy,
        };
        // Persist the evasion audit trail as a first-class artifact so the
        // operator's report shows exactly what variants were sent.
        this.persistToolArtifact("waf_evasion", {
          url,
          vendor: verdict.fingerprint?.vendor ?? "generic",
          reason: verdict.reason,
          authorized_engagement: true,
          attempts: campaign.attempts,
          bypassed: campaign.bypassed,
          bypass_strategy: campaign.bypassStrategy,
        });
        if (campaign.bypassed && lastSend) {
          chosen = lastSend;
        }
      }
    } else if (verdict.fingerprint) {
      // WAF present but this response looks legitimate — note it so the agent
      // knows it is operating behind an edge filter.
      wafInfo = {
        detected: true,
        blocked: false,
        vendor: verdict.fingerprint.vendor,
        label: verdict.fingerprint.label,
        confidence: verdict.fingerprint.confidence,
        reason: verdict.reason,
        authorized_engagement: true,
      };
    }

    const output: Record<string, unknown> = {
      status: chosen.res.status,
      headers: Object.fromEntries(chosen.res.headers.entries()),
      body: chosen.body.slice(0, 10_000), // cap response size
    };
    if (wafInfo) output.waf = wafInfo;

    // Persist as run artifact (record the headers actually sent so the
    // operator can confirm attribution was attached on engagement-tagged
    // traffic).
    this.persistToolArtifact("http_request", {
      request: {
        url,
        method,
        headers: chosen.sentHeaders,
        body: body?.slice(0, 2_000),
      },
      response: { status: chosen.res.status, body: chosen.body.slice(0, 5_000) },
      ...(wafInfo ? { waf: wafInfo } : {}),
    });

    return { success: true, output };
  }

  private async sendPromptTool(args: Record<string, unknown>): Promise<ToolResult> {
    const prompt = args.prompt as string;

    try {
      const res = await sendPrompt(this.ctx.target, prompt, { timeout: 30_000 });
      const text = extractResponseText(res.body);

      // Persist as run artifact
      this.persistToolArtifact("send_prompt", {
        request: { prompt: prompt.slice(0, 2_000), target: this.ctx.target },
        response: { text: text.slice(0, 5_000), raw: JSON.stringify(res.body).slice(0, 5_000) },
      });

      return { success: true, output: { response: text, raw: res.body } };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  /** Persist a tool call's request/response as a first-class run artifact via the event pipeline. */
  private persistToolArtifact(toolName: string, data: Record<string, unknown>): void {
    if (!this.db) return;
    try {
      this.db.logEvent({
        scanId: this.ctx.scanId,
        stage: "attack",
        eventType: "tool_artifact",
        payload: { tool: toolName, ...data },
        timestamp: Date.now(),
      });
    } catch {
      // Non-critical — don't fail the tool call if artifact persistence fails
    }
  }

  // ── Crawl helpers ──

  private parseHtml(html: string, baseUrl: string): {
    links: string[];
    forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>;
    scripts: string[];
  } {
    const base = new URL(baseUrl);
    const links: string[] = [];
    const scripts: string[] = [];
    const forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }> = [];

    // Extract links
    const hrefRe = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;
    let m: RegExpExecArray | null;
    while ((m = hrefRe.exec(html)) !== null) {
      try {
        const resolved = new URL(m[1], baseUrl);
        if (resolved.hostname === base.hostname) {
          links.push(resolved.toString());
        }
      } catch { /* skip malformed URLs */ }
    }

    // Extract script sources
    const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
    while ((m = scriptRe.exec(html)) !== null) {
      try {
        scripts.push(new URL(m[1], baseUrl).toString());
      } catch { /* skip */ }
    }

    // Extract forms with their inputs
    const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    while ((m = formRe.exec(html)) !== null) {
      const attrs = m[1];
      const body = m[2];

      const actionMatch = /action\s*=\s*["']([^"']*)["']/i.exec(attrs);
      const methodMatch = /method\s*=\s*["']([^"']*)["']/i.exec(attrs);

      let action = baseUrl;
      if (actionMatch) {
        try { action = new URL(actionMatch[1], baseUrl).toString(); } catch { /* keep default */ }
      }
      const method = (methodMatch?.[1] ?? "GET").toUpperCase();

      const inputs: Array<{ name: string; type: string }> = [];
      const inputRe = /<(?:input|textarea|select)\b([^>]*)>/gi;
      let im: RegExpExecArray | null;
      while ((im = inputRe.exec(body)) !== null) {
        const iattrs = im[1];
        const nameMatch = /name\s*=\s*["']([^"']*)["']/i.exec(iattrs);
        const typeMatch = /type\s*=\s*["']([^"']*)["']/i.exec(iattrs);
        if (nameMatch) {
          inputs.push({ name: nameMatch[1], type: typeMatch?.[1] ?? "text" });
        }
      }

      forms.push({ action, method, inputs });
    }

    return { links: [...new Set(links)], forms, scripts: [...new Set(scripts)] };
  }

  private parseCookies(headers: Headers): string[] {
    const cookies: string[] = [];
    headers.forEach((value, key) => {
      if (key.toLowerCase() === "set-cookie") {
        cookies.push(value);
      }
    });
    return cookies;
  }

  private async crawl(args: Record<string, unknown>): Promise<ToolResult> {
    const startUrl = args.url as string;
    const maxDepth = Math.min(Math.max((args.depth as number) ?? 1, 1), 3);

    // Validate the URL scheme and resolve against target origin for relative URLs
    let resolved: URL;
    try {
      resolved = new URL(startUrl, this.ctx.target);
    } catch {
      return { success: false, output: null, error: `Invalid URL: ${startUrl}` };
    }

    if (!["http:", "https:"].includes(resolved.protocol)) {
      return { success: false, output: null, error: `Unsupported protocol: ${resolved.protocol}` };
    }

    if (this.ctx.scope) {
      const verdict = this.ctx.scope.match(resolved.toString());
      if (!verdict.allowed) {
        this.ctx.enforcement?.noteOutOfScopeBlocked();
        return { success: false, output: null, error: `crawl refused: ${verdict.reason}` };
      }
    }
    // http_audit path allowlist on the crawl seed URL (FROZEN CONTRACT).
    if (this.ctx.enforcement) {
      const pathVerdict = this.ctx.enforcement.pathPolicy.match(resolved.toString());
      if (!pathVerdict.allowed) {
        this.ctx.enforcement.noteOutOfScopeBlocked();
        return { success: false, output: null, error: `crawl refused: ${pathVerdict.reason}` };
      }
    }

    const originHost = resolved.hostname;
    const visited = new Set<string>();
    const results: Array<{
      url: string;
      status: number;
      links: string[];
      forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>;
      scripts: string[];
      cookies: string[];
      textContent?: string;
    }> = [];

    const queue: Array<{ url: string; depth: number }> = [{ url: resolved.toString(), depth: 1 }];

    while (queue.length > 0) {
      const item = queue.shift()!;
      const normalizedUrl = item.url.split("#")[0]; // strip fragment
      if (visited.has(normalizedUrl)) continue;
      visited.add(normalizedUrl);

      // Same-origin check
      let parsed: URL;
      try {
        parsed = new URL(normalizedUrl);
      } catch { continue; }
      if (parsed.hostname !== originHost) continue;

      // Scope enforcement (pwnkit#215). Same-origin already restricts the
      // crawl to one host, but if that host is out of scope we still must
      // refuse — operators sometimes scan dev.example.com against a scope
      // that only allows prod.example.com.
      if (this.ctx.scope) {
        const verdict = this.ctx.scope.match(normalizedUrl);
        if (!verdict.allowed) {
          this.ctx.enforcement?.noteOutOfScopeBlocked();
          continue;
        }
      }
      // http_audit path allowlist per crawled page (FROZEN CONTRACT). Each
      // page about to be fetched counts as one in-scope or out-of-scope
      // request for the enforcement_summary.
      if (this.ctx.enforcement) {
        const pathVerdict = this.ctx.enforcement.pathPolicy.match(normalizedUrl);
        if (!pathVerdict.allowed) {
          this.ctx.enforcement.noteOutOfScopeBlocked();
          continue;
        }
        this.ctx.enforcement.noteInScope();
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10_000);

      try {
        const crawlAuthHeaders = this.activeAuthHeaders();
        // Attribution-header injection (pwnkit#216). Crawler hits every
        // discovered link, so this is the highest-volume fetch site —
        // attribution here is what most defenders will see in their logs.
        // The default `pwnkit-crawler/1.0` UA is replaced with the
        // engagement-tagged UA inside applyAttribution when configured.
        //
        // Manual redirect handling (pwnkit#238). `redirect: "manual"` and
        // a per-hop scope+origin check below stop attribution headers
        // from leaking to a 3xx target on a different host. Each Location
        // is validated BEFORE the next fetch, so the next request only
        // ships if the destination is still in-scope and same-origin.
        const buildCrawlInit = (urlForAttribution: string): RequestInit => {
          const init = applyAttribution(
            urlForAttribution,
            {
              method: "GET",
              signal: controller.signal,
              redirect: "manual",
              headers: { "User-Agent": "pwnkit-crawler/1.0", ...crawlAuthHeaders },
            },
            this.ctx.attribution,
            this.ctx.scope,
          )!;
          // crawl explicitly wants the engagement-tagged UA (not the
          // generic crawler one) when attribution is configured. We
          // overwrite here because the attribution path keeps caller UA
          // for principle-of-least-surprise in other call sites.
          if (this.ctx.attribution?.userAgentToken) {
            (init.headers as Record<string, string>)["User-Agent"] =
              formatUserAgent(this.ctx.attribution.userAgentToken);
          }
          return init;
        };

        const MAX_REDIRECTS = 5;
        let currentUrl = normalizedUrl;
        let redirectCount = 0;
        let res: Response;
        let redirectBailReason: string | null = null;
        // Walk the redirect chain ourselves; each hop is scope+origin
        // validated before we re-issue with attribution attached.
        while (true) {
          if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(currentUrl);
          // js/no-ssrf FP: `currentUrl` is the validated crawl seed (or a
          // same-origin, in-scope redirect target re-validated each hop below);
          // cross-origin / out-of-scope / private-IP hops are refused. Crawling
          // the in-scope target is intended pwnkit behaviour.
          // foxguard:ignore
          res = await fetch(currentUrl, buildCrawlInit(currentUrl));
          if (this.ctx.rateLimiter) this.ctx.rateLimiter.noteResponse(currentUrl, res);
          // Capture cookies on every hop so authenticated crawls persist
          // session state across pages (pwnkit#564).
          this.captureActiveCookies(res);

          if (res.status < 300 || res.status >= 400) break;
          const location = res.headers.get("location");
          if (!location) break; // 30x without Location → treat as terminal

          if (++redirectCount > MAX_REDIRECTS) {
            redirectBailReason = "too many redirects";
            break;
          }

          let next: URL;
          try {
            next = new URL(location, currentUrl);
          } catch {
            redirectBailReason = "malformed redirect target";
            break;
          }
          if (!["http:", "https:"].includes(next.protocol)) {
            redirectBailReason = "non-http redirect target";
            break;
          }
          if (next.hostname !== originHost) {
            redirectBailReason = "cross-origin redirect target";
            break;
          }
          if (this.ctx.scope) {
            const verdict = this.ctx.scope.match(next.toString());
            if (!verdict.allowed) {
              redirectBailReason = `out-of-scope redirect target: ${verdict.reason}`;
              break;
            }
          }
          currentUrl = next.toString();
        }

        clearTimeout(timer);

        if (redirectBailReason) {
          // Refused mid-chain — record the page as visited but don't
          // read the body; the response in hand is the final 30x and
          // we never sent attribution to the off-scope/cross-origin
          // destination.
          results.push({
            url: normalizedUrl,
            status: res.status,
            links: [],
            forms: [],
            scripts: [],
            cookies: this.parseCookies(res.headers),
          });
          (results[results.length - 1] as Record<string, unknown>).error = redirectBailReason;
          continue;
        }

        const contentType = res.headers.get("content-type") ?? "";
        if (!contentType.includes("html") && !contentType.includes("text")) {
          results.push({
            url: normalizedUrl,
            status: res.status,
            links: [],
            forms: [],
            scripts: [],
            cookies: this.parseCookies(res.headers),
          });
          continue;
        }

        const html = await res.text();
        const { links, forms, scripts } = this.parseHtml(html.slice(0, 500_000), normalizedUrl);
        const cookies = this.parseCookies(res.headers);

        // Extract visible text content so the agent can read credentials, hints, etc.
        const textContent = html
          .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
          .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
          .replace(/<[^>]+>/g, " ")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 2000);

        results.push({ url: normalizedUrl, status: res.status, links, forms, scripts, cookies, textContent });

        // Enqueue discovered links for deeper crawling
        if (item.depth < maxDepth) {
          for (const link of links) {
            queue.push({ url: link, depth: item.depth + 1 });
          }
        }
      } catch (err) {
        clearTimeout(timer);
        const msg = err instanceof Error ? err.message : String(err);
        results.push({
          url: normalizedUrl,
          status: 0,
          links: [],
          forms: [],
          scripts: [],
          cookies: [],
        });
        // Include the error inline so the agent sees partial results
        (results[results.length - 1] as Record<string, unknown>).error = msg;
      }
    }

    this.persistToolArtifact("crawl", {
      startUrl: resolved.toString(),
      depth: maxDepth,
      pagesVisited: results.length,
    });

    return {
      success: true,
      output: {
        pages: results,
        totalPages: results.length,
        totalLinks: results.reduce((n, p) => n + p.links.length, 0),
        totalForms: results.reduce((n, p) => n + p.forms.length, 0),
      },
    };
  }

  private async submitForm(args: Record<string, unknown>): Promise<ToolResult> {
    const rawUrl = args.url as string;
    const method = ((args.method as string) ?? "POST").toUpperCase();
    const fields = (args.fields as Record<string, string>) ?? {};
    const formAuthHeaders = this.activeAuthHeaders();
    const extraHeaders = { ...formAuthHeaders, ...(args.headers as Record<string, string>) ?? {} };

    // Validate URL against same-origin policy (same as http_request)
    let resolved: URL;
    try {
      const validated = validateTargetUrl(this.ctx.target, rawUrl, this.ctx.scope, this.ctx.enforcement);
      resolved = new URL(validated);
    } catch (err) {
      return { success: false, output: null, error: err instanceof Error ? err.message : `Invalid URL: ${rawUrl}` };
    }

    // Encode fields as application/x-www-form-urlencoded
    const encoded = new URLSearchParams(fields).toString();

    let fetchUrl = resolved.toString();
    const fetchOpts: RequestInit = {
      method,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...extraHeaders,
      },
      redirect: "manual",
    };

    if (method === "GET") {
      // Append fields to query string
      const withParams = new URL(fetchUrl);
      for (const [k, v] of Object.entries(fields)) {
        withParams.searchParams.set(k, v);
      }
      fetchUrl = withParams.toString();
    } else {
      fetchOpts.body = encoded;
    }

    const controller = new AbortController();
    fetchOpts.signal = controller.signal;
    const timer = setTimeout(() => controller.abort(), 10_000);

    try {
      // Attribution-header injection (pwnkit#216). submit_form is one
      // of the noisier fetch sites in pen-test contexts (login attempts,
      // CSRF probes), so attribution here is critical for deconfliction.
      const submitInit = applyAttribution(fetchUrl, fetchOpts, this.ctx.attribution, this.ctx.scope)!;
      // #214: rate-limit the form submission before dispatching.
      if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(fetchUrl);
      // js/no-ssrf FP: `fetchUrl` derives from validateTargetUrl() above
      // (same-origin + scope + private-IP/localhost block). Submitting forms to
      // the in-scope target is intended pwnkit behaviour.
      // foxguard:ignore
      const res = await fetch(fetchUrl, submitInit);
      if (this.ctx.rateLimiter) this.ctx.rateLimiter.noteResponse(fetchUrl, res);
      // Capture the session cookie a login form sets, so the very next
      // request is authenticated without manual `curl -c/-b` jars (pwnkit#564).
      this.captureActiveCookies(res);
      clearTimeout(timer);
      const text = await res.text();

      const output = {
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        body: text.slice(0, 10_000),
      };

      this.persistToolArtifact("submit_form", {
        request: { url: fetchUrl, method, headers: submitInit.headers as Record<string, string>, fields },
        response: { status: output.status, body: output.body.slice(0, 5_000) },
      });

      return { success: true, output };
    } catch (err) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  // ── Access-control probe (pwnkit#564) ──

  /**
   * Resolve the principals this probe can act as. Prefers the live
   * `SessionEngine` (so per-identity cookie jars + re-auth apply); falls back
   * to the resolved identity list / legacy `authConfig` with static auth only.
   */
  private resolveProbeIdentities(): ProbePrincipal[] {
    const session = this.ctx.session;
    if (session) {
      return session.all.map((s) => ({
        label: s.label,
        role: s.role,
        headers: () => session.headersFor(s.label, this.ctx.target),
        capture: (res: Response) => {
          session.capture(s.label, res.headers, this.ctx.target);
          session.handleAuthStatus(s.label, res.status, this.ctx.target);
        },
      }));
    }
    const identities = resolveIdentities({ auth: this.ctx.authConfig, identities: this.ctx.identities });
    return identities.map((idn: NamedIdentity) => ({
      label: idn.label,
      role: idn.role,
      headers: () => buildAuthHeaders(idn.auth),
      capture: () => {},
    }));
  }

  /** Issue one request to the target as a specific principal. */
  private async fetchAs(
    principal: ProbePrincipal,
    rawUrl: string,
    method: string,
    body: string | undefined,
    extraHeaders: Record<string, string>,
  ): Promise<ProbeResponse> {
    // Same-origin / scope / path-allowlist enforcement as every other tool.
    const url = validateTargetUrl(this.ctx.target, rawUrl, this.ctx.scope, this.ctx.enforcement);
    const headers = { "Content-Type": "application/json", ...principal.headers(), ...extraHeaders };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    try {
      const fetchInit = applyAttribution(
        url,
        { method, headers, body: body ?? undefined, signal: controller.signal, redirect: "manual" },
        this.ctx.attribution,
        this.ctx.scope,
      )!;
      if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(url);
      // js/no-ssrf FP: `url` is the operator-specified probe target validated by
      // validateTargetUrl() above (same-origin + scope + private-IP/localhost
      // block + path allowlist). The access-control probe replays requests to
      // the in-scope target as different identities — intended behaviour.
      // foxguard:ignore
      const res = await fetch(url, fetchInit);
      if (this.ctx.rateLimiter) this.ctx.rateLimiter.noteResponse(url, res);
      principal.capture(res);
      const text = await res.text();
      return {
        identity: principal.label,
        role: principal.role,
        url,
        method,
        status: res.status,
        contentType: res.headers.get("content-type") ?? "",
        body: text.slice(0, 10_000),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  private async accessControlProbe(args: Record<string, unknown>): Promise<ToolResult> {
    const rawUrl = args.url as string;
    if (!rawUrl) return { success: false, output: null, error: "url is required" };
    const method = ((args.method as string) ?? "GET").toUpperCase();
    const body = args.body as string | undefined;
    const extraHeaders = (args.headers as Record<string, string>) ?? {};
    const expectDenied = args.expect_denied === true;

    const principals = this.resolveProbeIdentities();
    if (principals.length < 2) {
      return {
        success: false,
        output: null,
        error:
          `access_control_probe needs at least 2 identities — configure scan \`identities\` ` +
          `(label + role + auth) for the principals you want to diff. Currently available: ${principals.length}.`,
      };
    }

    const baselineLabel = (args.baseline_identity as string) ?? this.ctx.session?.activeLabel ?? principals[0].label;
    const baseline = principals.find((p) => p.label === baselineLabel);
    if (!baseline) {
      return {
        success: false,
        output: null,
        error: `unknown baseline_identity "${baselineLabel}"; known identities: ${principals.map((p) => p.label).join(", ")}`,
      };
    }

    let compareLabels: string[];
    if (Array.isArray(args.compare_identities) && (args.compare_identities as unknown[]).length > 0) {
      compareLabels = (args.compare_identities as unknown[]).map(String);
    } else {
      compareLabels = principals.filter((p) => p.label !== baselineLabel).map((p) => p.label);
    }

    // Authorized baseline request.
    let baselineResp: ProbeResponse;
    try {
      baselineResp = await this.fetchAs(baseline, rawUrl, method, body, extraHeaders);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: `baseline request failed: ${msg}` };
    }

    const comparisons: Record<string, unknown>[] = [];
    for (const label of compareLabels) {
      const principal = principals.find((p) => p.label === label);
      if (!principal) {
        comparisons.push({ identity: label, error: `unknown identity "${label}"` });
        continue;
      }
      let resp: ProbeResponse;
      try {
        resp = await this.fetchAs(principal, rawUrl, method, body, extraHeaders);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        comparisons.push({ identity: label, role: principal.role, error: msg });
        continue;
      }
      const diff = diffAccessResponses(baselineResp, resp, {
        baselineRole: baseline.role,
        comparisonRole: principal.role,
        expectDenied,
      });
      comparisons.push({
        identity: label,
        role: principal.role,
        status: resp.status,
        ...diff,
        evidence: probeEvidence(resp),
      });
    }

    const broken = comparisons.filter((c) => c.broken === true);
    const output = {
      url: baselineResp.url,
      method,
      baseline: {
        identity: baseline.label,
        role: baseline.role,
        status: baselineResp.status,
        evidence: probeEvidence(baselineResp),
      },
      comparisons,
      broken_count: broken.length,
      verdict: broken.length > 0 ? "broken_access_control" : "no_break_detected",
      summary:
        broken.length > 0
          ? `Authorization boundary broken: ${broken
              .map((b) => `${b.identity} (${b.verdict})`)
              .join(", ")} reached ${baseline.label}'s resource at ${baselineResp.url}. ` +
            `Save a finding with the A-vs-B evidence below.`
          : `No access-control break detected at ${baselineResp.url}: all comparison identities were denied or got distinct resources.`,
    };

    this.persistToolArtifact("access_control_probe", {
      url: baselineResp.url,
      method,
      baseline: baseline.label,
      compared: compareLabels,
      broken_count: broken.length,
    });

    return { success: true, output };
  }

  /**
   * Scope-validated request returning status + body text, mirroring the
   * enforcement path of `fetchAs`/`httpRequest` (validateTargetUrl + scope +
   * SSRF guard + attribution + rate limiter). No identity auth is injected —
   * the caller passes any auth via `headers`. Used by the detection probes.
   */
  private async scopedFetchText(
    rawUrl: string,
    method: string,
    body: string | undefined,
    headers: Record<string, string>,
  ): Promise<{ status: number; text: string }> {
    const url = validateTargetUrl(this.ctx.target, rawUrl, this.ctx.scope, this.ctx.enforcement);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    try {
      const fetchInit = applyAttribution(
        url,
        { method, headers, body: body ?? undefined, signal: controller.signal, redirect: "manual" },
        this.ctx.attribution,
        this.ctx.scope,
      )!;
      if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(url);
      // foxguard:ignore — `url` validated by validateTargetUrl above
      // (same-origin + scope + private-IP/localhost block + path allowlist).
      const res = await fetch(url, fetchInit);
      if (this.ctx.rateLimiter) this.ctx.rateLimiter.noteResponse(url, res);
      const text = await res.text();
      return { status: res.status, text };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * #774 — drive the structural / JSON-key SQLi break→balance loop over live
   * HTTP and return the verdict + iteration trail. The KEY (`base_key`) is the
   * injection surface; each iteration mutates it into a copy of `body`.
   */
  private async structuralSqliProbe(args: Record<string, unknown>): Promise<ToolResult> {
    const url = args.url as string;
    const baseKey = args.base_key as string;
    if (!url) return { success: false, output: null, error: "url is required" };
    if (!baseKey) return { success: false, output: null, error: "base_key is required" };
    const method = ((args.method as string) ?? "POST").toUpperCase();
    const baseBody =
      args.body && typeof args.body === "object"
        ? (args.body as Record<string, unknown>)
        : {};
    const maxIterations =
      typeof args.max_iterations === "number" ? args.max_iterations : undefined;

    const sendKey = async (payload: {
      key: string;
    }): Promise<ProbeObservation> => {
      // The key is the injection surface — set the mutated key with a benign
      // value in a copy of the base body; other fields go verbatim.
      const bodyObj: Record<string, unknown> = { ...baseBody, [payload.key]: "1" };
      const json = JSON.stringify(bodyObj);
      try {
        const { status, text } = await this.scopedFetchText(url, method, json, {
          "Content-Type": "application/json",
        });
        return { payloadKey: payload.key, responseText: text, status };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { payloadKey: payload.key, responseText: msg };
      }
    };

    let result;
    try {
      result = await runStructuralSqliProbeAsync({ baseKey, maxIterations }, sendKey);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: `structural_sqli_probe failed: ${msg}` };
    }

    this.persistToolArtifact("structural_sqli_probe", {
      url,
      base_key: baseKey,
      verdict: result.verdict,
      dialect: result.dialect,
    });

    const summary =
      result.verdict === "confirmed"
        ? `Structural SQL injection CONFIRMED on JSON key "${baseKey}" at ${url} (${result.dialect ?? "dialect unpinned"}): a balanced key parsed cleanly while the broken key errored. Save a finding with the iteration trail.`
        : result.verdict === "error_signal"
          ? `Key "${baseKey}" reaches the SQL parser (broken key errored, ${result.dialect ?? "dialect unpinned"}) but no clean differential confirmation within ${result.trail.length} iterations — likely structural SQLi; inspect the trail or re-probe.`
          : `No structural SQLi signal on key "${baseKey}" at ${url}: the broken key never triggered a SQL error (surface is not concatenating the key into SQL).`;

    return {
      success: true,
      output: {
        url,
        base_key: baseKey,
        verdict: result.verdict,
        dialect: result.dialect,
        iterations: result.trail.length,
        trail: result.trail,
        summary,
      },
    };
  }

  /**
   * #775 — classify the WRITE impact of a prompt-layer DB asset the agent has
   * already read. Verification-only: pure classification over read-only
   * evidence, no writes.
   */
  private async promptLayerProbe(args: Record<string, unknown>): Promise<ToolResult> {
    if (typeof args.writable !== "boolean") {
      return { success: false, output: null, error: "writable (boolean) is required" };
    }
    const asset: PromptLayerAsset = {
      table: args.table as string | undefined,
      column: args.column as string | undefined,
      sample: args.sample as string | undefined,
      writable: args.writable,
      reReadAtInference: args.re_read_at_inference === true,
    };
    const result = classifyPromptLayerImpact(asset);
    return {
      success: true,
      output: {
        is_prompt_layer: result.isPromptLayer,
        impacts: result.impacts,
        severity: result.severity,
        narrative: result.narrative,
      },
    };
  }

  private async shellExec(args: Record<string, unknown>): Promise<ToolResult> {
    let command = (args.command as string)?.trim();
    if (!command) {
      return { success: false, output: null, error: "Command is required" };
    }

    // Programmatic scope pre-flight (pwnkit#215). The bash subprocess can
    // reach out to anywhere — we don't have an egress proxy yet (issue
    // is acknowledged in the DoD), so the best we can do is grep the
    // command for obvious URLs and refuse if any are out of scope. This
    // catches the common case (`curl https://evil.com/x`); a cleverer
    // agent that hides the URL behind base64 / DNS / a temp file is NOT
    // caught here, and that gap is documented as a follow-up.
    if (this.ctx.scope) {
      const urls = extractUrls(command);
      for (const url of urls) {
        const verdict = this.ctx.scope.match(url);
        if (!verdict.allowed) {
          this.ctx.enforcement?.noteOutOfScopeBlocked();
          return {
            success: false,
            output: null,
            error: `bash refused: command references out-of-scope URL '${url}' (${verdict.reason})`,
          };
        }
        // http_audit path allowlist on bash-extracted URLs (FROZEN CONTRACT).
        if (this.ctx.enforcement) {
          const pathVerdict = this.ctx.enforcement.pathPolicy.match(url);
          if (!pathVerdict.allowed) {
            this.ctx.enforcement.noteOutOfScopeBlocked();
            return {
              success: false,
              output: null,
              error: `bash refused: command references out-of-path URL '${url}' (${pathVerdict.reason})`,
            };
          }
        }
      }

      // Generic-scanner-traffic suppression (pwnkit#217). When scope is
      // loaded the engagement is presumed to be a coordinated-disclosure
      // run, and most venue policies explicitly forbid the named
      // generic scanners (sqlmap/nikto/gobuster/…) because they
      // fingerprint themselves on the wire. The shell-first agent has
      // `http_request` + `crawl` for the actual probing it needs to do.
      // `--allow-scanners` (threaded down as `ctx.allowScanners`)
      // overrides this gate for engagements that explicitly permit
      // those tools.
      if (!this.ctx.allowScanners) {
        const hit = detectScannerBinary(command);
        if (hit) {
          return {
            success: false,
            output: null,
            error: `bash refused: ${hit.reason}`,
          };
        }
      }
    }

    // ── http_audit bash-egress SSRF gate (FROZEN CONTRACT) ──
    // Close the gap where bash curl/wget/python-http bypasses the
    // host+path allowlist that http_request/crawl/submit_form enforce.
    // Any HTTP-egress segment MUST carry at least one explicit http(s) URL
    // (which the scope+path block above already verified is in-scope AND
    // in-path). An egress command with no statically-resolvable URL is
    // refused fail-closed — its destination can't be audited, which defeats
    // the bounded-egress guarantee of http_audit. Non-egress bash is
    // untouched. Only active in http_audit mode (enforcement set).
    if (this.ctx.enforcement) {
      const egressSegments = detectHttpEgressSegments(command);
      for (const segment of egressSegments) {
        const urlsInSegment = extractUrls(segment);
        if (urlsInSegment.length === 0) {
          this.ctx.enforcement.noteOutOfScopeBlocked();
          return {
            success: false,
            output: null,
            error:
              `bash refused (http_audit): HTTP-egress command '${segment.slice(0, 80)}' has no explicit ` +
              `in-scope http(s) URL to verify against the host+path allowlist. Use the http_request tool, ` +
              `or pass a literal in-scope URL.`,
          };
        }
        // URLs present in the segment were already host+path validated in
        // the scope block above (any out-of-scope URL would have returned).
      }
    }

    // ── Close the bash rate-limiter bypass (pwnkit#568) ──
    // The bash subprocess shells out to curl/wget/python-http, which bypass
    // node's `fetch` and therefore the per-host RateLimiter (#214) that the
    // http_request / crawl / submit_form tools pace against. Without an egress
    // proxy we can't throttle the subprocess socket itself, but we CAN pace +
    // count BEFORE exec: for every explicit, in-scope http(s) URL an egress
    // segment will hit, acquire a token from the SAME per-host bucket (so bash
    // traffic paces identically to the fetch tools and honours any active 429
    // cool-off) and tally it on the enforcement tracker, so bash-issued
    // requests show up in `requests_in_scope` / peak-RPS instead of being
    // invisible. URLs were already host+path validated above when scope is set;
    // when scope is unset we still pace whatever explicit URLs are present.
    if (this.ctx.rateLimiter || this.ctx.enforcement) {
      const egressSegments = detectHttpEgressSegments(command);
      const pacedUrls = new Set<string>();
      for (const segment of egressSegments) {
        for (const egressUrl of extractUrls(segment)) {
          if (pacedUrls.has(egressUrl)) continue;
          pacedUrls.add(egressUrl);
          if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(egressUrl);
          this.ctx.enforcement?.noteInScope();
        }
      }
    }

    // Deterministic auth-header injection (pwnkit#282). When `authConfig`
    // is set, rewrite curl/wget invocations whose URL is in scope and
    // which don't already carry explicit auth, so the env-var
    // indirection (`$AUTH_CURL_FLAG` / `$AUTH_HEADER:$AUTH_VALUE`) lands
    // in the bash command before exec. Python `requests` invocations
    // are refused with a hint pointing at the `http_request` tool.
    //
    // Only run when authConfig is set (no auth ⇒ nothing to inject) AND
    // scope is set (no scope ⇒ can't verify in-scope ⇒ don't leak auth
    // to potentially-non-engagement targets).
    if (this.ctx.authConfig && this.ctx.scope) {
      const verdict = injectAuthIntoBashCommand(command, this.ctx.scope);
      if (verdict.kind === "refuse") {
        return { success: false, output: null, error: `bash refused: ${verdict.reason}` };
      }
      if (verdict.kind === "rewrite") {
        command = verdict.command;
      }
    }

    // Per-call requested timeout (caller arg) is clamped against the wallclock
    // ceiling. Even if the caller asks for a longer one, we never exceed the
    // ceiling — a runaway subprocess (e.g. python3 requests.post with no
    // timeout) must not be able to wedge the agent indefinitely.
    const ceilingMs = resolveBashWallclockCeilingMs();
    const requestedMs = Math.max(1, ((args.timeout as number) ?? 30) * 1000);
    const timeoutMs = Math.min(requestedMs, ceilingMs);

    const env = { ...sanitizedEnv(), TARGET: this.ctx.target, ...this.buildAuthEnvVars() };

    const outcome = await runBashWithWallclock(command, { timeoutMs, ceilingMs, env });

    if (outcome.kind === "timeout") {
      this.persistToolArtifact("bash", {
        command: command.slice(0, 500),
        output: outcome.partial.slice(0, 2_000),
        timedOut: true,
        timeoutMs,
      });
      return {
        success: false,
        output: null,
        error: `bash tool timed out after ${Math.round(timeoutMs / 1000)}s (PWNKIT_BASH_TIMEOUT_MS=${ceilingMs})`,
      };
    }

    if (outcome.kind === "error") {
      return { success: false, output: null, error: outcome.message.slice(0, 2_000) };
    }

    const combined = outcome.combined.slice(0, 10_000);

    // Many pentesting tools exit non-zero on findings — if we got output,
    // surface it as success regardless of exit code (preserves prior behaviour).
    if (outcome.exitCode === 0 || combined.length > 0) {
      this.persistToolArtifact("bash", {
        command: command.slice(0, 500),
        output: combined.slice(0, 2_000),
        ...(outcome.exitCode !== 0 ? { exitCode: outcome.exitCode } : {}),
      });
      return { success: true, output: combined };
    }

    return {
      success: false,
      output: null,
      error: `bash exited with code ${outcome.exitCode}`,
    };
  }

  // ── Browser automation (Playwright) ──

  private async ensureBrowser(): Promise<{ page: any }> {
    if (this._browserPage) return { page: this._browserPage };

    // @ts-ignore — playwright is an optional dependency
    const { chromium } = await import("playwright");
    this._browser = await chromium.launch({ headless: true });
    // Attribution-header injection (pwnkit#216). Playwright doesn't run
    // through `applyAttribution` — it has its own request pipeline — so
    // we set `extraHTTPHeaders` on the context, which Chrome attaches to
    // every outgoing request. The browser only navigates to in-scope
    // hosts (validateTargetUrl is enforced before goto), so attribution
    // here is bounded to in-scope traffic in the same way as the fetch
    // sites. Same UA-override rule: when an engagement token is set, it
    // replaces the default `pwnkit-browser/1.0`.
    const attribution = this.ctx.attribution;
    const browserUa = attribution?.userAgentToken
      ? formatUserAgent(attribution.userAgentToken)
      : "pwnkit-browser/1.0";
    const context = await this._browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent: browserUa,
      ...(attribution && Object.keys(attribution.headers).length > 0
        ? { extraHTTPHeaders: attribution.headers }
        : {}),
    });
    this._browserPage = await context.newPage();

    // Capture dialogs (alert/confirm/prompt) — key XSS signal
    this._browserPage.on("dialog", async (dialog: any) => {
      this._browserDialogs.push(`${dialog.type()}: ${dialog.message()}`);
      await dialog.dismiss().catch(() => {});
    });

    // Capture console messages
    this._browserPage.on("console", (msg: any) => {
      if (this._browserConsole.length < 50) {
        this._browserConsole.push(`[${msg.type()}] ${msg.text()}`);
      }
    });

    return { page: this._browserPage };
  }

  private async browserAction(args: Record<string, unknown>): Promise<ToolResult> {
    const action = args.action as string;
    if (!action) {
      return { success: false, output: null, error: "action is required" };
    }

    if (!(await this.isPlaywrightAvailable())) {
      return {
        success: false,
        output: null,
        error: "playwright is not installed. Install it with: npm i playwright && npx playwright install chromium",
      };
    }

    // Clear per-action dialog/console buffers
    this._browserDialogs = [];
    this._browserConsole = [];

    const ACTION_TIMEOUT = 10_000;

    try {
      const { page } = await this.ensureBrowser();

      let result: unknown;

      switch (action) {
        case "navigate": {
          const rawNavUrl = args.url as string;
          if (!rawNavUrl) return { success: false, output: null, error: "url is required for navigate" };
          // Validate against same-origin policy (same as http_request/submit_form)
          let url: string;
          try {
            url = validateTargetUrl(this.ctx.target, rawNavUrl, this.ctx.scope, this.ctx.enforcement);
          } catch (err) {
            return { success: false, output: null, error: err instanceof Error ? err.message : `Invalid URL: ${rawNavUrl}` };
          }
          const response = await page.goto(url, { timeout: ACTION_TIMEOUT, waitUntil: "domcontentloaded" });
          // Post-navigation scope re-check (pwnkit#218 review).
          // `validateTargetUrl` only vets the requested URL; `page.goto`
          // follows redirects, so an in-scope URL that 302s off-origin
          // leaves the browser sitting on a foreign page that subsequent
          // click/content/evaluate calls would then operate on. Compare
          // the post-navigation URL against scope and refuse if it
          // drifted off-host before returning success.
          const finalUrl = page.url();
          if (this.ctx.scope && finalUrl) {
            const verdict = this.ctx.scope.match(finalUrl);
            if (!verdict.allowed) {
              return {
                success: false,
                output: null,
                error: `navigate refused: redirected to out-of-scope URL '${finalUrl}' (${verdict.reason})`,
              };
            }
          }
          result = {
            url: finalUrl,
            status: response?.status() ?? null,
            title: await page.title(),
            dialogs: [...this._browserDialogs],
            console: this._browserConsole.slice(0, 20),
          };
          break;
        }

        case "click": {
          const selector = args.selector as string;
          if (!selector) return { success: false, output: null, error: "selector is required for click" };
          await page.click(selector, { timeout: ACTION_TIMEOUT });
          // Wait briefly for any navigation or DOM updates
          await page.waitForTimeout(500);
          result = {
            clicked: selector,
            url: page.url(),
            title: await page.title(),
            dialogs: [...this._browserDialogs],
            console: this._browserConsole.slice(0, 20),
          };
          break;
        }

        case "fill": {
          const selector = args.selector as string;
          const value = args.value as string;
          if (!selector) return { success: false, output: null, error: "selector is required for fill" };
          if (value === undefined) return { success: false, output: null, error: "value is required for fill" };
          await page.fill(selector, value, { timeout: ACTION_TIMEOUT });
          result = {
            filled: selector,
            value,
            dialogs: [...this._browserDialogs],
          };
          break;
        }

        case "evaluate": {
          const expression = args.value as string;
          if (!expression) return { success: false, output: null, error: "value (JavaScript) is required for evaluate" };
          const evalResult = await page.evaluate(expression).catch((e: Error) => `Error: ${e.message}`);
          result = {
            result: typeof evalResult === "object" ? JSON.stringify(evalResult) : String(evalResult),
            dialogs: [...this._browserDialogs],
            console: this._browserConsole.slice(0, 20),
          };
          break;
        }

        case "content": {
          const html = await page.content();
          // Extract visible text for readability
          const text = await page.evaluate(() => document.body?.innerText?.slice(0, 5000) ?? "").catch(() => "");
          result = {
            url: page.url(),
            title: await page.title(),
            html: html.slice(0, 10_000),
            text: (text as string).slice(0, 5_000),
            dialogs: [...this._browserDialogs],
          };
          break;
        }

        case "screenshot": {
          const buffer = await page.screenshot({ type: "png", fullPage: false });
          const base64 = buffer.toString("base64").slice(0, 50_000); // cap at ~37KB image
          result = {
            url: page.url(),
            title: await page.title(),
            screenshot_base64: base64,
            dialogs: [...this._browserDialogs],
          };
          break;
        }

        default:
          return {
            success: false,
            output: null,
            error: `Unknown browser action: ${action}. Valid: navigate, click, fill, evaluate, content, screenshot`,
          };
      }

      this.persistToolArtifact("browser", {
        action,
        url: (args.url as string) ?? page.url(),
        dialogs: [...this._browserDialogs],
      });

      return { success: true, output: result };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        output: { dialogs: [...this._browserDialogs], console: this._browserConsole.slice(0, 10) },
        error: msg.slice(0, 2_000),
      };
    }
  }

  private async spawnAgent(args: Record<string, unknown>): Promise<ToolResult> {
    const task = args.task as string;
    if (!task) return { success: false, output: null, error: "Task description is required" };

    const maxTurns = Math.min((args.max_turns as number) ?? 15, 25);

    try {
      // Dynamic import to avoid circular dependency
      const { runNativeAgentLoop } = await import("./native-loop.js");
      const { LlmApiRuntime } = await import("../runtime/llm-api.js");

      const rt = new LlmApiRuntime({ type: "api" as any, timeout: 60_000 });
      if (!(await rt.isAvailable())) {
        return { success: false, output: null, error: "No API key available for sub-agent" };
      }

      const subTools: ToolDefinition[] = ["bash", "save_finding", "done"]
        .map((n) => TOOL_DEFINITIONS[n])
        .filter((t): t is ToolDefinition => t !== undefined);

      // pwnkit#218 review: propagate scope + auth to the spawned loop so
      // the sub-agent's bash/http_request gates use the same policy as
      // the parent. Without this, a parent scan locked to in-scope hosts
      // could spawn a child that hits arbitrary URLs via bash/curl.
      const state = await runNativeAgentLoop({
        config: {
          role: "attack",
          systemPrompt: `You are a focused exploitation agent. Your ONLY job:\n\n${task}\n\nUse bash to run curl, python3, or any command. Save findings with save_finding. Call done when finished.`,
          tools: subTools,
          maxTurns,
          target: this.ctx.target,
          scanId: this.ctx.scanId + "-sub",
          scope: this.ctx.scope,
          authConfig: this.ctx.authConfig,
        },
        runtime: rt,
        db: null,
      });

      // Merge sub-agent findings into parent context
      for (const f of state.findings) {
        this.ctx.findings.push(f);
      }

      return {
        success: true,
        output: {
          turns: state.turnCount,
          findings: state.findings.length,
          summary: state.summary,
          done: state.done,
        },
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg.slice(0, 500) };
    }
  }

  private saveFinding(args: Record<string, unknown>): ToolResult {
    // pwnkit#283 — refuse empty-PoC findings upstream. Disclose already
    // refuses empty PoCs at render time (`disclose/template.ts` EmptyPocError),
    // but accepting them here silently inflates mid-scan telemetry and burns
    // turns on findings that will be `_dropped/`'d at disclose time. Pull the
    // gate upstream so the agent sees its own bad finding rejected with a
    // specific hint — same retry-friendly shape as flag-validator at
    // `markDone`.
    const requestRaw = args.evidence_request;
    const responseRaw = args.evidence_response;
    const descriptionRaw = args.description;
    const requestEmpty =
      typeof requestRaw !== "string" || !requestRaw.trim();
    const responseEmpty =
      typeof responseRaw !== "string" || !responseRaw.trim();
    const pocStepsEmpty =
      !args.poc_steps ||
      (Array.isArray(args.poc_steps) && args.poc_steps.length === 0) ||
      (typeof args.poc_steps === "string" && !args.poc_steps.trim());
    const descriptionEmpty =
      typeof descriptionRaw !== "string" || !descriptionRaw.trim();
    if (requestEmpty && responseEmpty && pocStepsEmpty && descriptionEmpty) {
      return {
        success: false,
        output: null,
        error:
          "save_finding requires non-empty evidence_request, evidence_response, poc_steps, or description. " +
          "For static-analysis findings, provide a description with the code path and trigger conditions.",
      };
    }

    // pwnkit#409 — structural validation at the report-creation boundary.
    // CVE/CWE/CVSS shape + evidence-path traversal/symlink-escape guards.
    // Failures return as a structured `validation_failed` tool result so the
    // agent can self-correct on the same turn (same UX as flag-validator at
    // `markDone`). We deliberately do NOT auto-uppercase or re-format
    // malformed values: the model has to learn the canonical shape.
    //
    // We skip when `scopePath` is unset (no workspace root → no path guard
    // possible). CVE/CWE/CVSS still get checked; evidence paths get a
    // permissive pass since we have no root to compare against. In every
    // production code path scopePath IS set (it's the scan workspace).
    const draft: FindingDraft = {
      cve: typeof args.cve === "string" ? args.cve : undefined,
      cwe: typeof args.cwe === "string" ? args.cwe : undefined,
      cvss: typeof args.cvss === "string" ? args.cvss : undefined,
      cvssScore:
        typeof args.cvss_score === "number" ? args.cvss_score : undefined,
      evidence: parseEvidencePathsArg(args.evidence_paths),
    };
    if (this.ctx.scopePath) {
      const validation = validateFindingDraft(draft, {
        scanWorkspaceRoot: this.ctx.scopePath,
      });
      if (!validation.ok) {
        return buildValidationFailureResult(validation.errors);
      }
    }

    const finding: Finding = {
      id: randomUUID(),
      templateId: (args.template_id as string) ?? "manual",
      title: (args.title as string) ?? "Untitled finding",
      description: (args.description as string) ?? "",
      severity: (args.severity as Finding["severity"]) ?? "medium",
      category: (args.category as Finding["category"]) ?? "prompt-injection",
      status: "discovered",
      evidence: {
        request: (args.evidence_request as string) ?? "",
        response: (args.evidence_response as string) ?? "",
        analysis: args.evidence_analysis as string | undefined,
      },
      timestamp: Date.now(),
    };

    // pwnkit#170 — optional structured PoC step graph. The agent passes
    // `poc_steps` as a JSON-encoded string (LLM tool call wire format). We
    // tolerate already-parsed arrays too. Anything malformed is silently
    // dropped so a bad payload never blocks the finding from being saved.
    const pocSteps = parsePocStepsArg(args.poc_steps);
    if (pocSteps && pocSteps.length > 0) {
      finding.pocSteps = pocSteps;
    } else {
      // pwnkit#179 — fall back to a prose-derived heuristic graph when the
      // agent didn't supply one explicitly. The heuristic is conservative:
      // it returns undefined whenever it can't extract ≥ 2 steps cleanly,
      // and we leave `pocSteps` undefined in that case (downstream consumers
      // gate on field presence).
      const inferred = extractPocStepsFromProse({
        request: finding.evidence.request,
        response: finding.evidence.response,
        analysis: finding.evidence.analysis,
      });
      if (inferred && inferred.length >= 2) finding.pocSteps = inferred;
    }

    // pwnkit#193 — optional machine-executable verification spec. Same
    // wire-shape tolerance as poc_steps (object OR JSON string OR garbage).
    // When parseable, attach to the finding so cloud's canary watcher can
    // later evaluate it via `evaluateVerificationSpec`. Findings without a
    // spec stay backwards-compatible (field is undefined).
    const verificationSpec = parseVerificationSpecArg(args.verification_spec);
    if (verificationSpec) {
      finding.verificationSpec = verificationSpec;
    }

    // pwnkit#409 — propagate the validated CVE / CWE / CVSS values to the
    // Finding. The fields are already shape-checked above, so we attach as-is
    // (no auto-uppercase / canonicalisation — the agent submitted clean
    // values or we'd have returned validation_failed already). `Finding`
    // doesn't carry a top-level `cve` / `cwe` field today (the schema work
    // is tracked separately under pwnkit#382), so we attach to the closest
    // existing slots: `cvssVector` / `cvssScore` for CVSS, and stash CVE /
    // CWE on the evidence.analysis prefix as a structured tag the disclose
    // renderer can pluck later. When the Finding schema grows first-class
    // fields, replace this stub.
    if (draft.cvss) finding.cvssVector = draft.cvss;
    if (typeof draft.cvssScore === "number") finding.cvssScore = draft.cvssScore;
    if (draft.cve || draft.cwe) {
      const tags: string[] = [];
      if (draft.cve) tags.push(`CVE: ${draft.cve}`);
      if (draft.cwe) tags.push(`CWE: ${draft.cwe}`);
      const prefix = tags.join(" | ");
      finding.evidence.analysis = finding.evidence.analysis
        ? `${prefix}\n\n${finding.evidence.analysis}`
        : prefix;
    }

    // Hybrid confidence (LLM self-report + PoC-status floor). Closes the gap
    // where every cloud-side `findings.confidence` row was NULL because the
    // OSS engine never emitted a value. We mutate the call args in-place so
    // downstream readers — agent-runner's `postFinding(call.arguments)`
    // mid-scan webhook and the native-loop's `finding_ingested` bus event
    // (which reads from `block.input`, the same dict) — all see the same
    // computed value rather than the raw, possibly-absent LLM-reported one.
    // See finding-confidence.ts for the heuristic.
    const confidence = computeFindingConfidence(args.confidence, finding.pocSteps);
    if (confidence !== undefined) {
      finding.confidence = confidence;
      args.confidence = confidence;
    }

    // pwnkit#281 — dedup against in-memory ctx.findings before append.
    // Surfaced by the 2026-05-07 control-flow audit (§H3 "prompt doing what
    // code should do"). The agent prompt already asks the model to query
    // existing findings before saving, but nothing enforces it; the same
    // SQLi gets persisted across attack and verify stages and disclose then
    // renders N advisories from one bug.
    //
    // Similarity key is (category, normalizedTitle, evidenceRequestPrefix).
    // Exact match on (category, normalizedTitle) merges. Fuzzy match
    // (Levenshtein ≤ FUZZY_TITLE_DISTANCE_THRESHOLD on the normalized title
    // PLUS identical evidenceRequestPrefix) also merges — same-prefix is the
    // anti-hallucination check that prevents legitimately-distinct
    // endpoints from collapsing on a near-name collision.
    //
    // First-write-wins: we deliberately do NOT update the existing finding's
    // evidence/severity/confidence on a merge. The first record stays
    // authoritative. Re-running with stronger evidence requires
    // `update_finding` (an explicit, separate code path).
    const newNormTitle = normalizeFindingTitle(finding.title);
    const newEvidencePrefix = evidenceRequestPrefix(finding.evidence.request);
    const existing = this.ctx.findings.find((f) => {
      if (f.category !== finding.category) return false;
      const existingNormTitle = normalizeFindingTitle(f.title);
      if (existingNormTitle === newNormTitle) return true;
      const existingEvidencePrefix = evidenceRequestPrefix(f.evidence.request);
      if (existingEvidencePrefix !== newEvidencePrefix) return false;
      return (
        levenshtein(existingNormTitle, newNormTitle) <=
        FUZZY_TITLE_DISTANCE_THRESHOLD
      );
    });
    if (existing) {
      return {
        success: true,
        output: {
          findingId: existing.id,
          message: `merged with existing finding ${existing.id}`,
        },
      };
    }

    this.ctx.findings.push(finding);
    if (this.db && this.ctx.persistFindings !== false) {
      this.db.saveFinding(this.ctx.scanId, finding);
    }

    // pwnkit#567 — harvest reusable footholds (credentials/tokens/cookies/…)
    // out of this finding's evidence into the loot ledger so the agent can
    // chain them into follow-up requests via `use_loot`. No-op when the loot
    // feature is off (ctx.loot undefined). Best-effort: a harvest failure must
    // never block a finding from being saved.
    try {
      this.ctx.loot?.harvestFromFinding(finding);
    } catch {
      /* harvesting is best-effort and must not abort save_finding */
    }

    return { success: true, output: { findingId: finding.id, message: "Finding saved" } };
  }

  /**
   * `use_loot` (pwnkit#567) — return previously captured footholds so the agent
   * can replay a leaked credential / token / cookie / endpoint / hash / path in
   * a follow-up request. Read-only and TRUSTED (we construct the output). When
   * the loot feature is off (no ledger), returns an empty, explanatory result
   * rather than an error so the call is always safe.
   */
  private useLoot(args: Record<string, unknown>): ToolResult {
    const ledger = this.ctx.loot;
    if (!ledger || ledger.size === 0) {
      return {
        success: true,
        output: {
          count: 0,
          items: [],
          message:
            "No footholds captured yet. Keep probing — leaked credentials, tokens, cookies, endpoints, and hashes are harvested automatically and will appear here for reuse.",
        },
      };
    }
    const kindArg = typeof args.kind === "string" ? args.kind : undefined;
    const items = ledger.query({
      kind: kindArg as LootKind | undefined,
      search: typeof args.search === "string" ? args.search : undefined,
      id: typeof args.id === "string" ? args.id : undefined,
    });
    return {
      success: true,
      output: {
        count: items.length,
        items: items.map((it) => ({
          id: it.id,
          kind: it.kind,
          value: it.value,
          source: it.source,
          context: it.context,
          turn: it.turn,
        })),
      },
    };
  }

  private queryFindings(args: Record<string, unknown>): ToolResult {
    if (this.db) {
      const results = this.db.queryFindings({
        scanId: this.ctx.scanId,
        severity: args.severity as string | undefined,
        category: args.category as string | undefined,
        status: args.status as string | undefined,
        limit: (args.limit as number) ?? 20,
      });
      return { success: true, output: results };
    }

    // Fallback to in-memory
    let results = [...this.ctx.findings];
    if (args.severity) results = results.filter((f) => f.severity === args.severity);
    if (args.category) results = results.filter((f) => f.category === args.category);
    if (args.status) results = results.filter((f) => f.status === args.status);
    return { success: true, output: results.slice(0, (args.limit as number) ?? 20) };
  }

  private updateFinding(args: Record<string, unknown>): ToolResult {
    const id = args.finding_id as string;
    const status = args.status as string;

    const finding = this.ctx.findings.find((f) => f.id === id);
    if (finding) {
      finding.status = status as Finding["status"];
    }
    if (this.db) {
      this.db.updateFindingStatus(id, status);
    }

    return { success: true, output: { message: `Finding ${id} updated to ${status}` } };
  }

  private readFile(args: Record<string, unknown>): ToolResult {
    if (!this.ctx.scopePath) {
      return {
        success: false,
        output: null,
        error: "read_file requires a scoped local directory and is not available for remote target scanning",
      };
    }

    const requestedPath = args.path as string;
    const maxLines = (args.max_lines as number) ?? 500;
    const path = resolveScopedPath(this.ctx.scopePath, requestedPath);

    const content = readFileSync(path, "utf-8");
    const lines = content.split("\n");
    const truncated = lines.length > maxLines;
    const output = lines.slice(0, maxLines).join("\n");

    return {
      success: true,
      output: { content: output, totalLines: lines.length, truncated },
    };
  }

  /**
   * apply_patch — pwnkit#230. Structured DSL for reliable file edits.
   * Refuses to run without a scopePath (same gate as read_file/run_command);
   * paths are resolved through `resolveScopedPath` so patches cannot escape
   * the audit directory. The actual parsing and apply logic lives in
   * `apply-patch.ts` so it can be unit-tested without a ToolExecutor.
   */
  private applyPatch(args: Record<string, unknown>): ToolResult {
    if (!this.ctx.scopePath) {
      return {
        success: false,
        output: null,
        error: "apply_patch requires a scoped local directory and is not available for remote target scanning",
      };
    }

    const patchInput = args.patch;
    if (typeof patchInput !== "string" || patchInput.trim().length === 0) {
      return {
        success: false,
        output: null,
        error: "apply_patch: `patch` argument must be a non-empty string envelope",
      };
    }

    const scopePath = this.ctx.scopePath;
    try {
      const ops = parsePatch(patchInput);
      const result = applyPatchOps(ops, (logical) => resolveScopedPath(scopePath, logical));
      return { success: true, output: { applied: result.applied } };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  private runCommand(args: Record<string, unknown>): ToolResult {
    if (!this.ctx.scopePath) {
      return {
        success: false,
        output: null,
        error: "run_command requires a scoped local directory and is not available for remote target scanning",
      };
    }

    const command = (args.command as string).trim();
    if (containsUnquotedShellChars(command)) {
      return {
        success: false,
        output: null,
        error: `Shell operators (;, &, <, >, \`, $) are not allowed outside of quoted strings. Use pipe (|) for chaining. Permitted commands: ${[...ALLOWED_COMMANDS].join(", ")}`,
      };
    }

    // Split on pipe to support "grep foo | head -5" style commands.
    // Empty segments indicate shell operators like || or malformed pipes.
    // Quote-aware so a `|` inside a regex pattern (e.g.
    // `grep "foo\|bar" file`) doesn't get treated as a pipe break.
    const rawSegments = splitOnTopLevelPipes(command);
    if (rawSegments.some((segment) => segment.trim().length === 0)) {
      return { success: false, output: null, error: "Empty pipe segments are not allowed" };
    }

    const segments = rawSegments.map((s) => s.trim());
    if (segments.length === 0) {
      return { success: false, output: null, error: "Command cannot be empty" };
    }

    // Validate each segment
    const tokenizedSegments: string[][] = [];
    for (const segment of segments) {
      let tokens: string[];
      try {
        tokens = tokenizeCommand(segment);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { success: false, output: null, error: msg };
      }

      if (tokens.length === 0) {
        return { success: false, output: null, error: "Empty pipe segments are not allowed" };
      }

      if (!isCommandAllowed(tokens)) {
        return {
          success: false,
          output: null,
          error: `Command "${tokens[0]}" not allowed. Permitted: ${[...ALLOWED_COMMANDS].join(", ")}`,
        };
      }

      try {
        validateCommandTokens(tokens);
        validateScopedCommand(tokens, this.ctx.scopePath);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { success: false, output: null, error: msg };
      }

      tokenizedSegments.push(tokens);
    }

    const requestedCwd = args.cwd as string | undefined;
    const timeout = (args.timeout as number) ?? 30_000;
    const cwd = resolveScopedPath(this.ctx.scopePath, requestedCwd ?? ".");

    try {
      return executePipeline(tokenizedSegments, cwd, timeout);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg.slice(0, 2_000) };
    }
  }

  // ── PTY session management (feature-gated) ──

  private ensurePtyManager(): PtySessionManager {
    if (!this._ptyManager) {
      this._ptyManager = new PtySessionManager();
    }
    return this._ptyManager;
  }

  private async ptySession(args: Record<string, unknown>): Promise<ToolResult> {
    if (!featureFlags.ptySession) {
      return { success: false, output: null, error: "pty_session is disabled. Set PWNKIT_FEATURE_PTY_SESSION=1 to enable." };
    }

    const action = (args.action as string ?? "").trim();
    const sessionName = (args.session_name as string ?? "").trim();
    const input = args.input as string ?? "";
    const timeout = (args.timeout as number) ?? 5000;

    const mgr = this.ensurePtyManager();

    try {
      switch (action) {
        case "create": {
          if (!sessionName) {
            return { success: false, output: null, error: "session_name is required for create action." };
          }
          const session = mgr.createSession(sessionName, {
            env: { TARGET: this.ctx.target, ...this.buildAuthEnvVars() },
          });
          // Wait briefly for the shell prompt to appear
          const initialOutput = await mgr.read(session.id, 1000);
          return {
            success: true,
            output: `Session "${sessionName}" created (id: ${session.id}).\n${initialOutput}`,
          };
        }

        case "send": {
          if (!sessionName) {
            return { success: false, output: null, error: "session_name is required for send action." };
          }
          if (!input) {
            return { success: false, output: null, error: "input is required for send action." };
          }
          const session = mgr.findByName(sessionName);
          if (!session) {
            return { success: false, output: null, error: `No session named "${sessionName}" found.` };
          }
          // Drain any pending output first
          await mgr.read(session.id, 100);
          mgr.send(session.id, input);
          // Wait for response
          const output = await mgr.read(session.id, timeout);
          return { success: true, output: output || "(no output within timeout)" };
        }

        case "read": {
          if (!sessionName) {
            return { success: false, output: null, error: "session_name is required for read action." };
          }
          const session = mgr.findByName(sessionName);
          if (!session) {
            return { success: false, output: null, error: `No session named "${sessionName}" found.` };
          }
          const output = await mgr.read(session.id, timeout);
          return { success: true, output: output || "(no output within timeout)" };
        }

        case "close": {
          if (!sessionName) {
            return { success: false, output: null, error: "session_name is required for close action." };
          }
          const session = mgr.findByName(sessionName);
          if (!session) {
            return { success: false, output: null, error: `No session named "${sessionName}" found.` };
          }
          mgr.close(session.id);
          return { success: true, output: `Session "${sessionName}" closed.` };
        }

        case "list": {
          const sessions = mgr.listSessions();
          if (sessions.length === 0) {
            return { success: true, output: "No active sessions." };
          }
          const lines = sessions.map(
            (s) => `${s.name} (${s.id}) — ${s.alive ? "alive" : "dead"} — cwd: ${s.cwd}`
          );
          return { success: true, output: lines.join("\n") };
        }

        default:
          return { success: false, output: null, error: `Unknown pty_session action: "${action}". Use create, send, read, close, or list.` };
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  // ── Web search (anti-cheat gated) ──

  private static WEB_SEARCH_BLOCKLIST = [
    "writeup",
    "walkthrough",
    "solution",
    "ctf write",
    "how to solve",
    "flag{",
    "exploit-db",
  ];

  private async webSearch(args: Record<string, unknown>): Promise<ToolResult> {
    if (!featureFlags.webSearch) {
      return { success: false, output: null, error: "web_search is disabled. Set PWNKIT_FEATURE_WEB_SEARCH=1 to enable." };
    }

    const query = (args.query as string ?? "").trim();
    if (!query) {
      return { success: false, output: null, error: "query is required" };
    }

    // Anti-cheat: block queries that look for writeups/solutions
    const lowerQuery = query.toLowerCase();
    for (const blocked of ToolExecutor.WEB_SEARCH_BLOCKLIST) {
      if (lowerQuery.includes(blocked)) {
        return {
          success: false,
          output: null,
          error: `Blocked: search query contains disallowed term "${blocked}". Web search cannot be used to find writeups, solutions, or exploits.`,
        };
      }
    }

    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);

    try {
      // #214: rate-limit DDG search; share a bucket with any other
      // duckduckgo.com requests this scan happens to make.
      if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(url);
      const res = await fetch(url, {
        headers: { "User-Agent": "pwnkit/1.0" },
        signal: controller.signal,
      });
      if (this.ctx.rateLimiter) this.ctx.rateLimiter.noteResponse(url, res);
      clearTimeout(timer);

      if (!res.ok) {
        return { success: false, output: null, error: `Search failed with status ${res.status}` };
      }

      const html = await res.text();

      // Parse DuckDuckGo HTML results — each result lives in a <div class="result">
      const results: Array<{ title: string; url: string; snippet: string }> = [];
      const resultRe = /<a[^>]+class="result__a"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?<a[^>]+class="result__snippet"[^>]*>([\s\S]*?)<\/a>/gi;
      let m: RegExpExecArray | null;
      while ((m = resultRe.exec(html)) !== null && results.length < 5) {
        const rawUrl = m[1];
        const title = m[2].replace(/<[^>]+>/g, "").trim();
        const snippet = m[3].replace(/<[^>]+>/g, "").trim();

        // DuckDuckGo wraps URLs in a redirect — extract the actual destination
        let finalUrl = rawUrl;
        try {
          const parsed = new URL(rawUrl, "https://duckduckgo.com");
          const uddg = parsed.searchParams.get("uddg");
          if (uddg) finalUrl = decodeURIComponent(uddg);
        } catch { /* keep raw */ }

        if (title || snippet) {
          results.push({ title, url: finalUrl, snippet });
        }
      }

      if (results.length === 0) {
        return { success: true, output: { message: "No results found.", results: [] } };
      }

      const formatted = results
        .map((r, i) => `${i + 1}. ${r.title}\n   ${r.url}\n   ${r.snippet}`)
        .join("\n\n");

      return { success: true, output: { message: `Top ${results.length} results:`, formatted, results } };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: `Web search failed: ${msg}` };
    } finally {
      clearTimeout(timer);
    }
  }

  private async intelSearchAdvisories(args: Record<string, unknown>): Promise<ToolResult> {
    const ecosystem = String(args.ecosystem ?? "").trim();
    const packageName = String(args.package_name ?? args.packageName ?? "").trim();
    if (!ecosystem) return { success: false, output: null, error: "ecosystem is required" };
    if (!packageName) return { success: false, output: null, error: "package_name is required" };
    const version = typeof args.version === "string" && args.version.trim() ? args.version.trim() : undefined;
    const enrich = typeof args.enrich === "boolean" ? args.enrich : true;
    const result = await searchAdvisories({
      ecosystem,
      packageName,
      version,
      enrich,
    });
    return {
      success: true,
      output: {
        count: result.advisories.length,
        advisories: result.advisories.slice(0, 20),
        graph: {
          nodes: result.graph.nodes.slice(0, 80),
          edges: result.graph.edges.slice(0, 120),
        },
      },
    };
  }

  private async intelLookupCve(args: Record<string, unknown>): Promise<ToolResult> {
    const cveId = String(args.cve_id ?? args.cveId ?? "").trim();
    if (!cveId) return { success: false, output: null, error: "cve_id is required" };
    const intel = await lookupCve({ cveId });
    if (!intel) return { success: true, output: { cve_id: cveId.toUpperCase(), found: false } };
    return { success: true, output: { found: true, advisory: intel } };
  }

  private async intelSearchSimilar(args: Record<string, unknown>): Promise<ToolResult> {
    const cwe = typeof args.cwe === "string" && args.cwe.trim() ? args.cwe.trim() : undefined;
    const ecosystem = typeof args.ecosystem === "string" && args.ecosystem.trim() ? args.ecosystem.trim() : undefined;
    const keywords = typeof args.keywords === "string"
      ? args.keywords.split(",").map((item) => item.trim()).filter(Boolean)
      : undefined;
    const limit = typeof args.limit === "number" ? Math.min(Math.max(Math.trunc(args.limit), 1), 50) : 10;
    if (!cwe && (!keywords || keywords.length === 0)) {
      return { success: false, output: null, error: "provide cwe or keywords" };
    }
    const result = await searchSimilar({ cwe, ecosystem, keywords, limit });
    return {
      success: true,
      output: {
        count: result.advisories.length,
        advisories: result.advisories.slice(0, limit),
        graph: {
          nodes: result.graph.nodes.slice(0, 80),
          edges: result.graph.edges.slice(0, 120),
        },
      },
    };
  }

  private async intelBuildDossier(args: Record<string, unknown>): Promise<ToolResult> {
    const ecosystem = String(args.ecosystem ?? "").trim();
    const packageName = String(args.package_name ?? args.packageName ?? "").trim();
    if (!ecosystem) return { success: false, output: null, error: "ecosystem is required" };
    if (!packageName) return { success: false, output: null, error: "package_name is required" };
    const version = typeof args.version === "string" && args.version.trim() ? args.version.trim() : undefined;
    const keywords = typeof args.keywords === "string"
      ? args.keywords.split(",").map((item) => item.trim()).filter(Boolean)
      : undefined;
    const similarLimit = typeof args.similar_limit === "number"
      ? Math.min(Math.max(Math.trunc(args.similar_limit), 1), 50)
      : undefined;
    const includeSimilar = typeof args.include_similar === "boolean" ? args.include_similar : undefined;
    const dossier = await buildIntelDossier({
      ecosystem,
      packageName,
      version,
      keywords,
      similarLimit,
      includeSimilar,
    });
    return {
      success: true,
      output: {
        ...dossier,
        advisories: dossier.advisories.slice(0, 20),
        variantLeads: dossier.variantLeads.slice(0, 10),
        playbooks: dossier.playbooks.slice(0, 6).map((playbook) => ({
          ...playbook,
          steps: playbook.steps.slice(0, 5),
        })),
        graph: {
          nodes: dossier.graph.nodes.slice(0, 100),
          edges: dossier.graph.edges.slice(0, 160),
        },
      },
    };
  }

  private async intelSearchTargetHistory(args: Record<string, unknown>): Promise<ToolResult> {
    const target = typeof args.target === "string" && args.target.trim() ? args.target.trim() : undefined;
    const requestedRepoPath = typeof args.repo_path === "string" && args.repo_path.trim() ? args.repo_path.trim() : undefined;
    const repoPath = requestedRepoPath
      ? (this.ctx.scopePath ? resolveScopedPath(this.ctx.scopePath, requestedRepoPath) : requestedRepoPath)
      : this.ctx.scopePath;
    const repository = typeof args.repository === "string" && args.repository.trim() ? args.repository.trim() : undefined;
    const ecosystem = typeof args.ecosystem === "string" && args.ecosystem.trim() ? args.ecosystem.trim() : undefined;
    const packageName = String(args.package_name ?? args.packageName ?? "").trim() || undefined;
    const product = typeof args.product === "string" && args.product.trim() ? args.product.trim() : undefined;
    const vendor = typeof args.vendor === "string" && args.vendor.trim() ? args.vendor.trim() : undefined;
    const keywords = typeof args.keywords === "string"
      ? args.keywords.split(",").map((item) => item.trim()).filter(Boolean)
      : undefined;
    const limit = typeof args.limit === "number" ? Math.min(Math.max(Math.trunc(args.limit), 1), 50) : 20;
    if (!target && !repoPath && !repository && !packageName && !product && !vendor && (!keywords || keywords.length === 0)) {
      return { success: false, output: null, error: "provide target, repo_path, repository, package_name, product, vendor, keywords, or run with a scoped source path" };
    }
    const history = await searchTargetHistory({
      target,
      repoPath,
      repository,
      ecosystem,
      packageName,
      product,
      vendor,
      keywords,
      limit,
    });
    return {
      success: true,
      output: {
        ...history,
        advisories: history.advisories.slice(0, 20),
        playbooks: history.playbooks.slice(0, 6).map((playbook) => ({
          ...playbook,
          steps: playbook.steps.slice(0, 5),
        })),
        graph: {
          nodes: history.graph.nodes.slice(0, 100),
          edges: history.graph.edges.slice(0, 160),
        },
      },
    };
  }

  private updateTarget(args: Record<string, unknown>): ToolResult {
    if (args.type) this.ctx.targetInfo.type = args.type as TargetInfo["type"];
    if (args.model) this.ctx.targetInfo.model = args.model as string;
    if (args.system_prompt) this.ctx.targetInfo.systemPrompt = args.system_prompt as string;
    if (args.endpoints) {
      try {
        this.ctx.targetInfo.endpoints = JSON.parse(args.endpoints as string);
      } catch {
        /* ignore parse errors */
      }
    }
    if (args.features) {
      try {
        this.ctx.targetInfo.detectedFeatures = JSON.parse(args.features as string);
      } catch {
        /* ignore parse errors */
      }
    }

    if (this.db) {
      this.db.upsertTarget({
        url: this.ctx.target,
        type: this.ctx.targetInfo.type ?? "unknown",
        ...this.ctx.targetInfo,
      } as TargetInfo);
    }

    return { success: true, output: { message: "Target profile updated", target: this.ctx.targetInfo } };
  }

  // ── WordPress fingerprinter (feature-gated) ──

  private async wpFingerprint(args: Record<string, unknown>): Promise<ToolResult> {
    if (!featureFlags.wpFingerprint) {
      return {
        success: false,
        output: null,
        error:
          "wp_fingerprint is disabled. Enable with --features wp_fingerprint or PWNKIT_FEATURE_WP_FINGERPRINT=1.",
      };
    }

    // Same-origin enforcement: only probe the scan target.
    const base = validateTargetUrl(this.ctx.target, this.ctx.target, this.ctx.scope);

    // Build an auth-aware fetch wrapper that reuses the active identity's
    // credentials + captured session cookies (pwnkit#564).
    const authHeaders = this.activeAuthHeaders();
    const scope = this.ctx.scope;
    const rateLimiter = this.ctx.rateLimiter;
    const attribution = this.ctx.attribution;
    const wrappedFetch: FetchLike = async (url, init) => {
      // Scope check (pwnkit#215). runWpFingerprint walks the WP plugin
      // namespace by appending paths to `target`; under same-origin that
      // can't escape the host, but if the host itself is out-of-scope —
      // e.g. operator passed --scope without including the WP target —
      // we refuse here rather than fetching anyway.
      if (scope) {
        const verdict = scope.match(url);
        if (!verdict.allowed) {
          throw new Error(`wp_fingerprint scope violation: ${verdict.reason}`);
        }
      }
      const headers = {
        ...authHeaders,
        ...(init?.headers ?? {}),
      };
      // Attribution-header injection (pwnkit#216). wp_fingerprint runs
      // dozens of plugin probes in a tight loop, so attribution on
      // every probe is what tells defenders this is engagement traffic
      // rather than a botnet pulling /wp-content/plugins/* paths.
      const fetchInit = applyAttribution(
        url,
        { method: init?.method ?? "GET", headers, body: init?.body },
        attribution,
        scope,
      )!;
      // #214: each plugin/version probe goes through the per-host bucket.
      // wp_fingerprint can fan out to dozens of probes against a single
      // host — exactly the workload the limiter exists to pace.
      if (rateLimiter) await rateLimiter.acquire(url);
      const res = await fetch(url, fetchInit);
      // Post-redirect scope check (pwnkit#218 review). `fetch` follows
      // redirects by default, so an in-scope WordPress endpoint that
      // 302s to a foreign host would otherwise complete against the
      // foreign target and the body would be returned to the caller.
      // Re-validate the final `res.url` against scope and refuse if it
      // drifted off-host.
      if (scope && res.url && res.url !== url) {
        const verdict = scope.match(res.url);
        if (!verdict.allowed) {
          throw new Error(
            `wp_fingerprint refused: redirect to out-of-scope URL '${res.url}' (${verdict.reason})`,
          );
        }
      }
      if (rateLimiter) rateLimiter.noteResponse(url, res);
      return {
        ok: res.ok,
        status: res.status,
        text: () => res.text(),
        json: () => res.json(),
      };
    };

    try {
      const result = await runWpFingerprint({
        target: base,
        fetchImpl: wrappedFetch,
        maxPluginProbes: (args.max_plugin_probes as number) ?? 40,
        maxVulnerablePluginProbes: (args.max_vulnerable_plugin_probes as number) ?? 40,
        skipOsv: (args.skip_osv as boolean) ?? false,
        wpScanApiToken: (args.wpscan_api_token as string | undefined)
          ?? process.env.WPSCAN_API_TOKEN
          ?? process.env.PWNKIT_WPSCAN_API_TOKEN,
      });
      return {
        success: true,
        output: {
          summary: summarizeWpFingerprint(result),
          result,
        },
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  // ── Engagement-gated structured scanner wrappers (pwnkit#555) ──
  //
  // Shared glue for run_sqlmap / run_nmap / run_ffuf / run_nuclei. Each public
  // method validates the target against scope, acquires a rate-limit token,
  // builds a SAFE argv (delegated to the pure builders in scanner-tools.ts),
  // runs the binary under the wallclock ceiling (partial output on timeout),
  // parses stdout into a normalized result, emits a `scanner_tool_run` event,
  // and returns structured output + save_finding-ready evidence. Never raw
  // blobs back to the model.

  /**
   * Common preflight for every scanner wrapper:
   *   - hard-refuse unless ctx.allowScanners (defense-in-depth; the tool is
   *     also absent from the tool set in that case — see getToolsForRole);
   *   - scope-check the URL/host (out-of-scope → refuse);
   *   - acquire a per-host rate-limit token (best-effort; see the subprocess
   *     gap note in scanner-tools.ts).
   * Returns an error ToolResult to short-circuit, or null to proceed.
   */
  private async scannerPreflight(
    tool: string,
    scopeUrl: string,
  ): Promise<ToolResult | null> {
    if (!this.ctx.allowScanners) {
      return {
        success: false,
        output: null,
        error:
          `${tool} is disabled: generic scanners are suppressed unless the engagement was ` +
          `started with --allow-scanners (pwnkit#217). Use http_request/crawl for manual probing.`,
      };
    }
    if (this.ctx.scope) {
      const verdict = this.ctx.scope.match(scopeUrl);
      if (!verdict.allowed) {
        this.ctx.enforcement?.noteOutOfScopeBlocked();
        return {
          success: false,
          output: null,
          error: `${tool} refused: target out-of-scope '${scopeUrl}' (${verdict.reason})`,
        };
      }
    }
    if (this.ctx.rateLimiter) await this.ctx.rateLimiter.acquire(scopeUrl);
    return null;
  }

  /**
   * Run a scanner binary under the bash wallclock ceiling and parse its
   * stdout. Shapes the structured ToolResult, emits the scanner_tool_run
   * event, and projects save_finding-ready evidence. `timeoutSec` is the
   * caller-requested wallclock, clamped to the ceiling inside runScannerProcess.
   */
  private async executeScanner(
    tool: string,
    binary: string,
    argv: string[],
    parse: (raw: string) => ScannerParsedResult,
    timeoutSec: unknown,
  ): Promise<ToolResult> {
    const ceilingMs = resolveBashWallclockCeilingMs();
    const requestedMs = Math.max(1, ((timeoutSec as number) ?? 90) * 1000);
    const env = { ...sanitizedEnv(), TARGET: this.ctx.target };

    const outcome = await runScannerProcess(binary, argv, {
      timeoutMs: requestedMs,
      ceilingMs,
      env,
    });

    if (outcome.kind === "error") {
      this.persistToolArtifact("scanner_tool_run", {
        scanner: tool,
        binary,
        argv,
        error: outcome.message,
        durationMs: outcome.durationMs,
      });
      // ENOENT → the binary isn't installed on this runner. Surface a clear,
      // actionable error rather than a cryptic spawn failure.
      const hint = /ENOENT/.test(outcome.message)
        ? ` (is '${binary}' installed on the runner?)`
        : "";
      return {
        success: false,
        output: null,
        error: `${tool} failed: ${outcome.message}${hint}`,
      };
    }

    const raw =
      outcome.kind === "timeout" ? outcome.partial : outcome.combined;
    const exitCode = outcome.kind === "exit" ? outcome.exitCode : null;
    const timedOut = outcome.kind === "timeout";
    const result = parse(raw);
    const stats: ScannerRunStats = {
      binary,
      argv,
      durationMs: outcome.durationMs,
      timedOut,
      exitCode,
    };
    const suggested = suggestedFindingsFor(result, stats);

    this.persistToolArtifact("scanner_tool_run", {
      scanner: tool,
      binary,
      argv,
      exitCode,
      timedOut,
      durationMs: outcome.durationMs,
      summary: summarizeScannerResult(result),
      suggestedFindings: suggested.length,
    });

    return {
      success: true,
      output: {
        summary:
          summarizeScannerResult(result) +
          (timedOut ? " [PARTIAL — wallclock ceiling hit]" : ""),
        timed_out: timedOut,
        exit_code: exitCode,
        result,
        // save_finding-ready projections (the agent decides whether to save;
        // we never auto-save — operator gate + false-positive discipline).
        finding_evidence: suggested,
      },
    };
  }

  private async runSqlmap(args: Record<string, unknown>): Promise<ToolResult> {
    const url = String(args.url ?? "");
    if (!url) {
      return { success: false, output: null, error: "run_sqlmap requires a 'url'." };
    }
    const pre = await this.scannerPreflight("run_sqlmap", url);
    if (pre) return pre;
    const argv = buildSqlmapArgv({
      url,
      data: typeof args.data === "string" ? args.data : undefined,
      level: args.level as number | undefined,
      risk: args.risk as number | undefined,
      technique: typeof args.technique === "string" ? args.technique : undefined,
      dbms: typeof args.dbms === "string" ? args.dbms : undefined,
      enumerateDbs: args.enumerate_dbs === true,
      dump: args.dump === true,
      threads: args.threads as number | undefined,
    });
    return this.executeScanner("run_sqlmap", "sqlmap", argv, parseSqlmapOutput, args.timeout);
  }

  private async runNmap(args: Record<string, unknown>): Promise<ToolResult> {
    const target = String(args.target ?? "");
    if (!target) {
      return { success: false, output: null, error: "run_nmap requires a 'target'." };
    }
    // nmap takes a bare host; build a URL purely for the scope check.
    const scopeUrl = /^https?:\/\//i.test(target) ? target : `http://${target}`;
    const pre = await this.scannerPreflight("run_nmap", scopeUrl);
    if (pre) return pre;
    const argv = buildNmapArgv({
      target,
      ports: typeof args.ports === "string" ? args.ports : undefined,
      serviceDetection: args.service_detection === true,
      topPorts: args.top_ports as number | undefined,
      skipPing: args.skip_ping as boolean | undefined,
    });
    return this.executeScanner("run_nmap", "nmap", argv, parseNmapOutput, args.timeout);
  }

  private async runFfuf(args: Record<string, unknown>): Promise<ToolResult> {
    const url = String(args.url ?? "");
    const wordlist = String(args.wordlist ?? "");
    if (!url || !wordlist) {
      return {
        success: false,
        output: null,
        error: "run_ffuf requires 'url' (with a FUZZ keyword) and 'wordlist'.",
      };
    }
    if (!url.includes("FUZZ")) {
      return {
        success: false,
        output: null,
        error: "run_ffuf: 'url' must contain a FUZZ keyword, e.g. http://host/FUZZ.",
      };
    }
    const pre = await this.scannerPreflight("run_ffuf", url);
    if (pre) return pre;
    const argv = buildFfufArgv({
      url,
      wordlist,
      matchStatus: typeof args.match_status === "string" ? args.match_status : undefined,
      threads: args.threads as number | undefined,
    });
    return this.executeScanner("run_ffuf", "ffuf", argv, parseFfufOutput, args.timeout);
  }

  private async runNuclei(args: Record<string, unknown>): Promise<ToolResult> {
    const target = String(args.target ?? "");
    if (!target) {
      return { success: false, output: null, error: "run_nuclei requires a 'target'." };
    }
    const scopeUrl = /^https?:\/\//i.test(target) ? target : `http://${target}`;
    const pre = await this.scannerPreflight("run_nuclei", scopeUrl);
    if (pre) return pre;
    const argv = buildNucleiArgv({
      target,
      severity: typeof args.severity === "string" ? args.severity : undefined,
      tags: typeof args.tags === "string" ? args.tags : undefined,
    });
    return this.executeScanner("run_nuclei", "nuclei", argv, parseNucleiOutput, args.timeout);
  }

  private payloadLookup(args: Record<string, unknown>): ToolResult {
    const name = String(args.name ?? "");
    if (name === "jsfuck_alert") {
      return {
        success: true,
        output: {
          name,
          payload: JSFUCK_ALERT_PAYLOAD,
          description: "JSFuck-encoded alert(1) using only []()!+",
          emits: "1",
          bestFor: "Generic JavaScript execution proof when any alert is sufficient",
          avoidWhen: "The target checks for an exact required dialog/output string such as XSS",
        },
      };
    }
    if (name === "jsfuck_xss") {
      return {
        success: true,
        output: {
          name,
          payload: JSFUCK_XSS_PAYLOAD,
          description: "JSFuck-encoded alert('XSS') using only []()!+",
          emits: "XSS",
          bestFor: "Exact-output validators that require the dialog or script result to equal XSS",
          avoidWhen: "Only generic JS execution proof is needed and payload length matters more than exact output",
        },
      };
    }
    return {
      success: false,
      output: null,
      error: `Unknown payload: ${name}. Valid: jsfuck_alert, jsfuck_xss`,
    };
  }

  // ── MongoDB ObjectID forge (feature-gated, default ON) ──

  private mongoObjectIdForge(args: Record<string, unknown>): ToolResult {
    if (!featureFlags.mongoObjectIdForge) {
      return {
        success: false,
        output: null,
        error:
          "mongo_objectid is disabled. Enable with --features mongo_objectid_forge or PWNKIT_FEATURE_MONGO_OBJECTID_FORGE=1.",
      };
    }

    try {
      const timestamp = args.timestamp as number;
      const machineId = args.machineId as string;
      const counter = (args.counter as number) ?? 0;
      const count = (args.count as number | undefined) ?? 1;

      if (count <= 1) {
        const oid = forgeObjectId({ timestamp, machineId, counter });
        const parsed = parseObjectId(oid);
        return {
          success: true,
          output: {
            objectId: oid,
            components: parsed,
            hint: "Paste this 24-char hex string in place of any ObjectId in the target's URL/body to test IDOR. For the 'first user', try counter=0, then 1, 2, ...",
          },
        };
      }

      const sequence = forgeObjectIdSequence({
        timestamp,
        machineId,
        counterStart: counter,
        count,
      });
      return {
        success: true,
        output: {
          objectIds: sequence,
          count: sequence.length,
          counterStart: counter,
          counterEnd: counter + sequence.length - 1,
          hint: `Forged ${sequence.length} consecutive ObjectIds (counters ${counter}..${counter + sequence.length - 1}). Try them in order to enumerate IDOR victims.`,
        },
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: null, error: msg };
    }
  }

  // ── JIT Skill tools (#457) ──

  private listSkills(args: Record<string, unknown>): ToolResult {
    if (!featureFlags.jitSkills) {
      return { success: false, output: null, error: "JIT skills are not enabled." };
    }
    const tag = typeof args.tag === "string" ? args.tag : undefined;
    const summaries = listSkillSummaries({ tag, role: this.ctx.role });

    // Compute suggested flags from recent tool output context
    const registry = loadSkillRegistry();
    const allSkills = [...registry.values()];
    const suggestedIds = matchTriggers(
      this.ctx.recentToolResultTexts ?? [],
      allSkills,
    );

    const enriched = summaries.map((s) => ({
      ...s,
      suggested: suggestedIds.has(s.id),
    }));

    const total = enriched.length;
    const suggested_count = enriched.filter((s) => s.suggested).length;

    // Bus event: skill_listed — tracks JIT skill browse patterns for A/B
    // testing (#458).
    eventBus.emit("skill_listed", {
      total,
      suggested_count,
      tag,
      role: this.ctx.role,
    });

    return {
      success: true,
      output: {
        skills: enriched,
        total,
        suggested_count,
      },
    };
  }

  private loadSkill(args: Record<string, unknown>): ToolResult {
    if (!featureFlags.jitSkills) {
      return { success: false, output: null, error: "JIT skills are not enabled." };
    }
    const skillId = args.skill_id as string;
    if (!skillId) {
      return { success: false, output: null, error: "skill_id is required" };
    }

    // Check for double-load
    if (this.ctx.loadedSkills?.has(skillId)) {
      return {
        success: true,
        output: { kind: "already_loaded", skill_id: skillId, message: "Skill already loaded" },
      };
    }

    const skill = getSkillById(skillId);
    if (!skill) {
      return {
        success: false,
        output: null,
        error: `Unknown skill ID: "${skillId}". Use list_skills to see available skills.`,
      };
    }

    // Enforce role applicability
    if (!skill.applicable_roles.includes(this.ctx.role as any)) {
      return {
        success: false,
        output: null,
        error: `Skill "${skillId}" is not applicable to the "${this.ctx.role}" role.`,
      };
    }

    // Track the loaded skill
    if (!this.ctx.loadedSkills) {
      this.ctx.loadedSkills = new Set();
    }
    this.ctx.loadedSkills.add(skillId);

    // Bus event: skill_loaded — tracks JIT skill usage for A/B testing (#458).
    eventBus.emit("skill_loaded", {
      skill_id: skill.id,
      name: skill.name,
      estimated_tokens: skill.estimated_tokens,
      role: this.ctx.role,
    });

    return {
      success: true,
      output: {
        kind: "skill_loaded",
        skill_id: skill.id,
        name: skill.name,
        estimated_tokens: skill.estimated_tokens,
        content: skill.content,
      },
    };
  }

  private markDone(args: Record<string, unknown>): ToolResult {
    const summary = (args.summary as string) ?? "Task completed";

    // ── Coverage gate (#audit-laziness) ──
    // For audit / review sub-agents auditing a local source tree, refuse a
    // `done` call when the agent has not actually inspected source. The
    // gate is scoped to (role ∈ {audit,review}) AND a non-empty scopePath
    // — that's the package-audit / source-review shape from the
    // @vercel/og bug. Audit-role flag-hunting (no scopePath) is skipped
    // because there's no local source to read; the agent is talking to a
    // remote target. See `evaluateDoneCoverageGate` for the policy and
    // `PWNKIT_AUDIT_MIN_COVERAGE_FILES` / `PWNKIT_AUDIT_DONE_GATE` for
    // operator overrides.
    const isSourceAudit =
      (this.ctx.role === "audit" || this.ctx.role === "review")
      && typeof this.ctx.scopePath === "string"
      && this.ctx.scopePath.length > 0;
    if (isSourceAudit) {
      const decision = evaluateDoneCoverageGate({
        sourceFilesRead: this._sourceFilesRead.size,
        runCommandCount: this._runCommandCount,
        totalToolCalls: this._totalNonDoneToolCalls,
        elapsedMs: Date.now() - this._startedAt,
        priorRejections: this._doneRejections,
      });
      if (!decision.pass) {
        this._doneRejections += 1;
        return {
          success: false,
          output: null,
          error: decision.reason ?? "done rejected: insufficient audit coverage",
        };
      }
    }

    // ── Anti-honeypot heuristic (GitHub #82) ──
    // Scan the summary for a FLAG{...} token; if one is present and the
    // decoyDetection feature is enabled, validate its shape. Low-confidence
    // flags (looks like a decoy: sentence content, "DECOY"/"FAKE" markers,
    // too short, too long) are rejected once with a hint. A second call with
    // the same flag passes through.
    if (featureFlags.decoyDetection) {
      const flagMatch = summary.match(/FLAG\{[^}]*\}/i);
      if (flagMatch) {
        const proposedFlag = flagMatch[0];
        const validation = validateFlagShape(proposedFlag);
        if (!validation.ok && !this._rejectedDecoyFlags.has(proposedFlag)) {
          this._rejectedDecoyFlags.add(proposedFlag);
          return {
            success: false,
            output: null,
            error:
              `The flag \`${proposedFlag}\` has low shape confidence ` +
              `(${validation.confidence.toFixed(2)}) — looks like a decoy. ` +
              `${validation.reason} ` +
              `Continue exploring for at least one more layer; defenders sometimes plant ` +
              `fake flags in obvious locations (e.g. the first file a naive LFI exploit ` +
              `lands on). Verify the shape matches the suite's expected format (typically ` +
              `hex/uuid). If you genuinely cannot find another candidate, retry \`done\` ` +
              `with the same flag and it will be accepted.`,
          };
        }
      }
    }

    return {
      success: true,
      output: { done: true, summary },
    };
  }
}

// ── Helper: get tools for a specific agent role ──

export function getToolsForRole(role: string, opts?: { hasScope?: boolean; webMode?: boolean; hasBrowser?: boolean; allowScanners?: boolean }): ToolDefinition[] {
  const common = ["query_findings", "done"];
  const browserTools = opts?.hasBrowser ? ["browser"] : [];
  const webSearchTools = featureFlags.webSearch ? ["web_search"] : [];
  const ptyTools = featureFlags.ptySession ? ["pty_session"] : [];
  const payloadTools = ["payload_lookup"];
  const wpTools = featureFlags.wpFingerprint ? ["wp_fingerprint"] : [];
  const mongoTools = featureFlags.mongoObjectIdForge ? ["mongo_objectid"] : [];
  const skillTools = featureFlags.jitSkills ? ["list_skills", "load_skill"] : [];
  // pwnkit#567 — loot retrieval tool, only when the ledger feature is on.
  const lootTools = featureFlags.lootLedger ? ["use_loot"] : [];
  // pwnkit#555: scanner wrappers only when the engagement explicitly permits
  // generic-scanner traffic. Default-off preserves pwnkit#217 stealth.
  const scannerTools = opts?.allowScanners ? [...SCANNER_TOOL_NAMES] : [];
  const networkTools = [
    "http_request",
    "crawl",
    "submit_form",
    "access_control_probe",
    "bash",
    ...browserTools,
    ...webSearchTools,
    ...ptyTools,
    ...payloadTools,
    ...wpTools,
    ...mongoTools,
    ...skillTools,
    ...lootTools,
    ...scannerTools,
    "send_prompt",
    "save_finding",
    "update_finding",
    "update_target",
    ...common,
  ];
  const fileTools = ["read_file", "apply_patch", "run_command"];
  const allEnabledTools = Object.keys(TOOL_DEFINITIONS).filter((name) =>
    (featureFlags.jitSkills || (name !== "list_skills" && name !== "load_skill"))
    // Keep use_loot out of the audit/review "everything" set when the loot
    // ledger feature is off (parity with the JIT-skill gating above).
    && (featureFlags.lootLedger || name !== "use_loot")
    // Scanner wrappers stay out of the audit/review "everything" set too,
    // unless the engagement opted in. Without this they'd leak into
    // allEnabledTools regardless of allowScanners (regression of pwnkit#217).
    && (opts?.allowScanners || !SCANNER_TOOL_NAMES.includes(name)),
  );

  const roleTools: Record<string, string[]> = {
    discovery: networkTools,
    attack: networkTools,
    // Verify agent gets file tools when there's a local scope (audit/review mode)
    verify: opts?.hasScope ? [...networkTools, ...fileTools] : networkTools,
    report: [...common],
    audit: allEnabledTools,
    review: allEnabledTools,
  };

  const toolNames = roleTools[role] ?? allEnabledTools;
  return toolNames
    .map((name) => TOOL_DEFINITIONS[name])
    .filter((t): t is ToolDefinition => t !== undefined);
}
