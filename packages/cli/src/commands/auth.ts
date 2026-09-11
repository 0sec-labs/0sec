// `0sec auth` — 0sec-cloud authentication (CLI half of #303).
//
// Subcommands:
//   - login        opens a browser at <host>/cli-auth?session=… and polls
//                  for the mint endpoint to drop a scoped token in
//   - logout       deletes ~/.0sec/cloud.env
//   - status       loads creds, hits CloudClient.pingHealth(), reports
//
// The browser flow is backed by the 0cloud session-mint endpoint:
//   - `0sec auth login` opens `<host>/cli-auth?session=…` and polls the
//     session URL until browser confirmation makes a scoped token ready.
//   - `0sec auth login --token <value>` remains a manual credential path for
//     self-hosted or recovery use.
//   - `0sec auth status` works against any reachable cloud host that answers
//     GET /health with a 2xx and `{status: "ok"}`-shaped body.
//
// DIVERGENCE FROM h1.ts
// ──────────────────────
// H1 uses Basic auth with a username + token operators manually generate
// on the H1 site, so there's no `login` flow there at all — the loader
// just reads what the operator put in h1.env. Cloud uses Bearer auth
// with a scoped token minted by the server after a browser-based
// better-auth flow, so `0sec auth login` is the one extra surface.
//
// SECURITY: the token is never printed. `0sec auth status` echoes the
// host on success; on auth failure we surface the status code + path,
// never the token or the Authorization header.

import { spawn } from "node:child_process";
import { homeStateDir } from "@0sec/shared";
import { mkdirSync, writeFileSync, chmodSync, unlinkSync, existsSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import type { Command } from "commander";
import chalk from "chalk";
import { consolePresentationOutput } from "../presentation/process-output.js";
import {
  loadCloudCredentials,
  CloudAuthMissingError,
  CloudClient,
  CloudUnauthorizedError,
  CloudForbiddenError,
  CloudNetworkError,
  CloudError,
  DEFAULT_CLOUD_HOST,
} from "@0sec/core";

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;
const EXIT_AUTH = 2;
const EXIT_NET = 3;

// ── reusable flow for TUI, desktop daemon, and CLI ──

/**
 * Structured result from the hosted browser login flow. Callers use this to
 * decide next UI state rather than sniffing process exit codes or stdout.
 */
export type LoginResult =
  | { ok: true; host: string }
  | { ok: false; error: string; recoverable?: boolean; cancelled?: boolean };

/**
 * Options for `hostedBrowserLoginFlow`. Every seam is injectable so callers
 * in tests or non-CLI environments (TUI, desktop) never depend on real IO.
 * The `onStatus` callback fires for progress display; `signal` drives cancel.
 */
export interface HostedBrowserLoginOptions {
  host?: string;
  /** Override the poll-attempt budget. Default 150 (~5min @ 2s). */
  pollAttempts?: number;
  /** Override the poll interval in ms. Default 2000. */
  pollIntervalMs?: number;
  /** Test seam: skip the actual browser launch. */
  openBrowser?: (url: string) => void | Promise<void>;
  /** Test seam: override fetch impl for poll loop. */
  fetchImpl?: typeof fetch;
  /** Test seam: override home directory for credential file. */
  homeDir?: string;
  /** Test seam: override sleep so tests don't actually wait. */
  sleep?: (ms: number) => Promise<void>;
  /** AbortSignal for cancellation from the caller (Escape, unmount). */
  signal?: AbortSignal;
  /** Progress callback for UI display during the flow. Uses a bounded phase union. */
  onStatus?: (phase: HostedLoginPhase, message: string, loginUrl?: string) => void;
}

export interface LoginOptions {
  host?: string;
  token?: string;
  /** Override the poll-attempt budget (tests). Default 150 (~5min @ 2s). */
  pollAttempts?: number;
  /** Override the poll interval in ms (tests). Default 2000. */
  pollIntervalMs?: number;
  /** Test seam: skip the actual browser launch. */
  openBrowser?: (url: string) => void | Promise<void>;
  /** Test seam: override fetch impl for poll loop. */
  fetchImpl?: typeof fetch;
  /** Test seam: override home directory for credential file. */
  homeDir?: string;
  /** Test seam: override sleep so tests don't actually wait. */
  sleep?: (ms: number) => Promise<void>;
}

interface LogoutOptions {
  homeDir?: string;
}

interface StatusOptions {
  /** Test seam: override fetch impl. */
  fetchImpl?: typeof fetch;
}

export function registerAuthCommand(program: Command): void {
  const auth = program
    .command("auth")
    .description("0sec-cloud authentication")

  // ── 0sec auth login ──
  auth
    .command("login")
    .description("Log in to 0sec-cloud (opens browser; --token to paste directly)")
    .option("--host <url>", `Cloud host (default ${DEFAULT_CLOUD_HOST})`)
    .option("--token <value>", "Skip the browser flow and persist this token directly")
    .action(async (opts: { host?: string; token?: string }) => {
      await runLogin(opts);
    });

  // ── 0sec auth logout ──
  auth
    .command("logout")
    .description("Delete ~/.0sec/cloud.env")
    .action(() => {
      runLogout({});
    });

  // ── 0sec auth status ──
  auth
    .command("status")
    .description("Verify 0sec-cloud credentials against /health")
    .action(async () => {
      await runStatus({});
    });
}

// ── implementations ──
// Exported for the unit tests so we can drive the action without
// constructing a full Commander program.

/**
 * Bounded lifecycle phases emitted by `hostedBrowserLoginFlow` for display.
 * Every value is stable — callers MUST NOT test for arbitrary strings.
 */
export type HostedLoginPhase = "opening" | "opener-failed" | "polling" | "cancelled" | "ready" | "timeout";

/** Browser sign-in with caller-owned cancellation and daemon-side persistence.
 * Returned status contains no credentials and does not imply inference availability.
 */
export async function hostedBrowserLoginFlow(opts: HostedBrowserLoginOptions = {}): Promise<LoginResult> {
  const host = normaliseHostArg(opts.host ?? DEFAULT_CLOUD_HOST);
  if (host === null) {
    return { ok: false, error: "Cloud host must be an http(s) URL without credentials, query or fragment." };
  }
  const attempts = opts.pollAttempts ?? 150;
  const intervalMs = opts.pollIntervalMs ?? 2000;
  if (!Number.isSafeInteger(attempts) || attempts <= 0 || !Number.isFinite(intervalMs) || intervalMs < 0) {
    return { ok: false, error: "Invalid sign-in polling budget." };
  }
  const cancelled = (): LoginResult => {
    opts.onStatus?.("cancelled", "Sign-in cancelled.");
    return { ok: false, error: "Sign-in cancelled.", recoverable: true, cancelled: true };
  };
  if (opts.signal?.aborted) return cancelled();
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), 300_000);
  const signal = opts.signal ? AbortSignal.any([opts.signal, deadline.signal]) : deadline.signal;
  const session = randomBytes(9).toString("base64url").slice(0, 12);
  const loginUrl = `${host}/cli-auth?session=${session}`;
  const pollUrl = `${host}/cli-auth/sessions/${session}`;
  const timedOut = (): LoginResult => {
    opts.onStatus?.("timeout", "Sign-in timed out. Try again.");
    return { ok: false, error: "Sign-in timed out. Try again.", recoverable: true };
  };
  try {
    opts.onStatus?.("opening", "Opening browser for 0sec Cloud sign-in.", loginUrl);
    signal.throwIfAborted();
    try {
      await awaitLoginStep(Promise.resolve().then(() => {
        signal.throwIfAborted();
        return (opts.openBrowser ?? defaultOpenBrowser)(loginUrl);
      }), signal);
    } catch {
      signal.throwIfAborted();
      opts.onStatus?.("opener-failed", "Could not open a browser. Open this sign-in URL manually.", loginUrl);
    }
    const fetcher = opts.fetchImpl ?? fetch;
    for (let i = 0; i < attempts; i++) {
      signal.throwIfAborted();
      opts.onStatus?.("polling", "Waiting for browser sign-in.", loginUrl);
      signal.throwIfAborted();
      await awaitLoginStep(
        opts.sleep ? opts.sleep(intervalMs) : delay(intervalMs, undefined, { signal }),
        signal,
      );
      signal.throwIfAborted();
      const request = new AbortController();
      const requestTimer = setTimeout(() => request.abort(), 10_000);
      const requestSignal = AbortSignal.any([signal, request.signal]);
      try {
        let res: Response;
        try {
          res = await awaitLoginStep(fetcher(pollUrl, {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: requestSignal,
            redirect: "error",
          }), requestSignal);
        } catch {
          signal.throwIfAborted();
          continue;
        }
        signal.throwIfAborted();
        if (res.status === 200) {
          let body: unknown;
          try {
            body = await awaitLoginStep(res.json(), requestSignal);
          } catch {
            signal.throwIfAborted();
            if (requestSignal.aborted) continue;
            return { ok: false, error: "Login response was not valid JSON." };
          }
          signal.throwIfAborted();
          const rawStatus = body && typeof body === "object" ? (body as Record<string, unknown>).status : undefined;
          const status = sessionStatus(body);
          const token = extractToken(body);
          if (token) {
            if (rawStatus !== undefined && status !== "ready") {
              return { ok: false, error: "Login returned credentials before the session was ready." };
            }
            try {
              persistCredentials(host, token, opts.homeDir);
            } catch {
              return { ok: false, error: "Could not save 0sec Cloud credentials." };
            }
            opts.onStatus?.("ready", "Signed in to 0sec Cloud.");
            return { ok: true, host };
          }
          if (status === "pending") continue;
          if (status === "expired") return { ok: false, error: "Sign-in request expired. Try again.", recoverable: true };
          return { ok: false, error: "Login response did not contain valid credentials." };
        }
        if ([202, 204, 404].includes(res.status)) continue;
        if (res.status === 410) return { ok: false, error: "Sign-in request expired. Try again.", recoverable: true };
        return {
          ok: false,
          error: `0sec Cloud sign-in unavailable (HTTP ${res.status}). Use your own provider or try again later.`,
          recoverable: res.status === 429 || res.status >= 500,
        };
      } finally {
        clearTimeout(requestTimer);
        request.abort();
      }
    }
    return timedOut();
  } catch (error) {
    if (opts.signal?.aborted) return cancelled();
    if (deadline.signal.aborted) return timedOut();
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

/** Cancel even when an injected operation ignores its signal; remove listeners on settlement. */
async function awaitLoginStep<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      signal.removeEventListener("abort", onAbort);
      reject(signal.reason);
    };
    operation.then(
      (value) => { signal.removeEventListener("abort", onAbort); resolve(value); },
      (error) => { signal.removeEventListener("abort", onAbort); reject(error); },
    );
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
}

/** CLI command wrapper: calls hostedBrowserLoginFlow and prints results. */
export async function runLogin(opts: LoginOptions): Promise<void> {
  const host = normaliseHostArg(opts.host ?? DEFAULT_CLOUD_HOST);
  if (host === null) {
    consolePresentationOutput.stderr(chalk.red("Error: Cloud host must be an http(s) URL without credentials, query or fragment."), "auth.login.host-error");
    process.exitCode = EXIT_USER_ERROR;
    return;
  }

  // Direct token path: persist immediately, skip the browser dance.
  if (opts.token !== undefined) {
    const tok = opts.token.trim();
    if (!validCloudToken(tok)) {
      consolePresentationOutput.stderr(chalk.red("Error: --token must be a nonempty credential without whitespace."), "auth.login.token-empty");
      process.exitCode = EXIT_USER_ERROR;
      return;
    }
    try {
      persistCredentials(host, tok, opts.homeDir);
    } catch {
      consolePresentationOutput.stderr(chalk.red("Could not save 0sec Cloud credentials."), "auth.login.save-error");
      process.exitCode = EXIT_USER_ERROR;
      return;
    }
    consolePresentationOutput.stdout(`Logged in (host=${host})`, "auth.login.logged-in");
    process.exitCode = EXIT_OK;
    return;
  }

  // Browser flow via the reusable helper.
  const result = await hostedBrowserLoginFlow({
    host,
    pollAttempts: opts.pollAttempts,
    pollIntervalMs: opts.pollIntervalMs,
    openBrowser: opts.openBrowser,
    fetchImpl: opts.fetchImpl,
    homeDir: opts.homeDir,
    sleep: opts.sleep,
    onStatus: (phase, msg, url) => {
      if (phase === "opening") {
        consolePresentationOutput.stdout(chalk.dim("Opening browser..."), "auth.login.opening");
        if (url) consolePresentationOutput.stdout(chalk.dim(`  ${url}`), "auth.login.url");
        consolePresentationOutput.stdout("", "auth.login.empty-line");
        consolePresentationOutput.stdout(chalk.dim("Complete sign-in in the opened browser, then return here."), "auth.login.browser-hint");
        consolePresentationOutput.stdout("", "auth.login.empty-line");
      }
      if (phase === "opener-failed") {
        consolePresentationOutput.stderr(chalk.yellow(msg), "auth.login.browser-error");
      }
    },
  });

  if (result.ok) {
    consolePresentationOutput.stdout(`Logged in (host=${result.host})`, "auth.login.logged-in");
    process.exitCode = EXIT_OK;
  } else {
    consolePresentationOutput.stderr(chalk.red(result.error), "auth.login.error");
    process.exitCode = result.recoverable ? EXIT_NET : EXIT_USER_ERROR;
  }
}

export function runLogout(opts: LogoutOptions): void {
  const home = opts.homeDir ?? homedir();
  const osecPath = join(homeStateDir(opts.homeDir), "cloud.env");
  const cloudCredsPath = join(home, ".0cloud", "credentials.json");
  let deletedAny = false;

  // Delete 0sec credential file
  try {
    unlinkSync(osecPath);
    deletedAny = true;
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code !== "ENOENT") {
      consolePresentationOutput.stderr(chalk.red(`Could not delete ${osecPath}: ${err instanceof Error ? err.message : String(err)}`), "auth.logout.delete-error");
      process.exitCode = EXIT_USER_ERROR;
      return;
    }
  }

  // Also clean up 0cloud-compatible credential file
  try {
    unlinkSync(cloudCredsPath);
    deletedAny = true;
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code !== "ENOENT") {
      consolePresentationOutput.stderr(chalk.red(`Could not delete ${cloudCredsPath}: ${err instanceof Error ? err.message : String(err)}`), "auth.logout.delete-error");
      process.exitCode = EXIT_USER_ERROR;
      return;
    }
  }

  if (deletedAny) {
    consolePresentationOutput.stdout("Logged out", "auth.logout.deleted");
  } else {
    consolePresentationOutput.stdout("Logged out (no credentials file was present)", "auth.logout.not-found");
  }
  process.exitCode = EXIT_OK;
}

export async function runStatus(opts: StatusOptions): Promise<void> {
  let creds: { host: string; token: string };
  try {
    const c = loadCloudCredentials();
    creds = { host: c.host, token: c.token };
  } catch (err) {
    if (err instanceof CloudAuthMissingError) {
      consolePresentationOutput.stderr(chalk.red(err.message), "auth.status.auth-missing");
      process.exitCode = EXIT_AUTH;
      return;
    }
    consolePresentationOutput.stderr(chalk.red(err instanceof Error ? err.message : String(err)), "auth.status.load-error");
    process.exitCode = EXIT_AUTH;
    return;
  }

  const client = new CloudClient({ ...creds, fetchImpl: opts.fetchImpl });
  try {
    await client.pingHealth();
    consolePresentationOutput.stdout(`OK (host=${creds.host})`, "auth.status.ok");
    process.exitCode = EXIT_OK;
  } catch (err) {
    handleStatusError(err);
  }
}

function handleStatusError(err: unknown): void {
  if (err instanceof CloudUnauthorizedError) {
    consolePresentationOutput.stderr("FAIL (HTTP 401)", "auth.status.unauthorized");
    process.exitCode = EXIT_AUTH;
    return;
  }
  if (err instanceof CloudForbiddenError) {
    consolePresentationOutput.stderr(chalk.red(`FAIL (HTTP 403) — status: ${err.message}`), "auth.status.forbidden");
    process.exitCode = EXIT_AUTH;
    return;
  }
  if (err instanceof CloudNetworkError) {
    consolePresentationOutput.stderr(chalk.red(`FAIL (network) — status: ${err.message}`), "auth.status.network-error");
    process.exitCode = EXIT_NET;
    return;
  }
  if (err instanceof CloudError) {
    consolePresentationOutput.stderr(chalk.red(`FAIL (HTTP ${err.status ?? "?"}) — status`), "auth.status.cloud-error");
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  consolePresentationOutput.stderr(chalk.red(`FAIL — status: ${err instanceof Error ? err.message : String(err)}`), "auth.status.error");
  process.exitCode = EXIT_USER_ERROR;
}

// ── helpers ──

function normaliseHostArg(host: string | undefined): string | null {
  if (!host?.trim()) return null;
  try {
    const url = new URL(host.trim());
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) return null;
    return url.href.replace(/\/+$/, "");
  } catch {
    return null;
  }
}

function persistCredentials(host: string, token: string, homeDirOverride?: string): void {
  if (!validCloudToken(token)) throw new Error("Invalid Cloud credential");
  const home = homeDirOverride ?? homedir();
  const dir = homeStateDir(homeDirOverride);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, "cloud.env");
  const body =
    `# 0sec-cloud credentials. Managed by \`0sec auth\`.\n` +
    `# DO NOT commit this file or share its contents.\n` +
    `0SEC_CLOUD_HOST=${host}\n` +
    `0SEC_CLOUD_TOKEN=${token}\n`;
  writeFileSync(path, body, { mode: 0o600 });
  // writeFileSync's `mode` is honoured on create but POSIX semantics
  // mean an existing file keeps its old perms — so re-chmod explicitly.
  chmodSync(path, 0o600);
  // Defensive: warn if the file ended up world/group-readable anyway
  // (e.g. on Docker volumes that mask mode bits). We don't refuse to
  // continue — same trade-off as the H1 loader.
  if (!existsSync(path)) {
    // Should be impossible; we just wrote it.
    return;
  }

  // Write 0cloud-compatible credential file for unified auth.
  // Best-effort: don't fail the 0sec login if this secondary write fails.
  try {
    const cloudDir = join(home, ".0cloud");
    mkdirSync(cloudDir, { recursive: true });
    const cloudCredsPath = join(cloudDir, "credentials.json");
    // 0sec only knows the dashboard host (cloud.0sec.ai); the 0cloud
    // orchestrator API lives under /api on it. `api.0sec.ai` has no DNS
    // (#508), so derive the API base as `${host}/api` for 0cloud's
    // endpoint. orgId stays empty — 0cloud resolves org from its own
    // config / --org.
    const trimmedHost = host.replace(/\/+$/, "");
    const apiEndpoint = trimmedHost.endsWith("/api")
      ? trimmedHost
      : `${trimmedHost}/api`;
    const cloudCreds = JSON.stringify(
      {
        token,
        orgId: "",
        endpoint: apiEndpoint,
        dashboardUrl: host,
        createdAt: new Date().toISOString(),
      },
      null,
      2,
    ) + "\n";
    writeFileSync(cloudCredsPath, cloudCreds, { mode: 0o600 });
    chmodSync(cloudCredsPath, 0o600);
  } catch {
    // Silently ignore — the primary 0sec credential write succeeded.
  }
}

type CliAuthPollStatus = "pending" | "ready" | "expired";

function sessionStatus(body: unknown): CliAuthPollStatus | undefined {
  if (!body || typeof body !== "object") return undefined;
  const status = (body as Record<string, unknown>).status;
  return status === "pending" || status === "ready" || status === "expired"
    ? status
    : undefined;
}

function validCloudToken(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && !/[\s\x00-\x1f\x7f]/.test(value.trim());
}

/**
 * Extract a token from a `/cli-auth/sessions/<id>` response body. Keep the
 * legacy `access_token` spelling for compatible self-hosted receivers.
 */
function extractToken(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const obj = body as Record<string, unknown>;
  const candidates = [obj.token, obj.access_token];
  for (const c of candidates) {
    if (validCloudToken(c)) return c.trim();
  }
  return null;
}

/**
 * Open a URL in the user's default browser without adding a runtime
 * dependency. We use platform-detected child_process.spawn:
 *   - darwin → `open <url>`
 *   - win32  → fixed PowerShell script; URL passed as environment data
 *   - other  → `xdg-open <url>` (Linux + most BSDs)
 *
 * The spawned process is detached + unref'd so we don't keep the CLI
 * alive past the poll loop on exit.
 *
 * JUDGMENT CALL: we avoided the `opener` package even though it's ~30
 * LoC because (a) MIT, (b) zero transitive deps, and (c) we already
 * have a working no-dep implementation in `0sec doctor`-style code
 * elsewhere. Adding a dep for a 12-line function loses on the
 * dependency-cost calculus.
 */
function defaultOpenBrowser(url: string): Promise<void> {
  const plat = platform();
  return new Promise<void>((resolve, reject) => {
    const options = { detached: true, stdio: "ignore" as const, shell: false };
    // cmd /c start interprets URL metacharacters even though spawn uses no shell.
    // Never interpolate the URL into PowerShell source or its command arguments.
    const child = plat === "darwin"
      ? spawn("open", [url], options)
      : plat === "win32"
        ? spawn("powershell.exe", [
          "-NoProfile", "-NonInteractive", "-Command",
          "Start-Process -FilePath $env:OSEC_BROWSER_LOGIN_URL",
        ], { ...options, env: { ...process.env, OSEC_BROWSER_LOGIN_URL: url } })
        : spawn("xdg-open", [url], options);
    child.once("error", reject);
    child.once("spawn", () => { child.unref(); resolve(); });
  });
}
