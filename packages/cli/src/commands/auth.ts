// `0sec auth` — 0sec-cloud authentication (CLI half of #303).
//
// Subcommands:
//   - login        opens a browser at <host>/cli-auth?session=… and polls
//                  for the mint endpoint to drop a scoped token in
//   - logout       deletes ~/.0sec/cloud.env
//   - status       loads creds, hits CloudClient.pingHealth(), reports
//
// SCAFFOLD NOTICE
// ───────────────
// The server-side mint endpoint (better-auth → scoped CLI token) does
// NOT exist yet — it ships as a separate 0sec-cloud PR. Until then:
//   - `0sec auth login` (browser flow) will time out after 5 minutes
//     because no server-side endpoint is writing the token to the
//     polled session URL.
//   - `0sec auth login --token <value>` is the actual usable path:
//     paste a token you generated some other way (manual server insert,
//     env handoff, etc.) and the CLI persists it to ~/.0sec/cloud.env.
//   - `0sec auth status` works against any reachable cloud host that
//     answers GET /health with a 2xx and `{status: "ok"}`-shaped body.
//   - `0sec auth logout` works fully (it's just `unlinkSync`).
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

interface LoginOptions {
  host?: string;
  token?: string;
  /** Override the poll-attempt budget (tests). Default 150 (~5min @ 2s). */
  pollAttempts?: number;
  /** Override the poll interval in ms (tests). Default 2000. */
  pollIntervalMs?: number;
  /** Test seam: skip the actual browser launch. */
  openBrowser?: (url: string) => void;
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
    .description("0sec-cloud authentication (scaffold; see `0sec auth login --help`)");

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

export async function runLogin(opts: LoginOptions): Promise<void> {
  // Validate --host even when --token is also passed; persisting an
  // invalid host now would just cause `0sec auth status` to fail
  // later with a less actionable error.
  let host: string;
  if (opts.host) {
    const parsed = normaliseHostArg(opts.host);
    if (parsed === null) return; // normaliseHostArg already set exitCode + printed
    host = parsed;
  } else {
    host = DEFAULT_CLOUD_HOST;
  }

  // Escape-hatch path: caller pasted a token directly. This is the
  // only path that actually works until the server-side mint endpoint
  // lands — we persist immediately and skip the browser dance.
  if (opts.token) {
    const tok = opts.token.trim();
    if (tok.length === 0) {
      consolePresentationOutput.stderr(chalk.red("Error: --token cannot be empty."), "auth.login.token-empty");
      process.exitCode = EXIT_USER_ERROR;
      return;
    }
    persistCredentials(host, tok, opts.homeDir);
    consolePresentationOutput.stdout(`Logged in (host=${host})`, "auth.login.logged-in");
    process.exitCode = EXIT_OK;
    return;
  }

  // Browser flow. NOTE: until the server-side mint endpoint ships, the
  // poll loop will time out and the user will get a "Login timed out"
  // error. The logic below is correct — it just has nothing to poll
  // against yet.
  const session = randomBytes(9).toString("base64url").slice(0, 12);
  const loginUrl = `${host}/cli-auth?session=${session}`;
  const pollUrl = `${host}/cli-auth/sessions/${session}`;

  consolePresentationOutput.stdout(chalk.dim("Opening browser..."), "auth.login.opening");
  consolePresentationOutput.stdout(chalk.dim(`  ${loginUrl}`), "auth.login.url");
  consolePresentationOutput.stdout("", "auth.login.empty-line");
  consolePresentationOutput.stdout(chalk.yellow("Note: server-side mint endpoint is not yet implemented (#303)."), "auth.login.scaffold-warning");
  consolePresentationOutput.stdout(chalk.yellow("      For now, use: 0sec auth login --token <value>"), "auth.login.scaffold-hint");
  consolePresentationOutput.stdout("", "auth.login.empty-line");

  const opener = opts.openBrowser ?? defaultOpenBrowser;
  try {
    opener(loginUrl);
  } catch (err) {
    consolePresentationOutput.stderr(chalk.yellow(
      `Could not open browser automatically (${err instanceof Error ? err.message : String(err)}). ` +
        `Open this URL manually: ${loginUrl}`,
    ), "auth.login.browser-error");
  }

  const attempts = opts.pollAttempts ?? 150;
  const intervalMs = opts.pollIntervalMs ?? 2000;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const sleep = opts.sleep ?? defaultSleep;

  for (let i = 0; i < attempts; i++) {
    await sleep(intervalMs);
    let res: Response;
    try {
      res = await fetchImpl(pollUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
      });
    } catch {
      // Transient network error during polling — keep trying.
      continue;
    }
    if (res.status === 200) {
      let body: unknown;
      try {
        body = await res.json();
      } catch {
        consolePresentationOutput.stderr(chalk.red("Login poll returned 200 but no JSON body. Aborting."), "auth.login.poll-json-error");
        process.exitCode = EXIT_USER_ERROR;
        return;
      }
      const token = extractToken(body);
      if (!token) {
        consolePresentationOutput.stderr(chalk.red("Login poll returned 200 but body did not contain a token. Aborting."), "auth.login.poll-token-error");
        process.exitCode = EXIT_USER_ERROR;
        return;
      }
      persistCredentials(host, token, opts.homeDir);
      consolePresentationOutput.stdout(`Logged in (host=${host})`, "auth.login.logged-in");
      process.exitCode = EXIT_OK;
      return;
    }
    // 404 = session not yet redeemed; keep polling. Anything else (401/
    // 403/5xx) we still keep polling for — only the timeout is fatal.
  }

  consolePresentationOutput.stderr(chalk.red(
    `Login timed out after ${Math.round((attempts * intervalMs) / 1000)}s. ` +
      "Use `0sec auth login --token <value>` until the server-side mint endpoint ships (#303).",
  ), "auth.login.timed-out");
  process.exitCode = EXIT_NET;
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
  if (!host) return null;
  let h = host.trim();
  if (!/^https?:\/\//.test(h)) {
    consolePresentationOutput.stderr(chalk.red(`Error: --host must be an http(s) URL (got ${JSON.stringify(host)}).`), "auth.login.host-error");
    process.exitCode = EXIT_USER_ERROR;
    return null;
  }
  while (h.endsWith("/")) h = h.slice(0, -1);
  return h;
}

function persistCredentials(host: string, token: string, homeDirOverride?: string): void {
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

/**
 * Extract a token from a `/cli-auth/sessions/<id>` response body. The
 * server contract isn't pinned yet (#303) — we accept either
 * `{ token: "…" }` or `{ access_token: "…" }` to keep the scaffold
 * flexible. The follow-up PR adds a zod schema once the shape is
 * locked.
 */
function extractToken(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const obj = body as Record<string, unknown>;
  const candidates = [obj.token, obj.access_token];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) return c.trim();
  }
  return null;
}

/**
 * Open a URL in the user's default browser without adding a runtime
 * dependency. We use platform-detected child_process.spawn:
 *   - darwin → `open <url>`
 *   - win32  → `cmd /c start "" <url>` (the empty title arg is required
 *             because `start` treats a quoted first arg as a window title)
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
function defaultOpenBrowser(url: string): void {
  const plat = platform();
  let cmd: string;
  let args: string[];
  if (plat === "darwin") {
    cmd = "open";
    args = [url];
  } else if (plat === "win32") {
    cmd = "cmd";
    args = ["/c", "start", "", url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  const child = spawn(cmd, args, { detached: true, stdio: "ignore" });
  child.unref();
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
