// pwnkit-cloud credential resolver.
//
// Resolution order (first match wins):
//   1. Environment: PWNKIT_CLOUD_HOST + PWNKIT_CLOUD_TOKEN
//   2. ~/.pwnkit/cloud.env (line-by-line `KEY=VALUE`, no `dotenv` dep)
//
// PWNKIT_CLOUD_HOST is optional — if absent, we fall back to the
// canonical production host. PWNKIT_CLOUD_TOKEN is required.
//
// `~/.pwnkit/cloud.env` MUST be chmod 600. We warn (stderr) when it isn't,
// but we don't refuse to load — same trade-off as the H1 credential
// loader (see packages/core/src/h1/credentials.ts).
//
// DIVERGENCE FROM h1/credentials.ts:
//   - This is a Bearer-token scheme (single secret), not Basic-auth, so
//     there's no `identifier` field and no identifier-regex validation.
//   - Host is configurable so contributors can point at staging /
//     self-hosted instances without rebuilding the CLI.
//
// SECURITY: this module never logs or returns the token in error
// messages. `CloudAuthMissingError` carries no secret material.

import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Canonical production host. Override via PWNKIT_CLOUD_HOST or cloud.env. */
export const DEFAULT_CLOUD_HOST = "https://cloud.0sec.ai";

export interface CloudCredentials {
  host: string;
  token: string;
  /** Where the credentials came from. Useful for diagnostics that don't echo secrets. */
  source: "env" | "file";
}

/** Thrown when no credentials are configured at all. */
export class CloudAuthMissingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CloudAuthMissingError";
  }
}

/** Thrown when credentials exist but the server rejected them (401/403). */
export class CloudAuthError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "CloudAuthError";
  }
}

/**
 * Internal options for testability — lets credentials.test.ts inject a
 * fake home directory and a captured stderr writer without touching the
 * real `process` / `fs` globals.
 */
export interface LoadCloudCredentialsOptions {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  warn?: (message: string) => void;
}

export function loadCloudCredentials(opts: LoadCloudCredentialsOptions = {}): CloudCredentials {
  const env = opts.env ?? process.env;
  const home = opts.homeDir ?? homedir();
  const warn = opts.warn ?? ((m: string) => process.stderr.write(`${m}\n`));

  // 1. Env wins.
  const envTok = env.PWNKIT_CLOUD_TOKEN?.trim();
  if (envTok) {
    const envHost = normaliseHost(env.PWNKIT_CLOUD_HOST?.trim() ?? DEFAULT_CLOUD_HOST);
    return { host: envHost, token: envTok, source: "env" };
  }

  // 2. ~/.pwnkit/cloud.env fallback.
  const path = join(home, ".pwnkit", "cloud.env");
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === "ENOENT") {
      throw new CloudAuthMissingError(
        `pwnkit-cloud credentials not found. Run \`pwnkit auth login\` or set PWNKIT_CLOUD_TOKEN in env, ` +
          `or create ${path} (chmod 600) with PWNKIT_CLOUD_TOKEN=… (optionally PWNKIT_CLOUD_HOST=…).`,
      );
    }
    throw err;
  }

  // Mode check — warn only, never refuse to load.
  try {
    const st = statSync(path);
    const mode = st.mode & 0o777;
    if (mode !== 0o600) {
      warn(
        `[pwnkit cloud] WARNING: ${path} mode is ${mode.toString(8).padStart(3, "0")} (expected 600). ` +
          `Run: chmod 600 ${path}`,
      );
    }
  } catch {
    // stat failure on a file we just read is exotic; ignore.
  }

  const parsed = parseEnvFile(raw);
  const fileTok = parsed.PWNKIT_CLOUD_TOKEN?.trim();
  if (!fileTok) {
    throw new CloudAuthMissingError(
      `pwnkit-cloud credentials in ${path} are incomplete: PWNKIT_CLOUD_TOKEN is required.`,
    );
  }
  const fileHost = normaliseHost(parsed.PWNKIT_CLOUD_HOST?.trim() ?? DEFAULT_CLOUD_HOST);
  return { host: fileHost, token: fileTok, source: "file" };
}

/**
 * Strip a trailing slash so callers can always do `${host}/path` without
 * worrying about doubled separators. Rejects obviously broken URLs early
 * to fail fast rather than 404 at request time.
 */
function normaliseHost(host: string): string {
  let h = host;
  if (!/^https?:\/\//.test(h)) {
    throw new CloudAuthMissingError(
      `PWNKIT_CLOUD_HOST must be an http(s) URL (got ${JSON.stringify(host)}).`,
    );
  }
  while (h.endsWith("/")) h = h.slice(0, -1);
  return h;
}

/**
 * Minimal `KEY=VALUE` parser. Does NOT support quoted values, multi-line
 * values, escapes, or `export` prefixes — cloud.env is a tiny file we own
 * the format of. Lines starting with `#` or empty lines are skipped.
 * Anything else is rejected so a typo is loud rather than silent.
 */
function parseEnvFile(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) {
      throw new CloudAuthMissingError(
        `Malformed cloud.env at line ${i + 1}: expected KEY=VALUE, got ${JSON.stringify(line)}`,
      );
    }
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!/^[A-Z_][A-Z0-9_]*$/.test(key)) {
      throw new CloudAuthMissingError(
        `Malformed cloud.env at line ${i + 1}: invalid key ${JSON.stringify(key)}`,
      );
    }
    out[key] = value;
  }
  return out;
}
