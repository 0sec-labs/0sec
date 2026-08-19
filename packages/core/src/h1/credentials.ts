// HackerOne credential resolver.
//
// Resolution order (first match wins):
//   1. Environment: H1_API_IDENTIFIER + H1_API_TOKEN
//   2. ~/.0sec/h1.env  (line-by-line `KEY=VALUE`, no `dotenv` dep)
//
// The identifier is the friendly name the operator typed at token
// creation (NOT their H1 handle, NOT the token value). H1 enforces
// `^[A-Za-z0-9][A-Za-z0-9_-]*$`. We re-validate locally to fail fast
// before sending a request that will 401 server-side anyway.
//
// `~/.0sec/h1.env` MUST be chmod 600. We warn (stderr) when it isn't,
// but we don't refuse to load — the user might be debugging on a system
// where mode bits are not enforceable (Docker volume, network share).
//
// SECURITY: this module never logs or returns the token in error
// messages. The `H1AuthMissingError` is the only typed error we throw,
// and it carries no secret material. Callers higher up the stack should
// likewise never echo the token back.

import { readFileSync, statSync } from "node:fs";
import { homeStateDir } from "@0sec/shared";
import { homedir } from "node:os";
import { join } from "node:path";

export interface H1Credentials {
  identifier: string;
  token: string;
  /** Where the credentials came from. Useful for diagnostics that don't echo secrets. */
  source: "env" | "file";
}

export class H1AuthMissingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "H1AuthMissingError";
  }
}

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

/**
 * Internal options for testability — lets credentials.test.ts inject a
 * fake home directory and a captured stderr writer without touching the
 * real `process` / `fs` globals.
 */
export interface LoadH1CredentialsOptions {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  warn?: (message: string) => void;
}

export function loadH1Credentials(opts: LoadH1CredentialsOptions = {}): H1Credentials {
  const env = opts.env ?? process.env;
  const warn = opts.warn ?? ((m: string) => process.stderr.write(`${m}\n`));

  // 1. Env wins.
  const envId = env.H1_API_IDENTIFIER?.trim();
  const envTok = env.H1_API_TOKEN?.trim();
  if (envId && envTok) {
    validateIdentifier(envId);
    return { identifier: envId, token: envTok, source: "env" };
  }

  // 2. ~/.0sec/h1.env fallback.
  const path = join(homeStateDir(opts.homeDir), "h1.env");
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === "ENOENT") {
      throw new H1AuthMissingError(
        `H1 credentials not found. Set H1_API_IDENTIFIER + H1_API_TOKEN in env, or create ${path} (chmod 600) with those keys.`,
      );
    }
    throw err;
  }

  // Mode check — warn only, never refuse to load.
  try {
    const st = statSync(path);
    // Mask to permission bits (low 9 bits). 0o600 = owner read+write only.
    const mode = st.mode & 0o777;
    if (mode !== 0o600) {
      warn(
        `[0sec h1] WARNING: ${path} mode is ${mode.toString(8).padStart(3, "0")} (expected 600). ` +
          `Run: chmod 600 ${path}`,
      );
    }
  } catch {
    // stat failure on a file we just read is exotic; ignore.
  }

  const parsed = parseEnvFile(raw);
  const fileId = parsed.H1_API_IDENTIFIER?.trim();
  const fileTok = parsed.H1_API_TOKEN?.trim();
  if (!fileId || !fileTok) {
    throw new H1AuthMissingError(
      `H1 credentials in ${path} are incomplete: need both H1_API_IDENTIFIER and H1_API_TOKEN.`,
    );
  }
  validateIdentifier(fileId);
  return { identifier: fileId, token: fileTok, source: "file" };
}

function validateIdentifier(id: string): void {
  if (!IDENTIFIER_RE.test(id)) {
    throw new H1AuthMissingError(
      `H1_API_IDENTIFIER ${JSON.stringify(id)} is invalid: must match ${IDENTIFIER_RE.source} ` +
        `(starts with letter/number; only letters, numbers, hyphens, underscores). ` +
        `This is the NAME you typed at token creation, NOT the token value or your H1 handle.`,
    );
  }
}

/**
 * Minimal `KEY=VALUE` parser. Does NOT support quoted values, multi-line
 * values, escapes, or `export` prefixes — h1.env is a tiny file we own
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
      throw new H1AuthMissingError(`Malformed h1.env at line ${i + 1}: expected KEY=VALUE, got ${JSON.stringify(line)}`);
    }
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!/^[A-Z0-9_]+$/.test(key)) {
      throw new H1AuthMissingError(`Malformed h1.env at line ${i + 1}: invalid key ${JSON.stringify(key)}`);
    }
    out[key] = value;
  }
  return out;
}
