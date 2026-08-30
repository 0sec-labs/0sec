/**
 * Per-provider LLM credentials, persisted to `~/.0sec/credentials.json`.
 *
 * The runtime resolves provider credentials from environment variables only
 * (see `provider-status.ts`, transcribed from `llm-api.ts`). That is fine for
 * a shell with the right exports and hostile to everyone else: an operator who
 * has not exported the variable gets a turn that dies with zero tokens, and
 * the fix — an export that survives the next terminal — lives outside the
 * tool. This module is the durable side of that. The console can write a key
 * here once; `credentialEnvPatch` turns the file back into the env additions
 * the runtime already knows how to read, so nothing downstream has to learn a
 * second credential source.
 *
 * `PROVIDERS` is imported, never re-derived. Several providers deviate from
 * the `<VENDOR>_API_KEY` pattern and one is OAuth rather than an API key; a
 * second copy of that table here would drift from the runtime silently, which
 * for credentials means writing a secret into a variable nobody reads.
 *
 * This file holds secrets, so three rules are absolute and each is enforced
 * below rather than left to callers:
 *
 *   1. On-disk artefacts are owner-only — 0600 for the file, 0700 for the
 *      directory — and are re-tightened on every save, not just at creation.
 *   2. An explicit shell export always beats the file. The store is a
 *      convenience for the unconfigured case; it may never quietly shadow a
 *      credential the operator chose in their environment.
 *   3. Nothing here prints. Not to stdout, not to stderr, not on an error
 *      path — this runs inside a TUI that owns the terminal, and the values
 *      involved are exactly the ones that must never reach a scrollback
 *      buffer or a CI log. `redactSecret` exists so display code has a safe
 *      option; the raw values leave this module only through the env patch.
 *
 * Like the settings store next door, I/O failure is reported as a return
 * value: a read-only `$HOME` is an inconvenience, not a reason to lose the
 * console.
 */

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { homeStateDir } from "@0sec/shared";

import { PROVIDERS } from "./provider-status.js";

export interface StoredCredentials {
  /** providerId -> secret value. */
  [providerId: string]: string;
}

/** Basename of the credential file inside the 0sec state directory. */
const CREDENTIALS_FILENAME = "credentials.json";

/** Owner-only: nobody else on the machine has business reading this file. */
const FILE_MODE = 0o600;
/**
 * Owner-only on the directory too. A 0600 file inside a 0755 directory still
 * leaks its existence and its size to every local account, and a directory
 * that is group- or world-*writable* would let another account replace the
 * file wholesale — a credential swap, not just a disclosure.
 */
const DIR_MODE = 0o700;

/**
 * Credentials live beside the rest of the per-user engine state (scan DB,
 * journals, TUI settings) rather than in a bespoke directory, so
 * `homeStateDir` from `@0sec/shared` — not a local `".0sec"` literal — decides
 * where that is. One definition of the state root means a future relocation or
 * an `$XDG_STATE_HOME` migration happens in one place.
 */
export function credentialsFilePath(homeDir?: string): string {
  return join(homeStateDir(homeDir), CREDENTIALS_FILENAME);
}

/** API-key providers the generic key store is allowed to persist. */
const STORABLE_PROVIDER_IDS = new Set(
  PROVIDERS.filter((provider) => provider.auth === "api-key").map((provider) => provider.id),
);

/**
 * An exported-but-empty value is the classic way credentials break: `export
 * ANTHROPIC_API_KEY=` in a shell profile, or a CI secret that resolved to the
 * empty string, leaves the name present while carrying nothing. Whitespace-only
 * is the same story — a stray newline from `$(cat key.txt)` is not a key.
 * `provider-status.ts` applies exactly this test when deciding whether a
 * provider is configured, and the two must agree or the console will report a
 * provider as dark while this module happily declines to fill it.
 */
function hasCredential(value: string | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Total, pure coercion of anything at all into a usable credential map.
 *
 * The file is hand-editable and therefore corruptible, but the stakes here are
 * higher than for display settings: a malformed entry must degrade to "this
 * provider is unconfigured", never to a key written into the wrong variable.
 * So an entry survives only if its id is a provider the runtime knows and its
 * value is a non-blank string. Unknown ids are dropped rather than carried
 * through, which also means a hand-added `"__proto__"` or `"constructor"` key
 * cannot reach the assignment below.
 *
 * Values are trimmed on the way in: whitespace around a pasted key is an
 * artefact of the paste, and leaving it would produce a credential that looks
 * present everywhere in the UI while failing every request.
 */
export function normalizeCredentials(raw: unknown): StoredCredentials {
  const out: StoredCredentials = {};
  // Arrays and `null` are typeof "object" too; neither can carry provider
  // entries, and treating them as an empty bag is the wanted "nothing is
  // configured" outcome rather than a special case that throws.
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return out;

  for (const [providerId, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!STORABLE_PROVIDER_IDS.has(providerId)) continue;
    if (typeof value !== "string") continue;
    const secret = value.trim();
    if (secret.length === 0) continue;
    out[providerId] = secret;
  }
  return out;
}

/**
 * Loads stored credentials, or nothing at all. Never throws and never reports:
 * a missing file is the common case (the operator has never used the credential
 * UI), and an unreadable or malformed one degrades to "no stored credentials",
 * which the console already knows how to render — the provider simply shows as
 * unconfigured and the operator can re-enter the key.
 *
 * Deliberately silent on failure: the obvious diagnostic here would be to
 * report what could not be parsed, and the thing that could not be parsed is a
 * file full of secrets.
 */
export function loadCredentials(homeDir?: string): StoredCredentials {
  try {
    const text = readFileSync(credentialsFilePath(homeDir), "utf8");
    return normalizeCredentials(JSON.parse(text));
  } catch {
    return {};
  }
}

/**
 * Persists credentials with owner-only permissions, reporting success as a
 * return value rather than an exception.
 *
 * Permissions are applied twice on purpose. The `mode` option on `writeFileSync`
 * and `mkdirSync` only takes effect when the entry is *created*, and even then
 * it is masked by the process umask; an existing world-readable file — left by
 * an older build, a restored backup, or a hand-edit — would keep its loose mode
 * silently. The explicit `chmodSync` calls therefore run unconditionally, so
 * every save is also a repair. `mode` on the create path still matters: it
 * closes the window between "file exists with the default mode" and "chmod
 * lands", during which the secret would be readable.
 *
 * The payload is normalised on the way out, so a caller cannot persist an
 * unknown provider or a blank value, and pretty-printed with a trailing
 * newline to stay diffable for an operator who does open it.
 */
export function saveCredentials(creds: StoredCredentials, homeDir?: string): boolean {
  try {
    const path = credentialsFilePath(homeDir);
    const dir = dirname(path);
    mkdirSync(dir, { recursive: true, mode: DIR_MODE });
    chmodSync(dir, DIR_MODE);
    writeFileSync(path, `${JSON.stringify(normalizeCredentials(creds), null, 2)}\n`, {
      encoding: "utf8",
      mode: FILE_MODE,
    });
    chmodSync(path, FILE_MODE);
    return true;
  } catch {
    return false;
  }
}

/**
 * The environment additions implied by the store — the bridge between a file
 * the runtime does not read and the variables it does.
 *
 * Precedence is the whole point: a variable already carrying a credential in
 * `env` is never touched. An `export` in the current shell is an explicit,
 * deliberate act, and a stored key silently overriding it would make "which
 * key did that run use?" unanswerable — exactly the question you need answered
 * when a request 401s or when a metered key racks up spend. An exported-but-
 * empty variable is treated as absent, matching `provider-status.ts`: it is a
 * broken export, not a choice.
 *
 * The check spans *all* of a provider's variables, not just the one we would
 * write. A parent process that supplied `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN`
 * already configured that provider; injecting a stored access token alongside
 * it would mix credentials from two sources into one auth attempt, and the
 * runtime prefers ours — which is precisely the silent override this rule forbids.
 *
 * When we do fill, we fill `envVars[0]`: that list is ordered by the runtime's
 * own preference, so the first entry is the variable it actually reads first.
 *
 * Pure over its arguments — no `process.env` read, no mutation of either input.
 * Callers merge the result themselves and can therefore preview a patch, log
 * its *keys*, or apply it to a child process rather than this one.
 */
export function credentialEnvPatch(
  creds: StoredCredentials,
  env: Record<string, string | undefined>,
): Record<string, string> {
  const stored = normalizeCredentials(creds);
  const patch: Record<string, string> = {};

  for (const info of PROVIDERS) {
    const secret = stored[info.id];
    if (secret === undefined) continue;
    if (info.envVars.some((name) => hasCredential(env[name]))) continue;
    const target = info.envVars[0];
    // A provider with no env vars cannot be configured this way at all; the
    // table has none today, but the guard keeps a future file-only provider
    // from producing an `undefined` key.
    if (target === undefined) continue;
    patch[target] = secret;
  }

  return patch;
}

/**
 * Fixed-width mask. Constant regardless of the input so the redacted form
 * leaks neither the secret nor its length — key length alone narrows down
 * which provider or key format is in play.
 */
const MASK = "••••••••";
/** How many trailing characters identify a key to the person who pasted it. */
const TAIL = 4;
/** How much leading context ("sk-ant-") is useful without being a key. */
const PREFIX = 6;
/** Below this, even four trailing characters is a third of the secret. */
const MIN_LENGTH_FOR_TAIL = 12;
/** Below this, prefix plus tail would expose more than half the secret. */
const MIN_LENGTH_FOR_PREFIX = 20;

/**
 * Display form of a secret, e.g. `sk-ant-…a4f2`. Never returns the input.
 *
 * The purpose is recognition, not verification: enough for an operator to tell
 * "the key I pasted" from "the key from last month" over a shoulder-surfable
 * terminal, and not enough to reconstruct anything. Short inputs are masked
 * outright — a four-character value has no safe fraction to reveal, and the
 * lengths that show up short are typos and truncated pastes, which the
 * operator diagnoses by re-entering rather than by reading back.
 */
export function redactSecret(secret: string): string {
  // Defensive against a `any`-typed caller as much as a blank value: the
  // failure mode of a wrong branch here is a printed secret.
  const value = typeof secret === "string" ? secret.trim() : "";
  if (value.length < MIN_LENGTH_FOR_TAIL) return MASK;

  const tail = value.slice(-TAIL);
  if (value.length < MIN_LENGTH_FOR_PREFIX) return `${MASK}${tail}`;
  return `${value.slice(0, PREFIX)}…${tail}`;
}
