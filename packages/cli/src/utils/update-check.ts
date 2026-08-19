/**
 * Background update notifier — once-per-day check against the GitHub
 * Releases API. Prints a one-line nudge on stderr when a newer version
 * is available, otherwise stays silent.
 *
 * Gated on:
 *   - 0SEC_UPDATE_CHECK=1 explicitly set by the user
 *   - stdout is a TTY (no log noise in CI / pipes)
 *   - CI / 0SEC_NO_UPDATE_CHECK / 0SEC_OFFLINE not set
 *   - last successful check was > 24h ago (rate-limit GH API + avoid
 *     pestering users on every invocation)
 *
 * Failure modes (network down, GH rate-limit, malformed response) all
 * silently no-op — never blocks the actual command, never prints an
 * error. The whole feature is convenience, not correctness.
 *
 * Cache: `~/.0sec/last-update-check` is a tiny JSON file recording
 * the last check timestamp + the latest version we saw. We update the
 * timestamp on every check (success or failure) so a transient outage
 * doesn't make us hammer the API.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homeStateDir } from "@0sec/shared";
import { join } from "node:path";
import { homedir } from "node:os";

const REPO = "0sec-labs/0sec";
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const CACHE_FILE = join(homeStateDir(), "last-update-check");
const FETCH_TIMEOUT_MS = 4000;

interface CheckCache {
  /** ISO timestamp of last check attempt (success or failure). */
  lastCheckedAt: string;
  /** Latest version seen on GitHub, if the last check succeeded. */
  latestVersion?: string;
}

export function shouldRunCheck(
  env: NodeJS.ProcessEnv = process.env,
  isTty = Boolean(process.stdout.isTTY),
): boolean {
  if (!isTty) return false;
  if (env["0SEC_UPDATE_CHECK"] !== "1") return false;
  if (env.CI === "1" || env.CI === "true") return false;
  if (env["0SEC_NO_UPDATE_CHECK"] === "1") return false;
  if (env["0SEC_OFFLINE"] === "1") return false;
  return true;
}

function readCache(): CheckCache | null {
  try {
    if (!existsSync(CACHE_FILE)) return null;
    const raw = readFileSync(CACHE_FILE, "utf8");
    return JSON.parse(raw) as CheckCache;
  } catch {
    return null;
  }
}

function writeCache(cache: CheckCache): void {
  try {
    mkdirSync(homeStateDir(), { recursive: true });
    writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2));
  } catch {
    // Best-effort — if we can't write the cache, every run will re-check.
  }
}

/**
 * Compare two semver-shaped strings ("0.9.0", "0.10.0"). Returns
 * positive if `a > b`, negative if `a < b`, zero if equal. Tolerates
 * leading "v", missing patch, and trailing pre-release tags by
 * ignoring everything after the first hyphen.
 */
export function compareVersions(a: string, b: string): number {
  const norm = (s: string): number[] =>
    s.replace(/^v/, "").split("-")[0].split(".").map((p) => parseInt(p, 10) || 0);
  const [a1, a2 = 0, a3 = 0] = norm(a);
  const [b1, b2 = 0, b3 = 0] = norm(b);
  if (a1 !== b1) return a1 - b1;
  if (a2 !== b2) return a2 - b2;
  return a3 - b3;
}

async function fetchLatestTag(): Promise<string | null> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": `0sec-cli/update-check`,
      },
      signal: ac.signal,
    });
    if (!res.ok) return null;
    const json = (await res.json()) as { tag_name?: string };
    return typeof json.tag_name === "string" ? json.tag_name : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function printNudge(currentVersion: string, latestVersion: string): void {
  const ORANGE = "\x1b[38;2;250;178;131m";
  const DIM = "\x1b[2m";
  const RESET = "\x1b[0m";
  process.stderr.write(
    `${DIM}[0sec] update available: v${currentVersion} → ${ORANGE}${latestVersion}${RESET}${DIM}.` +
      ` run \`0sec upgrade\` to update.${RESET}\n`,
  );
}

/**
 * Fire-and-forget update check. Never throws, never blocks. Returns a
 * Promise that callers can `void` — they don't need to await.
 *
 * If the cached "latest" from a prior check is already newer than the
 * current version, we print the nudge synchronously without making a
 * fresh HTTP call (covers the case where the user upgraded their
 * checkout but hasn't yet upgraded the global binary).
 */
export async function maybeNotifyUpdate(currentVersion: string): Promise<void> {
  if (!shouldRunCheck()) return;

  const cache = readCache();
  const now = Date.now();

  // First, surface the cached result immediately (cheap, no HTTP).
  if (cache?.latestVersion && compareVersions(cache.latestVersion, currentVersion) > 0) {
    printNudge(currentVersion, cache.latestVersion);
  }

  // Then decide whether to do a fresh check.
  if (cache) {
    const last = Date.parse(cache.lastCheckedAt);
    if (Number.isFinite(last) && now - last < CHECK_INTERVAL_MS) return;
  }

  const tag = await fetchLatestTag();
  // Update timestamp regardless — if the API was unreachable, we still
  // want to back off the rate at which we ping it.
  const next: CheckCache = {
    lastCheckedAt: new Date(now).toISOString(),
    ...(tag ? { latestVersion: tag } : cache?.latestVersion ? { latestVersion: cache.latestVersion } : {}),
  };
  writeCache(next);

  if (!tag) return;
  if (compareVersions(tag, currentVersion) > 0) {
    // Avoid double-printing if we already nudged from the cache above.
    if (!cache?.latestVersion || compareVersions(tag, cache.latestVersion) > 0) {
      printNudge(currentVersion, tag);
    }
  }
}
