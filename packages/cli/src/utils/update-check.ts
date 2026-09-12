import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { homeStateDir } from "@0sec/shared";
import { loadLayeredSettings } from "../tui/settings.js";

const REPO = "0sec-labs/0sec";
const INSTALL_URL = `https://raw.githubusercontent.com/${REPO}/main/install.sh`;
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 4_000;
const INSTALL_TIMEOUT_MS = 120_000;

export type UpdatePolicy = "off" | "notify" | "automatic";
export interface NotifyOptions { policy?: UpdatePolicy }
export interface AutoUpdateOptions {
  version?: string;
  installDir?: string;
  /** Overall installer deadline, bounded by the normal two-minute limit. */
  timeoutMs?: number;
}
export interface AutoUpdateResult {
  success: boolean;
  installed: boolean;
  installedVersion?: string;
  error?: string;
  exitCode?: number;
  signal?: NodeJS.Signals;
}
interface CheckCache {
  lastCheckedAt: string;
  latestVersion?: string;
  lastInstallAttemptAt?: string;
  lastInstallTag?: string;
}
interface Version {
  parts: number[];
  prerelease: string[];
  complete: boolean;
}

function parseVersion(value: string): Version | null {
  if (value.length > 128) return null;
  const match = /^v?(0|[1-9]\d*)(?:\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?)?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(value);
  if (!match) return null;
  const parts = [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)];
  if (!parts.every(Number.isSafeInteger)) return null;
  const prerelease = match[4]?.split(".") ?? [];
  if (prerelease.some(part => /^\d+$/.test(part) && part.length > 1 && part.startsWith("0"))) return null;
  return { parts, prerelease, complete: match[3] !== undefined };
}

/** Invalid versions never qualify as a newer release. Build metadata is ignored. */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return 0;
  for (let i = 0; i < 3; i++) {
    if (left.parts[i] !== right.parts[i]) return left.parts[i] < right.parts[i] ? -1 : 1;
  }
  if (!left.prerelease.length || !right.prerelease.length) {
    return left.prerelease.length ? -1 : right.prerelease.length ? 1 : 0;
  }
  for (let i = 0; i < Math.max(left.prerelease.length, right.prerelease.length); i++) {
    const l = left.prerelease[i];
    const r = right.prerelease[i];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    if (l === r) continue;
    const ln = /^\d+$/.test(l);
    const rn = /^\d+$/.test(r);
    if (ln !== rn) return ln ? -1 : 1;
    if (ln && l.length !== r.length) return l.length < r.length ? -1 : 1;
    return l < r ? -1 : 1;
  }
  return 0;
}

function disabled(value: string | undefined): boolean {
  return value !== undefined && value !== "" && value !== "0" && value.toLowerCase() !== "false";
}

export function shouldRunCheck(
  env: NodeJS.ProcessEnv = process.env,
  isTty = Boolean(process.stdout.isTTY),
  policy?: UpdatePolicy,
): boolean {
  if (!isTty || disabled(env.CI) || disabled(env["0SEC_OFFLINE"]) || disabled(env["0SEC_NO_UPDATE_CHECK"])) return false;
  if (policy !== undefined) return policy !== "off";
  return env["0SEC_UPDATE_CHECK"] === "1";
}

function recent(timestamp: string | undefined, now: number): boolean {
  const age = now - Date.parse(timestamp ?? "");
  return Number.isFinite(age) && age >= 0 && age < CHECK_INTERVAL_MS;
}

function readCache(): CheckCache | null {
  try {
    const raw: unknown = JSON.parse(readFileSync(join(homeStateDir(), "last-update-check"), "utf8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
    const value = raw as Record<string, unknown>;
    if (typeof value.lastCheckedAt !== "string") return null;
    return {
      lastCheckedAt: value.lastCheckedAt,
      latestVersion: typeof value.latestVersion === "string" ? value.latestVersion : undefined,
      lastInstallAttemptAt: typeof value.lastInstallAttemptAt === "string" ? value.lastInstallAttemptAt : undefined,
      lastInstallTag: typeof value.lastInstallTag === "string" ? value.lastInstallTag : undefined,
    };
  } catch { return null; }
}

function writeCache(cache: CheckCache): void {
  try {
    mkdirSync(homeStateDir(), { recursive: true });
    writeFileSync(join(homeStateDir(), "last-update-check"), JSON.stringify(cache));
  } catch { /* An unwritable cache must not prevent the requested command. */ }
}

async function fetchLatestTag(): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "0sec-cli/update-check" },
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const data = await response.json() as { tag_name?: unknown; prerelease?: unknown; draft?: unknown };
    if (typeof data.tag_name !== "string" || data.prerelease === true || data.draft === true) return null;
    const version = parseVersion(data.tag_name);
    return version?.complete && version.prerelease.length === 0 ? data.tag_name : null;
  } catch { return null; }
  finally { clearTimeout(timer); }
}

let installInProgress = false;
const attemptedAutomaticTags = new Set<string>();

/** One canonical installer, shared by explicit upgrade and startup auto-update. */
export async function performAutoUpdate(options: AutoUpdateOptions = {}): Promise<AutoUpdateResult> {
  if (process.platform === "win32") return { success: false, installed: false, error: "Automatic installation is unavailable on Windows; download a release from https://github.com/0sec-labs/0sec/releases/latest." };
  if (disabled(process.env["0SEC_OFFLINE"]) || disabled(process.env["0SEC_NO_UPDATE_CHECK"])) {
    return { success: false, installed: false, error: "Updates are disabled by the current offline/update policy." };
  }
  if (installInProgress) return { success: false, installed: false, error: "An update is already in progress." };
  installInProgress = true;
  try {
    const tag = options.version ?? await fetchLatestTag();
    const version = tag ? parseVersion(tag) : null;
    if (!tag || !version?.complete) return { success: false, installed: false, error: "Could not resolve a valid release tag." };
    const normalizedTag = tag.startsWith("v") ? tag : `v${tag}`;
    const env: NodeJS.ProcessEnv = { ...process.env, RELEASE_BASE_URL: `https://github.com/${REPO}/releases/download/${normalizedTag}` };
    const installDir = options.installDir ?? process.env["0SEC_INSTALL_DIR"];
    if (installDir !== undefined) env.INSTALL_DIR = installDir;
    const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs! > 0
      ? Math.min(options.timeoutMs!, INSTALL_TIMEOUT_MS) : INSTALL_TIMEOUT_MS;
    return await new Promise<AutoUpdateResult>((resolve) => {
      // bash, not /bin/sh: dash does not implement pipefail. Every descendant
      // belongs to this process group so the deadline stops the whole pipeline.
      const child = spawn("bash", ["-o", "pipefail", "-c", `curl -fsSL --connect-timeout 10 --max-time 30 "${INSTALL_URL}" | bash`], {
        stdio: "inherit", env, detached: true,
      });
      let timedOut = false;
      let settled = false;
      let parentSignal: NodeJS.Signals | undefined;
      let killTimer: ReturnType<typeof setTimeout> | undefined;
      const finish = (result: AutoUpdateResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearTimeout(killTimer);
        process.removeListener("SIGINT", onInterrupt);
        process.removeListener("SIGTERM", onTerminate);
        resolve(result);
      };
      const terminate = (signal: NodeJS.Signals) => {
        if (child.pid === undefined) return;
        try { process.kill(-child.pid, signal); } catch { /* The owned process group already exited. */ }
      };
      const interrupt = (signal: NodeJS.Signals) => {
        if (parentSignal || settled) return;
        parentSignal = signal;
        clearTimeout(timer);
        terminate(signal);
        clearTimeout(killTimer);
        killTimer = setTimeout(() => {
          terminate("SIGKILL");
          finish({ success: false, installed: false, signal, error: `Installer stopped by ${signal}.` });
        }, 1_000);
      };
      const onInterrupt = () => interrupt("SIGINT");
      const onTerminate = () => interrupt("SIGTERM");
      const timer = setTimeout(() => {
        timedOut = true;
        terminate("SIGTERM");
        killTimer = setTimeout(() => {
          terminate("SIGKILL");
          finish({ success: false, installed: false, exitCode: 1, error: `Installer exceeded its ${timeoutMs}ms deadline.` });
        }, 1_000);
      }, timeoutMs);
      process.on("SIGINT", onInterrupt);
      process.on("SIGTERM", onTerminate);
      child.once("error", error => finish({ success: false, installed: false, exitCode: 1, error: `Could not start the installer: ${error.message}. Ensure bash and curl are available.` }));
      child.once("close", (code, signal) => {
        if (timedOut || parentSignal) return;
        if (signal) finish({ success: false, installed: false, signal, error: `Installer stopped by ${signal}.` });
        else if (code === 0) finish({ success: true, installed: true, installedVersion: normalizedTag, exitCode: 0 });
        else finish({ success: false, installed: false, exitCode: code ?? 1, error: `Installer exited with code ${code ?? 1}.` });
      });
    });
  } catch (error) {
    return { success: false, installed: false, exitCode: 1, error: error instanceof Error ? error.message : "Update failed." };
  } finally { installInProgress = false; }
}

/** Notify asynchronously, or await this function when automatic is explicit. */
export async function maybeNotifyUpdate(currentVersion: string, options: NotifyOptions = {}): Promise<void> {
  const policy = options.policy;
  if (!shouldRunCheck(process.env, Boolean(process.stdout.isTTY), policy) || !parseVersion(currentVersion)) return;
  const now = Date.now();
  let cache = readCache();
  if (!cache || !recent(cache.lastCheckedAt, now)) {
    const tag = await fetchLatestTag();
    cache = { ...cache, lastCheckedAt: new Date(now).toISOString(), latestVersion: tag ?? cache?.latestVersion };
    writeCache(cache);
  }
  const tag = cache.latestVersion;
  const candidate = tag ? parseVersion(tag) : null;
  if (!tag || !candidate?.complete || candidate.prerelease.length > 0 || compareVersions(tag, currentVersion) <= 0) return;
  if (policy !== "automatic") {
    process.stderr.write(`[0sec] Update available: ${currentVersion} → ${tag}. Run 0sec upgrade.\n`);
    return;
  }
  if (attemptedAutomaticTags.has(tag) || (cache.lastInstallTag === tag && recent(cache.lastInstallAttemptAt, now))) return;
  attemptedAutomaticTags.add(tag);
  writeCache({ ...cache, lastInstallTag: tag, lastInstallAttemptAt: new Date(now).toISOString() });
  process.stderr.write(`[0sec] Updating to ${tag} before starting the console…\n`);
  const result = await performAutoUpdate({ version: tag });
  if (result.signal) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.stderr.write(result.success
    ? `[0sec] Installed ${result.installedVersion}. This process is still ${currentVersion}; restart to use the update.\n`
    : `[0sec] Update not installed: ${result.error ?? "unknown error"} Continuing with ${currentVersion}.\n`);
}

/** Awaited at the entry point: only explicit automatic policy delays startup. */
export async function runStartupUpdate(version: string): Promise<void> {
  if (!shouldRunCheck(process.env, Boolean(process.stdout.isTTY), "notify")) return;
  const { settings, sources } = loadLayeredSettings();
  const policy = sources.updatePolicy === "global" ? settings.updatePolicy : undefined;
  if (policy === "automatic") await maybeNotifyUpdate(version, { policy });
  else if (policy !== "off") void maybeNotifyUpdate(version, { policy });
}
