import { createHash } from "node:crypto";
import { homeStateDir } from "@0sec/shared";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

interface CacheEnvelope<T> {
  key: string;
  source: string;
  fetchedAt: string;
  expiresAt: string;
  value: T;
}

export function defaultIntelCacheDir(): string {
  return join(homeStateDir(), "intel-cache");
}

export class IntelCache {
  constructor(private readonly cacheDir = defaultIntelCacheDir()) {}

  get<T>(source: string, key: string, opts: { offline?: boolean } = {}): T | null {
    const path = this.pathFor(source, key);
    if (!existsSync(path)) return null;
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as CacheEnvelope<T>;
      const expiresAtMs = Date.parse(parsed.expiresAt);
      if (Number.isNaN(expiresAtMs)) return null;
      if (!opts.offline && expiresAtMs <= Date.now()) return null;
      return parsed.value;
    } catch {
      return null;
    }
  }

  set<T>(source: string, key: string, value: T, ttlMs = DEFAULT_TTL_MS): void {
    const path = this.pathFor(source, key);
    mkdirSync(dirname(path), { recursive: true });
    const now = new Date();
    const envelope: CacheEnvelope<T> = {
      key,
      source,
      fetchedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      value,
    };
    writeFileSync(path, `${JSON.stringify(envelope, null, 2)}\n`);
  }

  private pathFor(source: string, key: string): string {
    const digest = createHash("sha256").update(key).digest("hex");
    return join(this.cacheDir, source, `${digest}.json`);
  }
}

export async function cachedJson<T>(
  cache: IntelCache,
  source: string,
  key: string,
  fetcher: () => Promise<T>,
  opts: { offline?: boolean; ttlMs?: number } = {},
): Promise<T> {
  const cached = cache.get<T>(source, key, { offline: opts.offline });
  if (cached) return cached;
  if (opts.offline) {
    throw new Error(`offline cache miss for ${source}:${key}`);
  }
  const value = await fetcher();
  cache.set(source, key, value, opts.ttlMs);
  return value;
}

export async function fetchJson(
  url: string,
  init: RequestInit = {},
  opts: { timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 20_000);
  try {
    const res = await (opts.fetchImpl ?? fetch)(url, {
      ...init,
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} for ${url}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
