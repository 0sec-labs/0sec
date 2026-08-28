/**
 * Models.dev catalog sync with a cached-with-offline-fallback strategy.
 *
 * The `/model` picker (model-catalog.ts) is derived from the hand-priced table
 * in @0sec/shared — authoritative for cost, but narrow. This module widens the
 * picker to every model the operator's provider actually offers by pulling the
 * public Models.dev catalog, without ever coupling the picker to a live network
 * call:
 *
 *   1. `syncModelCatalog()` fetches Models.dev, normalizes it, and writes a
 *      cache to `~/.0sec/model-catalog.json`. It NEVER throws — on any failure
 *      (offline, timeout, bad JSON) it returns null and leaves the cache as-is.
 *   2. `loadCatalogModels()` is synchronous and safe to call on the render
 *      path: it returns the freshest thing available — a fresh cache if within
 *      TTL, an expired cache if that's all we have, else the bundled offline
 *      snapshot. It too never throws.
 *
 * So the picker opens instantly off cache/offline data, and a fire-and-forget
 * `syncModelCatalog()` refreshes it for next time. Everything is injectable
 * (fetch, cache path, clock) so it is fully testable without a network.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homeStateDir } from "@0sec/shared";
import { OFFLINE_MODEL_CATALOG } from "./model-catalog.offline.js";

/** One normalized catalog entry. Prices are $/1M tokens when known. */
export interface SyncedModel {
  id: string;
  provider: string;
  /** Context window in tokens, when the feed reports it. */
  contextTokens?: number;
  input?: number;
  output?: number;
}

/** On-disk cache envelope. */
export interface CatalogCache {
  /** Epoch millis the cache was written. */
  fetchedAt: number;
  /** Where the rows came from — the URL, or "offline" for the bundled floor. */
  source: string;
  models: SyncedModel[];
}

export const MODELS_DEV_URL = "https://models.dev/api.json";
export const CATALOG_CACHE_FILENAME = "model-catalog.json";
/** Refresh once a day — matches the pricing-feed cadence. */
export const CATALOG_TTL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8_000;

export interface CatalogSyncOptions {
  /** Injectable fetch — defaults to the global. */
  fetchImpl?: typeof fetch;
  /** Override the cache file path (defaults to ~/.0sec/model-catalog.json). */
  cachePath?: string;
  /** Injectable clock for TTL math — defaults to Date.now. */
  now?: () => number;
  /** Catalog source URL — defaults to Models.dev. */
  url?: string;
  /** TTL for freshness decisions — defaults to one day. */
  ttlMs?: number;
}

/** Resolve the cache path, honoring an explicit override then ~/.0sec. */
export function catalogCachePath(opts: CatalogSyncOptions = {}): string {
  return opts.cachePath ?? join(homeStateDir(), CATALOG_CACHE_FILENAME);
}

/**
 * Normalize the Models.dev `api.json` shape into `SyncedModel[]`.
 *
 * Models.dev is keyed by provider id; each provider carries a `models` object
 * keyed by model id, each model optionally carrying `cost.{input,output}` and
 * `limit.context`. We parse defensively — the feed evolves, and a shape change
 * must degrade to "fewer rows," never a throw.
 */
export function normalizeModelsDev(raw: unknown): SyncedModel[] {
  if (typeof raw !== "object" || raw === null) return [];
  const out: SyncedModel[] = [];
  const seen = new Set<string>();

  for (const [providerId, providerVal] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof providerVal !== "object" || providerVal === null) continue;
    const models = (providerVal as Record<string, unknown>)["models"];
    if (typeof models !== "object" || models === null) continue;

    for (const [modelId, modelVal] of Object.entries(models as Record<string, unknown>)) {
      const id = typeof modelId === "string" ? modelId : undefined;
      if (!id || seen.has(id)) continue;
      const m = (typeof modelVal === "object" && modelVal !== null
        ? (modelVal as Record<string, unknown>)
        : {}) as Record<string, unknown>;

      const cost = (typeof m["cost"] === "object" && m["cost"] !== null
        ? (m["cost"] as Record<string, unknown>)
        : {}) as Record<string, unknown>;
      const limit = (typeof m["limit"] === "object" && m["limit"] !== null
        ? (m["limit"] as Record<string, unknown>)
        : {}) as Record<string, unknown>;

      const entry: SyncedModel = { id, provider: providerId };
      if (typeof cost["input"] === "number") entry.input = cost["input"];
      if (typeof cost["output"] === "number") entry.output = cost["output"];
      if (typeof limit["context"] === "number") entry.contextTokens = limit["context"];
      out.push(entry);
      seen.add(id);
    }
  }
  return out;
}

function readCache(path: string): CatalogCache | null {
  try {
    if (!existsSync(path)) return null;
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !Array.isArray((parsed as CatalogCache).models) ||
      typeof (parsed as CatalogCache).fetchedAt !== "number"
    ) {
      return null;
    }
    return parsed as CatalogCache;
  } catch {
    return null;
  }
}

function writeCache(path: string, cache: CatalogCache): void {
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(cache, null, 2), { mode: 0o600 });
  } catch {
    // Best effort: an unwritable cache dir just means we re-fetch next time.
  }
}

/** True when the cache exists and is within TTL. */
export function isCacheFresh(cache: CatalogCache | null, opts: CatalogSyncOptions = {}): boolean {
  if (!cache) return false;
  const now = (opts.now ?? Date.now)();
  const ttl = opts.ttlMs ?? CATALOG_TTL_MS;
  return now - cache.fetchedAt < ttl;
}

/**
 * Return the best catalog available *without* touching the network. Freshness
 * order: fresh cache → any cache (even expired) → bundled offline snapshot.
 * Synchronous and total — safe on the render path.
 */
export function loadCatalogModels(opts: CatalogSyncOptions = {}): CatalogCache {
  const cache = readCache(catalogCachePath(opts));
  if (cache && cache.models.length > 0) return cache;
  return { fetchedAt: 0, source: "offline", models: OFFLINE_MODEL_CATALOG };
}

/**
 * Refresh the catalog from Models.dev and write the cache. Returns the new
 * cache on success, or null on any failure (never throws). If `force` is false
 * (default) and the cache is already fresh, returns the existing cache without
 * a network call so `/model` can call this unconditionally on open.
 */
export async function syncModelCatalog(
  opts: CatalogSyncOptions & { force?: boolean } = {},
): Promise<CatalogCache | null> {
  const path = catalogCachePath(opts);
  const existing = readCache(path);
  if (!opts.force && isCacheFresh(existing, opts) && (existing?.models.length ?? 0) > 0) {
    return existing;
  }

  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") return null;
  const url = opts.url ?? MODELS_DEV_URL;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, { signal: controller.signal });
    if (!res.ok) return null;
    const json = (await res.json()) as unknown;
    const models = normalizeModelsDev(json);
    if (models.length === 0) return null;
    const cache: CatalogCache = {
      fetchedAt: (opts.now ?? Date.now)(),
      source: url,
      models,
    };
    writeCache(path, cache);
    return cache;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
