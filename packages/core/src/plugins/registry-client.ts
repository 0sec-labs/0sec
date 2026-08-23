/**
 * Marketplace registry client (0sec plugin system, part of DESIGN.md §5).
 *
 * ── What this is, and what it is NOT ──────────────────────────────────────────
 *
 * This module fetches a marketplace INDEX — a list of `{ id, version, manifest,
 * source, signature? }` records — validates every entry through the stage-1
 * validator, and applies the signature policy. That is the whole job.
 *
 * It is NOT a live marketplace. Two things ship deliberately unfinished, and
 * pretending otherwise would be the dangerous mistake:
 *
 *   1. **No registry endpoint ships.** {@link DEFAULT_REGISTRY_URL} is EMPTY on
 *      purpose (same discipline as the feedback endpoint): there is no default
 *      host to fetch from, so nothing fetches until an operator points this at a
 *      URL they chose. An empty URL is a clear no-op, never a silent default.
 *   2. **No real signing key ships and the crypto is a STUB.** The signature
 *      POLICY here is real and tested — refuse-by-default when a verification
 *      key is configured — but the Ed25519 verification itself is a placeholder
 *      ({@link createStubSignatureVerifier} refuses everything). Do not mistake
 *      this for shipped signing. A real verifier is injected at the boundary
 *      once a signing key exists.
 *
 * ── The index is DATA, never code ─────────────────────────────────────────────
 *
 * Nothing in this module (or on the install path that consumes its output)
 * executes anything from the index. An entry is parsed JSON: its `manifest` is
 * run through `validatePluginManifest`, its `source.files` are treated as opaque
 * strings to be written to disk, and there is no `import()`, `require`, `eval`,
 * `Function`, or process spawn anywhere. Installing is copying validated bytes
 * to disk; it cannot run an install script because the code that would run one
 * does not exist. Execution only ever happens later, in `loader.ts`, and only
 * for an id an operator has separately ENABLED (see `enablement.ts`).
 *
 * ── HTTPS only ───────────────────────────────────────────────────────────────
 *
 * A registry index carries the manifests an operator will base a trust decision
 * on; fetching it over cleartext http would let a network attacker rewrite that
 * basis. http is refused outright, not downgraded-with-a-warning.
 */

import {
  manifestKindOf,
  validatePluginManifest,
  validateConfigArtifact,
  validateThemeArtifact,
  type ConfigArtifactManifest,
  type PluginCapability,
  type PluginManifest,
  type ThemeArtifactManifest,
} from "./manifest.js";
import { aggregateCapabilities } from "./enablement.js";

/**
 * Default marketplace endpoint.
 *
 * INTENTIONALLY EMPTY — there is no confirmed registry host. Leaving this blank
 * (rather than inventing a URL) means every code path that would fetch is a
 * clear no-op until an operator supplies a URL they trust.
 *
 * TODO: confirm registry endpoint.
 */
export const DEFAULT_REGISTRY_URL = "";

/** Hard cap on a fetched registry index body. The registry is the most
 * untrusted input in this subsystem — bound it like every sibling layer
 * (manifest 256 KiB, enablement 1 MiB, protocol frames 1 MiB). */
export const MAX_REGISTRY_INDEX_BYTES = 4 * 1024 * 1024; // 4 MiB
/** Abort a registry fetch that has not completed within this window. */
export const REGISTRY_FETCH_TIMEOUT_MS = 15_000;
/** Cap on entries processed from one index (memory-amplification bound). */
export const MAX_REGISTRY_ENTRIES = 5_000;

// ── Wire shapes (all untrusted) ──────────────────────────────────────────────

/**
 * Where a plugin's files come from. For this scaffold the index carries the
 * files inline as a `filename -> contents` map (the marketplace serves small
 * pure-JS plugins). Keeping them inline keeps install a pure "write these bytes"
 * step with no second fetch and no archive extraction to get wrong.
 */
export interface RegistrySource {
  kind: "inline";
  files: Record<string, string>;
}

/** One raw entry as it appears in a fetched index. Every field is untrusted. */
export interface RawRegistryEntry {
  id: string;
  version: string;
  manifest: unknown;
  source: unknown;
  signature?: string;
}

/** The fetched index. Either `{ entries: [...] }` or a bare array is accepted. */
export interface RawRegistryIndex {
  entries: RawRegistryEntry[];
}

export type SignatureState =
  /** A configured key verified the entry's signature. */
  | "verified"
  /** No verification key is configured; the entry is unverified but allowed. */
  | "unverified"
  /** Refused: a key is configured but the entry carries no signature. */
  | "refused-unsigned"
  /** Refused: a key is configured and the signature did not verify. */
  | "refused-bad-signature";

/** A validated, installable entry. Its manifest has passed stage-1 validation. */
export interface InstallableEntry {
  id: string;
  version: string;
  manifest: PluginManifest;
  /** Aggregated capability set, for a capability summary at approval time. */
  capabilities: PluginCapability[];
  files: Record<string, string>;
  signature?: string;
  signatureState: Extract<SignatureState, "verified" | "unverified">;
}

/** An entry that could not be surfaced as installable, with a reason. */
export interface DroppedEntry {
  id?: string;
  reason: string;
}

// ── Theme / config artifacts in the index (DATA, not code) ────────────────────
//
// The registry index carries THREE artifact kinds side by side, discriminated by
// the `kind` field of each entry's `manifest` (see manifest.ts / ARTIFACT_KINDS):
//
//   - kind absent / "tool"  → a tool plugin. Parsed into `RegistryResult.entries`
//                             as an InstallableEntry, exactly as before. Carries
//                             a `source` (inline files) and rides the plugin
//                             install → enable → run path.
//   - kind "theme"          → a colour palette. Parsed into `RegistryResult.artifacts`
//                             as an InstallableThemeArtifact. Carries NO source
//                             files and NO capabilities — it is inert data written
//                             verbatim to the themes dir and never loaded as code.
//   - kind "config"         → a settings bundle. Parsed into `.artifacts` as an
//                             InstallableConfigArtifact. Also inert data.
//
// Wire shape of a theme entry (all fields untrusted, validated as data):
//
//   {
//     "id": "acme.midnight",
//     "version": "1.0.0",
//     "manifest": {
//       "kind": "theme",
//       "id": "acme.midnight", "name": "Acme Midnight", "version": "1.0.0",
//       "theme": {
//         "label": "Midnight", "description": "…", "mode": "dark",
//         "palette": { "CANVAS": "#0A0E14", "TEXT": "#E8ECF2", … }
//       }
//     },
//     "signature": "…"            // optional; same policy as tool entries
//   }
//
// A config entry mirrors this with `"kind": "config"` and a `"config": { … }`
// bag of settings keys instead of a `theme`. Neither may carry `source`,
// `tools`, or `capabilities`; the manifest validators reject those outright.

/** A validated theme artifact fetched from the index. Inert data. */
export interface InstallableThemeArtifact {
  kind: "theme";
  id: string;
  version: string;
  manifest: ThemeArtifactManifest;
  signature?: string;
  signatureState: Extract<SignatureState, "verified" | "unverified">;
}

/** A validated config artifact fetched from the index. Inert data. */
export interface InstallableConfigArtifact {
  kind: "config";
  id: string;
  version: string;
  manifest: ConfigArtifactManifest;
  signature?: string;
  signatureState: Extract<SignatureState, "verified" | "unverified">;
}

export type InstallableArtifact = InstallableThemeArtifact | InstallableConfigArtifact;

export interface RegistryResult {
  /** Tool plugins — the install → enable → run path. */
  entries: InstallableEntry[];
  /** Theme + config data artifacts. Never carry code or capabilities. */
  artifacts: InstallableArtifact[];
  dropped: DroppedEntry[];
}

// ── Signature verification (POLICY real, CRYPTO stubbed) ──────────────────────

/**
 * The verification hook. `keyConfigured` is the policy switch: when true,
 * verification is REQUIRED and an unsigned or bad-signature entry is refused.
 * `verify` is the injected crypto — real Ed25519 in production (once a key
 * exists), a stub today.
 */
export interface SignatureVerifier {
  /** True when an operator configured a verification key ⇒ refuse-by-default. */
  readonly keyConfigured: boolean;
  /**
   * Verify `signature` over the canonical payload of an entry. Returns true
   * only for a good signature. Called ONLY when `keyConfigured` is true and a
   * signature is present.
   */
  verify(canonicalPayload: string, signature: string): boolean;
}

/**
 * The default verifier: NO key configured. Verification is not required, so
 * entries are allowed through as `unverified`. This is what ships until a
 * signing key exists.
 */
export const unconfiguredVerifier: SignatureVerifier = {
  keyConfigured: false,
  verify: () => false,
};

/**
 * STUB verifier — NOT REAL CRYPTO.
 *
 * It declares a key IS configured (so the refuse-by-default policy is in force)
 * but its `verify` refuses EVERYTHING. That is the correct fail-closed
 * behaviour while no real Ed25519 implementation and no real signing key exist:
 * with this verifier installed, every signed entry is refused rather than
 * trusted on the strength of a placeholder check. Swap it for a real injected
 * verifier once signing ships. Do not ship this believing it verifies anything.
 */
export function createStubSignatureVerifier(): SignatureVerifier {
  return {
    keyConfigured: true,
    // Real crypto pending: Ed25519 verify against the configured public key.
    verify: () => false,
  };
}

/**
 * Canonical bytes a signature is computed over: the entry minus its signature,
 * with object keys sorted so serialization is stable. Exported so a signer and
 * this verifier agree byte-for-byte.
 */
export function canonicalEntryPayload(entry: {
  id: string;
  version: string;
  manifest: unknown;
  source: unknown;
}): string {
  return stableStringify({
    id: entry.id,
    version: entry.version,
    manifest: entry.manifest,
    source: entry.source,
  });
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

/**
 * Apply the signature policy to one entry. Pure.
 *
 *   - no key configured  → "unverified" (allowed)
 *   - key, no signature  → "refused-unsigned"
 *   - key, bad signature → "refused-bad-signature"
 *   - key, good signature→ "verified"
 */
export function evaluateSignature(
  entry: { id: string; version: string; manifest: unknown; source: unknown; signature?: string },
  verifier: SignatureVerifier,
): SignatureState {
  if (!verifier.keyConfigured) return "unverified";
  if (typeof entry.signature !== "string" || entry.signature.length === 0) {
    return "refused-unsigned";
  }
  const payload = canonicalEntryPayload(entry);
  return verifier.verify(payload, entry.signature) ? "verified" : "refused-bad-signature";
}

// ── Parsing / validation (pure) ──────────────────────────────────────────────

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function coerceInlineSource(source: unknown): { ok: true; files: Record<string, string> } | { ok: false; reason: string } {
  if (!isPlainObject(source)) return { ok: false, reason: "`source` must be an object" };
  if (source.kind !== "inline") {
    return { ok: false, reason: `unsupported source kind ${JSON.stringify(String(source.kind))}` };
  }
  if (!isPlainObject(source.files)) {
    return { ok: false, reason: "`source.files` must be an object of filename → contents" };
  }
  const files: Record<string, string> = {};
  for (const [name, contents] of Object.entries(source.files)) {
    if (typeof contents !== "string") {
      return { ok: false, reason: `file ${JSON.stringify(name)} contents must be a string` };
    }
    files[name] = contents;
  }
  return { ok: true, files };
}

export interface ParseOptions {
  verifier?: SignatureVerifier;
  reservedToolNames?: readonly string[];
}

/**
 * Turn one raw entry into an {@link InstallableEntry}, or drop it with a reason.
 * A malformed manifest, an entry whose declared `id`/`version` disagree with its
 * manifest, an unusable source, or a signature the policy refuses all yield a
 * drop — never an installable. Pure.
 */
export function installableFromEntry(
  raw: unknown,
  opts: ParseOptions = {},
): { ok: true; entry: InstallableEntry } | { ok: false; dropped: DroppedEntry } {
  const verifier = opts.verifier ?? unconfiguredVerifier;
  if (!isPlainObject(raw)) {
    return { ok: false, dropped: { reason: "entry is not an object" } };
  }
  const id = typeof raw.id === "string" ? raw.id : undefined;

  const validation = validatePluginManifest(raw.manifest, {
    reservedToolNames: opts.reservedToolNames,
  });
  if (!validation.ok) {
    return {
      ok: false,
      dropped: { id, reason: `invalid manifest: ${validation.errors.join("; ")}` },
    };
  }
  const manifest = validation.manifest;

  if (id !== undefined && id !== manifest.id) {
    return {
      ok: false,
      dropped: {
        id,
        reason: `index id "${id}" does not match manifest id "${manifest.id}"`,
      },
    };
  }
  if (typeof raw.version === "string" && raw.version !== manifest.version) {
    return {
      ok: false,
      dropped: {
        id: manifest.id,
        reason: `index version "${raw.version}" does not match manifest version "${manifest.version}"`,
      },
    };
  }

  const source = coerceInlineSource(raw.source);
  if (!source.ok) {
    return { ok: false, dropped: { id: manifest.id, reason: source.reason } };
  }

  const signature = typeof raw.signature === "string" ? raw.signature : undefined;
  const sigState = evaluateSignature(
    { id: manifest.id, version: manifest.version, manifest: raw.manifest, source: raw.source, signature },
    verifier,
  );
  if (sigState === "refused-unsigned" || sigState === "refused-bad-signature") {
    return {
      ok: false,
      dropped: {
        id: manifest.id,
        reason:
          sigState === "refused-unsigned"
            ? "signature required (a verification key is configured) but the entry is unsigned"
            : "signature verification failed",
      },
    };
  }

  return {
    ok: true,
    entry: {
      id: manifest.id,
      version: manifest.version,
      manifest,
      capabilities: aggregateCapabilities(manifest),
      files: source.files,
      signature,
      signatureState: sigState,
    },
  };
}

/**
 * Turn one raw entry into an {@link InstallableArtifact} (theme or config), or
 * drop it with a reason. Applies the SAME signature policy as tool entries, but
 * over a payload with no `source` (data artifacts carry none). Pure.
 *
 * Only ever called for entries whose manifest kind is "theme" or "config"; a
 * tool entry goes through {@link installableFromEntry} instead.
 */
export function artifactFromEntry(
  raw: unknown,
  opts: ParseOptions = {},
): { ok: true; artifact: InstallableArtifact } | { ok: false; dropped: DroppedEntry } {
  const verifier = opts.verifier ?? unconfiguredVerifier;
  if (!isPlainObject(raw)) {
    return { ok: false, dropped: { reason: "entry is not an object" } };
  }
  const id = typeof raw.id === "string" ? raw.id : undefined;
  const kind = manifestKindOf(raw.manifest);

  const validation =
    kind === "theme"
      ? validateThemeArtifact(raw.manifest)
      : validateConfigArtifact(raw.manifest);
  if (!validation.ok) {
    return {
      ok: false,
      dropped: { id, reason: `invalid ${kind ?? "artifact"} manifest: ${validation.errors.join("; ")}` },
    };
  }
  const manifest = validation.manifest;

  if (id !== undefined && id !== manifest.id) {
    return {
      ok: false,
      dropped: { id, reason: `index id "${id}" does not match manifest id "${manifest.id}"` },
    };
  }
  if (typeof raw.version === "string" && raw.version !== manifest.version) {
    return {
      ok: false,
      dropped: {
        id: manifest.id,
        reason: `index version "${raw.version}" does not match manifest version "${manifest.version}"`,
      },
    };
  }
  // Data artifacts must not smuggle a source (which would carry files/code).
  if (raw.source !== undefined) {
    return {
      ok: false,
      dropped: { id: manifest.id, reason: "a theme/config artifact must not carry a `source`" },
    };
  }

  const signature = typeof raw.signature === "string" ? raw.signature : undefined;
  const sigState = evaluateSignature(
    { id: manifest.id, version: manifest.version, manifest: raw.manifest, source: null, signature },
    verifier,
  );
  if (sigState === "refused-unsigned" || sigState === "refused-bad-signature") {
    return {
      ok: false,
      dropped: {
        id: manifest.id,
        reason:
          sigState === "refused-unsigned"
            ? "signature required (a verification key is configured) but the entry is unsigned"
            : "signature verification failed",
      },
    };
  }

  const artifact =
    manifest.kind === "theme"
      ? ({ kind: "theme", id: manifest.id, version: manifest.version, manifest, signature, signatureState: sigState } as InstallableThemeArtifact)
      : ({ kind: "config", id: manifest.id, version: manifest.version, manifest, signature, signatureState: sigState } as InstallableConfigArtifact);
  return { ok: true, artifact };
}

/**
 * Parse an already-fetched index body into a {@link RegistryResult}. Total: any
 * shape yields a result (possibly all-dropped), never a throw. Accepts either
 * `{ entries: [...] }` or a bare array. Tool entries land in `entries`, theme/
 * config entries in `artifacts`, and everything unusable in `dropped`.
 */
export function parseRegistryIndex(raw: unknown, opts: ParseOptions = {}): RegistryResult {
  let list: unknown[];
  if (Array.isArray(raw)) {
    list = raw;
  } else if (isPlainObject(raw) && Array.isArray(raw.entries)) {
    list = raw.entries;
  } else {
    return {
      entries: [],
      artifacts: [],
      dropped: [{ reason: "index must be an array or `{ entries: [...] }`" }],
    };
  }

  const entries: InstallableEntry[] = [];
  const artifacts: InstallableArtifact[] = [];
  const dropped: DroppedEntry[] = [];
  for (const rawEntry of list) {
    if (entries.length + artifacts.length + dropped.length >= MAX_REGISTRY_ENTRIES) {
      dropped.push({ reason: `registry index truncated at ${MAX_REGISTRY_ENTRIES} entries` });
      break;
    }
    const manifest = isPlainObject(rawEntry) ? rawEntry.manifest : undefined;
    const kind = manifestKindOf(manifest);
    if (kind === "theme" || kind === "config") {
      const result = artifactFromEntry(rawEntry, opts);
      if (result.ok) artifacts.push(result.artifact);
      else dropped.push(result.dropped);
    } else {
      // kind "tool" (or absent, or unknown) → the tool path, which reports its
      // own reason for an unknown kind via validatePluginManifest's kind gate.
      const result = installableFromEntry(rawEntry, opts);
      if (result.ok) entries.push(result.entry);
      else dropped.push(result.dropped);
    }
  }
  return { entries, artifacts, dropped };
}

// ── Fetch (injected fetch; HTTPS only) ───────────────────────────────────────

export interface FetchRegistryOptions extends ParseOptions {
  /** Injected fetch. Tests NEVER supply the real one. */
  fetchImpl: typeof fetch;
  /** Hard cap on the fetched index body in bytes. Default {@link MAX_REGISTRY_INDEX_BYTES}. */
  maxIndexBytes?: number;
  /** Abort the fetch after this many ms. Default {@link REGISTRY_FETCH_TIMEOUT_MS}. */
  timeoutMs?: number;
}

/**
 * Read a response body as JSON without buffering an unbounded stream. When the
 * injected fetch exposes a byte stream (real `fetch`), read it chunk-by-chunk
 * and abort past `maxBytes`; otherwise fall back to the mock's `.json()`.
 */
async function readBoundedJson(res: Response, maxBytes: number): Promise<unknown> {
  const reader = (res as { body?: { getReader?: () => ReadableStreamDefaultReader<Uint8Array> } }).body?.getReader?.();
  if (!reader) return res.json();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch { /* best effort */ }
      throw new RangeError(`registry index exceeds ${maxBytes} byte cap`);
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.byteLength; }
  return JSON.parse(new TextDecoder().decode(buf));
}

export type FetchRegistryResult =
  | { ok: true; result: RegistryResult }
  | { ok: false; error: string };

/**
 * Fetch and parse a registry index. Refuses an empty URL (clear no-op) and any
 * non-https URL before touching the network. Never throws — a network or parse
 * failure is reported as `{ ok: false }`.
 */
export async function fetchRegistryIndex(
  url: string,
  opts: FetchRegistryOptions,
): Promise<FetchRegistryResult> {
  const trimmed = (url ?? "").trim();
  if (trimmed.length === 0) {
    return {
      ok: false,
      error:
        "no registry endpoint is configured; set a registry URL to browse or install plugins " +
        "(DEFAULT_REGISTRY_URL is intentionally empty — no marketplace host ships)",
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, error: `registry URL ${JSON.stringify(trimmed)} is not a valid URL` };
  }
  if (parsed.protocol !== "https:") {
    return {
      ok: false,
      error: `registry URL must be https; refusing ${JSON.stringify(parsed.protocol)} (a cleartext index can be rewritten in transit)`,
    };
  }

  const maxBytes = opts.maxIndexBytes ?? MAX_REGISTRY_INDEX_BYTES;
  const timeoutMs = opts.timeoutMs ?? REGISTRY_FETCH_TIMEOUT_MS;
  let body: unknown;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await opts.fetchImpl(trimmed, {
      method: "GET",
      headers: { Accept: "application/json" },
      // The https-only guard above covers only the INITIAL url. Follow no
      // redirect: a 30x to http:// or an internal host would reintroduce the
      // cleartext-downgrade / SSRF we just refused. Fail closed.
      redirect: "manual",
      signal: controller.signal,
    });
    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      return {
        ok: false,
        error: `registry URL redirected (HTTP ${res.status || "opaque"}); refusing to follow (a redirect can downgrade to http or point at an internal host)`,
      };
    }
    if (!res.ok) {
      return { ok: false, error: `registry fetch failed: HTTP ${res.status}` };
    }
    const declared = Number(res.headers?.get?.("content-length") ?? "");
    if (Number.isFinite(declared) && declared > maxBytes) {
      return { ok: false, error: `registry index too large: ${declared} bytes exceeds ${maxBytes} cap` };
    }
    body = await readBoundedJson(res, maxBytes);
  } catch (err) {
    const timedOut = err instanceof Error && err.name === "AbortError";
    return {
      ok: false,
      error: timedOut
        ? `registry fetch timed out after ${timeoutMs}ms`
        : `registry fetch failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    clearTimeout(timer);
  }

  return { ok: true, result: parseRegistryIndex(body, opts) };
}

// ── Pure queries over a parsed result ────────────────────────────────────────

/** Case-insensitive substring match over id, name, version, and tool names. */
export function searchInstallable(entries: readonly InstallableEntry[], query: string): InstallableEntry[] {
  const q = query.trim().toLowerCase();
  if (q.length === 0) return [...entries];
  return entries.filter((e) => {
    if (e.id.toLowerCase().includes(q)) return true;
    if (e.manifest.name.toLowerCase().includes(q)) return true;
    if (e.version.toLowerCase().includes(q)) return true;
    return e.manifest.tools.some((t) => t.name.toLowerCase().includes(q));
  });
}

/** Find one installable entry by exact id. */
export function findInstallable(
  entries: readonly InstallableEntry[],
  id: string,
): InstallableEntry | undefined {
  return entries.find((e) => e.id === id);
}

/** Find one data artifact (theme/config) by exact id. */
export function findArtifact(
  artifacts: readonly InstallableArtifact[],
  id: string,
): InstallableArtifact | undefined {
  return artifacts.find((a) => a.id === id);
}

/** Case-insensitive substring match over a data artifact's id, name, and version. */
export function searchArtifacts(
  artifacts: readonly InstallableArtifact[],
  query: string,
): InstallableArtifact[] {
  const q = query.trim().toLowerCase();
  if (q.length === 0) return [...artifacts];
  return artifacts.filter(
    (a) =>
      a.id.toLowerCase().includes(q) ||
      a.manifest.name.toLowerCase().includes(q) ||
      a.version.toLowerCase().includes(q),
  );
}
