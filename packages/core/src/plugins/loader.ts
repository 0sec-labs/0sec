/**
 * Plugin loader — discovery, spawn, handshake, dispatch (0sec plugin system,
 * stages 2 + 3 of DESIGN.md).
 *
 * This is the HOST side of the boundary whose wire format lives in
 * `protocol.ts`. It is the only module that spawns a plugin, the only module
 * that decides a plugin's tools exist, and the only module that routes a call
 * into one. Everything it does is arranged around four invariants:
 *
 *  1. **One authorization path.** A contributed tool becomes visible to the
 *     engine ONLY through {@link PluginHost.registerTools}, which runs every
 *     tool through `gateFlagsFor` (the single capability→gate translation from
 *     `manifest.ts`) and stores the resulting flags alongside it. `gateMaps()`
 *     then derives the same three `Record<string, true>` shapes the built-ins
 *     use, so a plugin tool declaring `network` is gated by scope-on-demand and
 *     the yolo hard-deny exactly like `http_request`. There is no second,
 *     lighter path — DESIGN.md §2 calls that out as the naive-and-wrong design.
 *
 *  2. **Install ≠ enablement.** Discovery reads ONE explicitly configured
 *     directory under the per-user state dir. It never walks the project tree,
 *     and {@link PluginHost.load} refuses any plugin id absent from the
 *     caller-supplied `enabled` list. Dropping a directory on disk grants
 *     nothing — DESIGN.md §4, and the specific criticism we made of dsh.
 *
 *  3. **The child is untrusted.** It is spawned with no shell, a fixed argv, an
 *     explicit cwd, and an env built by `allowlistedChildEnv` MINUS the target
 *     auth block (see {@link buildPluginEnv}). It receives no scope object, no
 *     auth config, no credentials, and no handle to host state. Everything it
 *     sends back is decoded totally and, for anything reaching a model,
 *     sanitized through the codebase's existing untrusted-input defense.
 *
 *  4. **Fail-soft, always.** A plugin that crashes, hangs, floods stdout, or
 *     answers with garbage degrades to "that plugin is unavailable". It cannot
 *     throw into a turn, cannot block one past a bounded timeout, and cannot
 *     take the session down.
 *
 * ── A plugin CANNOT register a guard, hook, interceptor or listener ──────────
 *
 * This is deliberate and load-bearing, not an unimplemented feature. The wire
 * protocol has no message for it and this loader exposes no API for it: a
 * plugin contributes TOOLS and answers `call_tool`, full stop.
 *
 * The reason is the dsh flaw we are explicitly not reproducing. dsh's
 * `tools/pre-execute` waterfall lets a listener return without calling
 * `next()`, which short-circuits the remainder of the chain — i.e. any plugin
 * that can register an interceptor can SUPPRESS the authorization pipeline that
 * is supposed to be authorizing it. Since 0sec's gates are the only thing
 * standing between a model and un-scoped egress on an authorized engagement,
 * handing that switch to third-party code would void the entire capability
 * model. So: guards are HOST-side only. `plugins/guards.ts` is deny-only and
 * monotonic by construction, its guard set is assembled in-process, and
 * model-authored guards are handled separately by `self-extension.ts`. An
 * out-of-process plugin has no way to add, reorder, or bypass any of them.
 *
 * ── Why `reload()` is only safe at a turn boundary ───────────────────────────
 *
 * A reload is a genuine restart: kill the child, respawn it, re-handshake,
 * re-validate the manifest, re-derive gate flags. It is emphatically NOT
 * module-cache surgery — there is no module to cache, which is one more reason
 * the subprocess design is the right one for hot-swap.
 *
 * The consequence is that a reload MUTATES THE GATE MAPS: tools disappear and
 * (possibly with different capabilities) reappear. The console resolves a
 * call's gate flags at several points spread across a single turn — scope
 * resolution, the yolo hard-deny, the local-directory prompt, the copilot
 * prompt, and the guard floor each read the maps independently. If the maps
 * changed between two of those reads, a call could be approved against one
 * capability set and executed against another: an operator could approve a
 * `filesystem-read` tool and have a reloaded, now-`network` tool run under that
 * approval. Reload must therefore be sequenced between turns, when no call is
 * in flight and no approval decision is outstanding. {@link PluginHost.reload}
 * rejects when the plugin has in-flight calls, but the caller still owns the
 * "no turn is running" half of that contract — the loader cannot see turns.
 */

import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import { homeStateDir } from "@0sec/shared";

import { allowlistedChildEnv } from "../agent/sanitized-env.js";
import type { ToolDefinition, ToolParam } from "../agent/types.js";
import { sanitizeUntrustedToolResult } from "../untrusted-sanitizer.js";
import {
  gateFlagsFor,
  validatePluginManifest,
  type PluginCapability,
  type PluginManifest,
  type PluginToolManifest,
} from "./manifest.js";
import {
  encodeHostMessage,
  FrameReader,
  decodePluginMessage,
  type PluginMessage,
  type ProtocolDecodeFailure,
} from "./protocol.js";

// ── On-disk layout and permissions ───────────────────────────────────────────

/** Directory under the per-user state dir that holds installed plugins. */
export const PLUGINS_ROOT_NAME = "plugins";

/** The manifest filename inside a plugin directory. */
export const PLUGIN_MANIFEST_FILE = "plugin.json";

/**
 * The entrypoint filename inside a plugin directory.
 *
 * FIXED BY CONVENTION, never manifest-controlled. `validatePluginManifest`
 * drops unknown keys, so a manifest has nowhere to put an `exec`/`entry` field
 * — which means a manifest can never point the loader at an arbitrary binary or
 * at a path outside its own directory. The plugin is always run as
 * `<node> <pluginDir>/plugin.js`.
 */
export const PLUGIN_ENTRY_FILE = "plugin.js";

/** Plugin directories are private to the user. */
export const PLUGIN_DIR_MODE = 0o700;
/** Any file this module creates is private to the user. */
export const PLUGIN_FILE_MODE = 0o600;

/** Largest manifest we will read off disk. */
const MAX_MANIFEST_BYTES = 256 * 1024;

// ── Defaults / bounds ────────────────────────────────────────────────────────

/** A plugin that has not handshaken within this window is killed, not awaited. */
export const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5_000;
/** A `call_tool` that has not answered within this window fails, not hangs. */
export const DEFAULT_CALL_TIMEOUT_MS = 30_000;
/** Concurrent in-flight calls per plugin. Beyond this, calls fail fast. */
export const MAX_INFLIGHT_CALLS = 16;
/**
 * Undecodable / uncorrelatable frames a plugin may emit before we stop
 * believing it speaks the protocol at all and mark it unavailable. This is the
 * "floods stdout with garbage" containment: framing bounds the memory, this
 * bounds the CPU and the log noise.
 */
export const MAX_PROTOCOL_ERRORS = 32;

// ── Plugin id safety ─────────────────────────────────────────────────────────

/**
 * Plugin id charset, mirroring `manifest.ts`'s own rule (which is not exported).
 * Applied BEFORE any path join.
 *
 * Traversal is REJECTED, never sanitized: there is no stripping of `..`, no
 * normalization, no "clean it up and continue". `.`/`..`, any `/` or `\`, any
 * NUL, any absolute path, any Windows drive letter, and anything with an
 * uppercase or non-ASCII character all fail this test outright, because a
 * sanitizer is a thing that can be wrong once and a rejection cannot.
 */
const PLUGIN_ID_RE = /^[a-z][a-z0-9]*([._-][a-z0-9]+)*$/;
const PLUGIN_ID_MAX = 64;

/** True only for an id that is safe to use as a single path segment. */
export function isSafePluginId(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > PLUGIN_ID_MAX) return false;
  if (value === "." || value === "..") return false;
  if (value.includes("/") || value.includes("\\") || value.includes("\0")) return false;
  return PLUGIN_ID_RE.test(value);
}

/** Absolute path of the plugin root: `<homeStateDir>/plugins`. */
export function pluginsRootDir(homeDir?: string): string {
  return join(homeStateDir(homeDir), PLUGINS_ROOT_NAME);
}

/**
 * Create the plugin root `0700` if absent and repair its mode if present.
 * Best-effort: a failure here is reported by returning `false`, never thrown.
 */
export function ensurePluginsRoot(dir: string): boolean {
  try {
    mkdirSync(dir, { recursive: true, mode: PLUGIN_DIR_MODE });
    chmodSync(dir, PLUGIN_DIR_MODE);
    return true;
  } catch {
    return false;
  }
}

// ── Discovery ────────────────────────────────────────────────────────────────

export interface DiscoveredPlugin {
  id: string;
  dir: string;
  manifestPath: string;
  entryPath: string;
  manifest: PluginManifest;
}

export type DiscoveryResult =
  | { ok: true; plugin: DiscoveredPlugin }
  | { ok: false; errors: string[] };

/**
 * Enumerate the plugin ids INSTALLED under `root`. This is an inventory for a
 * UI, not an activation: nothing here loads, spawns, or enables anything, and
 * an entry appearing in this list has no effect on a session until an operator
 * puts its id in the `enabled` set. Directory names that are not safe plugin
 * ids are skipped silently rather than sanitized.
 */
export function listInstalledPluginIds(root: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const name of entries) {
    if (!isSafePluginId(name)) continue;
    try {
      if (!statSync(join(root, name)).isDirectory()) continue;
    } catch {
      continue;
    }
    out.push(name);
  }
  return out.sort();
}

/**
 * Read and validate one installed plugin's manifest. Total: every failure mode
 * (bad id, missing directory, missing/oversized/unparseable manifest, manifest
 * that fails stage-1 validation, id mismatch, missing entrypoint) returns
 * errors instead of throwing.
 */
export function readInstalledPlugin(
  root: string,
  pluginId: string,
  opts?: { reservedToolNames?: readonly string[] },
): DiscoveryResult {
  if (!isSafePluginId(pluginId)) {
    return {
      ok: false,
      errors: [
        `plugin id ${JSON.stringify(String(pluginId))} is not a safe identifier; ` +
          "ids must match ^[a-z][a-z0-9]*([._-][a-z0-9]+)*$ and are rejected, not sanitized",
      ],
    };
  }
  if (!isAbsolute(root)) {
    return { ok: false, errors: ["plugin root must be an absolute path"] };
  }

  const dir = join(root, pluginId);
  const manifestPath = join(dir, PLUGIN_MANIFEST_FILE);
  const entryPath = join(dir, PLUGIN_ENTRY_FILE);

  let rawText: string;
  try {
    const stat = statSync(manifestPath);
    if (!stat.isFile()) {
      return { ok: false, errors: [`${PLUGIN_MANIFEST_FILE} is not a regular file`] };
    }
    if (stat.size > MAX_MANIFEST_BYTES) {
      return {
        ok: false,
        errors: [`${PLUGIN_MANIFEST_FILE} exceeds ${MAX_MANIFEST_BYTES} bytes`],
      };
    }
    rawText = readFileSync(manifestPath, "utf-8");
  } catch {
    return { ok: false, errors: [`no readable ${PLUGIN_MANIFEST_FILE} for plugin "${pluginId}"`] };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return { ok: false, errors: [`${PLUGIN_MANIFEST_FILE} is not valid JSON`] };
  }

  const result = validatePluginManifest(parsed, {
    reservedToolNames: opts?.reservedToolNames,
  });
  if (!result.ok) return { ok: false, errors: result.errors };

  if (result.manifest.id !== pluginId) {
    return {
      ok: false,
      errors: [
        `manifest declares id "${result.manifest.id}" but is installed as "${pluginId}"; ` +
          "a plugin may not claim another plugin's identity",
      ],
    };
  }
  if (!existsSync(entryPath)) {
    return { ok: false, errors: [`plugin "${pluginId}" has no ${PLUGIN_ENTRY_FILE} entrypoint`] };
  }

  return { ok: true, plugin: { id: pluginId, dir, manifestPath, entryPath, manifest: result.manifest } };
}

// ── Transport ────────────────────────────────────────────────────────────────

/** Exactly what the host will exec. No shell string exists anywhere. */
export interface PluginSpawnSpec {
  command: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
}

/** Callbacks the loader hands the transport at spawn time (never later). */
export interface PluginChannelHandlers {
  /** A raw stdout chunk from the child. May be a partial frame. */
  onData(chunk: string): void;
  /** The child is gone (exit, signal, or spawn error). Called at most once. */
  onExit(reason: string): void;
}

export interface PluginChannel {
  /** Write already-framed bytes to the child's stdin. Must not throw. */
  write(data: string): void;
  /** Terminate the child unconditionally. Must be idempotent and not throw. */
  kill(): void;
}

/**
 * Injection seam. Unit tests supply a fake transport so no real process is
 * spawned; one integration test uses {@link nodeChildSpawner} against a tiny
 * inline script to prove the real stdio path works.
 */
export type PluginSpawner = (
  spec: PluginSpawnSpec,
  handlers: PluginChannelHandlers,
) => PluginChannel;

/**
 * Build the child environment.
 *
 * `allowlistedChildEnv` is the codebase's single answer to "what may a child
 * process see" — an ALLOWLIST, not a denylist, precisely because a denylist
 * always misses the next secret. A recent audit found five separate credential
 * leaks from children handed `process.env`; this is not going to be the sixth.
 *
 * Plugins then get LESS than that baseline. The allowlist deliberately carries
 * `TARGET` / `AUTH_HEADER` / `AUTH_VALUE` / `AUTH_CURL_FLAG` because 0sec's own
 * scanner children legitimately authenticate to the engagement target. A
 * third-party plugin is a strictly lower trust tier and, per the plugin
 * security contract, receives no auth config at all — so those four names are
 * subtracted here. Everything a plugin needs to reach the target must arrive as
 * `call_tool` arguments the operator's gates have already authorized.
 */
export function buildPluginEnv(
  pluginId: string,
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const base = allowlistedChildEnv(
    {
      // Non-secret, and screened by `allowlistedChildEnv` regardless.
      "0SEC_PLUGIN_ID": pluginId,
      "0SEC_PLUGIN_PROTOCOL": "1",
    },
    env,
  );
  for (const name of TARGET_AUTH_ENV_NAMES) delete base[name];
  return base;
}

/** Target-auth names withheld from plugins (see {@link buildPluginEnv}). */
const TARGET_AUTH_ENV_NAMES = ["TARGET", "AUTH_HEADER", "AUTH_VALUE", "AUTH_CURL_FLAG"] as const;

/**
 * The real transport: a `node:child_process` spawn hardened as follows.
 *
 *   - `shell: false` (the default, stated explicitly) — no string is ever
 *     handed to a shell, so nothing in a plugin id, path, or manifest can be
 *     shell-interpreted.
 *   - Fixed argv: `[<entry>]` under the CURRENT node binary (`process.execPath`).
 *     The plugin does not choose the interpreter and does not choose the flags.
 *   - `cwd` set EXPLICITLY to the plugin's own directory, never inherited — a
 *     child that inherits the operator's cwd starts life pointed at the
 *     engagement repo.
 *   - `env` from {@link buildPluginEnv}: an allowlist minus target auth.
 *   - `detached: false` so the child dies with its process group rather than
 *     surviving as an orphan holding an open socket.
 *   - stdio fully piped; stderr is read and DISCARDED after a bounded prefix so
 *     a child cannot flood the operator's terminal or the host's memory.
 */
export const nodeChildSpawner: PluginSpawner = (spec, handlers) => {
  let exited = false;
  const finish = (reason: string): void => {
    if (exited) return;
    exited = true;
    handlers.onExit(reason);
  };

  let child: ReturnType<typeof spawn>;
  try {
    child = spawn(spec.command, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      shell: false,
      detached: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err) {
    // Spawn can throw synchronously (ENOENT on some platforms, EACCES, …).
    // Report it through the same path as any other death.
    queueMicrotask(() => finish(`plugin failed to spawn: ${describeError(err)}`));
    return { write: () => {}, kill: () => {} };
  }

  child.stdout?.setEncoding("utf-8");
  child.stdout?.on("data", (chunk: string) => {
    try {
      handlers.onData(chunk);
    } catch {
      // A handler must never be able to kill the stream reader.
    }
  });
  // stderr is drained (never left to fill the pipe buffer and deadlock the
  // child) and bounded. It is intentionally not surfaced as protocol data.
  let stderrSeen = 0;
  child.stderr?.setEncoding("utf-8");
  child.stderr?.on("data", (chunk: string) => {
    stderrSeen = Math.min(stderrSeen + chunk.length, 1_000_000);
  });
  child.on("error", (err) => finish(`plugin process error: ${describeError(err)}`));
  child.on("exit", (code, signal) =>
    finish(
      signal
        ? `plugin process terminated by ${signal}`
        : `plugin process exited with code ${code ?? "unknown"}`,
    ),
  );
  child.stdin?.on("error", () => {
    // EPIPE when the child is already gone. The `exit` handler owns the
    // teardown; swallowing here keeps a write from becoming an unhandled error.
  });

  return {
    write(data: string): void {
      try {
        child.stdin?.write(data);
      } catch {
        // Best-effort: a failed write becomes a call timeout, not a throw.
      }
    },
    kill(): void {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already dead.
      }
    },
  };
};

function describeError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// ── Registry ─────────────────────────────────────────────────────────────────

/**
 * One contributed tool as the host sees it. The three flags are the OUTPUT of
 * `gateFlagsFor` and nothing else ever computes them — that is what makes the
 * single-authorization-path invariant checkable.
 */
export interface RegisteredPluginTool {
  readonly pluginId: string;
  readonly name: string;
  readonly definition: ToolDefinition;
  readonly capabilities: readonly PluginCapability[];
  readonly networkCapable: boolean;
  readonly localScope: boolean;
  readonly readOnly: boolean;
}

/** The three name-keyed maps the console's gates read. */
export interface PluginGateMaps {
  networkCapable: Record<string, true>;
  localScope: Record<string, true>;
  readOnly: Record<string, true>;
}

// ── Events ───────────────────────────────────────────────────────────────────

export type PluginHostEvent =
  | { type: "plugin_loaded"; pluginId: string; tools: string[] }
  | { type: "plugin_unloaded"; pluginId: string; tools: string[] }
  | { type: "plugin_unavailable"; pluginId: string; reason: string; tools: string[] }
  | { type: "plugin_protocol_error"; pluginId: string; reason: string; detail: string };

// ── Results ──────────────────────────────────────────────────────────────────

export type LoadResult =
  | { ok: true; pluginId: string; tools: string[] }
  | { ok: false; pluginId: string; errors: string[] };

export type PluginCallResult =
  | {
      ok: true;
      /** Sanitized and framed; safe to hand to a model context. */
      content: string;
      /** True when the plugin itself reported failure (content is the reason). */
      failed: boolean;
      truncated: boolean;
      neutralized: boolean;
      markers: string[];
    }
  | { ok: false; error: string };

// ── Internal per-plugin state ────────────────────────────────────────────────

type PluginState = "loading" | "ready" | "unavailable";

interface PendingCall {
  resolve(result: PluginCallResult): void;
  timer: ReturnType<typeof setTimeout>;
}

interface LivePlugin {
  readonly id: string;
  readonly manifest: PluginManifest;
  readonly channel: PluginChannel;
  readonly reader: FrameReader;
  /** Bumped on every (re)spawn so a dead child's late events are ignored. */
  readonly generation: number;
  state: PluginState;
  toolNames: string[];
  pending: Map<string, PendingCall>;
  protocolErrors: number;
  onHandshake?: (msg: PluginMessage | null, failure?: string) => void;
}

export interface PluginHostOptions {
  /**
   * Absolute plugin root. Defaults to `<homeStateDir>/plugins`. An explicit
   * value exists for tests and for an operator who keeps state elsewhere; it is
   * NEVER derived from the project tree, and no directory is ever scanned for
   * plugins other than this one.
   */
  pluginsDir?: string;
  homeDir?: string;
  /**
   * Ids the operator has EXPLICITLY enabled (per-project, per DESIGN.md §4).
   * `load()` refuses anything not in this set. Installing is not enabling.
   */
  enabled?: readonly string[];
  /**
   * Built-in tool names a plugin may not shadow — the keys of `TOOL_DISPATCH`
   * plus the three gate maps. Supplied by the caller so this module never
   * imports the engine (and never drifts from it silently).
   */
  reservedToolNames?: readonly string[];
  /** Version of @0sec/core, for `minCoreVersion` enforcement. */
  coreVersion?: string;
  spawner?: PluginSpawner;
  handshakeTimeoutMs?: number;
  callTimeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  onEvent?: (event: PluginHostEvent) => void;
}

/**
 * Owns every loaded plugin, its child process, and the registry of contributed
 * tools. One instance per session.
 */
export class PluginHost {
  private readonly plugins = new Map<string, LivePlugin>();
  /** name → tool. The SINGLE source of truth for what a plugin contributed. */
  private readonly tools = new Map<string, RegisteredPluginTool>();
  private readonly reserved: ReadonlySet<string>;
  private readonly enabled: ReadonlySet<string>;
  private readonly root: string;
  private readonly spawner: PluginSpawner;
  private readonly handshakeTimeoutMs: number;
  private readonly callTimeoutMs: number;
  private readonly env: NodeJS.ProcessEnv;
  private readonly coreVersion: string | undefined;
  private readonly onEvent: ((event: PluginHostEvent) => void) | undefined;
  private generation = 0;
  private callSeq = 0;

  constructor(opts: PluginHostOptions = {}) {
    this.root = opts.pluginsDir ?? pluginsRootDir(opts.homeDir);
    this.enabled = new Set(opts.enabled ?? []);
    this.reserved = new Set(opts.reservedToolNames ?? []);
    this.spawner = opts.spawner ?? nodeChildSpawner;
    this.handshakeTimeoutMs = opts.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
    this.callTimeoutMs = opts.callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS;
    this.env = opts.env ?? process.env;
    this.coreVersion = opts.coreVersion;
    this.onEvent = opts.onEvent;
  }

  // ── Registry reads ─────────────────────────────────────────────────────────

  /** Tool definitions to merge into `getToolsForRole`. Sorted, stable. */
  toolDefinitions(): ToolDefinition[] {
    return [...this.tools.values()]
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((t) => t.definition);
  }

  /** Every registered tool with its resolved gate flags. */
  registeredTools(): RegisteredPluginTool[] {
    return [...this.tools.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * The three gate maps, derived fresh from `gateFlagsFor` output. The console
   * merges these into its own literals so plugin tools land in the SAME maps as
   * the built-ins.
   */
  gateMaps(): PluginGateMaps {
    const maps: PluginGateMaps = {
      networkCapable: Object.create(null) as Record<string, true>,
      localScope: Object.create(null) as Record<string, true>,
      readOnly: Object.create(null) as Record<string, true>,
    };
    for (const tool of this.tools.values()) {
      if (tool.networkCapable) maps.networkCapable[tool.name] = true;
      if (tool.localScope) maps.localScope[tool.name] = true;
      if (tool.readOnly) maps.readOnly[tool.name] = true;
    }
    return maps;
  }

  /**
   * Flags for one tool, or `undefined` when this host does not own the name.
   * Lets the console set `capabilitiesResolved` truthfully for a plugin tool
   * instead of denying it as "unknown" via `guardUnresolvedCapabilities`.
   */
  capabilityFlagsFor(
    name: string,
  ): { networkCapable: boolean; localScope: boolean; readOnly: boolean } | undefined {
    const tool = this.tools.get(name);
    if (!tool) return undefined;
    return {
      networkCapable: tool.networkCapable,
      localScope: tool.localScope,
      readOnly: tool.readOnly,
    };
  }

  /** True when `name` is a currently-registered plugin tool. */
  ownsTool(name: string): boolean {
    return this.tools.has(name);
  }

  /** Ids currently loaded, with their state. Diagnostics / UI. */
  status(): { pluginId: string; state: PluginState; tools: string[] }[] {
    return [...this.plugins.values()]
      .map((p) => ({ pluginId: p.id, state: p.state, tools: [...p.toolNames] }))
      .sort((a, b) => a.pluginId.localeCompare(b.pluginId));
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  /**
   * Discover, validate, spawn, handshake and register one plugin.
   *
   * Nothing is registered until the handshake has succeeded AND the running
   * child's announced tool set matches the on-disk manifest the operator
   * enabled. Any failure kills the child and leaves the registry byte-identical
   * to what it was before the call.
   */
  async load(pluginId: string): Promise<LoadResult> {
    if (!isSafePluginId(pluginId)) {
      return {
        ok: false,
        pluginId: String(pluginId),
        errors: [
          `plugin id ${JSON.stringify(String(pluginId))} is not a safe identifier; rejected before any path join`,
        ],
      };
    }
    if (this.plugins.has(pluginId)) {
      return { ok: false, pluginId, errors: [`plugin "${pluginId}" is already loaded`] };
    }
    // DESIGN.md §4: install must not imply enablement.
    if (!this.enabled.has(pluginId)) {
      return {
        ok: false,
        pluginId,
        errors: [
          `plugin "${pluginId}" is installed but not enabled for this project; ` +
            "an operator must enable it explicitly",
        ],
      };
    }

    const discovered = readInstalledPlugin(this.root, pluginId, {
      reservedToolNames: [...this.reserved],
    });
    if (!discovered.ok) return { ok: false, pluginId, errors: discovered.errors };
    const { manifest, dir, entryPath } = discovered.plugin;

    if (manifest.minCoreVersion && this.coreVersion) {
      if (!satisfiesMinVersion(this.coreVersion, manifest.minCoreVersion)) {
        return {
          ok: false,
          pluginId,
          errors: [
            `plugin "${pluginId}" requires @0sec/core >= ${manifest.minCoreVersion}, running ${this.coreVersion}`,
          ],
        };
      }
    }

    // Cross-plugin collisions. Built-in collisions were already rejected by
    // `validatePluginManifest` via `reservedToolNames`; this catches two
    // plugins claiming the same name. Rejected wholesale — never partially
    // registered, never shadowing.
    const collisions = manifest.tools.map((t) => t.name).filter((n) => this.tools.has(n));
    if (collisions.length > 0) {
      return {
        ok: false,
        pluginId,
        errors: [
          `plugin "${pluginId}" declares tool name(s) already contributed by another plugin: ${collisions.join(", ")}`,
        ],
      };
    }

    const spec: PluginSpawnSpec = {
      command: process.execPath,
      args: [entryPath],
      cwd: dir,
      env: buildPluginEnv(pluginId, this.env),
    };

    const generation = ++this.generation;
    const reader = new FrameReader();
    let live: LivePlugin;

    const channel = this.spawner(spec, {
      onData: (chunk) => this.handleData(pluginId, generation, chunk),
      onExit: (reason) => this.handleExit(pluginId, generation, reason),
    });

    live = {
      id: pluginId,
      manifest,
      channel,
      reader,
      generation,
      state: "loading",
      toolNames: [],
      pending: new Map(),
      protocolErrors: 0,
    };
    this.plugins.set(pluginId, live);

    const handshake = await this.awaitHandshake(live);
    if (!handshake.ok) {
      this.teardown(pluginId, handshake.error, /* emitUnavailable */ false);
      return { ok: false, pluginId, errors: [handshake.error] };
    }

    // The running child must match what the operator approved on disk.
    // Enablement approved a specific capability set; a child that announces a
    // different one at runtime is refused rather than silently trusted.
    const drift = manifestDrift(manifest, handshake.manifest);
    if (drift.length > 0) {
      this.teardown(pluginId, "handshake manifest diverged from the enabled manifest", false);
      return { ok: false, pluginId, errors: drift };
    }

    // Register from the ON-DISK manifest — the artifact the operator enabled.
    const names = this.registerTools(pluginId, manifest.tools);
    live.state = "ready";
    live.toolNames = names;
    this.emit({ type: "plugin_loaded", pluginId, tools: [...names] });
    return { ok: true, pluginId, tools: names };
  }

  /**
   * Kill the child and remove every tool it contributed. After `unload`, the
   * registry is identical to what it was before the matching `load`.
   */
  unload(pluginId: string): void {
    const live = this.plugins.get(pluginId);
    if (!live) return;
    const tools = [...live.toolNames];
    this.teardown(pluginId, "plugin unloaded by the operator", false);
    this.emit({ type: "plugin_unloaded", pluginId, tools });
  }

  /**
   * Genuine restart: kill + respawn + re-handshake + re-validate. See the
   * module header for why this is only safe at a turn boundary.
   *
   * Refused while calls are in flight — tearing the child down mid-call would
   * strand the turn on a tool whose gate flags are about to change.
   */
  async reload(pluginId: string): Promise<LoadResult> {
    const live = this.plugins.get(pluginId);
    if (live && live.pending.size > 0) {
      return {
        ok: false,
        pluginId,
        errors: [
          `plugin "${pluginId}" has ${live.pending.size} call(s) in flight; ` +
            "reload is only safe at a turn boundary",
        ],
      };
    }
    this.unload(pluginId);
    return this.load(pluginId);
  }

  /** Unload everything. Safe to call twice. */
  shutdown(): void {
    for (const id of [...this.plugins.keys()]) this.unload(id);
  }

  // ── Dispatch ───────────────────────────────────────────────────────────────

  /**
   * Invoke a contributed tool. NEVER throws and never waits longer than the
   * per-call timeout. A dead, hung, unavailable, or unknown plugin resolves to
   * `{ ok: false }` so the turn continues with a tool error instead of a crash.
   *
   * NOTE ON AUTHORIZATION: this is the DISPATCH path, deliberately downstream
   * of the gates. The console must have already run its scope / local-scope /
   * copilot / guard checks using the flags in `gateMaps()`. This method does
   * not re-implement them — two authorization paths is the anti-pattern
   * DESIGN.md §2 rejects.
   */
  async call(
    toolName: string,
    args: Record<string, unknown>,
    opts?: { timeoutMs?: number },
  ): Promise<PluginCallResult> {
    const tool = this.tools.get(toolName);
    if (!tool) return { ok: false, error: `no plugin contributes a tool named "${toolName}"` };

    const live = this.plugins.get(tool.pluginId);
    if (!live || live.state !== "ready") {
      return {
        ok: false,
        error: `plugin "${tool.pluginId}" is unavailable; tool "${toolName}" cannot run`,
      };
    }
    if (live.pending.size >= MAX_INFLIGHT_CALLS) {
      return {
        ok: false,
        error: `plugin "${tool.pluginId}" already has ${MAX_INFLIGHT_CALLS} calls in flight`,
      };
    }

    const id = `c${++this.callSeq}`;
    const timeoutMs = opts?.timeoutMs ?? this.callTimeoutMs;

    return new Promise<PluginCallResult>((resolve) => {
      let settled = false;
      const settle = (result: PluginCallResult): void => {
        if (settled) return;
        settled = true;
        const entry = live.pending.get(id);
        if (entry) {
          clearTimeout(entry.timer);
          live.pending.delete(id);
        }
        resolve(result);
      };

      const timer = setTimeout(() => {
        // No retry, ever: a hung plugin that is retried is a hung plugin twice.
        settle({
          ok: false,
          error: `plugin "${tool.pluginId}" did not answer tool "${toolName}" within ${timeoutMs}ms`,
        });
      }, timeoutMs);
      timer.unref?.();

      live.pending.set(id, { resolve: settle, timer });
      live.channel.write(
        encodeHostMessage({ v: 1, kind: "call_tool", id, tool: toolName, args }),
      );
    });
  }

  // ── Internals ──────────────────────────────────────────────────────────────

  /**
   * THE SINGLE REGISTRATION PATH.
   *
   * Every contributed tool in the entire system passes through this function
   * and nowhere else. It is the only writer of `this.tools`, and it is the only
   * caller of `gateFlagsFor` in this module. That is what makes the invariant
   * auditable: you cannot add a plugin tool to the registry without its gate
   * flags being computed by the same conservative translation the built-ins'
   * capabilities would go through, and you cannot compute those flags in a
   * second, laxer place because there is no second place.
   */
  private registerTools(pluginId: string, tools: readonly PluginToolManifest[]): string[] {
    const names: string[] = [];
    for (const tool of tools) {
      const flags = gateFlagsFor(tool);
      const definition: ToolDefinition = {
        name: tool.name,
        description: tool.description,
        parameters: toToolParams(tool.parameters),
      };
      if (tool.required && tool.required.length > 0) definition.required = [...tool.required];

      this.tools.set(tool.name, {
        pluginId,
        name: tool.name,
        definition,
        capabilities: [...tool.capabilities],
        networkCapable: flags.networkCapable,
        localScope: flags.localScope,
        readOnly: flags.readOnly,
      });
      names.push(tool.name);
    }
    return names;
  }

  /** Wait for the first well-formed handshake, or kill the child. */
  private awaitHandshake(
    live: LivePlugin,
  ): Promise<{ ok: true; manifest: PluginManifest } | { ok: false; error: string }> {
    return new Promise((resolve) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        live.onHandshake = undefined;
        // Killed, not awaited: a plugin that cannot say hello in time is not a
        // plugin we wait on while the operator's session stalls.
        resolve({
          ok: false,
          error: `plugin "${live.id}" did not handshake within ${this.handshakeTimeoutMs}ms; child killed`,
        });
      }, this.handshakeTimeoutMs);
      timer.unref?.();

      live.onHandshake = (msg, failure) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        live.onHandshake = undefined;
        if (!msg || msg.kind !== "handshake") {
          resolve({ ok: false, error: failure ?? `plugin "${live.id}" failed to handshake` });
          return;
        }
        resolve({ ok: true, manifest: msg.manifest });
      };
    });
  }

  /**
   * Liveness test used between every step of frame handling.
   *
   * `teardown` DELETES the plugin record, so identity against the map is the
   * authoritative "is this child still ours" question — it is true only for the
   * current generation of a still-loaded plugin. Checking it after each frame
   * is what stops a burst of frames from continuing to be processed (or worse,
   * dispatched) after one of them killed the plugin.
   */
  private isLive(live: LivePlugin): boolean {
    return this.plugins.get(live.id) === live;
  }

  /** stdout chunk → frames → decoded messages. Never throws. */
  private handleData(pluginId: string, generation: number, chunk: string): void {
    const live = this.plugins.get(pluginId);
    // A late chunk from a killed child must never touch the new one.
    if (!live || live.generation !== generation) return;

    const batch = live.reader.push(chunk);
    for (const failure of batch.failures) {
      this.noteProtocolError(live, failure);
      if (!this.isLive(live)) return;
    }

    for (const frame of batch.frames) {
      const decoded = decodePluginMessage(frame, {
        reservedToolNames: [...this.reserved],
        expectPluginId: pluginId,
      });
      if (!decoded.ok) {
        // A malformed handshake must fail the load rather than sit until the
        // handshake timeout: report it to the waiter, then count it.
        if (live.onHandshake) live.onHandshake(null, `${decoded.reason}: ${decoded.detail}`);
        this.noteProtocolError(live, decoded);
        if (!this.isLive(live)) return;
        continue;
      }
      this.handleMessage(live, decoded.message);
      if (!this.isLive(live)) return;
    }
  }

  private handleMessage(live: LivePlugin, msg: PluginMessage): void {
    switch (msg.kind) {
      case "handshake": {
        if (live.onHandshake) {
          live.onHandshake(msg);
          return;
        }
        // A second handshake is a protocol violation, not a re-registration:
        // accepting one would let a running plugin swap its own capabilities
        // out from under the gate maps mid-session.
        this.noteProtocolError(live, {
          ok: false,
          reason: "unknown-kind",
          detail: "plugin sent a second handshake after it was already loaded",
        });
        return;
      }
      case "tool_result": {
        const pending = live.pending.get(msg.id);
        if (!pending) {
          // Uncorrelated result: either a duplicate answer or unsolicited
          // traffic. Counted, so a flood of them costs the plugin its life.
          this.noteProtocolError(live, {
            ok: false,
            reason: "malformed-field",
            detail: `tool_result for unknown or already-settled call id`,
          });
          return;
        }
        const sanitized = sanitizeUntrustedToolResult(msg.content);
        pending.resolve({
          ok: true,
          content: sanitized.content,
          failed: !msg.ok,
          truncated: msg.truncated,
          neutralized: sanitized.neutralized,
          markers: sanitized.markers,
        });
        return;
      }
      case "error": {
        if (msg.id) {
          const pending = live.pending.get(msg.id);
          if (pending) {
            pending.resolve({
              ok: false,
              error: `plugin "${live.id}" reported ${msg.code}: ${msg.message.slice(0, 500)}`,
            });
            return;
          }
        }
        this.noteProtocolError(live, {
          ok: false,
          reason: "malformed-field",
          detail: `plugin-level error ${msg.code}`,
        });
        return;
      }
      case "list_tools": {
        // The manifest is the contract; a runtime tool list cannot widen it.
        // We accept and ignore the frame so a chatty SDK is not fatal.
        return;
      }
    }
  }

  /**
   * Count one protocol violation. Past {@link MAX_PROTOCOL_ERRORS} the plugin
   * is no longer treated as speaking the protocol and is torn down. Combined
   * with `FrameReader`'s memory bound, this is the full "floods stdout"
   * containment: bounded memory, bounded work, bounded lifetime.
   */
  private noteProtocolError(live: LivePlugin, failure: ProtocolDecodeFailure): void {
    if (!this.isLive(live)) return;
    live.protocolErrors += 1;
    this.emit({
      type: "plugin_protocol_error",
      pluginId: live.id,
      reason: failure.reason,
      detail: failure.detail,
    });
    if (live.protocolErrors > MAX_PROTOCOL_ERRORS) {
      this.teardown(
        live.id,
        `plugin "${live.id}" exceeded ${MAX_PROTOCOL_ERRORS} protocol errors`,
        true,
      );
    }
  }

  /** The child died on its own. Same containment as any other failure. */
  private handleExit(pluginId: string, generation: number, reason: string): void {
    const live = this.plugins.get(pluginId);
    if (!live || live.generation !== generation) return;
    if (live.onHandshake) {
      live.onHandshake(null, `plugin "${pluginId}" died before handshaking: ${reason}`);
      return;
    }
    this.teardown(pluginId, reason, true);
  }

  /**
   * ATOMIC crash containment.
   *
   * Removing the tools, marking the plugin unavailable and dropping it from the
   * plugin map happen in one synchronous block with no `await` between them, so
   * there is no interleaving in which `call()` finds a tool in the registry
   * whose plugin has already died. After this returns, dispatching into a dead
   * child is impossible by construction: the name is simply not in `this.tools`.
   */
  private teardown(pluginId: string, reason: string, emitUnavailable: boolean): void {
    const live = this.plugins.get(pluginId);
    if (!live) return;

    live.state = "unavailable";
    const tools = [...live.toolNames];

    // 1. De-register every tool this plugin owned.
    for (const name of tools) {
      const entry = this.tools.get(name);
      if (entry?.pluginId === pluginId) this.tools.delete(name);
    }
    live.toolNames = [];

    // 2. Drop the plugin record.
    this.plugins.delete(pluginId);

    // 3. Fail every in-flight call with a real answer (never leave a turn
    //    awaiting a promise that can no longer settle).
    const pending = [...live.pending.values()];
    live.pending.clear();
    for (const p of pending) {
      clearTimeout(p.timer);
      p.resolve({ ok: false, error: `plugin "${pluginId}" is unavailable: ${reason}` });
    }

    // 4. Release the handshake waiter, if any.
    const waiter = live.onHandshake;
    live.onHandshake = undefined;
    if (waiter) waiter(null, reason);

    // 5. Kill the child last, so no late event can find live state.
    try {
      live.channel.kill();
    } catch {
      // Best-effort.
    }
    live.reader.reset();

    if (emitUnavailable) {
      this.emit({ type: "plugin_unavailable", pluginId, reason, tools });
    }
  }

  /** Event delivery is fail-soft: a throwing consumer cannot break a load. */
  private emit(event: PluginHostEvent): void {
    if (!this.onEvent) return;
    try {
      this.onEvent(event);
    } catch {
      // Never let an observer affect plugin lifecycle.
    }
  }
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

/**
 * Compare the enabled (on-disk) manifest with what the running child announced.
 * Returns a list of divergences; empty means they agree.
 *
 * Why this matters: enablement is an operator approving a specific set of tools
 * and capabilities. If the child could announce something else at runtime, an
 * approved `filesystem-read` plugin could come up as a `network` one, and the
 * approval would be for a program that no longer exists.
 */
export function manifestDrift(onDisk: PluginManifest, announced: PluginManifest): string[] {
  const errors: string[] = [];
  if (onDisk.id !== announced.id) {
    errors.push(`handshake id "${announced.id}" does not match installed id "${onDisk.id}"`);
  }
  if (onDisk.version !== announced.version) {
    errors.push(
      `handshake version "${announced.version}" does not match installed version "${onDisk.version}"`,
    );
  }

  const diskByName = new Map(onDisk.tools.map((t) => [t.name, t]));
  const announcedByName = new Map(announced.tools.map((t) => [t.name, t]));

  for (const name of announcedByName.keys()) {
    if (!diskByName.has(name)) {
      errors.push(`plugin announced tool "${name}" that its installed manifest does not declare`);
    }
  }
  for (const [name, diskTool] of diskByName) {
    const other = announcedByName.get(name);
    if (!other) {
      errors.push(`plugin did not announce declared tool "${name}"`);
      continue;
    }
    const a = [...diskTool.capabilities].sort().join(",");
    const b = [...other.capabilities].sort().join(",");
    if (a !== b) {
      errors.push(
        `tool "${name}" announced capabilities [${b}] but its installed manifest declares [${a}]`,
      );
    }
  }
  return errors;
}

/** `have >= want` for the manifest's semver-ish triple. Total; never throws. */
export function satisfiesMinVersion(have: string, want: string): boolean {
  const parse = (v: string): [number, number, number] | null => {
    const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v);
    if (!m) return null;
    return [Number(m[1]), Number(m[2]), Number(m[3])];
  };
  const h = parse(have);
  const w = parse(want);
  // Unparseable on either side ⇒ fail closed: we cannot prove the requirement
  // is met, so we do not claim it is.
  if (!h || !w) return false;
  for (let i = 0; i < 3; i++) {
    if (h[i] !== w[i]) return h[i] > w[i];
  }
  return true;
}

const PARAM_TYPES = new Set(["string", "number", "boolean", "object", "array"]);

/**
 * Convert a manifest's loose `parameters` bag into typed `ToolParam`s.
 *
 * Total and conservative: an entry that is not a recognizable param shape is
 * DROPPED rather than passed through, because these values are serialized
 * straight into the model's `input_schema` and an arbitrary object there is
 * both a prompt-shaping and a provider-compatibility hazard.
 */
function toToolParams(raw: Record<string, unknown>): Record<string, ToolParam> {
  const out: Record<string, ToolParam> = {};
  if (typeof raw !== "object" || raw === null) return out;
  for (const [key, value] of Object.entries(raw)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") continue;
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    const rec = value as Record<string, unknown>;
    const type = typeof rec.type === "string" && PARAM_TYPES.has(rec.type) ? rec.type : "string";
    const param: ToolParam = {
      type: type as ToolParam["type"],
      description: typeof rec.description === "string" ? rec.description.slice(0, 2000) : "",
    };
    if (Array.isArray(rec.enum) && rec.enum.every((e) => typeof e === "string")) {
      param.enum = rec.enum as string[];
    }
    if (typeof rec.items === "object" && rec.items !== null && !Array.isArray(rec.items)) {
      param.items = rec.items as ToolParam["items"];
    }
    out[key] = param;
  }
  return out;
}
