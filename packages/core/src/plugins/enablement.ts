/**
 * Per-project plugin enablement store (0sec plugin system, DESIGN.md §4).
 *
 * ── The three states this module is the boundary between ──────────────────────
 *
 * DESIGN.md §2/§4 is built on keeping three states strictly separate, and this
 * module owns the wall between the first two:
 *
 *   1. **Installed** — a plugin's files exist under the plugins root. Nothing in
 *      this module (or anywhere on the install path) executes plugin code:
 *      installing writes files, enabling writes ONE json record, and neither
 *      spawns a process, imports a module, or runs a script. Execution only ever
 *      happens in `loader.ts`, at scan time, and ONLY for ids this store reports
 *      as cleanly enabled.
 *   2. **Enabled** — an operator has, for THIS project, recorded that a plugin
 *      may participate. That is exactly what a record here means and nothing
 *      more. `loader.load()` refuses any id absent from the enabled set it is
 *      handed; {@link loadableIds} is what produces that set.
 *   3. **Running** — a tool is actually invoked. That is the loader's subprocess
 *      dispatch and is out of scope here.
 *
 * herdr's model — install implies enablement, code runs at install time — is the
 * thing §2/§4 rejects. Here, install and enable are separate writes, enable is
 * per-project, and enable records the SPECIFIC capability set the operator saw.
 *
 * ── Why enablement pins a capability set (the re-approval rule) ───────────────
 *
 * An operator does not approve "this plugin"; they approve "this plugin doing
 * THESE things" — the aggregated capability set shown at approval time. So the
 * record stores that set. {@link reconcile} then compares it against what the
 * plugin's on-disk manifest declares NOW. If the files vanished, or the current
 * capability set differs from the approved one (a widened set being the
 * dangerous case, but ANY change forces the question), the plugin is reported
 * `stale` / `missing` and {@link loadableIds} EXCLUDES it. A wider capability
 * set than what was approved must never be loaded under the old approval — that
 * would let a plugin update quietly acquire `network` under a `filesystem-read`
 * blessing.
 *
 * ── Keying + storage ─────────────────────────────────────────────────────────
 *
 * The store is keyed by the realpath of the project directory (like the hub
 * mailbox) so a symlink cannot alias two projects into one approval scope, and
 * it lives under the per-user state dir — never in the project tree, which may
 * be a shared clone or a world-readable mount. One file per project, `0600`,
 * under a `0700` directory.
 *
 * ── Totality ─────────────────────────────────────────────────────────────────
 *
 * The pure decision functions never touch I/O. The fs layer NEVER throws: an
 * unreadable, missing, or corrupt store degrades to "nothing is enabled", which
 * is the fail-closed answer — a plugin whose approval cannot be read is not
 * loaded.
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

import { homeStateDir } from "@0sec/shared";

import { isSafePluginId } from "./loader.js";
import { PLUGIN_CAPABILITIES, type PluginCapability, type PluginManifest } from "./manifest.js";

// ── On-disk layout / permissions ─────────────────────────────────────────────

/**
 * Directory under the per-user state dir that holds enablement records. It is
 * DELIBERATELY not the plugins root: a name under the plugins root would be
 * listed by `listInstalledPluginIds` as a phantom installed plugin.
 */
export const ENABLEMENT_DIR_NAME = "plugin-enablement";
/** Records are private to the user. */
export const ENABLEMENT_DIR_MODE = 0o700;
export const ENABLEMENT_FILE_MODE = 0o600;
/** Bump only on an incompatible on-disk shape change. */
export const ENABLEMENT_SCHEMA_VERSION = 1;
/** Largest enablement file we will read off disk. */
const MAX_ENABLEMENT_BYTES = 1024 * 1024;

// ── Record shapes ────────────────────────────────────────────────────────────

/** What the operator approved for one plugin, in one project. */
export interface EnabledPluginRecord {
  /** Plugin version at approval time. Surfaced on drift; does not gate loading. */
  version: string;
  /**
   * The aggregated, sorted, de-duplicated capability set the operator saw and
   * approved. Loadability is gated on this still matching the on-disk manifest.
   */
  capabilities: PluginCapability[];
  /** Injected approval timestamp (ms). Never read from a clock in this module. */
  enabledAt: number;
}

export interface EnablementRecord {
  schema: number;
  /** realpath of the project at write time. Diagnostic only; key is the hash. */
  project: string;
  enabled: Record<string, EnabledPluginRecord>;
}

/** A snapshot of what is actually installed, for {@link reconcile}. */
export interface InstalledPluginView {
  id: string;
  version: string;
  /** Aggregated current capability set (see {@link aggregateCapabilities}). */
  capabilities: PluginCapability[];
}

export type EnablementStatus =
  /** Installed, and its capability set matches what was approved. Loadable. */
  | "enabled"
  /** Installed, but its capability set changed since approval. NOT loadable. */
  | "stale-capabilities"
  /** Enabled but its files are gone. NOT loadable. */
  | "missing";

export interface ReconciledPlugin {
  pluginId: string;
  status: EnablementStatus;
  approvedCapabilities: PluginCapability[];
  approvedVersion: string;
  /** null when the plugin is no longer installed. */
  currentCapabilities: PluginCapability[] | null;
  currentVersion: string | null;
  /** Human-readable explanation, present for non-`enabled` statuses. */
  reason?: string;
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

/** A fresh, empty record for a project with no approvals yet. */
export function emptyEnablement(project = ""): EnablementRecord {
  return { schema: ENABLEMENT_SCHEMA_VERSION, project, enabled: {} };
}

/**
 * The capability set an operator approves for a whole plugin: the union of
 * every tool's declared capabilities, de-duplicated and returned in the stable
 * {@link PLUGIN_CAPABILITIES} order so two equal sets always serialize equal.
 */
export function aggregateCapabilities(manifest: PluginManifest): PluginCapability[] {
  const present = new Set<PluginCapability>();
  for (const tool of manifest.tools ?? []) {
    for (const cap of tool.capabilities ?? []) {
      if ((PLUGIN_CAPABILITIES as readonly string[]).includes(cap)) present.add(cap);
    }
  }
  return PLUGIN_CAPABILITIES.filter((c) => present.has(c));
}

/** Order-independent equality of two capability sets. */
function sameCapabilitySet(a: readonly PluginCapability[], b: readonly PluginCapability[]): boolean {
  const key = (xs: readonly PluginCapability[]): string =>
    PLUGIN_CAPABILITIES.filter((c) => xs.includes(c)).join(",");
  return key(a) === key(b);
}

/** True only when `pluginId` has an approval record in this project. */
export function isEnabled(record: EnablementRecord, pluginId: string): boolean {
  return Object.prototype.hasOwnProperty.call(record.enabled, pluginId);
}

export type EnableResult =
  | { ok: true; record: EnablementRecord }
  | { ok: false; error: string };

/**
 * Record an approval. Pure: returns a NEW record, mutates nothing. The plugin
 * id is validated as a safe path segment BEFORE it can ever be used as a key —
 * a traversal-shaped id is rejected here, long before any fs join. The
 * capability set is normalized to the aggregated, sorted form so what is stored
 * is exactly what will later be compared.
 */
export function enable(
  record: EnablementRecord,
  pluginId: string,
  opts: { version: string; capabilities: readonly PluginCapability[]; now: number },
): EnableResult {
  if (!isSafePluginId(pluginId)) {
    return {
      ok: false,
      error: `plugin id ${JSON.stringify(String(pluginId))} is not a safe identifier; rejected, not sanitized`,
    };
  }
  const capabilities = PLUGIN_CAPABILITIES.filter((c) => opts.capabilities.includes(c));
  const next: EnablementRecord = {
    schema: ENABLEMENT_SCHEMA_VERSION,
    project: record.project,
    enabled: { ...record.enabled },
  };
  next.enabled[pluginId] = {
    version: opts.version,
    capabilities,
    enabledAt: opts.now,
  };
  return { ok: true, record: next };
}

/** Remove an approval. Pure; a no-op if the id was not enabled. */
export function disable(record: EnablementRecord, pluginId: string): EnablementRecord {
  if (!isEnabled(record, pluginId)) return record;
  const enabled = { ...record.enabled };
  delete enabled[pluginId];
  return { schema: ENABLEMENT_SCHEMA_VERSION, project: record.project, enabled };
}

/**
 * Cross-reference the approval record against what is actually installed. Every
 * enabled id gets exactly one {@link ReconciledPlugin}, sorted by id. This is
 * the single place the re-approval rule lives: a widened (or otherwise changed)
 * capability set, or a vanished plugin, is surfaced as non-loadable.
 */
export function reconcile(
  record: EnablementRecord,
  installed: readonly InstalledPluginView[],
): ReconciledPlugin[] {
  const byId = new Map(installed.map((p) => [p.id, p]));
  const out: ReconciledPlugin[] = [];

  for (const pluginId of Object.keys(record.enabled)) {
    const approval = record.enabled[pluginId];
    const current = byId.get(pluginId);

    if (!current) {
      out.push({
        pluginId,
        status: "missing",
        approvedCapabilities: approval.capabilities,
        approvedVersion: approval.version,
        currentCapabilities: null,
        currentVersion: null,
        reason:
          `plugin "${pluginId}" is enabled but no longer installed; ` +
          "re-install and re-enable it to approve it again",
      });
      continue;
    }

    if (!sameCapabilitySet(approval.capabilities, current.capabilities)) {
      out.push({
        pluginId,
        status: "stale-capabilities",
        approvedCapabilities: approval.capabilities,
        approvedVersion: approval.version,
        currentCapabilities: current.capabilities,
        currentVersion: current.version,
        reason:
          `plugin "${pluginId}" now declares capabilities [${current.capabilities.join(", ") || "none"}] ` +
          `but was approved for [${approval.capabilities.join(", ") || "none"}]; ` +
          "re-enable it to approve the new capability set",
      });
      continue;
    }

    out.push({
      pluginId,
      status: "enabled",
      approvedCapabilities: approval.capabilities,
      approvedVersion: approval.version,
      currentCapabilities: current.capabilities,
      currentVersion: current.version,
    });
  }

  return out.sort((a, b) => a.pluginId.localeCompare(b.pluginId));
}

/**
 * The set of ids safe to hand to `loader.load()` — ONLY those whose approval is
 * still valid against the current on-disk manifest. Stale and missing ids are
 * excluded, so a plugin whose capabilities widened is never silently loaded.
 */
export function loadableIds(reconciled: readonly ReconciledPlugin[]): string[] {
  return reconciled
    .filter((r) => r.status === "enabled")
    .map((r) => r.pluginId)
    .sort();
}

// ── Coercion (total; trusts nothing on disk) ─────────────────────────────────

/**
 * Turn arbitrary parsed JSON into a valid {@link EnablementRecord}. Total: any
 * shape yields a usable record, dropping entries it cannot make sense of rather
 * than throwing. A corrupt file therefore reads as "fewer / no approvals",
 * never as an error and never as an over-broad approval.
 */
export function coerceEnablementRecord(raw: unknown, project: string): EnablementRecord {
  const base = emptyEnablement(project);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return base;
  const obj = raw as Record<string, unknown>;

  const enabledRaw = obj.enabled;
  if (typeof enabledRaw !== "object" || enabledRaw === null || Array.isArray(enabledRaw)) {
    return base;
  }

  for (const [pluginId, value] of Object.entries(enabledRaw as Record<string, unknown>)) {
    // A key that is not a safe plugin id could never have been written by
    // `enable`; refuse to trust it (prototype-pollution-shaped keys included).
    if (!isSafePluginId(pluginId)) continue;
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    const rec = value as Record<string, unknown>;

    const version = typeof rec.version === "string" ? rec.version : "";
    const enabledAt = typeof rec.enabledAt === "number" && Number.isFinite(rec.enabledAt)
      ? rec.enabledAt
      : 0;
    const capsRaw = Array.isArray(rec.capabilities) ? rec.capabilities : [];
    const capabilities = PLUGIN_CAPABILITIES.filter((c) => capsRaw.includes(c));

    base.enabled[pluginId] = { version, capabilities, enabledAt };
  }
  return base;
}

// ── fs layer (never throws) ──────────────────────────────────────────────────

/** Absolute path of the enablement directory: `<homeStateDir>/plugin-enablement`. */
export function enablementDir(homeDir?: string): string {
  return join(homeStateDir(homeDir), ENABLEMENT_DIR_NAME);
}

/** Stable per-project filename: `sha256(realpath(project)).json`. */
export function enablementFilePath(projectPath: string, homeDir?: string): string {
  let real: string;
  try {
    real = realpathSync(projectPath);
  } catch {
    real = resolve(projectPath);
  }
  const hash = createHash("sha256").update(real, "utf8").digest("hex");
  return join(enablementDir(homeDir), `${hash}.json`);
}

/**
 * Read this project's approvals. NEVER throws: a missing file, unreadable file,
 * oversized file, non-JSON file, or structurally garbage file all degrade to an
 * empty record — the fail-closed answer.
 */
export function readEnablement(projectPath: string, homeDir?: string): EnablementRecord {
  let real: string;
  try {
    real = realpathSync(projectPath);
  } catch {
    real = resolve(projectPath);
  }
  const path = enablementFilePath(projectPath, homeDir);
  let text: string;
  try {
    text = readFileSync(path, "utf-8");
  } catch {
    return emptyEnablement(real);
  }
  if (text.length > MAX_ENABLEMENT_BYTES) return emptyEnablement(real);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return emptyEnablement(real);
  }
  return coerceEnablementRecord(parsed, real);
}

/**
 * Persist this project's approvals. NEVER throws: a failure to create the
 * directory or write the file is reported by returning `false`. Writes `0600`
 * under a `0700` directory and re-chmods (POSIX keeps an existing file's mode on
 * rewrite).
 */
export function writeEnablement(
  projectPath: string,
  record: EnablementRecord,
  homeDir?: string,
): boolean {
  const dir = enablementDir(homeDir);
  const path = enablementFilePath(projectPath, homeDir);
  try {
    mkdirSync(dir, { recursive: true, mode: ENABLEMENT_DIR_MODE });
    chmodSync(dir, ENABLEMENT_DIR_MODE);
  } catch {
    // Directory may already exist with the right mode; fall through and let the
    // write decide success.
  }
  try {
    const normalized: EnablementRecord = {
      schema: ENABLEMENT_SCHEMA_VERSION,
      project: record.project,
      enabled: record.enabled,
    };
    writeFileSync(path, `${JSON.stringify(normalized, null, 2)}\n`, {
      mode: ENABLEMENT_FILE_MODE,
    });
    chmodSync(path, ENABLEMENT_FILE_MODE);
    return true;
  } catch {
    return false;
  }
}
