/**
 * Third-party plugin manifest — schema + validation (0sec plugin system, stage 1).
 *
 * This module is the FOUNDATION of the plugin system: the typed contract a
 * plugin declares itself against, and the pure validator that turns untrusted
 * input into either a trusted `PluginManifest` or a list of actionable errors.
 * Loading, sandboxing and dispatch are deliberately OUT of scope here (see
 * DESIGN.md, "staged plan"). Nothing in this file touches `process`, the
 * filesystem, the network, or stdout/stderr, and it has no dependencies — it is
 * pure and total so it can run anywhere (validator in the loader, in a preview
 * UI, in a test) without side effects.
 *
 * ── Why the capability model is the spine ────────────────────────────────────
 *
 * The console's authorization gates in `console/turn-engine.ts`
 * (`NETWORK_CAPABLE_TOOLS`, `LOCAL_SCOPE_TOOLS`, `READ_ONLY_TOOLS`) are keyed on
 * TOOL NAME. A built-in tool is dangerous-by-registration: it appears in those
 * maps, so scope-on-demand, the yolo hard-deny, the local-filesystem gate and
 * the co-pilot approval prompt all fire on it. A plugin-contributed tool whose
 * name is absent from every map would be treated as the LEAST dangerous class:
 * no scope approval, not network-capable, no co-pilot confirmation — a complete
 * bypass of every gate, on a product whose whole job is authorized offensive
 * testing and which (per its own docs) does not sandbox by default.
 *
 * So capability declaration here is MANDATORY and FAIL-CLOSED:
 *   - `capabilities` is a required, non-optional field on every plugin tool.
 *   - An empty capability list is rejected — you cannot express "no
 *     capabilities" and thereby claim the least-dangerous class.
 *   - `gateFlagsFor` is the SINGLE translation from declared capabilities to the
 *     engine's three gate flags, and it is conservative: anything it is unsure
 *     about resolves to the MOST restrictive flag. The loader (a later stage)
 *     feeds these flags into the SAME gate maps the built-ins use, so there is
 *     exactly one authorization path, never a parallel one.
 */

// ── Capability model ─────────────────────────────────────────────────────────

/**
 * The capabilities a plugin tool may declare. Each maps onto a concrete danger
 * the console already gates for built-ins. This is a CLOSED set: an input that
 * names anything outside it is rejected (see `isKnownCapability`), never
 * silently ignored — an unrecognized capability must fail loud, not fail open.
 *
 *   - "network"          — performs engagement egress (HTTP, DNS, any socket).
 *                          Maps to NETWORK_CAPABLE_TOOLS: forces scope approval.
 *   - "process-exec"     — spawns processes / runs commands. Also engagement
 *                          egress in practice (a spawned process can open any
 *                          socket), so it ALSO implies network-capable.
 *   - "filesystem-read"  — reads the local filesystem. Maps to LOCAL_SCOPE_TOOLS.
 *   - "filesystem-write" — writes/patches the local filesystem. Maps to
 *                          LOCAL_SCOPE_TOOLS and is never read-only.
 *   - "findings-write"   — mutates the findings store (save/update finding).
 *                          A state mutation, so never read-only.
 */
export type PluginCapability =
  | "network"
  | "filesystem-read"
  | "filesystem-write"
  | "process-exec"
  | "findings-write";

/** The closed set of valid capabilities, in a stable declaration order. */
export const PLUGIN_CAPABILITIES: readonly PluginCapability[] = [
  "network",
  "filesystem-read",
  "filesystem-write",
  "process-exec",
  "findings-write",
] as const;

function isKnownCapability(x: unknown): x is PluginCapability {
  return typeof x === "string" && (PLUGIN_CAPABILITIES as readonly string[]).includes(x);
}

// ── Manifest shapes ──────────────────────────────────────────────────────────

export interface PluginToolManifest {
  /** Dispatch key + prompt-facing + UI-facing name. Charset-constrained. */
  name: string;
  description: string;
  /** JSON-schema-ish properties bag, passed through to the tool definition. */
  parameters: Record<string, unknown>;
  required?: string[];
  /**
   * MANDATORY. Non-empty. Drives the authorization gates via `gateFlagsFor`.
   * There is intentionally no way to declare zero capabilities.
   */
  capabilities: PluginCapability[];
}

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  /** Optional minimum @0sec/core version this plugin requires (semver-ish). */
  minCoreVersion?: string;
  tools: PluginToolManifest[];
}

export type ValidationResult =
  | { ok: true; manifest: PluginManifest }
  | { ok: false; errors: string[] };

// ── Naming constraints ───────────────────────────────────────────────────────

/**
 * Tool-name charset. A plugin tool name travels to three untrusting places:
 *   1. the model prompt (as the callable tool name),
 *   2. `TOOL_DISPATCH` keys and the gate maps (object property keys),
 *   3. operator-facing UI (approval prompts, the TUI).
 * We therefore mirror the built-ins' de-facto convention exactly:
 * lowercase ASCII letters, digits and underscore, and NOT starting with a
 * digit. This keeps names usable as identifiers, prevents prototype-pollution
 * style keys (`__proto__`, `constructor` contain no digits but ARE letters, so
 * they are additionally denied below), forbids whitespace/quotes/control chars
 * that could break prompt or UI rendering, and rules out homoglyph/unicode
 * spoofing of a built-in name. Length is bounded so a name cannot bloat the
 * prompt or overflow UI chrome.
 */
const TOOL_NAME_RE = /^[a-z][a-z0-9_]*$/;
const TOOL_NAME_MAX = 48;
/** Object keys that must never be usable as a dispatch/gate-map key. */
const FORBIDDEN_NAME_KEYS: readonly string[] = ["__proto__", "prototype", "constructor"];

/**
 * Plugin id charset. Ids are namespaced identifiers (think `acme.sqli-pack`);
 * they never reach the model or a dispatch key, so they may carry dots and
 * hyphens, but stay ASCII + bounded to keep them safe in logs and UI.
 */
const PLUGIN_ID_RE = /^[a-z][a-z0-9]*([._-][a-z0-9]+)*$/;
const PLUGIN_ID_MAX = 64;

/** Semver-ish: MAJOR.MINOR.PATCH with an optional -prerelease / +build tail. */
const VERSION_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const DESCRIPTION_MAX = 2000;
const MAX_TOOLS_PER_PLUGIN = 64;

// ── Small pure helpers ───────────────────────────────────────────────────────

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === "string" && x.length > 0;
}

// ── gateFlagsFor: the single capability → gate translation ────────────────────

/**
 * Translate a tool's declared capabilities into the three gate flags the
 * console keys its authorization on. This is the ONLY place capabilities become
 * gate semantics, and it is deliberately CONSERVATIVE — every branch that is
 * uncertain resolves toward the more restrictive answer:
 *
 *   networkCapable  true if "network" OR "process-exec" is declared. A process
 *                   can open any socket, so exec implies egress. This flag feeds
 *                   NETWORK_CAPABLE_TOOLS → scope-on-demand + yolo hard-deny.
 *
 *   localScope      true if "filesystem-read" OR "filesystem-write" is declared.
 *                   Feeds LOCAL_SCOPE_TOOLS → the local-filesystem scope gate.
 *
 *   readOnly        true ONLY when the capability set is non-empty AND every
 *                   declared capability is a pure read ("filesystem-read" is the
 *                   only read capability today). network/process-exec/
 *                   filesystem-write/findings-write are all effectful, so any of
 *                   them present makes the tool NOT read-only. An EMPTY set is
 *                   never read-only — fail closed. readOnly feeds READ_ONLY_TOOLS
 *                   → the co-pilot approval exemption, so a wrong `true` here
 *                   would skip operator confirmation; that is why the rule is
 *                   "all reads" and not "any read".
 *
 * Note the asymmetry that keeps this fail-closed: capabilities this function
 * does not recognize can only ever be present in a set that ALSO fails
 * validation, but even if one slipped through, an unknown capability satisfies
 * neither the network nor the local branch (so it never grants a lighter gate)
 * and is not the read capability (so it forces readOnly to false). Unknown ⇒
 * most restrictive.
 */
export function gateFlagsFor(tool: PluginToolManifest): {
  networkCapable: boolean;
  localScope: boolean;
  readOnly: boolean;
} {
  // Defensive: treat a missing/garbage capabilities field as the empty set,
  // which yields the most restrictive flags (never read-only). `gateFlagsFor`
  // must be as total as the validator that guards it.
  const caps: unknown[] = Array.isArray(tool?.capabilities) ? tool.capabilities : [];

  const has = (c: PluginCapability): boolean => caps.includes(c);

  const networkCapable = has("network") || has("process-exec");
  const localScope = has("filesystem-read") || has("filesystem-write");

  // The set of capabilities we consider a pure read. Kept as an explicit list
  // so adding a future read-only capability is a one-line, obvious change.
  const READ_CAPS: readonly PluginCapability[] = ["filesystem-read"];
  const nonEmpty = caps.length > 0;
  const allKnownReads =
    nonEmpty && caps.every((c) => isKnownCapability(c) && READ_CAPS.includes(c));

  return { networkCapable, localScope, readOnly: allKnownReads };
}

// ── validatePluginManifest: pure, total, actionable ──────────────────────────

/**
 * Validate untrusted input into a `PluginManifest`. Pure and TOTAL: any input
 * (null, a string, an array, deeply nested garbage, a manifest with 40 problems)
 * returns a `ValidationResult` and never throws. On failure, `errors` is a list
 * of specific messages — one per distinct problem — each naming the offending
 * field so a plugin author can fix them all in one pass.
 *
 * `opts.reservedToolNames` is the collision list the CALLER supplies (built-in
 * tool names — the keys of `TOOL_DISPATCH` plus the gate maps). A plugin tool
 * whose name matches a reserved name is rejected: a plugin must never be able to
 * shadow `run_command`, `save_finding`, etc. and thereby redefine a gated tool.
 */
export function validatePluginManifest(
  raw: unknown,
  opts?: { reservedToolNames?: readonly string[] },
): ValidationResult {
  const errors: string[] = [];
  const reserved = new Set(opts?.reservedToolNames ?? []);

  if (!isPlainObject(raw)) {
    return { ok: false, errors: ["manifest must be a JSON object"] };
  }

  // ── top-level id / name / version ──
  const id = raw.id;
  if (!isNonEmptyString(id)) {
    errors.push("`id` is required and must be a non-empty string");
  } else if (id.length > PLUGIN_ID_MAX) {
    errors.push(`\`id\` must be at most ${PLUGIN_ID_MAX} characters`);
  } else if (!PLUGIN_ID_RE.test(id)) {
    errors.push(
      "`id` must be a lowercase dotted/hyphenated identifier (e.g. \"acme.sqli-pack\")",
    );
  }

  if (!isNonEmptyString(raw.name)) {
    errors.push("`name` is required and must be a non-empty string");
  } else if (raw.name.length > DESCRIPTION_MAX) {
    errors.push(`\`name\` must be at most ${DESCRIPTION_MAX} characters`);
  }

  const version = raw.version;
  if (!isNonEmptyString(version)) {
    errors.push("`version` is required and must be a non-empty string");
  } else if (!VERSION_RE.test(version)) {
    errors.push('`version` must be semver-like "MAJOR.MINOR.PATCH" (e.g. "1.0.0")');
  }

  if (raw.minCoreVersion !== undefined) {
    if (!isNonEmptyString(raw.minCoreVersion) || !VERSION_RE.test(raw.minCoreVersion)) {
      errors.push('`minCoreVersion`, when present, must be semver-like "MAJOR.MINOR.PATCH"');
    }
  }

  // ── tools[] ──
  const tools = raw.tools;
  const validatedTools: PluginToolManifest[] = [];
  if (!Array.isArray(tools)) {
    errors.push("`tools` is required and must be an array");
  } else if (tools.length === 0) {
    errors.push("`tools` must declare at least one tool");
  } else if (tools.length > MAX_TOOLS_PER_PLUGIN) {
    errors.push(`\`tools\` may declare at most ${MAX_TOOLS_PER_PLUGIN} tools`);
  } else {
    const seen = new Set<string>();
    tools.forEach((t, i) => {
      const validated = validateTool(t, i, reserved, seen, errors);
      if (validated) validatedTools.push(validated);
    });
  }

  if (errors.length > 0) return { ok: false, errors };

  // Everything validated — build the trusted manifest. Fields are re-read from
  // the (now-checked) raw object; unknown extra keys are dropped, not carried.
  const manifest: PluginManifest = {
    id: id as string,
    name: raw.name as string,
    version: version as string,
    tools: validatedTools,
  };
  if (raw.minCoreVersion !== undefined) {
    manifest.minCoreVersion = raw.minCoreVersion as string;
  }
  return { ok: true, manifest };
}

/**
 * Validate one entry of `tools[]`. Pushes every problem it finds onto `errors`
 * (prefixed with the tool's index/name so multi-tool manifests stay
 * diagnosable) and returns the cleaned tool, or `null` if it was unusable.
 * `seen` tracks names already used WITHIN this manifest to catch intra-plugin
 * duplicates; `reserved` is the built-in collision list.
 */
function validateTool(
  t: unknown,
  index: number,
  reserved: ReadonlySet<string>,
  seen: Set<string>,
  errors: string[],
): PluginToolManifest | null {
  const where = `tools[${index}]`;
  if (!isPlainObject(t)) {
    errors.push(`${where} must be an object`);
    return null;
  }

  let nameOk = false;
  const name = t.name;
  if (!isNonEmptyString(name)) {
    errors.push(`${where}.name is required and must be a non-empty string`);
  } else if (name.length > TOOL_NAME_MAX) {
    errors.push(`${where}.name "${name}" exceeds ${TOOL_NAME_MAX} characters`);
  } else if (FORBIDDEN_NAME_KEYS.includes(name)) {
    errors.push(`${where}.name "${name}" is a forbidden reserved key`);
  } else if (!TOOL_NAME_RE.test(name)) {
    errors.push(
      `${where}.name "${name}" must be lowercase [a-z0-9_], not start with a digit`,
    );
  } else if (reserved.has(name)) {
    errors.push(
      `${where}.name "${name}" collides with a built-in tool; plugins may not shadow built-ins`,
    );
  } else if (seen.has(name)) {
    errors.push(`${where}.name "${name}" is declared more than once in this manifest`);
  } else {
    nameOk = true;
    seen.add(name);
  }

  const label = isNonEmptyString(name) ? `"${name}"` : `at index ${index}`;

  if (!isNonEmptyString(t.description)) {
    errors.push(`tool ${label}: \`description\` is required and must be a non-empty string`);
  } else if (t.description.length > DESCRIPTION_MAX) {
    errors.push(`tool ${label}: \`description\` must be at most ${DESCRIPTION_MAX} characters`);
  }

  if (!isPlainObject(t.parameters)) {
    errors.push(`tool ${label}: \`parameters\` is required and must be an object`);
  }

  if (t.required !== undefined) {
    if (!Array.isArray(t.required) || !t.required.every((r) => typeof r === "string")) {
      errors.push(`tool ${label}: \`required\`, when present, must be an array of strings`);
    }
  }

  // ── capabilities: MANDATORY, non-empty, all-known ──
  const caps = t.capabilities;
  let capsOk = false;
  if (!Array.isArray(caps)) {
    errors.push(
      `tool ${label}: \`capabilities\` is required and must be a non-empty array — ` +
        "a tool that declares nothing is treated as the most dangerous class and rejected",
    );
  } else if (caps.length === 0) {
    errors.push(
      `tool ${label}: \`capabilities\` must not be empty — declare what the tool actually does; ` +
        '"no capabilities" is not expressible',
    );
  } else {
    const unknown = caps.filter((c) => !isKnownCapability(c));
    if (unknown.length > 0) {
      errors.push(
        `tool ${label}: unknown capabilit${unknown.length > 1 ? "ies" : "y"} ` +
          `${unknown.map((u) => JSON.stringify(u)).join(", ")}; ` +
          `allowed: ${PLUGIN_CAPABILITIES.join(", ")}`,
      );
    } else {
      capsOk = true;
    }
  }

  if (!nameOk || !capsOk) return null;
  // Only reachable when name + capabilities are clean; the description/params
  // problems (if any) are already recorded and will fail the whole manifest.
  return {
    name: name as string,
    description: typeof t.description === "string" ? t.description : "",
    parameters: isPlainObject(t.parameters) ? t.parameters : {},
    ...(Array.isArray(t.required) ? { required: t.required as string[] } : {}),
    capabilities: (caps as PluginCapability[]).slice(),
  };
}
