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

  // ── artifact kind gate ──
  // A manifest may now declare a `kind` (see ARTIFACT_KINDS). This validator is
  // the TOOL path: it accepts only a tool manifest (kind absent or "tool") so
  // that existing manifests validate EXACTLY as before, and refuses a theme/
  // config artifact rather than mis-validating it as a bag of tools. Themes and
  // configs carry NO tools and NO capabilities, so they must never reach this
  // function's output (and thus never the loader / capability gates); route them
  // through `validateArtifactManifest` instead.
  if (raw.kind !== undefined && raw.kind !== "tool") {
    return {
      ok: false,
      errors: [
        `manifest \`kind\` ${JSON.stringify(raw.kind)} is not a tool manifest; ` +
          "a theme/config artifact carries no tools and must be validated as data",
      ],
    };
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

// ── Artifact kinds: tool | theme | config ────────────────────────────────────
//
// A manifest describes one of three artifact KINDS. A tool manifest is the
// original shape (validated by `validatePluginManifest`), and stays the default:
// a manifest with no `kind` field, or `kind: "tool"`, is a tool plugin exactly
// as before. The two new kinds are pure DATA:
//
//   - "theme"  — carries a colour palette (a token → #RRGGBB map) plus display
//                metadata. NO tools, NO capabilities, NO code. The palette is
//                validated STRUCTURALLY here (object of string tokens); the full
//                WCAG contrast validation (validateTheme) runs at install time in
//                the CLI, which is the only layer that owns that check.
//   - "config" — carries a settings bundle (a partial TuiSettings object) to be
//                merged into a config layer. Also NO tools, NO capabilities.
//
// The security spine: a theme/config artifact must NEVER be able to reach the
// tool loader or the capability gates. That is enforced two ways — the tool
// validator refuses any non-"tool" kind (see the kind gate in
// `validatePluginManifest`), and the artifact validators below REJECT any
// manifest that declares `tools` or `capabilities`. Data cannot smuggle code in.

/** The closed set of artifact kinds, in a stable order. */
export const ARTIFACT_KINDS = ["tool", "theme", "config"] as const;
export type ArtifactKind = (typeof ARTIFACT_KINDS)[number];

/** A palette as it rides a theme manifest: token name → colour string. Validated
 *  structurally here; contrast/completeness is the CLI's `validateTheme`. */
export type ArtifactPalette = Record<string, string>;

export interface ThemeArtifactManifest {
  kind: "theme";
  id: string;
  name: string;
  version: string;
  minCoreVersion?: string;
  theme: {
    label?: string;
    description?: string;
    mode?: "dark" | "light";
    palette: ArtifactPalette;
  };
}

export interface ConfigArtifactManifest {
  kind: "config";
  id: string;
  name: string;
  version: string;
  minCoreVersion?: string;
  /** Partial settings bundle. Opaque here (the CLI owns the settings schema); a
   *  plain object of key → value that the importer normalises before use. */
  config: Record<string, unknown>;
}

export type ArtifactManifest =
  | PluginManifest
  | ThemeArtifactManifest
  | ConfigArtifactManifest;

export type ArtifactValidationResult =
  | { ok: true; kind: "tool"; manifest: PluginManifest }
  | { ok: true; kind: "theme"; manifest: ThemeArtifactManifest }
  | { ok: true; kind: "config"; manifest: ConfigArtifactManifest }
  | { ok: false; errors: string[] };

/** Read the declared kind of a raw manifest, defaulting to "tool". Returns
 *  `undefined` for a non-object or an unrecognised kind string. */
export function manifestKindOf(raw: unknown): ArtifactKind | undefined {
  if (!isPlainObject(raw)) return undefined;
  if (raw.kind === undefined) return "tool";
  if (typeof raw.kind === "string" && (ARTIFACT_KINDS as readonly string[]).includes(raw.kind)) {
    return raw.kind as ArtifactKind;
  }
  return undefined;
}

/** Shared top-level id/name/version checks for the data artifacts. Pushes
 *  problems onto `errors`; returns the cleaned trio when all three are valid. */
function validateArtifactHead(
  raw: Record<string, unknown>,
  errors: string[],
): { id: string; name: string; version: string; minCoreVersion?: string } | null {
  const id = raw.id;
  if (!isNonEmptyString(id)) {
    errors.push("`id` is required and must be a non-empty string");
  } else if (id.length > PLUGIN_ID_MAX) {
    errors.push(`\`id\` must be at most ${PLUGIN_ID_MAX} characters`);
  } else if (!PLUGIN_ID_RE.test(id)) {
    errors.push('`id` must be a lowercase dotted/hyphenated identifier (e.g. "acme.midnight")');
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
  let minCoreVersion: string | undefined;
  if (raw.minCoreVersion !== undefined) {
    if (!isNonEmptyString(raw.minCoreVersion) || !VERSION_RE.test(raw.minCoreVersion)) {
      errors.push('`minCoreVersion`, when present, must be semver-like "MAJOR.MINOR.PATCH"');
    } else {
      minCoreVersion = raw.minCoreVersion;
    }
  }
  // A data artifact must never carry code or capabilities — reject loudly.
  if ("tools" in raw) {
    errors.push("a theme/config artifact must not declare `tools` (data carries no code)");
  }
  if ("capabilities" in raw) {
    errors.push("a theme/config artifact must not declare `capabilities` (data has none)");
  }
  if (errors.length > 0) return null;
  return {
    id: id as string,
    name: raw.name as string,
    version: version as string,
    ...(minCoreVersion !== undefined ? { minCoreVersion } : {}),
  };
}

/** Validate a theme artifact manifest. Pure, total, actionable. The palette is
 *  checked structurally (object of string tokens); full contrast validation is
 *  the CLI's job at install time and is deliberately NOT done here. */
export function validateThemeArtifact(
  raw: unknown,
): { ok: true; manifest: ThemeArtifactManifest } | { ok: false; errors: string[] } {
  if (!isPlainObject(raw)) return { ok: false, errors: ["manifest must be a JSON object"] };
  if (raw.kind !== "theme") {
    return { ok: false, errors: [`expected \`kind: "theme"\`, got ${JSON.stringify(raw.kind)}`] };
  }
  const errors: string[] = [];
  const head = validateArtifactHead(raw, errors);

  const themeRaw = raw.theme;
  let palette: ArtifactPalette | null = null;
  let label: string | undefined;
  let description: string | undefined;
  let mode: "dark" | "light" | undefined;
  if (!isPlainObject(themeRaw)) {
    errors.push("`theme` is required and must be an object with a `palette`");
  } else {
    if (!isPlainObject(themeRaw.palette)) {
      errors.push("`theme.palette` is required and must be an object of token → colour");
    } else {
      const bad = Object.entries(themeRaw.palette).filter(([, v]) => typeof v !== "string");
      if (bad.length > 0) {
        errors.push(
          `\`theme.palette\` values must be strings; non-string: ${bad.map(([k]) => k).join(", ")}`,
        );
      } else if (Object.keys(themeRaw.palette).length === 0) {
        errors.push("`theme.palette` must not be empty");
      } else {
        palette = { ...(themeRaw.palette as ArtifactPalette) };
      }
    }
    if (themeRaw.label !== undefined && !isNonEmptyString(themeRaw.label)) {
      errors.push("`theme.label`, when present, must be a non-empty string");
    } else if (typeof themeRaw.label === "string") {
      label = themeRaw.label;
    }
    if (themeRaw.description !== undefined && typeof themeRaw.description !== "string") {
      errors.push("`theme.description`, when present, must be a string");
    } else if (typeof themeRaw.description === "string") {
      description = themeRaw.description;
    }
    if (themeRaw.mode !== undefined && themeRaw.mode !== "dark" && themeRaw.mode !== "light") {
      errors.push('`theme.mode`, when present, must be "dark" or "light"');
    } else if (themeRaw.mode === "dark" || themeRaw.mode === "light") {
      mode = themeRaw.mode;
    }
  }

  if (errors.length > 0 || !head || !palette) {
    return { ok: false, errors: errors.length > 0 ? errors : ["invalid theme artifact"] };
  }
  return {
    ok: true,
    manifest: {
      kind: "theme",
      id: head.id,
      name: head.name,
      version: head.version,
      ...(head.minCoreVersion !== undefined ? { minCoreVersion: head.minCoreVersion } : {}),
      theme: {
        ...(label !== undefined ? { label } : {}),
        ...(description !== undefined ? { description } : {}),
        ...(mode !== undefined ? { mode } : {}),
        palette,
      },
    },
  };
}

/** Validate a config artifact manifest. Pure, total. The `config` bag is opaque
 *  here — the CLI's `normalizeSettings` is the schema authority and runs on
 *  import — so this only checks it is a plain object. */
export function validateConfigArtifact(
  raw: unknown,
): { ok: true; manifest: ConfigArtifactManifest } | { ok: false; errors: string[] } {
  if (!isPlainObject(raw)) return { ok: false, errors: ["manifest must be a JSON object"] };
  if (raw.kind !== "config") {
    return { ok: false, errors: [`expected \`kind: "config"\`, got ${JSON.stringify(raw.kind)}`] };
  }
  const errors: string[] = [];
  const head = validateArtifactHead(raw, errors);
  if (!isPlainObject(raw.config)) {
    errors.push("`config` is required and must be an object of settings");
  }
  if (errors.length > 0 || !head) {
    return { ok: false, errors: errors.length > 0 ? errors : ["invalid config artifact"] };
  }
  return {
    ok: true,
    manifest: {
      kind: "config",
      id: head.id,
      name: head.name,
      version: head.version,
      ...(head.minCoreVersion !== undefined ? { minCoreVersion: head.minCoreVersion } : {}),
      config: { ...(raw.config as Record<string, unknown>) },
    },
  };
}

/**
 * Validate an untrusted manifest of ANY artifact kind, dispatching on `kind`.
 * The single entry point a registry parser or importer should use when it does
 * not know the kind in advance. Backward compatible: a manifest with no kind, or
 * `kind: "tool"`, is validated by `validatePluginManifest` and returned as a
 * tool. Total — never throws.
 */
export function validateArtifactManifest(
  raw: unknown,
  opts?: { reservedToolNames?: readonly string[] },
): ArtifactValidationResult {
  const kind = manifestKindOf(raw);
  if (kind === undefined) {
    const declared = isPlainObject(raw) ? raw.kind : undefined;
    return {
      ok: false,
      errors: [
        `unknown manifest \`kind\` ${JSON.stringify(declared)}; ` +
          `allowed: ${ARTIFACT_KINDS.join(", ")}`,
      ],
    };
  }
  if (kind === "theme") {
    const res = validateThemeArtifact(raw);
    return res.ok ? { ok: true, kind: "theme", manifest: res.manifest } : res;
  }
  if (kind === "config") {
    const res = validateConfigArtifact(raw);
    return res.ok ? { ok: true, kind: "config", manifest: res.manifest } : res;
  }
  const res = validatePluginManifest(raw, opts);
  return res.ok ? { ok: true, kind: "tool", manifest: res.manifest } : res;
}
