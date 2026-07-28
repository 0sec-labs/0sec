/**
 * The craft-loop seam for prover plugins.
 *
 * Deliberately shaped like `agent/input-encoder.ts`: a `*ToolDef()` factory plus
 * a `run*` string-in/string-out handler, so `craft-scan.ts` gains two entries in
 * its `tools` array and two dispatch lines and nothing else. `AGENTS.md` is
 * explicit that new behaviour goes in a focused module rather than another
 * branch in a god-module (`tools.ts` at 4000+ lines, `agentic-scanner.ts` at
 * 2700+), and the craft loop is already carrying more than its share.
 *
 * It also matters that the agent has *already been taught this shape*. It knows
 * `fdp_encode` returns a python `b"..."` literal it can paste into a generator;
 * these tools return the same thing. Same idiom, no new habits.
 *
 * ## Why `prover_construct` self-validates
 *
 * `encodeFdp` round-trips its own output through a faithful decoder before
 * returning, so a bug in the encoder surfaces as an error rather than as a
 * silently wrong PoC. The same discipline applies here: whatever
 * `construct` produces is immediately run back through `validate`, and any
 * remaining defect is reported alongside the bytes. If the plugin's builder and
 * its validator ever disagree, the agent finds out at construction time instead
 * of after spending a graded submit.
 */

import { fromHex, pythonLiteral, toHex } from "./binary.js";
import { getProverPluginById, listProverPluginIds, selectProverPlugin, PROVER_PLUGIN_REGISTRY } from "./registry.js";
import type { ProverPlugin, ValidationReport } from "./types.js";

/** Above this size the python literal is unreadable, so we hand over base64 instead. */
const LITERAL_LIMIT = 1024;

function catalog(): string {
  return PROVER_PLUGIN_REGISTRY.map((p) => `${p.id} (${p.title})`).join("; ");
}

/**
 * Tool definitions for the craft agent. Returned as a list so wiring is a
 * single spread in `craft-scan.ts`'s `tools` array and adding a third tool
 * later needs no change at the call site.
 */
export function proverToolDefs(): Array<{
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}> {
  return [
    {
      name: "prover_construct",
      description:
        "Build a structurally VALID container for a known binary format, or repair the framing of one you already have. " +
        "This is not a primer — it emits real bytes with real checksums, lengths and directory offsets computed for you. " +
        "Use it whenever the format has a checksum or an offset table (PNG chunk CRCs, ZIP central-directory offsets): " +
        "those are the fields that make a hand-built PoC get rejected before the parser reaches the bug. " +
        "It NEVER edits a semantic field — your planted width, length, count or size is written verbatim, because that " +
        "is usually the trigger. Pass `baseHex` to repair an existing candidate (every change is reported so you learn " +
        "what was wrong), or `params` to build one from scratch. " +
        `Formats: ${catalog()}.`,
      input_schema: {
        type: "object",
        properties: {
          format: {
            type: "string",
            description: `Format id or fuzzer name (e.g. png, libpng_read_fuzzer, zip). Known ids: ${listProverPluginIds().join(", ")}. Omit to infer from baseHex's magic bytes.`,
          },
          baseHex: {
            type: "string",
            description: "Hex of an existing candidate to REPAIR. Omit to build a minimal valid container from scratch.",
          },
          params: {
            type: "object",
            description:
              "Format-specific structural knobs. Unknown keys are rejected (a silently-ignored typo would give you a file you did not build). Call with an empty object first to see the accepted keys.",
          },
        },
        required: [],
      },
    },
    {
      name: "prover_validate",
      description:
        "Statically check whether candidate bytes are well-formed enough to REACH the parser, before you spend a graded " +
        "submit on them. Returns a structural walk (chunk list / entry table) plus fatal defects (the parser bails here — " +
        "your bug is unreachable) and warnings (malformed, but the parser gets past it — often exactly what you intended). " +
        "This does NOT tell you whether the bug triggers; only the oracle decides that. It tells you whether the input is " +
        "even in the game. " +
        `Formats: ${catalog()}.`,
      input_schema: {
        type: "object",
        properties: {
          bytesHex: { type: "string", description: "Hex of the candidate PoC bytes to check." },
          format: {
            type: "string",
            description: `Format id or fuzzer name. Omit to infer from the magic bytes. Known ids: ${listProverPluginIds().join(", ")}.`,
          },
        },
        required: ["bytesHex"],
      },
    },
  ];
}

/**
 * Resolve which plugin handles this call. An explicit id wins; otherwise we ask
 * the registry to rank, using the sample bytes (magic-byte evidence) and any
 * free-text hint. Failure is a message the agent can act on, listing what IS
 * available — the same "unknown format, here is the catalogue" behaviour
 * `format_reference` already has.
 */
function resolve(
  format: string | undefined,
  sample: Uint8Array | undefined,
): { ok: true; plugin: ProverPlugin; why: string } | { ok: false; error: string } {
  if (format && format.trim() !== "") {
    const exact = getProverPluginById(format);
    if (exact) return { ok: true, plugin: exact, why: `explicit format '${exact.id}'` };
  }
  const selection = selectProverPlugin({
    ...(format ? { hint: format } : {}),
    ...(sample ? { sample } : {}),
  });
  if (selection) {
    return { ok: true, plugin: selection.plugin, why: `${selection.plugin.id} — ${selection.match.reason}` };
  }
  return {
    ok: false,
    error:
      `No prover plugin for ${format ? `format "${format}"` : "these bytes"}. Available: ${listProverPluginIds().join(", ")}. ` +
      "For any other format, call format_reference for the byte layout and build the container in your generator by hand.",
  };
}

/** Render a validation report as agent-readable text. */
function renderReport(report: ValidationReport): string {
  const lines: string[] = [];
  lines.push(report.wellFormed ? "STRUCTURE OK — a parser will walk this." : "NOT WELL-FORMED — the parser bails before your bug.");
  if (report.structure.length > 0) lines.push("Structure:", ...report.structure.map((s) => `  ${s}`));
  const fatal = report.defects.filter((d) => d.severity === "fatal");
  const warn = report.defects.filter((d) => d.severity === "warning");
  if (fatal.length > 0) {
    lines.push(`FATAL (${fatal.length}) — these make the vulnerable code unreachable:`);
    for (const d of fatal) {
      lines.push(`  [${d.field}${d.offset !== undefined ? ` @${d.offset}` : ""}] ${d.message}${d.repairable ? " (repairable: call prover_construct with baseHex)" : ""}`);
    }
  }
  if (warn.length > 0) {
    lines.push(`WARNINGS (${warn.length}) — malformed but still reachable; often intentional in a PoC:`);
    for (const d of warn) {
      lines.push(`  [${d.field}${d.offset !== undefined ? ` @${d.offset}` : ""}] ${d.message}`);
    }
  }
  if (report.defects.length === 0) lines.push("No structural defects found.");
  return lines.join("\n");
}

/** Render produced bytes in the form the agent will paste into its generator. */
function renderBytes(bytes: Uint8Array): string {
  if (bytes.length <= LITERAL_LIMIT) {
    return (
      `${bytes.length} bytes\n` +
      `python: sys.argv[1] payload = ${pythonLiteral(bytes)}\n` +
      `hex: ${toHex(bytes)}`
    );
  }
  const b64 = Buffer.from(bytes).toString("base64");
  return (
    `${bytes.length} bytes (too large for an inline literal)\n` +
    `python: import base64; payload = base64.b64decode("${b64}")`
  );
}

/**
 * Handler for `prover_construct`. Returns a `tool_result` string: either the
 * constructed bytes plus the repair log and a fresh validation of the result,
 * or an actionable error.
 */
export function runProverConstruct(input: unknown): string {
  const raw = (input ?? {}) as { format?: unknown; baseHex?: unknown; params?: unknown };
  const format = typeof raw.format === "string" ? raw.format : undefined;

  let base: Uint8Array | undefined;
  if (typeof raw.baseHex === "string" && raw.baseHex.trim() !== "") {
    const parsed = fromHex(raw.baseHex);
    if (!parsed) return "prover_construct error: `baseHex` is not valid hex.";
    base = parsed;
  }

  if (raw.params !== undefined && (typeof raw.params !== "object" || raw.params === null || Array.isArray(raw.params))) {
    return "prover_construct error: `params` must be an object.";
  }
  const params = raw.params as Record<string, unknown> | undefined;

  const resolved = resolve(format, base);
  if (!resolved.ok) return `prover_construct error: ${resolved.error}`;
  const { plugin } = resolved;

  const result = plugin.construct({ ...(base ? { base } : {}), ...(params ? { params } : {}) });
  if (!result.ok) return `prover_construct (${plugin.id}) failed: ${result.error}`;

  const lines: string[] = [`Constructed with the ${plugin.id} prover (${resolved.why}).`, renderBytes(result.bytes)];
  if (result.repairs.length > 0) {
    lines.push(`Repaired ${result.repairs.length} framing field(s) — reproduce these in your generator:`);
    for (const r of result.repairs) {
      lines.push(`  @${r.offset >= 0 ? r.offset : "end"} ${r.field}: ${r.from} → ${r.to}\n      why: ${r.why}`);
    }
  }
  if (result.notes.length > 0) lines.push("Notes:", ...result.notes.map((n) => `  ${n}`));

  // Self-check, in the spirit of encodeFdp's round-trip: if the builder and the
  // validator disagree, the agent learns now rather than after a graded submit.
  const report = plugin.validate(result.bytes);
  if (!report.wellFormed) {
    lines.push(
      "WARNING — the constructed bytes still fail this plugin's own validation. Either your params planted a fatal " +
        "defect deliberately (fine, but confirm it is the one you meant) or this is a plugin bug:",
      renderReport(report),
    );
  } else if (report.defects.length > 0) {
    lines.push(renderReport(report));
  }
  return lines.join("\n");
}

/** Handler for `prover_validate`. */
export function runProverValidate(input: unknown): string {
  const raw = (input ?? {}) as { bytesHex?: unknown; format?: unknown };
  if (typeof raw.bytesHex !== "string" || raw.bytesHex.trim() === "") {
    return "prover_validate error: `bytesHex` is required (hex of the candidate PoC bytes).";
  }
  const bytes = fromHex(raw.bytesHex);
  if (!bytes) return "prover_validate error: `bytesHex` is not valid hex.";
  const format = typeof raw.format === "string" ? raw.format : undefined;

  const resolved = resolve(format, bytes);
  if (!resolved.ok) return `prover_validate error: ${resolved.error}`;
  const report = resolved.plugin.validate(bytes);
  return `Validated with the ${resolved.plugin.id} prover (${resolved.why}).\n${renderReport(report)}`;
}

/**
 * Single dispatch entry point, so `craft-scan.ts` adds one branch rather than
 * one per tool. Returns `undefined` when `name` is not a prover tool, letting
 * the caller fall through to its own dispatch chain.
 */
export function runProverTool(name: string, input: unknown): string | undefined {
  if (name === "prover_construct") return runProverConstruct(input);
  if (name === "prover_validate") return runProverValidate(input);
  return undefined;
}

/** Tool names this module handles — used by the craft loop's read-only tool set. */
export const PROVER_TOOL_NAMES: readonly string[] = Object.freeze(["prover_construct", "prover_validate"]);
