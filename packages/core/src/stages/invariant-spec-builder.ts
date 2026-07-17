/**
 * Shared invariant-spec extraction primitive — the ONE mechanical step both
 * invariant discovery axes have in common: present a subsystem's source to a
 * single native LLM tool call and return the parsed tool result.
 *
 * Two callers consume the result in DELIBERATELY different ways, and those
 * strategies stay separate (this module does not merge them):
 *
 *   - {@link ../stages/subsystem-invariant-model.ts} (Engine A, seedless) extracts a
 *     rich per-object model, STORES it as durable JSON, and re-runs a deterministic
 *     checker against it for free — the compounding, re-checkable artifact.
 *   - {@link ../stages/invariant-candidates.ts} (concurrency) fuses spec-recovery and
 *     violation-hunting into ONE turn and returns the race candidates inline.
 *
 * What is genuinely identical between them — and all this primitive owns — is the
 * extraction harness: clip each file, wrap it in a `### FILE:` / `## Subsystem
 * source` prompt, run ONE `LlmApiRuntime.executeNative` tool call, and pull the
 * `tool_use` input for the requested tool. The task-specific tool schema, system
 * prompt, result shape, and source-reading containment policy stay with each
 * caller — they are what makes the two axes distinct.
 */

import { LlmApiRuntime } from "../runtime/llm-api.js";

/** Default chars of source sent to the model per file (clipped with a marker). */
const DEFAULT_MAX_CHARS_PER_FILE = 24_000;

/** A native (Anthropic-shape) LLM tool the extraction emits its result through. */
export interface InvariantExtractionTool {
  /** The tool name the model must call; its `tool_use` input is what we return. */
  name: string;
  description: string;
  /** JSON-schema for the tool input (passed through to the runtime verbatim). */
  input_schema: unknown;
}

/** One read subsystem source file (each caller reads under its OWN containment policy). */
export interface SubsystemSource {
  file: string;
  text: string;
}

/** Clip a source string to `n` chars, appending a truncation marker when cut. */
export function clipSource(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + `\n...[truncated ${s.length - n} chars]` : s;
}

export interface ExtractInvariantSpecInput {
  /** The already-read subsystem sources (repo-relative labels + full text). */
  sources: SubsystemSource[];
  /** Task-specific system prompt (durable-model build vs. one-turn spec+violate — kept distinct). */
  system: string;
  /** Task-specific emit tool (schema + name — distinct per consumption strategy). */
  tool: InvariantExtractionTool;
  /** LLM model override. */
  model?: string;
  /** Chars of source sent per file (default {@link DEFAULT_MAX_CHARS_PER_FILE}; clipped with a marker). */
  maxCharsPerFile?: number;
  /** Prefix for the `"<errorLabel> LLM call failed"` error (e.g. `"invariant-model"`). */
  errorLabel: string;
}

/**
 * The SHARED extraction step: present `sources` to one native LLM tool call and
 * return the parsed `tool_use` input for `tool.name`, or `null` when the model
 * emitted no such call (each caller decides how to treat an empty result). This is
 * the whole of what the durable-model builder and the one-turn candidate generator
 * have in common — everything downstream of the returned value stays per-caller.
 */
export async function extractInvariantSpec<T>(input: ExtractInvariantSpecInput): Promise<T | null> {
  const maxCharsPerFile = input.maxCharsPerFile ?? DEFAULT_MAX_CHARS_PER_FILE;
  const sourceBlocks = input.sources
    .map((s) => `### FILE: ${s.file}\n\`\`\`c\n${clipSource(s.text, maxCharsPerFile)}\n\`\`\``)
    .join("\n\n");
  const messages = [{ role: "user", content: [{ type: "text", text: `## Subsystem source\n\n${sourceBlocks}` }] }];

  const rt = new LlmApiRuntime({ type: "api", ...(input.model ? { model: input.model } : {}), timeout: 300_000 });
  try {
    const res = (await rt.executeNative(input.system, messages as never, [input.tool] as never, {
      onThinking() {}, onDelta() {}, onText() {}, onUsage() {},
    } as never)) as { content?: Array<Record<string, unknown>> };
    const call = (res.content ?? []).find(
      (b) =>
        (b as { type?: string; name?: string }).type === "tool_use" &&
        (b as { name?: string }).name === input.tool.name,
    ) as { input?: T } | undefined;
    return call?.input ?? null;
  } catch (e) {
    throw new Error(`${input.errorLabel} LLM call failed: ${String(e).slice(0, 200)}`);
  }
}
