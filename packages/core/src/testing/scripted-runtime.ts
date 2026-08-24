import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeContentBlock,
  NativeMessage,
  NativeToolDef,
} from "../runtime/types.js";

/** One recorded `executeNative` call — lets a test assert what the loop sent. */
export interface RecordedCall {
  readonly system: string;
  readonly messages: NativeMessage[];
  readonly tools: NativeToolDef[];
}

/** An end-of-turn text result (the model replies and stops). */
export function endTurn(text: string): NativeRuntimeResult {
  return { content: [{ type: "text", text }], stopReason: "end_turn", durationMs: 1 };
}

/** A tool-use turn: the model calls `name` with `input` (optionally with lead text). */
export function toolUse(
  name: string,
  input: Record<string, unknown> = {},
  opts: { id?: string; text?: string } = {},
): NativeRuntimeResult {
  const content: NativeContentBlock[] = [];
  if (opts.text) content.push({ type: "text", text: opts.text });
  content.push({ type: "tool_use", id: opts.id ?? `call_${name}`, name, input });
  return { content, stopReason: "tool_use", durationMs: 1 };
}

/**
 * A scripted {@link NativeRuntime} for tests: replays a queue of pre-baked
 * results so an agent/turn loop runs deterministically with no LLM or API key.
 * Records every `executeNative` call (system/messages/tools) so a test can
 * assert the loop wired the real tool registry and conversation history through.
 *
 * Consolidates the ~15 ad-hoc `ScriptedRuntime` copies that had accreted across
 * the core test suites. `onExhausted` picks the behaviour when the script runs
 * out: `"throw"` (default — surfaces a too-short script) or `"repeat-last"`
 * (keeps a loop running to its own turn cap instead of crashing).
 */
export class ScriptedNativeRuntime implements NativeRuntime {
  readonly type = "api" as const;
  readonly calls: RecordedCall[] = [];
  private index = 0;

  constructor(
    private readonly script: readonly NativeRuntimeResult[],
    private readonly onExhausted: "throw" | "repeat-last" = "throw",
  ) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
  ): Promise<NativeRuntimeResult> {
    // Snapshot messages — the loops mutate the array in place across turns.
    this.calls.push({ system, messages: structuredClone(messages), tools });
    if (this.index < this.script.length) return this.script[this.index++]!;
    if (this.onExhausted === "repeat-last" && this.script.length > 0) {
      return this.script[this.script.length - 1]!;
    }
    throw new Error("ScriptedNativeRuntime: script exhausted");
  }
}

/** Convenience factory for {@link ScriptedNativeRuntime}. */
export function scriptedNativeRuntime(
  script: readonly NativeRuntimeResult[],
  onExhausted: "throw" | "repeat-last" = "throw",
): ScriptedNativeRuntime {
  return new ScriptedNativeRuntime(script, onExhausted);
}
