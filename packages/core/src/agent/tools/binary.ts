import type { ToolDefinition } from "../types.js";
import { ZEROVERSE_TOOL_DEFINITION } from "./0verse.js";

/** Opt-in binary analysis is intentionally isolated from generic scanner tools. */
export const BINARY_TOOL_NAMES = ["analyze_binary"] as const;

export const binaryToolDefinitions: Record<(typeof BINARY_TOOL_NAMES)[number], ToolDefinition> = {
  analyze_binary: ZEROVERSE_TOOL_DEFINITION,
};

export const binaryDispatch: Record<(typeof BINARY_TOOL_NAMES)[number], string> = {
  analyze_binary: "analyzeBinary",
};
