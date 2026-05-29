/**
 * Tool dispatch table (pwnkit#614).
 *
 * Merges every per-domain `*Dispatch` map (tool name → ToolExecutor handler
 * method name) into one lookup table. `ToolExecutor._dispatch` resolves the
 * handler off the instance by this name instead of a hand-written switch, so
 * adding a tool only touches its domain module (its `*Dispatch` map +
 * definition) — never a shared dispatch chokepoint. The handler bodies stay
 * private methods on the class; this table only carries their names.
 *
 * This barrel changes only when a NEW DOMAIN is added, not per-tool.
 */
import { reconDispatch } from "./recon.js";
import { findingsDispatch } from "./findings.js";
import { systemDispatch } from "./system.js";
import { accessControlDispatch } from "./access-control.js";
import { exploitDispatch } from "./exploit.js";
import { intelDispatch } from "./intel.js";
import { skillsDispatch } from "./skills.js";
import { scannerDispatch } from "./scanner.js";

export const TOOL_DISPATCH: Record<string, string> = {
  ...reconDispatch,
  ...findingsDispatch,
  ...systemDispatch,
  ...accessControlDispatch,
  ...exploitDispatch,
  ...intelDispatch,
  ...skillsDispatch,
  ...scannerDispatch,
};
