/**
 * Runtime-environment probes for deciding whether to launch the opentui
 * (Bun-targeted) TUI flow. Kept deliberately free of opentui imports so
 * callers can check Bun-availability without eagerly loading a chunk
 * that only resolves cleanly under Bun.
 */

export function isBunRuntime(): boolean {
  return typeof globalThis === "object" && globalThis !== null && "Bun" in globalThis;
}

export function canUseOpenTui(): boolean {
  return !!(process.stdout.isTTY && process.stdin.isTTY);
}
