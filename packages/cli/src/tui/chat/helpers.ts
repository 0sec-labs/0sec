import {
  ScopePolicy,
  type ConsoleAutonomyMode,
  type ConsoleScopeRequest,
  type ConsoleScopeResolution,
} from "@0sec/core";
import type { Theme } from "../theme-context.js";
import type { HerdDetailTone } from "../herd-layout.js";
import type { SlashCommand } from "../slash-commands.js";

export function modeLabel(mode: ConsoleAutonomyMode): string {
  if (mode === "standard") return "Standard";
  if (mode === "recon") return "Recon";
  return mode === "copilot" ? "Co-pilot" : "YOLO";
}

/**
 * Colour for an autonomy mode, shared by the header indicator and any other
 * place the mode is shown: Standard=white (neutral), Recon=blue (passive),
 * Co-pilot=purple (the brand accent), YOLO=red (no prompts).
 */
export function modeColorFor(mode: ConsoleAutonomyMode, theme: Theme): string {
  if (mode === "recon") return theme.INFO;
  if (mode === "copilot") return theme.BRAND;
  if (mode === "yolo") return theme.ERROR;
  return theme.TEXT;
}

/**
 * Map a herd focus line's tone onto the theme — the same mapping `herd-screen`
 * uses for its focus panes, mirrored here so the INLINE focus view drilled into
 * from the chat renders identically. Red (ERROR) is never produced from a tone;
 * WARNING carries a failed status, so the "red = errors" invariant holds.
 */
export function herdToneColor(theme: Theme, tone: HerdDetailTone): string {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "accent":
      return theme.ACCENT;
    case "warn":
      return theme.WARNING;
    case "muted":
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

export function completionFor(command: SlashCommand, args = ""): string {
  const base = `/${command.name}`;
  if (args) return `${base} ${args}`;
  return command.usage?.includes(" ") ? `${base} ` : base;
}

export function commandMatchesPrefix(command: SlashCommand, rawName: string): boolean {
  return rawName.length === 0
    || command.name.startsWith(rawName)
    || command.aliases.some((alias) => alias.startsWith(rawName));
}

export function buildScopeResolution(request: ConsoleScopeRequest): ConsoleScopeResolution | null {
  const raw = request.currentScope?.raw ?? {};
  const inScope = new Set(raw.in_scope ?? []);
  let target = request.target.trim();

  for (const requestedUrl of request.requestedUrls) {
    try {
      const url = new URL(requestedUrl);
      inScope.add(url.hostname);
      if (!target) target = url.origin;
    } catch {
      return null;
    }
  }

  if (!target || inScope.size === 0) return null;
  const scope = ScopePolicy.fromJson({ ...raw, in_scope: [...inScope] });
  if (request.requestedUrls.some((url) => !scope.match(url).allowed)) return null;
  return { target, scope };
}
