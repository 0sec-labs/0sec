/**
 * The single source of truth for every keyboard shortcut the chat console
 * (`chat-screen.tsx`) binds.
 *
 * This module is PURE DATA — no React, no OpenTUI, no `@0sec/core` — so it can
 * be imported by the reference view, the settings surface, and a future
 * remapping layer alike, and unit-tested without a terminal.
 *
 * ## Accuracy rule
 *
 * Nothing here is invented. Every entry was read off a real `useKeyboard`
 * branch in `chat-screen.tsx`, and each carries a `handler` field quoting the
 * guard it was captured from so the registry can be re-verified against the
 * code. When a single action is reachable by more than one chord (the palette
 * on Ctrl+P *or* Ctrl+K, scrolling on PageUp *or* Ctrl+Up), the alternates are
 * shown together in one `keys` string rather than split into look-alike rows.
 *
 * Modal overlays (the command/theme/model picker, the approval and
 * `ask_operator` cards, the secret-entry prompt) reuse Up/Down to move,
 * Enter to confirm and Esc to cancel — the same keys documented here for the
 * base composer, given a modal meaning while the overlay is up. They are not
 * repeated as separate entries; the descriptions below name those meanings.
 *
 * ## Intended future: live remapping (out of scope here)
 *
 * This registry is deliberately the *only* place the full binding set is
 * enumerated, so that a later phase can hang key remapping off it: a persisted
 * overrides store keyed by {@link Keybinding.id}, an edit UI that writes it, and
 * a lookup that `chat-screen.tsx`'s handlers consult instead of their current
 * hard-coded `key.name === …` guards. Today those guards are still the runtime
 * authority and this module only DESCRIBES them — keep the two in sync until the
 * handlers are migrated to read from here. See the task's "phase-2" note.
 */

/** The surface each shortcut belongs to, used to group the reference view. */
export type KeybindingCategory =
  | "Composer"
  | "Navigation"
  | "Session"
  | "View"
  | "Autonomy";

export interface Keybinding {
  /**
   * A stable, unique identifier — the key a future overrides store would use.
   * Never shown to the operator; safe to rely on across releases.
   */
  readonly id: string;
  /** The chord(s), formatted for display, e.g. "Ctrl+B" or "PageUp / Ctrl+Up". */
  readonly keys: string;
  /** One line describing what the chord does. */
  readonly description: string;
  readonly category: KeybindingCategory;
  /**
   * The `chat-screen.tsx` guard this binding was captured from, quoted verbatim
   * so the registry can be checked against the handler that implements it. Not
   * rendered — this is provenance for maintainers, not operator-facing help.
   */
  readonly handler: string;
}

/**
 * Every keyboard shortcut the chat console binds, in reading order by category.
 *
 * The order within a category is roughly by how often an operator reaches for
 * the key, not alphabetical, so the reference reads top-to-bottom like a
 * cheat-sheet.
 */
export const KEYBINDINGS: readonly Keybinding[] = [
  // ── Composer ──────────────────────────────────────────────────────────────
  {
    id: "composer.send",
    keys: "Enter",
    description:
      "Send the message or run the highlighted slash command; queues the line when a turn is already in flight.",
    category: "Composer",
    handler: 'if (key.name === "return") { … send / queue / dequeue }',
  },
  {
    id: "composer.newline",
    keys: "Shift+Enter",
    description:
      "Insert a newline instead of sending (terminals without the kitty protocol fall through to send).",
    category: "Composer",
    handler: 'if (key.name === "return" && key.shift) setComposerText(`${…}\\n`)',
  },
  {
    id: "composer.complete-command",
    keys: "Tab",
    description: "Complete the highlighted slash command in the command menu.",
    category: "Composer",
    handler:
      'if (key.name === "tab") setComposerText(completionFor(selectedSlashCommand, …))',
  },
  {
    id: "composer.edit-queued",
    keys: "Ctrl+Y",
    description:
      "Pull the most recently queued message back into the composer to edit, re-send, or drop.",
    category: "Composer",
    handler:
      'if (key.ctrl && key.name === "y" && queuedRef.current.length > 0) …',
  },
  {
    id: "composer.delete-word",
    keys: "Ctrl+W / Alt+Backspace",
    description: "Delete the word before the cursor.",
    category: "Composer",
    handler:
      'if (key.ctrl && key.name === "w") / if (key.name === "backspace" && (key.meta || key.option || key.ctrl)) → deletePreviousWord',
  },
  {
    id: "composer.delete-to-start",
    keys: "Ctrl+U",
    description: "Delete from the cursor to the start of the line.",
    category: "Composer",
    handler: 'if (key.ctrl && key.name === "u") → deleteToLineStart',
  },

  // ── Navigation ──────────────────────────────────────────────────────────────
  {
    id: "nav.palette",
    keys: "Ctrl+P / Ctrl+K",
    description: "Open the slash-command palette.",
    category: "Navigation",
    handler: 'if (key.ctrl && (key.name === "p" || key.name === "k")) setComposerText("/")',
  },
  {
    id: "nav.history-prev",
    keys: "Up",
    description:
      "Recall the previous submitted message into the composer (also moves the selection in menus and overlays).",
    category: "Navigation",
    handler: 'if (key.name === "up") recallComposerHistory("up")',
  },
  {
    id: "nav.history-next",
    keys: "Down",
    description:
      "Recall the next message, or — on an empty composer with workers running — drop into the active-subagents list.",
    category: "Navigation",
    handler:
      'if (key.name === "down") { setAgentNavIndex(0) | recallComposerHistory("down") }',
  },
  {
    id: "nav.escape",
    keys: "Esc",
    description:
      "Step back one level: close the command menu, then clear the draft, then interrupt a running turn, then leave the screen.",
    category: "Navigation",
    handler: 'if (key.name === "escape") { … interruptTurn() … onGoBack() }',
  },
  {
    id: "nav.scroll-up",
    keys: "PageUp / Ctrl+Up",
    description: "Scroll the transcript up by half a viewport.",
    category: "Navigation",
    handler:
      'if (key.name === "pageup" || (key.ctrl && key.name === "up")) transcriptRef.current?.scrollBy(-0.5, "viewport")',
  },
  {
    id: "nav.scroll-down",
    keys: "PageDown / Ctrl+Down",
    description: "Scroll the transcript down by half a viewport.",
    category: "Navigation",
    handler:
      'if (key.name === "pagedown" || (key.ctrl && key.name === "down")) transcriptRef.current?.scrollBy(0.5, "viewport")',
  },
  {
    id: "nav.focus-subagent",
    keys: "Enter",
    description:
      "In the active-subagents list, drill into the highlighted subagent's live focus view.",
    category: "Navigation",
    handler: 'if (agentNavIndex >= 0) { if (key.name === "return") setFocusAgentId(agent.agent_id) }',
  },
  {
    id: "nav.leave-subagent",
    keys: "Left / Esc",
    description:
      "Return from the active-subagents list or a subagent focus view back to the composer.",
    category: "Navigation",
    handler:
      'if (focusAgentId) / if (agentNavIndex >= 0) { if (key.name === "escape" || key.name === "left") … }',
  },

  // ── Session ─────────────────────────────────────────────────────────────────
  {
    id: "session.quit",
    keys: "Ctrl+C",
    description: "Press twice within 3 seconds to quit; the first press arms and warns.",
    category: "Session",
    handler: 'if (key.ctrl && key.name === "c") requestExitRef.current()',
  },

  // ── View ────────────────────────────────────────────────────────────────────
  {
    id: "view.left-sidebar",
    keys: "Ctrl+B",
    description: "Toggle the left sidebar (persists across the session).",
    category: "View",
    handler: 'if (key.ctrl && key.name === "b") updateSetting("showLeftSidebar", …)',
  },
  {
    id: "view.right-sidebar",
    keys: "Ctrl+L",
    description: "Toggle the right sidebar (persists across the session).",
    category: "View",
    handler: 'if (key.ctrl && key.name === "l") updateSetting("showRightSidebar", …)',
  },
  {
    id: "view.transcript-detail",
    keys: "Ctrl+R",
    description:
      "Toggle the whole transcript between collapsed and expanded tool/reasoning detail (persists across the session).",
    category: "View",
    handler:
      'if (key.ctrl && key.name === "r") updateSetting("transcriptDetail", …)',
  },

  // ── Autonomy ─────────────────────────────────────────────────────────────────
  {
    id: "autonomy.cycle-mode",
    keys: "Shift+Tab",
    description:
      "Cycle the autonomy mode: Standard → Co-pilot → YOLO → Recon (YOLO is skipped when no scope is configured).",
    category: "Autonomy",
    handler: 'if (key.name === "tab" && key.shift) routeSlashCommand(`/mode ${next}`)',
  },
] as const;

/** The category order the reference view renders in. */
export const KEYBINDING_CATEGORIES: readonly KeybindingCategory[] = [
  "Composer",
  "Navigation",
  "Session",
  "View",
  "Autonomy",
];

/**
 * Group the registry by category, preserving both the category order in
 * {@link KEYBINDING_CATEGORIES} and each binding's order within its category.
 *
 * Only categories that actually have bindings appear in the returned map, so a
 * consumer can iterate it directly without emitting an empty heading. Any
 * binding whose category is somehow outside the known list is still included,
 * appended after the known ones, so nothing is silently dropped.
 */
export function keybindingsByCategory(
  bindings: readonly Keybinding[] = KEYBINDINGS,
): Map<KeybindingCategory, Keybinding[]> {
  const grouped = new Map<KeybindingCategory, Keybinding[]>();
  const push = (binding: Keybinding) => {
    const existing = grouped.get(binding.category);
    if (existing) existing.push(binding);
    else grouped.set(binding.category, [binding]);
  };

  // Emit in the canonical category order first…
  for (const category of KEYBINDING_CATEGORIES) {
    for (const binding of bindings) {
      if (binding.category === category) push(binding);
    }
  }
  // …then anything with an unknown category, so it is surfaced rather than lost.
  for (const binding of bindings) {
    if (!KEYBINDING_CATEGORIES.includes(binding.category)) push(binding);
  }

  return grouped;
}
