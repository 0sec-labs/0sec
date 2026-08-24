import { describe, expect, it } from "vitest";

import {
  KEYBINDINGS,
  KEYBINDING_CATEGORIES,
  keybindingsByCategory,
  type Keybinding,
  type KeybindingCategory,
} from "./keybindings.js";

describe("KEYBINDINGS registry", () => {
  it("is non-empty", () => {
    expect(KEYBINDINGS.length).toBeGreaterThan(0);
  });

  it("gives every binding a unique id", () => {
    const ids = KEYBINDINGS.map((binding) => binding.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("fills every field with non-empty, trimmed text", () => {
    for (const binding of KEYBINDINGS) {
      for (const field of ["id", "keys", "description", "category", "handler"] as const) {
        const value = binding[field];
        expect(typeof value, `${binding.id}.${field}`).toBe("string");
        expect(value.length, `${binding.id}.${field}`).toBeGreaterThan(0);
        expect(value, `${binding.id}.${field}`).toBe(value.trim());
      }
    }
  });

  it("only uses known categories", () => {
    for (const binding of KEYBINDINGS) {
      expect(KEYBINDING_CATEGORIES).toContain(binding.category);
    }
  });

  it("ends every description with a full stop", () => {
    // The reference view reads as prose; a description missing its period reads
    // as truncated.
    for (const binding of KEYBINDINGS) {
      expect(binding.description.endsWith("."), binding.id).toBe(true);
    }
  });

  it("documents the load-bearing chords the operator relies on", () => {
    // A regression guard: these are the shortcuts the task called out by name.
    // If a rename or refactor drops one from the registry, this fails loudly.
    const byId = new Map(KEYBINDINGS.map((binding) => [binding.id, binding]));
    const expected: Record<string, { keys: string; category: KeybindingCategory }> = {
      "view.left-sidebar": { keys: "Ctrl+B", category: "View" },
      "view.right-sidebar": { keys: "Ctrl+L", category: "View" },
      "view.transcript-detail": { keys: "Ctrl+R", category: "View" },
      "autonomy.cycle-mode": { keys: "Shift+Tab", category: "Autonomy" },
      "nav.palette": { keys: "Ctrl+P / Ctrl+K", category: "Navigation" },
      "session.quit": { keys: "Ctrl+C", category: "Session" },
      "composer.send": { keys: "Enter", category: "Composer" },
      "composer.edit-queued": { keys: "Ctrl+Y", category: "Composer" },
      "composer.newline": { keys: "Shift+Enter", category: "Composer" },
      "nav.escape": { keys: "Esc", category: "Navigation" },
      "nav.scroll-up": { keys: "PageUp / Ctrl+Up", category: "Navigation" },
      "nav.scroll-down": { keys: "PageDown / Ctrl+Down", category: "Navigation" },
    };
    for (const [id, spec] of Object.entries(expected)) {
      const binding = byId.get(id);
      expect(binding, id).toBeDefined();
      expect(binding?.keys, id).toBe(spec.keys);
      expect(binding?.category, id).toBe(spec.category);
    }
  });
});

describe("keybindingsByCategory", () => {
  it("groups every binding under its category", () => {
    const grouped = keybindingsByCategory();
    const flattened = [...grouped.values()].flat();
    expect(flattened.length).toBe(KEYBINDINGS.length);
    for (const [category, bindings] of grouped) {
      for (const binding of bindings) {
        expect(binding.category).toBe(category);
      }
    }
  });

  it("preserves the canonical category order", () => {
    const grouped = keybindingsByCategory();
    const seen = [...grouped.keys()];
    const expectedOrder = KEYBINDING_CATEGORIES.filter((category) =>
      KEYBINDINGS.some((binding) => binding.category === category),
    );
    expect(seen).toEqual(expectedOrder);
  });

  it("preserves each binding's order within its category", () => {
    const grouped = keybindingsByCategory();
    for (const [category, bindings] of grouped) {
      const fromRegistry = KEYBINDINGS.filter((binding) => binding.category === category);
      expect(bindings.map((b) => b.id)).toEqual(fromRegistry.map((b) => b.id));
    }
  });

  it("only emits categories that have bindings", () => {
    const grouped = keybindingsByCategory();
    for (const bindings of grouped.values()) {
      expect(bindings.length).toBeGreaterThan(0);
    }
  });

  it("surfaces a binding with an unknown category rather than dropping it", () => {
    const rogue: Keybinding = {
      id: "rogue.binding",
      keys: "Ctrl+Z",
      description: "A binding with a category outside the known set.",
      category: "Nonsense" as KeybindingCategory,
      handler: "test-only",
    };
    const grouped = keybindingsByCategory([...KEYBINDINGS, rogue]);
    const flattened = [...grouped.values()].flat();
    expect(flattened.map((b) => b.id)).toContain("rogue.binding");
    // It lands after every known-category binding.
    expect(flattened[flattened.length - 1]?.id).toBe("rogue.binding");
  });

  it("returns an empty map for an empty registry", () => {
    expect(keybindingsByCategory([]).size).toBe(0);
  });
});
