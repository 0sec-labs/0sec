import type { ToolDefinition } from "./types.js";

/**
 * Progressive tool disclosure (the tool-curation paper's deferred-loading
 * technique) for high-cardinality tool sources.
 *
 * The built-in security tool set is deliberately consolidated to stay under the
 * ~30-50-tool degradation threshold, so it is advertised in full. External MCP
 * servers are the real cardinality problem: a single server can expose dozens of
 * tools (a mail server alone can be 25+), and dumping them all into every turn's
 * tool set both blows the token budget and measurably degrades tool selection.
 *
 * This registry keeps such a catalog DEFERRED behind two always-advertised
 * control tools:
 *   - `list_tools`  — the model searches the catalog by keyword and sees
 *                     one-line descriptions of what is available but not loaded.
 *   - `load_tool`   — the model loads the specific tools it needs by name; only
 *                     then do their full schemas enter the advertised set.
 *
 * The registry is session-scoped and mutated only at turn boundaries (a
 * `load_tool` call on turn N makes the tool callable on turn N+1, exactly like
 * self-extension), so it never mutates a tool set mid-round.
 */

/** Always-advertised control tools. */
export const LIST_TOOLS_NAME = "list_tools";
export const LOAD_TOOL_NAME = "load_tool";
export const DEFERRED_CONTROL_TOOL_NAMES = [LIST_TOOLS_NAME, LOAD_TOOL_NAME] as const;

/**
 * Below this many deferrable tools, deferral is pure overhead — advertise them
 * all directly. At or above it, defer behind list_tools/load_tool.
 */
export const DEFERRED_TOOLS_MIN = 12;

/** How many characters of a tool description `list_tools` shows per entry. */
const CATALOG_DESC_MAX = 160;

/** How many catalog entries `list_tools` returns at most per call. */
const LIST_TOOLS_PAGE = 60;

export interface DeferredCatalogEntry {
  name: string;
  description: string;
  loaded: boolean;
}

export interface LoadToolResult {
  /** Names newly loaded (or already loaded) — now in the advertised set. */
  loaded: string[];
  /** Requested names that are not in the catalog. */
  unknown: string[];
}

/** `list_tools` definition — always safe (read-only, no side effects). */
export const listToolsDef: ToolDefinition = {
  name: LIST_TOOLS_NAME,
  description:
    "List additional tools available to load this session (e.g. connected MCP-server tools) that are NOT yet in your tool set. Optionally filter by a keyword. Use load_tool to make the ones you need callable.",
  parameters: {
    query: {
      type: "string",
      description:
        "Optional keyword to filter tools by name or description (case-insensitive). Omit to list everything available.",
    },
  },
  required: [],
};

/** `load_tool` definition — makes deferred tools callable on the next turn. */
export const loadToolDef: ToolDefinition = {
  name: LOAD_TOOL_NAME,
  description:
    "Load one or more deferred tools by exact name so they enter your tool set and become callable on your next turn. Discover names with list_tools first. Load only what you need.",
  parameters: {
    names: {
      type: "array",
      description: "Exact tool names to load (from list_tools).",
      items: { type: "string" },
    },
  },
  required: ["names"],
};

export class DeferredToolRegistry {
  private readonly catalog = new Map<string, ToolDefinition>();
  private readonly loaded = new Set<string>();

  /**
   * Seed / refresh the deferrable catalog. Idempotent: re-seeding with the same
   * defs is a no-op, a def that disappeared (server dropped) is pruned from both
   * the catalog and the loaded set, and a name already loaded stays loaded.
   */
  seed(defs: readonly ToolDefinition[]): void {
    const present = new Set<string>();
    for (const def of defs) {
      this.catalog.set(def.name, def);
      present.add(def.name);
    }
    for (const name of [...this.catalog.keys()]) {
      if (!present.has(name)) {
        this.catalog.delete(name);
        this.loaded.delete(name);
      }
    }
  }

  /** Total deferrable tools known this session. */
  size(): number {
    return this.catalog.size;
  }

  isLoaded(name: string): boolean {
    return this.loaded.has(name);
  }

  isControlTool(name: string): boolean {
    return name === LIST_TOOLS_NAME || name === LOAD_TOOL_NAME;
  }

  /**
   * Load the named tools. Unknown names are reported, not loaded; a re-load of
   * an already-loaded tool is idempotent. Returns what happened so the tool
   * result can tell the model precisely.
   */
  load(names: readonly string[]): LoadToolResult {
    const loaded: string[] = [];
    const unknown: string[] = [];
    for (const raw of names) {
      const name = typeof raw === "string" ? raw.trim() : "";
      if (!name) continue;
      if (this.catalog.has(name)) {
        this.loaded.add(name);
        loaded.push(name);
      } else {
        unknown.push(name);
      }
    }
    return { loaded, unknown };
  }

  /** Full definitions of currently-loaded tools, to inject into the tool set. */
  loadedDefinitions(): ToolDefinition[] {
    const out: ToolDefinition[] = [];
    for (const name of this.loaded) {
      const def = this.catalog.get(name);
      if (def) out.push(def);
    }
    return out;
  }

  /** Catalog view for `list_tools`, optionally filtered by keyword. */
  catalogEntries(query?: string): DeferredCatalogEntry[] {
    const q = (query ?? "").trim().toLowerCase();
    const out: DeferredCatalogEntry[] = [];
    for (const def of this.catalog.values()) {
      if (q && !def.name.toLowerCase().includes(q) && !def.description.toLowerCase().includes(q)) {
        continue;
      }
      out.push({ name: def.name, description: def.description, loaded: this.loaded.has(def.name) });
    }
    out.sort((a, b) => a.name.localeCompare(b.name));
    return out;
  }
}

/** Format a `list_tools` result as model-facing text. */
export function formatToolCatalog(entries: readonly DeferredCatalogEntry[], query?: string): string {
  if (entries.length === 0) {
    return query && query.trim()
      ? `No loadable tools match "${query.trim()}".`
      : "No additional loadable tools are available this session.";
  }
  const shown = entries.slice(0, LIST_TOOLS_PAGE);
  const lines = shown.map((e) => {
    const desc = e.description.length > CATALOG_DESC_MAX
      ? `${e.description.slice(0, CATALOG_DESC_MAX - 1)}…`
      : e.description;
    return `- ${e.name}${e.loaded ? " [loaded]" : ""} — ${desc}`;
  });
  const header = `${entries.length} loadable tool(s)${query && query.trim() ? ` matching "${query.trim()}"` : ""}. Call load_tool with the exact names you need:`;
  const footer = entries.length > shown.length
    ? `\n… and ${entries.length - shown.length} more (narrow with a query).`
    : "";
  return `${header}\n${lines.join("\n")}${footer}`;
}

/** Format a `load_tool` result as model-facing text. */
export function formatLoadResult(result: LoadToolResult): string {
  const parts: string[] = [];
  if (result.loaded.length > 0) {
    parts.push(
      `Loaded ${result.loaded.length} tool(s), callable on your next turn: ${result.loaded.join(", ")}.`,
    );
  }
  if (result.unknown.length > 0) {
    parts.push(
      `Not found (use list_tools for exact names): ${result.unknown.join(", ")}.`,
    );
  }
  if (parts.length === 0) return "No tool names were provided.";
  return parts.join(" ");
}
