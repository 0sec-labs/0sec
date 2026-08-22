import { describe, expect, it } from "vitest";

import {
  buildHelpPanel,
  buildScopePanel,
  buildStatusPanel,
  buildToolsPanel,
  panelColumns,
  type HelpCommand,
  type PanelData,
  type PanelRow,
} from "./panels.js";

/** Row shapes that have historically broken column arithmetic. */
const ROW_SHAPES: Record<string, PanelRow[]> = {
  allLabelled: [
    { label: "/help", value: "Show available slash commands" },
    { label: "/mode [standard|copilot|yolo]", value: "Set the approval mode" },
  ],
  noneLabelled: [{ value: "read_file" }, { value: "run_command" }],
  mixed: [
    { value: "Info", heading: true },
    { label: "target", value: "https://example.com" },
    { value: "a full-width note" },
  ],
  absurdLabel: [
    { label: "/x".repeat(120), value: "description that must survive" },
    { label: "/y", value: "another" },
  ],
  headingOnly: [{ value: "Rules", heading: true }],
  empty: [],
};

function everyWidth(fn: (width: number) => void): void {
  for (let width = 0; width <= 200; width += 1) fn(width);
}

describe("panelColumns", () => {
  it("never lets the columns claim more cells than the panel body", () => {
    for (const [shape, rows] of Object.entries(ROW_SHAPES)) {
      everyWidth((width) => {
        const cols = panelColumns(rows, width);
        const claimed = cols.labelWidth + cols.gap + cols.valueWidth;
        expect(
          claimed,
          `${shape} overflowed at innerWidth ${width}: ${claimed} > ${width}`,
        ).toBeLessThanOrEqual(width);
      });
    }
  });

  it("never returns a negative width", () => {
    for (const rows of Object.values(ROW_SHAPES)) {
      everyWidth((width) => {
        const cols = panelColumns(rows, width);
        expect(cols.labelWidth).toBeGreaterThanOrEqual(0);
        expect(cols.gap).toBeGreaterThanOrEqual(0);
        expect(cols.valueWidth).toBeGreaterThanOrEqual(0);
      });
      // Geometry can arrive negative mid-resize.
      const cols = panelColumns(rows, -40);
      expect(cols.labelWidth).toBe(0);
      expect(cols.gap).toBe(0);
      expect(cols.valueWidth).toBe(0);
    }
  });

  it("holds the invariant at the degenerate widths 0, 1 and 2", () => {
    for (const rows of Object.values(ROW_SHAPES)) {
      for (const width of [0, 1, 2]) {
        const cols = panelColumns(rows, width);
        expect(cols.labelWidth + cols.gap + cols.valueWidth).toBeLessThanOrEqual(width);
      }
    }
  });

  it("drops the label column entirely when no row has a label", () => {
    for (const width of [0, 1, 10, 80, 200]) {
      const cols = panelColumns(ROW_SHAPES.noneLabelled!, width);
      expect(cols.labelWidth).toBe(0);
      expect(cols.gap).toBe(0);
      expect(cols.valueWidth).toBe(width);
    }
  });

  it("sizes the label column to the longest label when it fits", () => {
    const cols = panelColumns(
      [
        { label: "mode", value: "standard" },
        { label: "target", value: "https://example.com" },
      ],
      80,
    );
    expect(cols.labelWidth).toBe("target".length);
    expect(cols.gap).toBe(1);
    expect(cols.valueWidth).toBe(80 - "target".length - 1);
  });

  it("caps an absurdly long label at 40% rather than starving the value column", () => {
    const cols = panelColumns(ROW_SHAPES.absurdLabel!, 100);
    expect(cols.labelWidth).toBe(40);
    expect(cols.gap).toBe(1);
    expect(cols.valueWidth).toBe(59);
  });

  it("ignores heading text when sizing the label column", () => {
    const cols = panelColumns(
      [
        { value: "A very long heading line indeed", heading: true },
        { label: "id", value: "42" },
      ],
      80,
    );
    expect(cols.labelWidth).toBe("id".length);
  });
});

// ---------------------------------------------------------------------------

const COMMANDS: HelpCommand[] = [
  {
    name: "help",
    aliases: ["?", "commands"],
    description: "Show available slash commands",
    usage: "/help [command]",
    category: "info",
  },
  { name: "status", aliases: [], description: "Show session status", category: "info" },
  { name: "clear", aliases: ["new"], description: "Clear the conversation", category: "session" },
  {
    name: "mode",
    aliases: [],
    description: "Set the approval mode",
    usage: "/mode [standard|copilot|yolo]",
    category: "mode",
  },
  { name: "exit", aliases: ["quit"], description: "End the session", category: "system" },
];

function headings(panel: PanelData): string[] {
  return panel.rows.filter((r) => r.heading).map((r) => r.value);
}

function rowFor(panel: PanelData, label: string): PanelRow | undefined {
  return panel.rows.find((r) => r.label === label);
}

describe("buildHelpPanel", () => {
  it("groups commands by category, in a stable order, with headings", () => {
    const panel = buildHelpPanel(COMMANDS);
    expect(panel.title).toBe("Slash commands");
    expect(headings(panel)).toEqual(["Info", "Session", "Mode", "System"]);

    // Each heading must be immediately followed by its own commands.
    const infoIndex = panel.rows.findIndex((r) => r.heading && r.value === "Info");
    expect(panel.rows[infoIndex + 1]?.label).toBe("/help [command]");
    expect(panel.rows[infoIndex + 2]?.label).toBe("/status");
  });

  it("uses the usage hint as the label when a command takes arguments", () => {
    const panel = buildHelpPanel(COMMANDS);
    expect(rowFor(panel, "/mode [standard|copilot|yolo]")?.value).toContain(
      "Set the approval mode",
    );
    expect(rowFor(panel, "/status")).toBeDefined();
  });

  it("appends aliases only when the command has them", () => {
    const panel = buildHelpPanel(COMMANDS);
    expect(rowFor(panel, "/help [command]")?.value).toBe(
      "Show available slash commands (/?, /commands)",
    );
    expect(rowFor(panel, "/status")?.value).toBe("Show session status");
    expect(rowFor(panel, "/status")?.value).not.toContain("(");
  });

  it("reports the count in the subtitle and reflects the query when given", () => {
    expect(buildHelpPanel(COMMANDS).subtitle).toBe("5 commands");

    const filtered = buildHelpPanel(COMMANDS, "mode");
    expect(filtered.subtitle).toContain("mode");
    expect(filtered.subtitle).toMatch(/matching/i);
    expect(filtered.rows.some((r) => r.label === "/mode [standard|copilot|yolo]")).toBe(true);
    expect(filtered.rows.some((r) => r.label === "/exit")).toBe(false);
  });

  it("returns an empty-state row — never zero rows — for a non-matching query", () => {
    const panel = buildHelpPanel(COMMANDS, "zzzznope");
    expect(panel.rows.length).toBeGreaterThan(0);
    expect(panel.rows[0]?.value).toContain("zzzznope");
    expect(panel.rows[0]?.value).toMatch(/no commands match/i);
    expect(panel.title).toBe("Slash commands");
  });

  it("returns an empty-state row for an empty vocabulary", () => {
    const panel = buildHelpPanel([]);
    expect(panel.rows).toHaveLength(1);
    expect(panel.rows[0]?.value).toMatch(/no slash commands/i);
  });
});

describe("buildToolsPanel", () => {
  it("lists one row per tool and reports the count", () => {
    const panel = buildToolsPanel(["read_file", "run_command", "http_request"]);
    expect(panel.title).toBe("Tools");
    expect(panel.subtitle).toBe("3 tools");
    expect(panel.rows.map((r) => r.value)).toEqual([
      "read_file",
      "run_command",
      "http_request",
    ]);
  });

  it("returns an empty-state row for an empty tool list", () => {
    const panel = buildToolsPanel([]);
    expect(panel.rows).toHaveLength(1);
    expect(panel.rows[0]?.value).toMatch(/no tools are registered/i);
  });
});

describe("buildStatusPanel", () => {
  const BASE = {
    mode: "standard",
    scopeRules: [] as readonly string[],
    toolCount: 12,
    turns: 3,
    inputTokens: 1200,
    outputTokens: 340,
  };

  it("says 'not set' for a missing target and 'scope on demand' for empty scope", () => {
    const panel = buildStatusPanel(BASE);
    expect(rowFor(panel, "target")?.value).toBe("not set");
    expect(rowFor(panel, "scope")?.value).toBe("scope on demand");
    expect(rowFor(panel, "model")?.value).toBe("not set");
  });

  it("formats tokens as in→out", () => {
    expect(rowFor(buildStatusPanel(BASE), "tokens")?.value).toBe("1200→340");
  });

  it("shows the provider in parens beside the model", () => {
    const panel = buildStatusPanel({ ...BASE, model: "claude-opus-5", provider: "anthropic" });
    expect(rowFor(panel, "model")?.value).toBe("claude-opus-5 (anthropic)");
  });

  it("keeps every row present even when optional inputs are missing", () => {
    const panel = buildStatusPanel(BASE);
    const labels = panel.rows.map((r) => r.label);
    expect(labels).toEqual([
      "model",
      "mode",
      "target",
      "scope",
      "tools",
      "turns",
      "tokens",
    ]);
  });

  it("joins configured scope rules", () => {
    const panel = buildStatusPanel({
      ...BASE,
      target: "https://example.com",
      scopeRules: ["*.example.com", "10.0.0.0/8"],
    });
    expect(rowFor(panel, "scope")?.value).toBe("*.example.com, 10.0.0.0/8");
    expect(rowFor(panel, "target")?.value).toBe("https://example.com");
  });
});

describe("buildScopePanel", () => {
  it("states that nothing is configured and that approval is required", () => {
    const panel = buildScopePanel({ mode: "standard", scopeRules: [] });
    expect(panel.title).toBe("Engagement scope");
    const text = panel.rows.map((r) => r.value).join(" ").toLowerCase();
    expect(text).toContain("no engagement scope is configured");
    expect(text).toContain("approval");
    expect(text).toMatch(/nothing is authorized/);
    // Must never imply an unconfigured scope is permissive.
    expect(text).not.toMatch(/all targets|everything (is )?in scope/);
  });

  it("lists one row per rule when scope is configured", () => {
    const rules = ["*.example.com", "10.0.0.0/8", "api.example.net"];
    const panel = buildScopePanel({
      mode: "copilot",
      target: "https://example.com",
      scopeRules: rules,
    });
    const values = panel.rows.map((r) => r.value);
    for (const rule of rules) expect(values).toContain(rule);
    expect(values.filter((v) => rules.includes(v))).toHaveLength(rules.length);
    expect(panel.subtitle).toContain("3 rules");
    expect(rowFor(panel, "mode")?.value).toBe("copilot");
  });
});

describe("every builder", () => {
  it("returns a non-empty title and at least one row for every input tested", () => {
    const panels: PanelData[] = [
      buildHelpPanel(COMMANDS),
      buildHelpPanel(COMMANDS, "mode"),
      buildHelpPanel(COMMANDS, "zzzznope"),
      buildHelpPanel([]),
      buildToolsPanel([]),
      buildToolsPanel(["read_file"]),
      buildStatusPanel({
        mode: "yolo",
        scopeRules: [],
        toolCount: 0,
        turns: 0,
        inputTokens: 0,
        outputTokens: 0,
      }),
      buildStatusPanel({
        model: "m",
        provider: "p",
        mode: "standard",
        target: "t",
        scopeRules: ["r"],
        toolCount: 1,
        turns: 1,
        inputTokens: 1,
        outputTokens: 1,
      }),
      buildScopePanel({ mode: "standard", scopeRules: [] }),
      buildScopePanel({ mode: "standard", target: "t", scopeRules: ["a", "b"] }),
    ];

    for (const panel of panels) {
      expect(panel.title.length).toBeGreaterThan(0);
      expect(panel.rows.length).toBeGreaterThan(0);
      // A row with no value would render as a blank line inside the panel.
      for (const row of panel.rows) expect(row.value.length).toBeGreaterThan(0);
      // The column allocation must survive real panel data at real widths.
      for (const width of [0, 1, 2, 40, 120]) {
        const cols = panelColumns(panel.rows, width);
        expect(cols.labelWidth + cols.gap + cols.valueWidth).toBeLessThanOrEqual(width);
      }
    }
  });
});
