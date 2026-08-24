import { describe, expect, it } from "vitest";

import {
  HERD_ACTIVITY_MAX,
  HERD_COMPOSER_CURSOR,
  HERD_COMPOSER_PROMPT,
  HERD_PEER_TTL_MS,
  HERD_STATUS_ORDER,
  abbreviateHomePath,
  applySubagentLifecycle,
  applySubagentProgress,
  buildHerdRows,
  clampHerdSelection,
  clipDetailLines,
  computeHerdFocusLayout,
  computeHerdLayout,
  computeHerdWindow,
  firstSelectableIndex,
  focusHeaderLines,
  formatRelativeAge,
  herdComposerFooterHint,
  herdComposerTextWidth,
  herdComposerVisibleDraft,
  herdDetailLines,
  herdFocusFooterHint,
  herdFocusTranscriptTitle,
  herdListHeading,
  herdListTitle,
  paneTitleColumns,
  herdRowLabelText,
  herdRowStatusText,
  herdStatusOf,
  isPeerStale,
  lastSelectableIndex,
  mergeSubagentRoster,
  moveHerdSelection,
  renderFocusActivity,
  subagentPeers,
  windowFocusTail,
  wrapCells,
  type HerdFocusLayout,
  type HerdLayout,
  type HerdPeer,
  type HerdRow,
  type HerdStatus,
  type HerdSubagentMap,
} from "./herd-layout.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

/**
 * A swept axis: every `step`th value in `[min, max]`, plus the boundary sizes
 * (`min`, `min+1`, `min+2`, `max`) always tested explicitly. This keeps the
 * small/edge and large-end coverage of a dense 0..max loop while running a
 * fraction of the iterations.
 */
const sweepAxis = (min: number, max: number, step: number): number[] => {
  const seen = new Set<number>([min, min + 1, min + 2, max]);
  for (let v = min; v <= max; v += step) seen.add(v);
  return [...seen].filter((v) => v >= min && v <= max).sort((a, b) => a - b);
};

const NOW = 1_000_000_000;

/** A peer that is `ageMs` old as of {@link NOW}, in the given phase. */
function peer(id: string, over: Partial<HerdPeer> = {}): HerdPeer {
  return {
    id,
    kind: "session",
    pid: 4242,
    cwd: "/home/dev/project",
    lastSeen: NOW,
    ...over,
  };
}

/** One peer per status bucket, so grouping has something in every group. */
function everyStatusRoster(): HerdPeer[] {
  return [
    peer("work", { activity: { phase: "working" } }),
    peer("idleone"),
    peer("blk", { activity: { phase: "blocked" } }),
    peer("fin", { activity: { phase: "done" } }),
    peer("dead", { lastSeen: NOW - HERD_PEER_TTL_MS - 1 }),
  ];
}

// ---------------------------------------------------------------------------
// Status derivation — must match registry.isStale at the TTL boundary
// ---------------------------------------------------------------------------

describe("status derivation mirrors registry.statusOf", () => {
  it("is INCLUSIVE-ALIVE at the TTL boundary", () => {
    // age exactly == ttl is still active; age one ms past becomes stale.
    const atBoundary = peer("p", { lastSeen: NOW - HERD_PEER_TTL_MS });
    const pastBoundary = peer("p", { lastSeen: NOW - HERD_PEER_TTL_MS - 1 });
    expect(isPeerStale(atBoundary, NOW)).toBe(false);
    expect(isPeerStale(pastBoundary, NOW)).toBe(true);
    expect(herdStatusOf(atBoundary, NOW)).not.toBe("stale");
    expect(herdStatusOf(pastBoundary, NOW)).toBe("stale");
  });

  it("honours a custom ttl and falls back on a bad one", () => {
    const p = peer("p", { lastSeen: NOW - 100 });
    expect(isPeerStale(p, NOW, 50)).toBe(true);
    expect(isPeerStale(p, NOW, 200)).toBe(false);
    // non-positive / non-finite ttl falls back to the default (not "everything stale")
    expect(isPeerStale(p, NOW, 0)).toBe(false);
    expect(isPeerStale(p, NOW, Number.NaN)).toBe(false);
    expect(isPeerStale(p, NOW, -5)).toBe(false);
  });

  it("stale wins over an activity phase", () => {
    const p = peer("p", {
      lastSeen: NOW - HERD_PEER_TTL_MS - 1,
      activity: { phase: "working" },
    });
    expect(herdStatusOf(p, NOW)).toBe("stale");
  });

  it("an active peer with no activity is idle", () => {
    expect(herdStatusOf(peer("p"), NOW)).toBe("idle");
  });
});

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

describe("buildHerdRows — grouping", () => {
  it("buckets peers into the right groups, in stable order, with counts", () => {
    const rows = buildHerdRows(everyStatusRoster(), NOW);
    const headings = rows.filter((r): r is Extract<HerdRow, { kind: "heading" }> => r.kind === "heading");
    expect(headings.map((h) => h.status)).toEqual(HERD_STATUS_ORDER);
    for (const h of headings) expect(h.count).toBe(1);
  });

  it("omits empty groups", () => {
    const rows = buildHerdRows([peer("a"), peer("b")], NOW); // both idle
    const statuses = new Set(rows.map((r) => r.status));
    expect([...statuses]).toEqual(["idle"]);
    expect(rows[0]).toMatchObject({ kind: "heading", status: "idle", count: 2 });
    expect(rows.filter((r) => r.kind === "peer")).toHaveLength(2);
  });

  it("preserves provider order within a group", () => {
    const rows = buildHerdRows([peer("first"), peer("second"), peer("third")], NOW);
    const ids = rows.filter((r) => r.kind === "peer").map((r) => (r.kind === "peer" ? r.peer.id : ""));
    expect(ids).toEqual(["first", "second", "third"]);
  });

  it("an all-empty roster yields no rows (empty state), not a crash", () => {
    expect(buildHerdRows([], NOW)).toEqual([]);
    // and the title reflects it
    const window = computeHerdWindow({ rows: [], selected: -1, visible: 10 });
    expect(herdListTitle(window)).toBe("HERD 0");
  });

  it("ignores malformed roster entries", () => {
    const rows = buildHerdRows(
      [peer("ok"), undefined as unknown as HerdPeer, { id: 5 } as unknown as HerdPeer],
      NOW,
    );
    expect(rows.filter((r) => r.kind === "peer")).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

describe("navigation skips headings, wraps and clamps", () => {
  const rows = buildHerdRows(everyStatusRoster(), NOW);

  it("first/last selectable land on peers, never headings", () => {
    expect(rows[firstSelectableIndex(rows)]?.kind).toBe("peer");
    expect(rows[lastSelectableIndex(rows)]?.kind).toBe("peer");
  });

  it("moving down never stops on a heading", () => {
    let index = firstSelectableIndex(rows);
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveHerdSelection(rows, index, 1);
      expect(rows[index]?.kind).toBe("peer");
    }
  });

  it("wraps from last peer forward to first and vice versa", () => {
    const first = firstSelectableIndex(rows);
    const last = lastSelectableIndex(rows);
    expect(moveHerdSelection(rows, last, 1)).toBe(first);
    expect(moveHerdSelection(rows, first, -1)).toBe(last);
  });

  it("clamps a stale index onto a peer", () => {
    expect(rows[clampHerdSelection(rows, 0)]?.kind).toBe("peer"); // 0 is a heading
    expect(rows[clampHerdSelection(rows, 999)]?.kind).toBe("peer");
    expect(clampHerdSelection([], 3)).toBe(-1);
  });

  it("a heading-only list terminates rather than spinning", () => {
    const headingOnly: HerdRow[] = [{ kind: "heading", status: "idle", count: 0 }];
    expect(moveHerdSelection(headingOnly, 0, 1)).toBe(-1);
    expect(firstSelectableIndex(headingOnly)).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// Windowing keeps the selection visible
// ---------------------------------------------------------------------------

describe("computeHerdWindow", () => {
  const rows = buildHerdRows(
    Array.from({ length: 20 }, (_, i) => peer(`p${i}`)),
    NOW,
  );

  it("keeps the cursor inside the window as it moves", () => {
    let anchor = 0;
    let selected = firstSelectableIndex(rows);
    for (let step = 0; step < 60; step++) {
      const window = computeHerdWindow({ rows, selected, visible: 6, anchor });
      expect(selected).toBeGreaterThanOrEqual(window.start);
      expect(selected).toBeLessThan(window.end);
      expect(window.end - window.start).toBe(window.count);
      anchor = window.start;
      selected = moveHerdSelection(rows, selected, 1);
    }
  });

  it("pulls in the group heading above the cursor when it can", () => {
    const grouped = buildHerdRows(everyStatusRoster(), NOW);
    // select the first peer of the "idle" group (its heading sits just above)
    const idleHeading = grouped.findIndex((r) => r.kind === "heading" && r.status === "idle");
    const firstIdlePeer = idleHeading + 1;
    const window = computeHerdWindow({ rows: grouped, selected: firstIdlePeer, visible: 3, anchor: firstIdlePeer });
    expect(window.start).toBeLessThanOrEqual(idleHeading);
  });

  it("degrades to empty at zero capacity", () => {
    const window = computeHerdWindow({ rows, selected: 1, visible: 0 });
    expect(window).toMatchObject({ start: 0, end: 0, count: 0 });
  });
});

// ---------------------------------------------------------------------------
// The sweep — nothing exceeds its container, at any geometry
// ---------------------------------------------------------------------------

function layoutNumbers(layout: HerdLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["paneGap", layout.paneGap],
    ["visibleRows", layout.visibleRows],
    ["list.width", layout.list.width],
    ["list.innerWidth", layout.list.innerWidth],
    ["list.height", layout.list.height],
    ["list.bodyRows", layout.list.bodyRows],
    ["detail.width", layout.detail.width],
    ["detail.innerWidth", layout.detail.innerWidth],
    ["detail.height", layout.detail.height],
    ["detail.bodyRows", layout.detail.bodyRows],
    ["row.width", layout.row.width],
    ["row.markerWidth", layout.row.markerWidth],
    ["row.markerGap", layout.row.markerGap],
    ["row.labelWidth", layout.row.labelWidth],
    ["row.statusGap", layout.row.statusGap],
    ["row.statusWidth", layout.row.statusWidth],
  ];
}

describe("computeHerdLayout — the sweep", () => {
  it("never lets a pane, a row or a column exceed what it was given", () => {
    for (const width of sweepAxis(0, 200, 3)) {
      for (const height of sweepAxis(0, 80, 2)) {
        const layout = computeHerdLayout({ width, height });
        const at = `${width}x${height}`;

        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
        }

        expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
          Math.max(0, width - 4),
        );

        // horizontal: panes + gap fit the content column
        if (layout.stacked) {
          expect(layout.list.width, `stacked list too wide at ${at}`).toBeLessThanOrEqual(
            layout.contentWidth,
          );
          expect(layout.detail.width, `stacked detail too wide at ${at}`).toBeLessThanOrEqual(
            layout.contentWidth,
          );
          expect(layout.paneGap, `stacked panes had a horizontal gap at ${at}`).toBe(0);
        } else if (layout.list.width > 0 && layout.detail.width > 0) {
          const claimed = layout.list.width + layout.paneGap + layout.detail.width;
          expect(claimed, `panes claimed ${claimed} of ${layout.contentWidth} at ${at}`)
            .toBeLessThanOrEqual(layout.contentWidth);
        }

        // the row columns sum EXACTLY to the row width, which is the list inner width
        const row = layout.row;
        expect(row.width, `row wider than the list pane at ${at}`).toBe(layout.list.innerWidth);
        const rowClaimed =
          row.markerWidth + row.markerGap + row.labelWidth + row.statusGap + row.statusWidth;
        expect(rowClaimed, `row claimed ${rowClaimed} of ${row.width} at ${at}`).toBe(row.width);

        // vertical: panes fit the body rows
        expect(layout.list.height, `list taller than the body at ${at}`).toBeLessThanOrEqual(
          layout.bodyRows,
        );
        expect(layout.detail.height, `detail taller than the body at ${at}`).toBeLessThanOrEqual(
          layout.bodyRows,
        );
        if (layout.stacked && layout.list.height > 0 && layout.detail.height > 0) {
          const rows = layout.list.height + layout.detail.height;
          expect(rows, `stacked panes claimed ${rows} of ${layout.bodyRows} rows at ${at}`)
            .toBeLessThanOrEqual(layout.bodyRows);
        }
        expect(layout.visibleRows, `visibleRows exceeded the list body at ${at}`)
          .toBeLessThanOrEqual(layout.list.bodyRows);

        // per-pane internal consistency
        for (const pane of [layout.list, layout.detail]) {
          if (pane.width > 0) expect(pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
          if (pane.height > 0) expect(pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
          expect(pane.innerWidth).toBeLessThanOrEqual(pane.width);
          expect(pane.bodyRows).toBeLessThanOrEqual(pane.height);
          if (pane.width > 0) {
            expect(pane.width - pane.innerWidth).toBe(layout.bordered ? 4 : 0);
          }
        }
      }
    }
  });

  it("keeps the body inside the terminal once the shell has taken its chrome", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeHerdLayout({ width, height });
        expect(
          layout.bodyRows + shellChromeRowsAt(width),
          `body + chrome exceeded height at ${width}x${height}`,
        ).toBeLessThanOrEqual(Math.max(height, shellChromeRowsAt(width)));
      }
    }
  });

  it("survives garbage geometry without throwing or producing garbage", () => {
    const junk = [Number.NaN, Infinity, -Infinity, -10, 3.7, undefined, null];
    for (const width of junk) {
      for (const height of junk) {
        const layout = computeHerdLayout({ width: width as number, height: height as number });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${String(width)}x${String(height)}`).toBe(true);
        }
      }
    }
  });

  it("stacks on a narrow terminal and splits on a wide one", () => {
    expect(computeHerdLayout({ width: 60, height: 40 }).stacked).toBe(true);
    expect(computeHerdLayout({ width: 79, height: 40 }).stacked).toBe(true);
    expect(computeHerdLayout({ width: 120, height: 40 }).stacked).toBe(false);
  });

  it("drops pane borders before it drops rows of content", () => {
    expect(computeHerdLayout({ width: 120, height: 40 }).bordered).toBe(true);
    expect(computeHerdLayout({ width: 120, height: 10 }).bordered).toBe(false);
  });
});

/** Re-derive the shell chrome the same way the layout does, for the body test. */
function shellChromeRowsAt(width: number): number {
  const total = Math.max(0, Math.trunc(width));
  const headerContentWidth = total - 4 - 4;
  const headerContentRows = headerContentWidth < 88 ? 3 : 2;
  const contentWidth = Math.max(1, total - 4);
  const footerRows = contentWidth >= 64 ? 1 : 3;
  return 1 + (headerContentRows + 3) + footerRows;
}

// ---------------------------------------------------------------------------
// Untrusted display — control characters are stripped
// ---------------------------------------------------------------------------

describe("untrusted peer fields render stripped", () => {
  const evil = "a\x1b[2Jb\x07‮c\td"; // CSI clear, BEL, RTL override, tab

  it("strips control characters from label and cwd", () => {
    const p = peer("id", { label: evil, cwd: `/home/dev/${evil}` });
    expect(herdRowLabelText(p)).not.toMatch(/[\x00-\x1f\x7f‮]/);
    expect(abbreviateHomePath(p.cwd, "/home/dev")).not.toMatch(/[\x00-\x1f\x7f‮]/);
    // ~ abbreviation still applies under home
    expect(abbreviateHomePath("/home/dev/project", "/home/dev")).toBe("~/project");
    expect(abbreviateHomePath("/home/dev", "/home/dev")).toBe("~");
  });

  it("strips control characters from detail lines and the status column", () => {
    const p = peer("id", {
      label: evil,
      cwd: `/x/${evil}`,
      activity: { phase: "working", tool: evil, note: evil },
    });
    for (const line of herdDetailLines(p, [], 60, NOW)) {
      expect(line.text, `detail line leaked control chars: ${JSON.stringify(line.text)}`)
        .not.toMatch(/[\x00-\x08\x0b-\x1f\x7f‮]/);
    }
    expect(herdRowStatusText(p, "working")).not.toMatch(/[\x00-\x1f\x7f‮]/);
  });

  it("strips control characters from an untrusted inbox message", () => {
    const p = peer("id");
    const lines = herdDetailLines(p, [{ from: "peer", body: evil, ts: NOW }], 60, NOW);
    for (const line of lines) {
      expect(line.text).not.toMatch(/[\x00-\x08\x0b-\x1f\x7f‮]/);
    }
  });
});

// ---------------------------------------------------------------------------
// Detail pane + helpers
// ---------------------------------------------------------------------------

describe("herdDetailLines", () => {
  it("returns nothing without a peer or width", () => {
    expect(herdDetailLines(undefined, [], 40, NOW)).toEqual([]);
    expect(herdDetailLines(peer("p"), [], 0, NOW)).toEqual([]);
  });

  it("reports an empty inbox honestly and a populated one with a count", () => {
    const empty = herdDetailLines(peer("p"), [], 60, NOW).map((l) => l.text);
    expect(empty).toContain("Inbox: empty");
    const full = herdDetailLines(
      peer("p"),
      [
        { from: "a", body: "hi", ts: NOW },
        { from: "b", body: "yo", ts: NOW },
      ],
      60,
      NOW,
    ).map((l) => l.text);
    expect(full).toContain("Inbox (2)");
  });

  it("no line ever exceeds the width", () => {
    const p = peer("p", {
      label: "a very long engagement label that will need wrapping across lines",
      cwd: "/home/dev/some/deeply/nested/project/directory/that/keeps/going",
      activity: { phase: "working", turn: 3, maxTurns: 8, tool: "read_file", note: "poking at auth" },
    });
    for (let width = 1; width <= 80; width++) {
      for (const line of herdDetailLines(p, [{ from: "peer", body: "a ".repeat(60), ts: NOW }], width, NOW)) {
        expect(line.text.length, `line "${line.text}" exceeded ${width}`).toBeLessThanOrEqual(width);
      }
    }
  });

  it("clipDetailLines marks the cut", () => {
    const lines = herdDetailLines(peer("p"), [], 40, NOW);
    const clipped = clipDetailLines(lines, 3, 40);
    expect(clipped).toHaveLength(3);
    expect(clipped.at(-1)?.text).toContain("...");
    expect(clipDetailLines(lines, 0, 40)).toEqual([]);
  });
});

describe("formatRelativeAge", () => {
  it("reads as expected across scales", () => {
    expect(formatRelativeAge(NOW, NOW)).toBe("just now");
    expect(formatRelativeAge(NOW + 5000, NOW)).toBe("just now"); // clock skew -> not the future
    expect(formatRelativeAge(NOW - 3000, NOW)).toBe("3s ago");
    expect(formatRelativeAge(NOW - 5 * 60_000, NOW)).toBe("5m ago");
    expect(formatRelativeAge(NOW - 2 * 3_600_000, NOW)).toBe("2h ago");
    expect(formatRelativeAge(NOW - 3 * 86_400_000, NOW)).toBe("3d ago");
  });
});

describe("wrapCells", () => {
  it("never emits a line wider than the limit and hard-breaks long tokens", () => {
    const long = "supercalifragilisticexpialidocious";
    for (let width = 1; width <= 40; width++) {
      for (const line of wrapCells(`${long} short words here ${long}`, width)) {
        expect(line.length).toBeLessThanOrEqual(width);
      }
    }
    expect(wrapCells("", 10)).toEqual([]);
    expect(wrapCells("x", 0)).toEqual([]);
  });
});

describe("herdRowStatusText", () => {
  it("prefers tool, then turn counter, then the status word", () => {
    expect(herdRowStatusText(peer("p", { activity: { phase: "working", tool: "grep" } }), "working")).toBe("grep");
    expect(herdRowStatusText(peer("p", { activity: { phase: "working", turn: 2, maxTurns: 9 } }), "working")).toBe("2/9");
    expect(herdRowStatusText(peer("p", { activity: { phase: "working", turn: 2 } }), "working")).toBe("t2");
    expect(herdRowStatusText(peer("p"), "idle")).toBe("idle");
    // stale never shows a stale tool as if it were live
    expect(herdRowStatusText(peer("p", { activity: { tool: "grep" } }), "stale")).toBe("stale");
  });
});

describe("steering composer helpers", () => {
  it("budgets the draft text so prompt + draft + cursor never exceed the row", () => {
    // Swept across every content width, including the degenerate small ones.
    for (let contentWidth = 0; contentWidth <= 200; contentWidth++) {
      const textWidth = herdComposerTextWidth(contentWidth);
      expect(isInteger(textWidth), `textWidth integer at ${contentWidth}`).toBe(true);
      expect(textWidth, `textWidth floored at 1 at ${contentWidth}`).toBeGreaterThanOrEqual(1);
      // The rendered line is prompt + (visible draft) + cursor; with a draft
      // longer than the column, the visible slice is exactly the text width, so
      // the whole line fits the content column whenever the column can hold the
      // prompt and cursor at all.
      const visible = herdComposerVisibleDraft("x".repeat(500), contentWidth);
      const lineLength = HERD_COMPOSER_PROMPT.length + visible.length + HERD_COMPOSER_CURSOR.length;
      if (contentWidth >= HERD_COMPOSER_PROMPT.length + HERD_COMPOSER_CURSOR.length + 1) {
        expect(lineLength, `line fits content column at ${contentWidth}`).toBeLessThanOrEqual(contentWidth);
      }
    }
  });

  it("shows the TAIL of a long draft so the newest characters stay visible", () => {
    const draft = "reproduce the IDOR on /api/orders/{id} then confirm the leak";
    const visible = herdComposerVisibleDraft(draft, 30);
    expect(draft.endsWith(visible)).toBe(true);
    expect(visible.length).toBe(herdComposerTextWidth(30));
  });

  it("passes a short draft through untouched and strips control sequences", () => {
    expect(herdComposerVisibleDraft("hi", 40)).toBe("hi");
    // A pasted escape/bidi sequence cannot reach the frame.
    expect(herdComposerVisibleDraft("a[31mb‮", 40)).toBe("ab");
  });

  it("the composing footer hint names send and cancel", () => {
    const hint = herdComposerFooterHint();
    expect(hint).toContain("enter send");
    expect(hint).toContain("esc cancel");
  });
});

// ---------------------------------------------------------------------------
// FOCUS MODE — live subagent reducers, content, and the focus layout sweep
// ---------------------------------------------------------------------------

function lifecycle(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    agent_id: "child-1",
    parent_scan_id: "scan-1",
    status: "running",
    task: "audit the auth flow",
    max_turns: 8,
    ...over,
  };
}

function progress(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    agent_id: "child-1",
    parent_scan_id: "scan-1",
    turn: 1,
    max_turns: 8,
    ...over,
  };
}

describe("subagent reducers (bus payload → live record)", () => {
  it("folds a lifecycle event into a keyed record", () => {
    const map = applySubagentLifecycle({}, lifecycle(), NOW);
    const rec = map["child-1"];
    expect(rec?.task).toBe("audit the auth flow");
    expect(rec?.status).toBe("running");
    expect(rec?.maxTurns).toBe(8);
    expect(rec?.lastSeen).toBe(NOW);
    expect(rec?.activity).toHaveLength(1);
    expect(rec?.activity[0]?.kind).toBe("lifecycle");
  });

  it("appends progress turns and tracks the latest tool/turn", () => {
    let map = applySubagentLifecycle({}, lifecycle(), NOW);
    map = applySubagentProgress(map, progress({ turn: 1, tool: "read_file" }), NOW + 1);
    map = applySubagentProgress(map, progress({ turn: 2, tool: "grep", note: "poking auth" }), NOW + 2);
    const rec = map["child-1"];
    expect(rec?.turn).toBe(2);
    expect(rec?.tool).toBe("grep");
    expect(rec?.note).toBe("poking auth");
    // one lifecycle + two progress entries, oldest first
    expect(rec?.activity.map((e) => e.kind)).toEqual(["lifecycle", "progress", "progress"]);
  });

  it("keeps terminal records (completed/failed) with their summary/error", () => {
    let map = applySubagentLifecycle({}, lifecycle(), NOW);
    map = applySubagentLifecycle(
      map,
      lifecycle({ status: "completed", turns: 5, findings: 2, summary: "found an IDOR" }),
      NOW + 10,
    );
    const rec = map["child-1"];
    expect(rec?.status).toBe("completed");
    expect(rec?.findings).toBe(2);
    expect(rec?.summary).toBe("found an IDOR");
    // record is retained (not dropped like the chat card's active set)
    expect(Object.keys(map)).toEqual(["child-1"]);
  });

  it("a late progress event never resurrects a terminal record", () => {
    let map = applySubagentLifecycle({}, lifecycle({ status: "completed" }), NOW);
    map = applySubagentProgress(map, progress({ turn: 9 }), NOW + 1);
    expect(map["child-1"]?.status).toBe("completed");
  });

  it("returns the SAME map on a payload with no agent_id (no repaint)", () => {
    const map = applySubagentLifecycle({}, lifecycle(), NOW);
    expect(applySubagentLifecycle(map, { status: "running" }, NOW)).toBe(map);
    expect(applySubagentProgress(map, { turn: 1 }, NOW)).toBe(map);
  });

  it("bounds the activity ring", () => {
    let map: HerdSubagentMap = applySubagentLifecycle({}, lifecycle(), NOW);
    for (let i = 0; i < HERD_ACTIVITY_MAX + 50; i++) {
      map = applySubagentProgress(map, progress({ turn: i }), NOW + i, 10);
    }
    expect(map["child-1"]?.activity.length).toBeLessThanOrEqual(10);
    // and the newest survive
    expect(map["child-1"]?.activity.at(-1)?.turn).toBe(HERD_ACTIVITY_MAX + 49);
  });

  it("survives garbage payload fields without throwing", () => {
    const map = applySubagentProgress(
      {},
      { agent_id: "x", turn: Number.NaN, max_turns: "nope", tool: 5 as unknown },
      NOW,
    );
    expect(map["x"]?.agentId).toBe("x");
    expect(map["x"]?.status).toBe("running");
  });
});

describe("subagentPeers + mergeSubagentRoster", () => {
  it("projects records onto subagent peers with mapped phases", () => {
    let map = applySubagentLifecycle({}, lifecycle({ agent_id: "run" }), NOW);
    map = applySubagentLifecycle(map, lifecycle({ agent_id: "q", status: "queued" }), NOW);
    map = applySubagentLifecycle(map, lifecycle({ agent_id: "done", status: "completed" }), NOW);
    const peers = subagentPeers(map, NOW);
    const byId = Object.fromEntries(peers.map((p) => [p.id, p]));
    expect(byId["run"]?.activity?.phase).toBe("working");
    expect(byId["q"]?.activity?.phase).toBe("idle");
    expect(byId["done"]?.activity?.phase).toBe("done");
    expect(peers.every((p) => p.kind === "subagent")).toBe(true);
  });

  it("merges provider peers first, provider winning on an id collision", () => {
    const provider: HerdPeer[] = [peer("shared"), peer("only-provider")];
    const live = subagentPeers(applySubagentLifecycle({}, lifecycle({ agent_id: "shared" }), NOW), NOW)
      .concat(subagentPeers(applySubagentLifecycle({}, lifecycle({ agent_id: "only-live" }), NOW), NOW));
    const merged = mergeSubagentRoster(provider, live);
    const ids = merged.map((p) => p.id);
    expect(ids).toEqual(["shared", "only-provider", "only-live"]);
    // provider's "shared" (a session) wins over the live subagent of the same id
    expect(merged.find((p) => p.id === "shared")?.kind).toBe("session");
  });

  it("is a no-op merge in either empty direction", () => {
    const provider = [peer("a")];
    expect(mergeSubagentRoster(provider, []).map((p) => p.id)).toEqual(["a"]);
    expect(mergeSubagentRoster([], provider).map((p) => p.id)).toEqual(["a"]);
  });
});

describe("focus content — header and transcript", () => {
  it("renders identity + status counters, preferring the live record", () => {
    let map = applySubagentLifecycle({}, lifecycle(), NOW);
    map = applySubagentProgress(map, progress({ turn: 3, tool: "curl" }), NOW + 1);
    const rec = map["child-1"];
    const p = subagentPeers(map, NOW).find((x) => x.id === "child-1");
    const text = focusHeaderLines(p, rec, 60, NOW + 2).map((l) => l.text);
    expect(text.some((t) => t.includes("audit the auth flow"))).toBe(true);
    expect(text).toContain("Status: running");
    expect(text).toContain("Turns: 3/8");
    expect(text.some((t) => t.startsWith("Tool: curl"))).toBe(true);
  });

  it("falls back to the peer when no live record is present", () => {
    const p = peer("solo", { activity: { phase: "working", turn: 2, maxTurns: 5 } });
    const text = focusHeaderLines(p, undefined, 50, NOW).map((l) => l.text);
    expect(text).toContain("solo");
    expect(text).toContain("Turns: 2/5");
  });

  it("no header or transcript line ever exceeds the width", () => {
    let map = applySubagentLifecycle(
      {},
      lifecycle({ task: "a very long task description that certainly needs wrapping across lines" }),
      NOW,
    );
    map = applySubagentProgress(map, progress({ turn: 1, tool: "read_file", note: "n ".repeat(40) }), NOW);
    map = applySubagentLifecycle(map, lifecycle({ status: "failed", error: "e ".repeat(40) }), NOW + 1);
    const rec = map["child-1"];
    const p = subagentPeers(map, NOW).find((x) => x.id === "child-1");
    for (let width = 1; width <= 80; width++) {
      for (const line of focusHeaderLines(p, rec, width, NOW)) {
        expect(line.text.length, `header "${line.text}" exceeded ${width}`).toBeLessThanOrEqual(width);
      }
      for (const line of renderFocusActivity(rec?.activity ?? [], width)) {
        expect(line.text.length, `activity "${line.text}" exceeded ${width}`).toBeLessThanOrEqual(width);
      }
    }
  });

  it("strips control characters from a child-authored task/note", () => {
    const evil = "a\x1b[2Jb\x07‮c\td";
    let map = applySubagentLifecycle({}, lifecycle({ task: evil }), NOW);
    map = applySubagentProgress(map, progress({ tool: evil, note: evil }), NOW);
    const rec = map["child-1"];
    const p = subagentPeers(map, NOW).find((x) => x.id === "child-1");
    for (const line of focusHeaderLines(p, rec, 60, NOW)) {
      expect(line.text).not.toMatch(/[\x00-\x08\x0b-\x1f\x7f‮]/);
    }
    for (const line of renderFocusActivity(rec?.activity ?? [], 60)) {
      expect(line.text).not.toMatch(/[\x00-\x08\x0b-\x1f\x7f‮]/);
    }
  });

  it("the transcript title counts entries; the focus hint names steer + back", () => {
    expect(herdFocusTranscriptTitle(0)).toBe("LIVE");
    expect(herdFocusTranscriptTitle(12)).toBe("LIVE 12");
    const hint = herdFocusFooterHint();
    expect(hint).toContain("m steer");
    expect(hint).toContain("esc back to list");
  });
});

describe("windowFocusTail", () => {
  it("follows the tail at offset 0 and scrolls back without overrunning", () => {
    // 20 lines, a 6-row window
    const total = 20;
    const cap = 6;
    const tail = windowFocusTail(total, cap, 0);
    expect(tail).toMatchObject({ start: 14, end: 20, count: 6, hasBelow: false, hasAbove: true });
    const back = windowFocusTail(total, cap, 5);
    expect(back).toMatchObject({ start: 9, end: 15, count: 6, hasAbove: true, hasBelow: true });
    // clamps a huge offset to the top
    const top = windowFocusTail(total, cap, 999);
    expect(top).toMatchObject({ start: 0, end: 6, hasAbove: false, hasBelow: true });
  });

  it("shows everything when the window is bigger than the content", () => {
    expect(windowFocusTail(3, 10, 0)).toMatchObject({ start: 0, end: 3, count: 3 });
    expect(windowFocusTail(0, 10, 0)).toMatchObject({ start: 0, end: 0, count: 0 });
    expect(windowFocusTail(10, 0, 0)).toMatchObject({ start: 0, end: 0, count: 0 });
  });
});

// ---------------------------------------------------------------------------
// The focus layout sweep — nothing exceeds its container, at any geometry
// ---------------------------------------------------------------------------

function focusLayoutNumbers(layout: HerdFocusLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["meta.width", layout.meta.width],
    ["meta.innerWidth", layout.meta.innerWidth],
    ["meta.height", layout.meta.height],
    ["meta.bodyRows", layout.meta.bodyRows],
    ["transcript.width", layout.transcript.width],
    ["transcript.innerWidth", layout.transcript.innerWidth],
    ["transcript.height", layout.transcript.height],
    ["transcript.bodyRows", layout.transcript.bodyRows],
  ];
}

describe("computeHerdFocusLayout — the sweep", () => {
  it("never lets a pane exceed the content column or the body rows", () => {
    for (const width of sweepAxis(0, 200, 3)) {
      for (const height of sweepAxis(0, 80, 2)) {
        for (const noticeRows of [0, 1]) {
          const layout = computeHerdFocusLayout({ width, height, noticeRows });
          const at = `${width}x${height}n${noticeRows}`;

          for (const [name, value] of focusLayoutNumbers(layout)) {
            expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
          }

          expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
            Math.max(0, width - 4),
          );

          // both panes are the full content column — never wider
          expect(layout.meta.width, `meta too wide at ${at}`).toBeLessThanOrEqual(layout.contentWidth);
          expect(layout.transcript.width, `transcript too wide at ${at}`).toBeLessThanOrEqual(
            layout.contentWidth,
          );

          // stacked heights fit the body rows
          const rows = layout.meta.height + layout.transcript.height;
          expect(rows, `focus panes claimed ${rows} of ${layout.bodyRows} at ${at}`).toBeLessThanOrEqual(
            layout.bodyRows,
          );

          // per-pane internal consistency, mirroring the list sweep
          for (const pane of [layout.meta, layout.transcript]) {
            if (pane.width > 0) expect(pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
            if (pane.height > 0) expect(pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
            expect(pane.innerWidth).toBeLessThanOrEqual(pane.width);
            expect(pane.bodyRows).toBeLessThanOrEqual(pane.height);
            if (pane.width > 0) {
              expect(pane.width - pane.innerWidth).toBe(layout.bordered ? 4 : 0);
            }
          }
        }
      }
    }
  });

  it("keeps the body inside the terminal once the shell has taken its chrome", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeHerdFocusLayout({ width, height });
        expect(
          layout.bodyRows + shellChromeRowsAt(width),
          `focus body + chrome exceeded height at ${width}x${height}`,
        ).toBeLessThanOrEqual(Math.max(height, shellChromeRowsAt(width)));
      }
    }
  });

  it("survives garbage geometry without throwing or producing garbage", () => {
    const junk = [Number.NaN, Infinity, -Infinity, -10, 3.7, undefined, null];
    for (const width of junk) {
      for (const height of junk) {
        const layout = computeHerdFocusLayout({ width: width as number, height: height as number });
        for (const [name, value] of focusLayoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${String(width)}x${String(height)}`).toBe(true);
        }
      }
    }
  });

  it("gives both panes room on a tall terminal and drops the meta first on a short one", () => {
    const tall = computeHerdFocusLayout({ width: 120, height: 40 });
    expect(tall.meta.height).toBeGreaterThan(0);
    expect(tall.transcript.height).toBeGreaterThan(0);
    expect(tall.bordered).toBe(true);
    // A terminal with room for only one pane keeps the transcript, drops meta.
    // At width 120 the shell takes 7 rows, so height 9 leaves a 2-row body —
    // enough for one unbordered pane but not two.
    const short = computeHerdFocusLayout({ width: 120, height: 9 });
    expect(short.transcript.height).toBeGreaterThan(0);
    expect(short.meta.height).toBe(0);
  });
});

describe("paneTitleColumns (herd)", () => {
  it("splits a header into title + meta whose cells sum to the inner width", () => {
    for (let width = 0; width <= 200; width++) {
      for (const metaLen of [0, 1, 3, 8, 20, 999]) {
        const cols = paneTitleColumns(width, metaLen);
        const claimed = cols.titleWidth + cols.gap + cols.metaWidth;
        for (const [name, value] of [
          ["titleWidth", cols.titleWidth],
          ["gap", cols.gap],
          ["metaWidth", cols.metaWidth],
        ] as const) {
          expect(isInteger(value), `${name} was ${value} at ${width}`).toBe(true);
        }
        expect(claimed, `claimed ${claimed} of ${width} with meta ${metaLen}`).toBe(Math.max(0, width));
        if (width > 0) expect(cols.titleWidth, `title squeezed out at ${width}`).toBeGreaterThan(0);
        expect(cols.gap === 0 || cols.metaWidth > 0).toBe(true);
      }
    }
  });
});

describe("herdListHeading", () => {
  it("names the pane and counts the roster, or the window when scrolled", () => {
    const grouped = buildHerdRows(
      [peer("a"), peer("b", { activity: { phase: "working" } })],
      NOW,
    );
    const whole = computeHerdWindow({ rows: grouped, selected: 1, visible: grouped.length });
    const heading = herdListHeading(whole);
    expect(heading.title).toBe("HERD");
    expect(heading.meta).toBe(`${whole.total}`);
    expect(herdListHeading(computeHerdWindow({ rows: [], selected: -1, visible: 4 }))).toEqual({
      title: "HERD",
      meta: "empty",
    });
    const scrolled = computeHerdWindow({ rows: grouped, selected: 3, visible: 2, anchor: 2 });
    if (scrolled.hasAbove || scrolled.hasBelow) {
      expect(herdListHeading(scrolled).meta).toMatch(/^\d+-\d+ \/ \d+$/);
    }
  });
});
