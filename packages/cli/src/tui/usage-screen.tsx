/** @jsxImportSource @opentui/react */
/**
 * The full-screen `/usage` report.
 *
 * A read-only mirror of what the bottom status bar already knows, given a whole
 * screen: the context window and how full it is, the token totals this turn and
 * across the session, an estimated dollar cost, the active model and provider,
 * and the run's tool-health issues. It is the console's answer to oh-my-pi's
 * `/usage`.
 *
 * Two properties are load-bearing, both inherited from `model-screen.tsx`:
 *
 * 1. **This component does no arithmetic and invents no number.** Every width,
 *    height, row count and meter fill comes off `usage-layout.ts`, which is
 *    swept across widths 0..200 and heights 0..80 by a test — Yoga shrinks
 *    siblings rather than clipping them, so a row that claims one cell too many
 *    paints two strings on top of each other. And every count, percentage and
 *    cost is decided in `buildUsageReport`, which renders an em-dash for what it
 *    was not given rather than a plausible-looking zero.
 *
 * 2. **The data is injected.** The snapshot arrives as a prop so the screen can
 *    be driven under a synthetic session without a live runtime; the lazy
 *    default (`readCurrentUsage`) returns an empty snapshot, so with no data
 *    wired the screen shows the model it was told about and `—` for the rest.
 */

import React, { useMemo } from "react";
import { TextAttributes } from "@opentui/core";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";

import { useTheme, type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import {
  buildUsageReport,
  clipUsageRows,
  computeUsageLayout,
  computeUsageTitleLayout,
  readCurrentUsage,
  usageFooterHint,
  usageMeterBar,
  usageTitle,
  usageTitleMeta,
  type UsageLayout,
  type UsagePane,
  type UsageReportRow,
  type UsageSnapshot,
  type UsageTone,
} from "./usage-layout.js";

export interface UsageFrameInput {
  /** The screen body, already sized to the rows the frame left it. */
  body: React.ReactNode;
  /** Footer text naming the bindings that actually work. */
  hint: string;
}

export interface UsageScreenProps {
  /**
   * Wraps the body in the console shell. Injected rather than imported so this
   * module does not depend on `run.tsx`, which owns `ShellFrame` and pulls in
   * every other screen with it — the same seam `model-screen.tsx` uses.
   */
  frame: (input: UsageFrameInput) => React.ReactNode;
  /**
   * The session-usage snapshot to display. Defaults to the lazy reader, which
   * returns an empty snapshot until the chat wires its live counts across; the
   * route supplies at least the active model it already knows.
   */
  usage?: UsageSnapshot;
  /** Leave the screen — Esc. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
}

function toneColor(theme: Theme, tone: UsageTone | undefined): string | undefined {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "accent":
      return theme.ACCENT;
    case "ok":
      return theme.SUCCESS;
    case "warn":
      return theme.WARNING;
    case "error":
      return theme.ERROR;
    case "label":
      return theme.TEXT;
    case "muted":
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

/**
 * A pane that states its own height.
 *
 * `height` includes the borders, and `flexShrink={0}` stops the column
 * squeezing the box behind its content's back — `@opentui/core` only clears
 * `flexShrink` for an explicit numeric width or height, not for a percentage
 * string. When the layout could not find room for the pane it reports zero and
 * nothing renders, which is the correct degradation: a missing pane is missing
 * information, a pane one row short of its content looks like a crash.
 */
function Pane({
  pane,
  bordered,
  title,
  children,
}: {
  pane: UsagePane;
  bordered: boolean;
  /** The header row node, already fitted to the pane's inner width. */
  title: React.ReactNode;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  if (pane.width <= 0 || pane.height <= 0) return null;
  return (
    <box
      flexDirection="column"
      width={pane.width}
      height={pane.height}
      flexShrink={0}
      flexGrow={0}
      minWidth={0}
      border={bordered || undefined}
      borderColor={bordered ? theme.BORDER : undefined}
      backgroundColor={bordered ? theme.PANEL : undefined}
      paddingX={bordered ? 1 : undefined}
    >
      {pane.hasTitle ? title : null}
      {children}
    </box>
  );
}

/**
 * The pane header: a bold, primary-toned title on the left and a right-aligned
 * summary meta on the right (the priced session cost, else the model). Widths
 * come off `computeUsageTitleLayout`, so the row claims exactly the pane's inner
 * width and the title survives when the header is too narrow for both.
 */
function TitleRow({ innerWidth, title, meta }: { innerWidth: number; title: string; meta: string }) {
  const theme = useTheme();
  const columns = computeUsageTitleLayout(innerWidth, meta.length);
  if (columns.width <= 0) return null;
  return (
    <box flexDirection="row" width={columns.width} flexShrink={0} minWidth={0}>
      <Cells width={columns.titleWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
        {title}
      </Cells>
      {columns.metaWidth > 0 ? (
        <>
          <Cells width={columns.gap}>{""}</Cells>
          <Cells width={columns.metaWidth} align="right" fg={theme.MUTED}>
            {meta}
          </Cells>
        </>
      ) : null}
    </box>
  );
}

/** One report row, rendered against the layout's column allocations. */
function ReportRow({
  row,
  layout,
  theme,
}: {
  row: UsageReportRow;
  layout: UsageLayout;
  theme: Theme;
}) {
  const inner = layout.pane.innerWidth;

  if (row.kind === "blank") {
    return (
      <Cells width={inner} fg={theme.MUTED}>
        {""}
      </Cells>
    );
  }

  if (row.kind === "heading") {
    return (
      <Cells width={inner} fg={toneColor(theme, row.tone)} attributes={TextAttributes.BOLD}>
        {row.label ?? ""}
      </Cells>
    );
  }

  if (row.kind === "text") {
    return (
      <Cells width={inner} fg={toneColor(theme, row.tone)}>
        {row.label ?? ""}
      </Cells>
    );
  }

  if (row.kind === "meter") {
    const meter = layout.meter;
    const barFg = toneColor(theme, row.tone);
    return (
      <box flexDirection="row" width={meter.width} flexShrink={0} minWidth={0}>
        <Cells width={meter.barCells} fg={barFg}>
          {usageMeterBar(row.fraction ?? 0, meter.barCells)}
        </Cells>
        <Cells width={meter.gap}>{""}</Cells>
        <Cells width={meter.captionWidth} fg={barFg}>
          {row.value ?? ""}
        </Cells>
      </box>
    );
  }

  // kv
  const kv = layout.kv;
  return (
    <box flexDirection="row" width={kv.width} flexShrink={0} minWidth={0}>
      <Cells width={kv.labelWidth} fg={theme.MUTED}>
        {row.label ?? ""}
      </Cells>
      <Cells width={kv.gap}>{""}</Cells>
      <Cells width={kv.valueWidth} align="right" fg={toneColor(theme, row.tone)}>
        {row.value ?? ""}
      </Cells>
    </box>
  );
}

export function UsageScreen({ frame, usage, onBack, onExit }: UsageScreenProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();

  // Resolved once from the injected snapshot (or the lazy default). Usage is a
  // point-in-time reading handed in by the route; it does not change under a
  // screen that has no way to run a turn.
  const snapshot = useMemo<UsageSnapshot>(() => usage ?? readCurrentUsage(), [usage]);
  const report = useMemo(() => buildUsageReport(snapshot), [snapshot]);

  const layout = computeUsageLayout({ width, height });
  const visible = clipUsageRows(report, layout.visibleRows);

  useKeyboard((key) => {
    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      onBack();
      return;
    }
  });

  const meta = usageTitleMeta(snapshot);
  const titleRow = (
    <TitleRow innerWidth={layout.pane.innerWidth} title={usageTitle()} meta={meta} />
  );

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <Pane pane={layout.pane} bordered={layout.bordered} title={titleRow}>
        {visible.map((row, index) => (
          <ReportRow key={`usage-${index}`} row={row} layout={layout} theme={theme} />
        ))}
      </Pane>
    </box>
  );

  return <>{frame({ body, hint: usageFooterHint() })}</>;
}
