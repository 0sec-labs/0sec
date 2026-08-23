/** @jsxImportSource @opentui/react */
/**
 * The full-screen finding-detail view.
 *
 * Open one finding, see everything about it — title, severity, category,
 * location, description, redacted evidence, remediation, CVSS and references —
 * and act on it: request a fix, copy a submission-ready report to the
 * clipboard, or move its status. It is the console's answer to "click a finding
 * and drill in", the read+act companion to the `/findings` list.
 *
 * Three properties are load-bearing, all inherited from `usage-screen.tsx` and
 * `model-screen.tsx`:
 *
 * 1. **This component does no arithmetic and invents no number.** Every width,
 *    height, row count and column split comes off `finding-detail-layout.ts`,
 *    which is swept across widths 0..200 and heights 0..80 by a test — Yoga
 *    shrinks siblings rather than clipping them, so a row that claims one cell
 *    too many paints two strings on top of each other.
 *
 * 2. **It invents no finding data.** Every field the finding does not carry
 *    renders as `—`, and evidence is only ever shown through the injected
 *    redactor (`redactSensitiveHeaders`), so a raw request pasted into a
 *    finding cannot leak a bearer token onto the screen.
 *
 * 3. **The data and the actions are injected.** The finding arrives as a prop
 *    (or is resolved lazily by id through an injected resolver) so the screen is
 *    testable without a live store; `onFix` / `onCopyReport` / `onSetStatus` are
 *    optional callbacks with graceful, note-only defaults. The screen never
 *    invokes a core tool directly — it hands the intent back to the coordinator,
 *    which wires it into the normal agent turn.
 */

import React, { useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { TextAttributes } from "@opentui/core";
import type { Finding } from "@0sec/shared";
import { renderPlatformReport, renderCvssSection, redactSensitiveHeaders } from "@0sec/core";

import { useTheme, type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import {
  buildFindingRows,
  computeFindingDetailLayout,
  computeScrollWindow,
  findingActions,
  findingDetailFooterHint,
  findingDetailTitle,
  maxScrollOffset,
  paneTitleColumns,
  type FindingAction,
  type FindingDetailLayout,
  type FindingDetailPane,
  type FindingDetailRow,
  type FindingDetailTone,
  type FindingStatusAction,
} from "./finding-detail-layout.js";

export interface FindingDetailFrameInput {
  /** The screen body, already sized to the rows the frame left it. */
  body: React.ReactNode;
  /** Footer text naming the bindings that actually work. */
  hint: string;
}

export interface FindingDetailScreenProps {
  /**
   * Wraps the body in the console shell. Injected rather than imported so this
   * module does not depend on `run.tsx`, which owns `ShellFrame` — the same seam
   * `usage-screen.tsx` and `model-screen.tsx` use.
   */
  frame: (input: FindingDetailFrameInput) => React.ReactNode;
  /** The finding to display. Optional so the screen renders under a test. */
  finding?: Finding;
  /** The finding id, when only the id is known and a resolver is wired. */
  findingId?: string;
  /**
   * Lazy resolver: given an id, return the finding from the store. Used only
   * when `finding` is absent. Injected so the screen never imports the DB.
   */
  resolveFinding?: (id: string) => Finding | undefined;
  /**
   * Request a fix. The intent is "generate and apply a fix for this finding",
   * routed through the normal agent turn by the coordinator (composer / steer).
   * Default: a note-only no-op — the screen does not touch core tools itself.
   */
  onFix?: (finding: Finding) => void;
  /**
   * Copy a submission-ready report for this finding. The screen renders the
   * markdown via `renderPlatformReport` and hands both the finding and the
   * rendered text across; the coordinator wires this to `copyToClipboard` with
   * a safe OSC 52 emitter. Default: a note-only no-op.
   */
  onCopyReport?: (finding: Finding, markdown: string) => void;
  /**
   * Move the finding's status (verified / dismissed). When omitted, the status
   * actions are not offered at all — the screen never shows a control that does
   * nothing.
   */
  onSetStatus?: (finding: Finding, status: FindingStatusAction) => void;
  /** Leave the screen — Esc. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
}

function toneColor(theme: Theme, tone: FindingDetailTone | undefined): string | undefined {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "heading":
      // Section labels (Location, Evidence, Remediation…) are small muted
      // headers, not accent shouts — the console's section-header house style.
      return theme.MUTED;
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
 * squeezing the box behind its content's back. When the layout could not find
 * room for the pane it reports zero and nothing renders — a missing pane is
 * missing information, a pane one row short of its content looks like a crash.
 */
function Pane({
  pane,
  bordered,
  title,
  titleFg,
  titleRight,
  titleRightFg,
  children,
}: {
  pane: FindingDetailPane;
  bordered: boolean;
  title: string;
  titleFg: string;
  /** Right-aligned decoration on the title row: a scroll caption or a notice. */
  titleRight?: string;
  titleRightFg?: string;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  if (pane.width <= 0 || pane.height <= 0) return null;
  // Split the single reserved title row into a left title and an optional
  // right caption/notice. The two columns plus the gap always sum to the
  // inner width, so the row can never overflow — and the caption never costs
  // an extra content row.
  const inner = pane.innerWidth;
  const right = titleRight ?? "";
  const rightWidth = right.length > 0 ? Math.min(right.length, Math.floor(inner / 2)) : 0;
  const gap = rightWidth > 0 && inner > rightWidth ? 1 : 0;
  const leftWidth = Math.max(0, inner - rightWidth - gap);
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
      {pane.hasTitle ? (
        <box flexDirection="row" width={inner} flexShrink={0} minWidth={0}>
          <Cells width={leftWidth} fg={titleFg} attributes={TextAttributes.BOLD}>
            {title}
          </Cells>
          <Cells width={gap}>{""}</Cells>
          <Cells width={rightWidth} align="right" fg={titleRightFg ?? theme.MUTED}>
            {right}
          </Cells>
        </box>
      ) : null}
      {children}
    </box>
  );
}

/** One content row, rendered against the layout's column allocations. */
function DetailRow({
  row,
  layout,
  theme,
}: {
  row: FindingDetailRow;
  layout: FindingDetailLayout;
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

  if (row.kind === "header") {
    // Two-column strong header: bold title left, severity badge right (a leading
    // "●" then the severity word, coloured by tone — red only for high/critical).
    const badgeText = row.badge ? `● ${row.badge}` : "";
    const cols = paneTitleColumns(inner, badgeText.length);
    return (
      <box flexDirection="row" width={inner} flexShrink={0} minWidth={0}>
        <Cells width={cols.titleWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
          {row.title}
        </Cells>
        <Cells width={cols.gap}>{""}</Cells>
        <Cells
          width={cols.metaWidth}
          align="right"
          fg={toneColor(theme, row.badgeTone)}
          attributes={TextAttributes.BOLD}
        >
          {badgeText}
        </Cells>
      </box>
    );
  }

  if (row.kind === "heading") {
    // A section label — small, muted and bold, with vertical rhythm from the
    // blank rows the builder inserts around it.
    return (
      <Cells width={inner} fg={toneColor(theme, row.tone)} attributes={TextAttributes.BOLD}>
        {row.text}
      </Cells>
    );
  }

  if (row.kind === "text") {
    return (
      <Cells width={inner} fg={toneColor(theme, row.tone)}>
        {row.text}
      </Cells>
    );
  }

  // kv
  const kv = layout.kv;
  return (
    <box flexDirection="row" width={kv.width} flexShrink={0} minWidth={0}>
      <Cells width={kv.labelWidth} fg={theme.MUTED}>
        {row.label}
      </Cells>
      <Cells width={kv.gap}>{""}</Cells>
      <Cells width={kv.valueWidth} fg={toneColor(theme, row.tone)}>
        {row.value}
      </Cells>
    </box>
  );
}

/** The footer action buttons, laid out in equal cells. */
function ActionBar({
  actions,
  layout,
  theme,
}: {
  actions: readonly FindingAction[];
  layout: FindingDetailLayout;
  theme: Theme;
}) {
  const action = layout.action;
  if (action.count <= 0) return null;
  const visible = actions.slice(0, action.count);
  return (
    <box flexDirection="row" width={action.width} flexShrink={0} minWidth={0}>
      {visible.map((item, index) => (
        <React.Fragment key={item.key}>
          {index > 0 ? <Cells width={action.gap}>{""}</Cells> : null}
          <Cells width={action.cellWidth} fg={theme.ACCENT}>
            {`[${item.key}] ${item.label}`}
          </Cells>
        </React.Fragment>
      ))}
    </box>
  );
}

/**
 * Render a finding into a plain CVSS line via `renderCvssSection`, stripping the
 * markdown emphasis/code markers so it reads cleanly in the terminal.
 */
function plainCvssLine(finding: Finding): string | undefined {
  const vector = finding.cvssVector;
  const score = finding.cvssScore;
  if (!vector || typeof score !== "number" || !Number.isFinite(score)) return undefined;
  const md = renderCvssSection({ vector, score, severity: finding.severity });
  return md.replace(/\*\*/g, "").replace(/`/g, "");
}

export function FindingDetailScreen({
  frame,
  finding: findingProp,
  findingId,
  resolveFinding,
  onFix,
  onCopyReport,
  onSetStatus,
  onBack,
  onExit,
}: FindingDetailScreenProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();
  const [offset, setOffset] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);

  // Resolve the finding once: the prop wins, else the lazy resolver by id.
  const finding = useMemo<Finding | undefined>(() => {
    if (findingProp) return findingProp;
    if (findingId && resolveFinding) return resolveFinding(findingId);
    return undefined;
  }, [findingProp, findingId, resolveFinding]);

  const canStatus = Boolean(onSetStatus);
  const actions = useMemo(() => findingActions({ canStatus }), [canStatus]);

  const layout = computeFindingDetailLayout({ width, height, actionCount: actions.length });

  const rows = useMemo(
    () =>
      buildFindingRows(finding, layout.pane.innerWidth, {
        redact: redactSensitiveHeaders,
        cvssLine: finding ? plainCvssLine(finding) : undefined,
      }),
    [finding, layout.pane.innerWidth],
  );

  const window = computeScrollWindow({
    total: rows.length,
    offset,
    visible: layout.visibleRows,
  });
  const visibleRows = rows.slice(window.start, window.end);

  const scrollBy = (delta: number) => {
    const max = maxScrollOffset(rows.length, layout.visibleRows);
    setOffset((current) => Math.max(0, Math.min(max, current + delta)));
  };

  const requestFix = () => {
    if (!finding) return;
    if (onFix) onFix(finding);
    setNotice(`Fix requested for ${finding.id}.`);
  };

  const copyReport = () => {
    if (!finding) return;
    if (!onCopyReport) {
      setNotice("Copy unavailable — no clipboard handler wired.");
      return;
    }
    let markdown: string;
    try {
      markdown = renderPlatformReport(finding).markdown;
    } catch {
      // renderPlatformReport throws EmptyPocError when the finding has no
      // reproducible PoC content; fall back to a minimal, honest report body.
      markdown = `# ${finding.title}\n\n${finding.description ?? ""}`.trim();
    }
    onCopyReport(finding, markdown);
    setNotice("Report copied to the clipboard.");
  };

  const setStatus = (status: FindingStatusAction) => {
    if (!finding || !onSetStatus) return;
    onSetStatus(finding, status);
    setNotice(status === "verified" ? "Marked verified." : "Marked dismissed.");
  };

  useKeyboard((key) => {
    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      onBack();
      return;
    }
    if (key.name === "up" || key.name === "k") {
      scrollBy(-1);
      return;
    }
    if (key.name === "down" || key.name === "j") {
      scrollBy(1);
      return;
    }
    if (key.name === "pageup") {
      scrollBy(-Math.max(1, layout.visibleRows - 1));
      return;
    }
    if (key.name === "pagedown" || key.name === "space") {
      scrollBy(Math.max(1, layout.visibleRows - 1));
      return;
    }
    if (key.name === "home" || key.name === "g") {
      setOffset(0);
      return;
    }
    if (key.name === "end" || (key.shift && key.name === "g")) {
      setOffset(maxScrollOffset(rows.length, layout.visibleRows));
      return;
    }
    if (key.name === "f") {
      requestFix();
      return;
    }
    if (key.name === "c") {
      copyReport();
      return;
    }
    if (canStatus && key.name === "v") {
      setStatus("verified");
      return;
    }
    if (canStatus && key.name === "d") {
      setStatus("dismissed");
      return;
    }
  });

  const scrollCaption =
    window.hasAbove || window.hasBelow
      ? `${window.start + 1}–${window.end} / ${window.total}${window.hasBelow ? " ↓" : ""}${window.hasAbove ? " ↑" : ""}`
      : "";

  // The title row carries either a transient notice or the scroll caption on
  // its right — neither costs a content row, so the pane geometry stays honest.
  const titleRight = notice ?? scrollCaption;
  const titleRightFg = notice ? theme.SUCCESS : theme.MUTED;

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <Pane
        pane={layout.pane}
        bordered={layout.bordered}
        title={findingDetailTitle(finding)}
        titleFg={theme.PRIMARY}
        titleRight={titleRight}
        titleRightFg={titleRightFg}
      >
        {visibleRows.map((row, index) => (
          <DetailRow key={`detail-${window.start + index}`} row={row} layout={layout} theme={theme} />
        ))}
      </Pane>
      <ActionBar actions={actions} layout={layout} theme={theme} />
    </box>
  );

  return <>{frame({ body, hint: findingDetailFooterHint({ canStatus }) })}</>;
}
