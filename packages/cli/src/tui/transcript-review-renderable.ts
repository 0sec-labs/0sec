import {
  TextBufferRenderable,
  type RenderContext,
  type TextBufferOptions,
} from "@opentui/core";
import { extend } from "@opentui/react";

export interface TranscriptReviewRenderableOptions extends TextBufferOptions {
  /** Complete review document; replaces the native text buffer atomically. */
  content?: string;
}

interface VisualAnchor {
  source: number;
  wrap: number;
}

/**
 * A single native text buffer with exact wrapped-row geometry. Unlike a React
 * list of variable-height cards, scrolling is entirely owned by TextBufferView.
 */
export class TranscriptReviewRenderable extends TextBufferRenderable {
  private _content = "";

  constructor(ctx: RenderContext, options: TranscriptReviewRenderableOptions) {
    super(ctx, options);
    this.content = options.content ?? "";
  }

  get content(): string {
    return this._content;
  }

  set content(value: string) {
    const next = String(value ?? "");
    if (next === this._content) return;

    const anchor = this.captureVisualAnchor();
    this._content = next;
    this.textBuffer.setText(next);
    this.updateTextInfo();
    this.restoreVisualAnchor(anchor);
  }

  protected override onResize(width: number, height: number): void {
    const anchor = this.captureVisualAnchor();
    if (this.wrapMode !== "none") this.textBufferView.setWrapWidth(width);
    super.onResize(width, height);
    this.restoreVisualAnchor(anchor);
    this.refreshLocalSelection();
  }

  private captureVisualAnchor(): VisualAnchor | null {
    const info = this.lineInfo;
    if (info.lineSources.length === 0) return null;

    const row = Math.min(Math.max(0, this.scrollY), info.lineSources.length - 1);
    const source = info.lineSources[row];
    const wrap = info.lineWraps[row];
    return source === undefined || wrap === undefined ? null : { source, wrap };
  }

  private restoreVisualAnchor(anchor: VisualAnchor | null): void {
    if (!anchor) {
      this.scrollY = this.scrollY;
      return;
    }

    const info = this.lineInfo;
    let row = info.lineSources.findIndex(
      (source, index) => source === anchor.source && (info.lineWraps[index] ?? 0) >= anchor.wrap,
    );
    if (row < 0) row = info.lineSources.findIndex((source) => source === anchor.source);
    this.scrollY = row >= 0 ? row : this.scrollY;
  }
}

extend({ "transcript-review": TranscriptReviewRenderable });

declare module "@opentui/react" {
  interface OpenTUIComponents {
    "transcript-review": typeof TranscriptReviewRenderable;
  }
}
