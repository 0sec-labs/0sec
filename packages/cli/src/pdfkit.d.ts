/**
 * Minimal type declarations for pdfkit.
 * These are used when @types/pdfkit is not yet installed.
 * After running `pnpm install`, the full types from @types/pdfkit will take precedence.
 */
declare module "pdfkit" {
  import { Writable } from "node:stream";

  interface PDFDocumentOptions {
    size?: string | [number, number];
    margins?: { top: number; bottom: number; left: number; right: number };
    info?: Record<string, unknown>;
    bufferPages?: boolean;
  }

  interface TextOptions {
    width?: number;
    height?: number;
    align?: "left" | "center" | "right" | "justify";
    continued?: boolean;
    ellipsis?: boolean | string;
    font?: string;
    fontSize?: number;
  }

  class PDFDocument {
    x: number;
    y: number;

    constructor(options?: PDFDocumentOptions);
    pipe(destination: Writable): Writable;
    end(): void;

    addPage(): this;
    switchToPage(pageNumber: number): this;
    bufferedPageRange(): { start: number; count: number };

    fontSize(size: number): this;
    font(name: string): this;
    fillColor(color: string): this;
    strokeColor(color: string): this;
    lineWidth(width: number): this;

    text(text: string, x?: number, y?: number, options?: TextOptions): this;
    text(text: string, options?: TextOptions): this;
    heightOfString(text: string, options?: TextOptions): number;

    moveTo(x: number, y: number): this;
    lineTo(x: number, y: number): this;
    stroke(): this;

    rect(x: number, y: number, w: number, h: number): this;
    fill(color: string): this;

    moveDown(lines?: number): this;
  }

  export default PDFDocument;
}
