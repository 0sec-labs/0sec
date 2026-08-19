import type { Finding } from "@0sec/shared";

export type SanitizerName = "asan" | "ubsan";
export type SanitizerPrimitive = "read" | "write" | "both" | "unknown";

export interface SanitizerFrame {
  functionName?: string;
  file?: string;
  line?: number;
}

export interface SanitizerVerdict {
  sanitizer: SanitizerName;
  kind: string;
  category: Finding["category"];
  primitive: SanitizerPrimitive;
  sourceFile?: string;
  sourceLine?: number;
  allocSize?: number;
  accessSize?: number;
  summary: string;
  frames: SanitizerFrame[];
}

const ASAN_CATEGORY_BY_KIND: Record<string, Finding["category"]> = {
  "heap-use-after-free": "use-after-free",
  "stack-use-after-return": "use-after-free",
  "stack-use-after-scope": "use-after-free",
  "double-free": "double-free",
  "attempting-double-free": "double-free",
  "stack-buffer-overflow": "stack-buffer-overflow",
  "heap-buffer-overflow": "heap-overflow",
  "global-buffer-overflow": "heap-overflow",
};

function categoryForAsan(kind: string, primitive: SanitizerPrimitive): Finding["category"] {
  if (
    (kind === "heap-buffer-overflow" || kind === "global-buffer-overflow") &&
    primitive === "read"
  ) {
    return "out-of-bounds-read";
  }
  if (
    (kind === "heap-buffer-overflow" || kind === "global-buffer-overflow") &&
    primitive === "write"
  ) {
    return "out-of-bounds-write";
  }
  return ASAN_CATEGORY_BY_KIND[kind] ?? "other";
}

function categoryForUbsan(message: string): { kind: string; category: Finding["category"] } {
  const lower = message.toLowerCase();
  if (lower.includes("signed integer overflow") || lower.includes("unsigned integer overflow")) {
    return { kind: "signed-integer-overflow", category: "integer-overflow" };
  }
  if (lower.includes("shift exponent") || lower.includes("shift base")) {
    return { kind: "shift-exponent", category: "integer-overflow" };
  }
  if (lower.includes("float-cast-overflow") || lower.includes("outside the range of representable values")) {
    return { kind: "float-cast-overflow", category: "integer-truncation" };
  }
  if (lower.includes("null pointer") || lower.includes("null-pointer")) {
    return { kind: "null-pointer-use", category: "null-deref" };
  }
  return { kind: "undefined-behavior", category: "other" };
}

function parsePrimitive(text: string): { primitive: SanitizerPrimitive; accessSize?: number } {
  const access = text.match(/\b(READ|WRITE) of size (\d+)/i);
  if (!access) return { primitive: "unknown" };
  return {
    primitive: access[1]!.toLowerCase() as "read" | "write",
    accessSize: Number(access[2]),
  };
}

function parseFrames(text: string): SanitizerFrame[] {
  const frames: SanitizerFrame[] = [];
  const frameRegex = /^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?:(\S+)\s+)?(.+?):(\d+)(?::\d+)?(?:\s|$)/gm;
  let match: RegExpExecArray | null;
  while ((match = frameRegex.exec(text)) !== null) {
    frames.push({
      functionName: match[1],
      file: match[2],
      line: Number(match[3]),
    });
  }
  return frames;
}

function parseAsan(text: string): SanitizerVerdict | null {
  const header = text.match(/ERROR:\s*AddressSanitizer:\s*([a-z0-9-]+)/i);
  if (!header?.[1]) return null;

  const kind = header[1].toLowerCase();
  const { primitive, accessSize } = parsePrimitive(text);
  const frames = parseFrames(text);
  let sourceFile = frames[0]?.file;
  let sourceLine = frames[0]?.line;

  const summary = text.match(/SUMMARY:\s*AddressSanitizer:\s*[a-z0-9-]+\s+(.+?):(\d+)(?::\d+)?/i);
  if ((!sourceFile || !sourceLine) && summary?.[1] && summary?.[2]) {
    sourceFile = summary[1];
    sourceLine = Number(summary[2]);
  }

  const allocMatch = text.match(/\b(\d+)-byte region\b/i);
  const allocSize = allocMatch?.[1] ? Number(allocMatch[1]) : undefined;

  return {
    sanitizer: "asan",
    kind,
    category: categoryForAsan(kind, primitive),
    primitive,
    sourceFile,
    sourceLine,
    allocSize,
    accessSize,
    summary: text.split("\n").find((line) => line.includes("ERROR: AddressSanitizer"))?.trim() ?? kind,
    frames,
  };
}

function parseUbsan(text: string): SanitizerVerdict | null {
  const runtime = text.match(/^(.+?):(\d+):(?:(\d+):)?\s*runtime error:\s*(.+)$/m);
  if (!runtime?.[1] || !runtime?.[2] || !runtime?.[4]) return null;

  const details = runtime[4].trim();
  const { kind, category } = categoryForUbsan(details);
  return {
    sanitizer: "ubsan",
    kind,
    category,
    primitive: "unknown",
    sourceFile: runtime[1],
    sourceLine: Number(runtime[2]),
    summary: details,
    frames: [],
  };
}

export function parseSanitizerLog(text: string): SanitizerVerdict | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  return parseAsan(trimmed) ?? parseUbsan(trimmed);
}

export function renderSanitizerVerdict(verdict: SanitizerVerdict): string {
  const loc = verdict.sourceFile
    ? `${verdict.sourceFile}${verdict.sourceLine ? `:${verdict.sourceLine}` : ""}`
    : "unknown location";
  const sizes = [
    verdict.accessSize !== undefined ? `access=${verdict.accessSize}` : null,
    verdict.allocSize !== undefined ? `allocation=${verdict.allocSize}` : null,
  ].filter(Boolean).join(", ");
  return [
    `${verdict.sanitizer.toUpperCase()} ${verdict.kind}`,
    `category=${verdict.category}`,
    `primitive=${verdict.primitive}`,
    `source=${loc}`,
    sizes || null,
  ].filter(Boolean).join("; ");
}
