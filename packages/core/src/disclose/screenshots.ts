import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Finding, PocStep } from "@pwnkit/shared";
import type { PocStepResult } from "./poc-runtime.js";
import { redactSensitiveHeaders } from "./template.js";

export interface ScreenshotResult {
  alt: string;
  path: string;
  relativePath: string;
  caption: string;
  sessionText: string;
  /** Optional step id when this frame corresponds to a `pocSteps` entry (#170). */
  stepId?: string;
  /** Frame number within a multi-frame render (1-indexed). Undefined for single-frame. */
  frame?: number;
}

export interface ScreenshotOptions {
  outputDir: string;
  /** Emit image paths relative to this directory (so the markdown sibling file can reference them). */
  markdownDir?: string;
  binary?: string;
  theme?: string;
  width?: number;
  fontSize?: number;
  background?: string;
  /** Override freeze detection (for tests). */
  available?: boolean;
  /**
   * When provided, render one PNG per step instead of a single composite PNG
   * (multi-frame, see #168 / #170). Each step's session text combines the
   * step's `summary` + `action` description with — when supplied — the matching
   * {@link PocStepResult} from a behavioural re-verify run (#171).
   */
  pocSteps?: PocStep[];
  /**
   * Per-step execution results, keyed by `stepId`. When a step has a matching
   * result the rendered frame embeds the observed stdout / stderr / response
   * body. When absent we fall back to a prose synthesis of the action alone.
   */
  stepResults?: Record<string, PocStepResult>;
}

const DEFAULT_OPTS: Required<Pick<ScreenshotOptions, "binary" | "theme" | "width" | "fontSize" | "background">> = {
  binary: "freeze",
  theme: "dracula",
  width: 1200,
  fontSize: 14,
  background: "#0f1117",
};

function slugify(input: string, max = 40): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max);
}

export function isFreezeAvailable(binary = DEFAULT_OPTS.binary): boolean {
  try {
    execFileSync(process.platform === "win32" ? "where" : "which", [binary], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Compose a shell-session text file from the finding's evidence. This is what
 * gets rendered into the terminal-style PNG. Keeps the request and response in
 * the same pane so the exploit and its observable effect appear together.
 */
export function composeExploitSession(finding: Finding): string {
  const lines: string[] = [];
  lines.push(`$ # PoC for: ${finding.title}`);
  lines.push(`$ # Category: ${finding.category} | severity: ${finding.severity}`);
  lines.push("");

  const request = finding.evidence?.request?.trim();
  const response = finding.evidence?.response?.trim();

  if (request) {
    const requestLines = redactSensitiveHeaders(request).split("\n");
    lines.push(`$ ${requestLines[0]}`);
    for (const line of requestLines.slice(1)) {
      lines.push(`  ${line}`);
    }
    lines.push("");
  }

  if (response) {
    lines.push(redactSensitiveHeaders(response));
  }

  const analysis = finding.evidence?.analysis?.trim();
  if (analysis) {
    lines.push("");
    lines.push("# Agent analysis:");
    for (const line of analysis.split("\n")) {
      lines.push(`# ${line}`);
    }
  }

  return lines.join("\n");
}

/**
 * Compose a shell-session text for a single PoC step. When a behavioural
 * re-verify result is present the rendered frame embeds the observed exit
 * code / status / stdout / response body — that's the input-output pair the
 * advisory's reader sees in the screenshot. Without a result we fall back to
 * a prose synthesis of the action alone (still useful as a static frame).
 */
export function composeStepSession(
  finding: Finding,
  step: PocStep,
  index: number,
  total: number,
  result?: PocStepResult,
): string {
  const lines: string[] = [];
  lines.push(`$ # PoC step ${index + 1}/${total} — ${step.kind}: ${step.summary}`);
  lines.push(`$ # Finding: ${finding.title}`);
  lines.push("");

  // Render the action verbatim — what the operator (or runtime) would do.
  switch (step.action.type) {
    case "shell": {
      const cmdLines = step.action.cmd.split("\n");
      lines.push(`$ ${cmdLines[0]}`);
      for (const l of cmdLines.slice(1)) lines.push(`  ${l}`);
      break;
    }
    case "http": {
      lines.push(`$ ${step.action.method.toUpperCase()} ${step.action.url}`);
      if (step.action.headers) {
        for (const [k, v] of Object.entries(step.action.headers)) {
          // Redact sensitive header values inline so the screenshot text
          // never leaks the operator's session / JWT / API key into a
          // published advisory (sensitive-data disclosure prevention).
          const headerLine = redactSensitiveHeaders(`${k}: ${v}`);
          lines.push(`  ${headerLine}`);
        }
      }
      if (step.action.body) {
        lines.push("");
        const redactedBody = redactSensitiveHeaders(step.action.body);
        for (const l of redactedBody.split("\n")) lines.push(`  ${l}`);
      }
      break;
    }
    case "docker": {
      lines.push(`$ docker run --rm ${step.action.args.join(" ")} ${step.action.image}`);
      break;
    }
    case "note": {
      lines.push(`$ # (note) ${step.action.text}`);
      break;
    }
  }

  // Embed observed effect from the behavioural re-verify when available.
  if (result) {
    lines.push("");
    if (result.observedExit !== undefined) {
      lines.push(`# exit=${result.observedExit}`);
    }
    if (result.observedStatus !== undefined) {
      lines.push(`# http-status=${result.observedStatus}`);
    }
    if (result.observedStdout && result.observedStdout.trim().length > 0) {
      for (const l of redactSensitiveHeaders(result.observedStdout).split("\n")) lines.push(l);
    }
    if (result.observedResponseBody && result.observedResponseBody.trim().length > 0) {
      for (const l of redactSensitiveHeaders(result.observedResponseBody).split("\n")) lines.push(l);
    }
    if (result.observedStderr && result.observedStderr.trim().length > 0) {
      lines.push("");
      for (const l of redactSensitiveHeaders(result.observedStderr).split("\n")) lines.push(`# stderr: ${l}`);
    }
    lines.push("");
    lines.push(`# verdict: ${result.kind}${result.error ? ` (${result.error})` : ""}`);
  } else {
    // No live result — narrate the predicate as the expected outcome.
    if (step.expect) {
      lines.push("");
      lines.push(`# expected: ${describeExpect(step.expect)}`);
    }
  }

  return lines.join("\n");
}

function describeExpect(expect: NonNullable<PocStep["expect"]>): string {
  switch (expect.type) {
    case "exit-zero":
      return "exit-zero";
    case "http-status": {
      const s = Array.isArray(expect.status) ? expect.status.join(",") : expect.status;
      return `http-status ∈ {${s}}`;
    }
    case "body-contains":
      return `body contains "${expect.text}"`;
    case "body-matches":
      return `body matches /${expect.pattern}/`;
    case "file-exists":
      return `file exists at ${expect.path}`;
  }
}

/**
 * Run `freeze` on a session file → PNG. Returns null on any failure (binary
 * missing, exit nonzero). Caller is responsible for `mkdirSync` of `outputDir`.
 */
function freezeSessionToPng(
  sessionFile: string,
  pngPath: string,
  opts: typeof DEFAULT_OPTS,
): boolean {
  try {
    execFileSync(
      opts.binary,
      [
        sessionFile,
        "--language", "bash",
        "--theme", opts.theme,
        "--window",
        "--padding", "20,30",
        "--margin", "10",
        "--background", opts.background,
        "--font.size", String(opts.fontSize),
        "--width", String(opts.width),
        "-o", pngPath,
      ],
      { stdio: "ignore" },
    );
    return true;
  } catch {
    return false;
  }
}

function relativiseFrom(pngPath: string, markdownDir: string | undefined): string {
  if (!markdownDir) return pngPath;
  if (pngPath.startsWith(markdownDir)) return "." + pngPath.slice(markdownDir.length);
  return pngPath;
}

// Overloads — when `pocSteps` is supplied we return an array of frames; when
// it's absent we return either a single result or null (the legacy single-
// frame contract). Internally both paths share the same freeze invocation.
export function renderExploitScreenshot(
  finding: Finding,
  options: ScreenshotOptions & { pocSteps: PocStep[] },
): ScreenshotResult[];
export function renderExploitScreenshot(
  finding: Finding,
  options: ScreenshotOptions,
): ScreenshotResult | null;
/**
 * Render the finding's exploit as one or more terminal-style PNGs.
 *
 * - When `options.pocSteps` is provided, render one PNG per step (#168 / #170)
 *   and return an array. An empty `pocSteps` array round-trips to `[]`.
 * - When absent, render a single composite frame from `evidence` (legacy path).
 *   Returns null when freeze is unavailable or rendering fails.
 */
export function renderExploitScreenshot(
  finding: Finding,
  options: ScreenshotOptions,
): ScreenshotResult | ScreenshotResult[] | null {
  const opts = { ...DEFAULT_OPTS, ...options };
  const available = options.available ?? isFreezeAvailable(opts.binary);

  // Multi-frame branch (pocSteps present, even if []). Always returns an
  // array — never null — so callers don't need to special-case "none rendered
  // because freeze missing" vs "graph was empty".
  if (options.pocSteps !== undefined) {
    if (!available || options.pocSteps.length === 0) return [];
    mkdirSync(opts.outputDir, { recursive: true });
    const baseSlug = slugify(`${finding.severity}-${finding.id.slice(0, 8)}-${finding.title}`);
    const frames: ScreenshotResult[] = [];
    for (let i = 0; i < options.pocSteps.length; i++) {
      const step = options.pocSteps[i];
      const result = options.stepResults?.[step.id];
      const stepSlug = `${baseSlug}-step-${i + 1}-${slugify(step.id, 30)}`;
      const sessionText = composeStepSession(finding, step, i, options.pocSteps.length, result);
      const sessionFile = join(opts.outputDir, `${stepSlug}.session.txt`);
      const pngPath = join(opts.outputDir, `${stepSlug}.png`);
      writeFileSync(sessionFile, sessionText, "utf8");
      const ok = freezeSessionToPng(sessionFile, pngPath, opts);
      if (!ok) continue; // skip this frame, keep going — don't kill the whole graph
      frames.push({
        alt: `exploit-${stepSlug}`,
        path: pngPath,
        relativePath: relativiseFrom(pngPath, options.markdownDir),
        caption: `${i + 1}. ${step.summary}`,
        sessionText,
        stepId: step.id,
        frame: i + 1,
      });
    }
    return frames;
  }

  // Single-frame legacy branch.
  if (!available) return null;
  mkdirSync(opts.outputDir, { recursive: true });
  const slug = slugify(`${finding.severity}-${finding.id.slice(0, 8)}-${finding.title}`);
  const sessionText = composeExploitSession(finding);
  const sessionFile = join(opts.outputDir, `${slug}.session.txt`);
  const pngPath = join(opts.outputDir, `${slug}.png`);
  writeFileSync(sessionFile, sessionText, "utf8");
  const ok = freezeSessionToPng(sessionFile, pngPath, opts);
  if (!ok) return null;
  return {
    alt: `exploit-${slug}`,
    path: pngPath,
    relativePath: relativiseFrom(pngPath, options.markdownDir),
    caption: finding.title,
    sessionText,
  };
}
