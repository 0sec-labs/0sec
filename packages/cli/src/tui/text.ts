export type TuiTextFitMode = "end" | "middle";

export interface TuiTextFitOptions {
  mode?: TuiTextFitMode;
  maxEncodedRun?: number;
}

const DEFAULT_ENCODED_RUN_MAX = 140;
const ENCODED_RUN_MAX_CAP = 1_000_000;
const ELLIPSIS = "...";
const ENCODED_PLACEHOLDER = "[encoded payload omitted]";

function stripTerminalControl(text: string): string {
  return text
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

function replaceLargeEncodedChunks(text: string, maxEncodedRun: number): string {
  const normalized = Number.isFinite(maxEncodedRun)
    ? Math.trunc(maxEncodedRun)
    : DEFAULT_ENCODED_RUN_MAX;
  const minRun = Math.min(Math.max(32, normalized), ENCODED_RUN_MAX_CAP);
  return text.replace(new RegExp(`[A-Za-z0-9+/_-]{${minRun},}={0,2}`, "g"), ENCODED_PLACEHOLDER);
}

export function sanitizeTuiText(value: unknown, options: TuiTextFitOptions = {}): string {
  return stripTerminalControl(replaceLargeEncodedChunks(String(value ?? ""), options.maxEncodedRun ?? DEFAULT_ENCODED_RUN_MAX))
    .replace(/\s+/g, " ")
    .trim();
}

export function fitTuiText(value: unknown, maxChars: number, options: TuiTextFitOptions = {}): string {
  const text = sanitizeTuiText(value, options);
  if (maxChars <= 0) return "";
  if (text.length <= maxChars) return text;
  if (maxChars <= ELLIPSIS.length) return ELLIPSIS.slice(0, maxChars);

  const budget = maxChars - ELLIPSIS.length;
  if (options.mode === "middle" && budget > 1) {
    const head = Math.ceil(budget / 2);
    const tail = Math.floor(budget / 2);
    return `${text.slice(0, head)}${ELLIPSIS}${text.slice(text.length - tail)}`;
  }

  return `${text.slice(0, budget)}${ELLIPSIS}`;
}

export function fitTuiUrl(value: unknown, maxChars: number): string {
  return fitTuiText(value, maxChars, { mode: "middle" });
}
