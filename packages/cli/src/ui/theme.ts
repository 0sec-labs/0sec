export const CANVAS = "#080808";
export const PANEL = "#111111";
export const PANEL_ALT = "#171515";
export const BORDER = "#25201D";
export const TEXT = "#F3EEE9";
export const MUTED = "#8A7D73";
export const PRIMARY = "#FFFFFF";
export const ACCENT = "#F3EEE9";
export const SUCCESS = "#22C55E";
export const WARNING = "#EAB308";
export const ERROR = "#DC2626";
export const INFO = "#B8AFA6";

export function severityTone(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return ERROR;
    case "medium":
      return WARNING;
    case "low":
      return INFO;
    default:
      return MUTED;
  }
}
