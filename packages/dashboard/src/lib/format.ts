export function formatTime(value: number | string): string {
  const date = typeof value === "number" ? new Date(value) : new Date(value);
  return date.toLocaleString();
}

export function formatDuration(durationMs: number | null | undefined): string {
  if (!durationMs || durationMs <= 0) return "n/a";
  if (durationMs < 1000) return `${durationMs}ms`;
  const totalSeconds = Math.round(durationMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) return `${totalSeconds}s`;
  return `${minutes}m ${seconds}s`;
}

export function summarizePayload(payload: Record<string, unknown> | null): string {
  if (!payload || Object.keys(payload).length === 0) return "No payload";

  if (typeof payload.summary === "string" && payload.summary.trim()) {
    return payload.summary.trim();
  }

  if (Array.isArray(payload.tools) && payload.tools.length > 0) {
    const turn = typeof payload.turn === "number" ? `turn ${payload.turn} · ` : "";
    return `${turn}tools: ${payload.tools.join(", ")}`;
  }

  if (typeof payload.excerpt === "string" && payload.excerpt.trim()) {
    const turn = typeof payload.turn === "number" ? `turn ${payload.turn} · ` : "";
    return `${turn}no tool calls · ${payload.excerpt.trim().slice(0, 120)}`;
  }

  return Object.entries(payload)
    .slice(0, 3)
    .map(([key, value]) => `${key}: ${formatScalar(value)}`)
    .join(" · ");
}

function formatScalar(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `${value.length} items`;
  if (value && typeof value === "object") return `${Object.keys(value).length} fields`;
  return "n/a";
}
