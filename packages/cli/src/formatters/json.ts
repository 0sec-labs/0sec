import type { ScanReport } from "@pwnkit/shared";

export function formatJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
