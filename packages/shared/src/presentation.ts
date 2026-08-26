import type {
  AuditReport,
  ReviewReport,
  ScanReport,
} from "./types.js";

/** Versioned canonical input for every UI and output adapter. */
export const PRESENTATION_PROTOCOL = "0sec.presentation/v1" as const;

export type PresentationSource = "core" | "cli" | "dashboard" | "adapter";

/**
 * A producer-ordered semantic event. `sequence` is monotonic only inside the
 * adapter instance that emitted it; consumers must not infer cross-process
 * delivery, replay, or exactly-once guarantees.
 */
export interface PresentationEvent {
  protocol: typeof PRESENTATION_PROTOCOL;
  kind: "event";
  source: PresentationSource;
  sequence: number;
  at: string;
  eventType: string;
  payload: Record<string, unknown>;
  scanId?: string;
  sessionId?: string;
}

export type PresentationReportDocument =
  | {
      protocol: typeof PRESENTATION_PROTOCOL;
      kind: "document";
      documentType: "scan-report";
      report: ScanReport;
    }
  | {
      protocol: typeof PRESENTATION_PROTOCOL;
      kind: "document";
      documentType: "audit-report";
      report: AuditReport;
    }
  | {
      protocol: typeof PRESENTATION_PROTOCOL;
      kind: "document";
      documentType: "review-report";
      report: ReviewReport;
    };

export interface CreatePresentationEventOptions {
  source: PresentationSource;
  sequence: number;
  at: string;
  eventType: string;
  payload: Record<string, unknown>;
  scanId?: string;
  sessionId?: string;
}

/** Construct a canonical event without adding transport-specific framing. */
export function createPresentationEvent(options: CreatePresentationEventOptions): PresentationEvent {
  return {
    protocol: PRESENTATION_PROTOCOL,
    kind: "event",
    source: options.source,
    sequence: options.sequence,
    at: options.at,
    eventType: options.eventType,
    payload: options.payload,
    ...(options.scanId ? { scanId: options.scanId } : {}),
    ...(options.sessionId ? { sessionId: options.sessionId } : {}),
  };
}

/** Wrap an existing public report without changing its schema or contents. */
export function createScanReportDocument(report: ScanReport): PresentationReportDocument {
  return { protocol: PRESENTATION_PROTOCOL, kind: "document", documentType: "scan-report", report };
}

/** Wrap an existing public report without changing its schema or contents. */
export function createAuditReportDocument(report: AuditReport): PresentationReportDocument {
  return { protocol: PRESENTATION_PROTOCOL, kind: "document", documentType: "audit-report", report };
}

/** Wrap an existing public report without changing its schema or contents. */
export function createReviewReportDocument(report: ReviewReport): PresentationReportDocument {
  return { protocol: PRESENTATION_PROTOCOL, kind: "document", documentType: "review-report", report };
}

/** Runtime discriminator for browser/SSE/NDJSON adapters. */
export function isPresentationEvent(value: unknown): value is PresentationEvent {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return candidate.protocol === PRESENTATION_PROTOCOL &&
    candidate.kind === "event" &&
    typeof candidate.source === "string" &&
    typeof candidate.sequence === "number" &&
    typeof candidate.at === "string" &&
    typeof candidate.eventType === "string" &&
    typeof candidate.payload === "object" &&
    candidate.payload !== null &&
    !Array.isArray(candidate.payload);
}
