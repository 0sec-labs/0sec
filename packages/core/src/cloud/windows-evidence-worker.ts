import { createHash } from "node:crypto";
import { VERSION } from "@0sec/shared";

const JOB_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const UPLOAD_GRANT = /^[A-Za-z0-9_-]{43}$/;
const DEFAULT_MAX_ATTEMPTS = 8;
const DEFAULT_RETRY_DELAY_MS = 250;
const DEFAULT_MAX_RETRY_DELAY_MS = 5_000;
const MAX_ENVELOPE_BYTES = 256 * 1024;

export interface WindowsEvidenceWorkerHandoff {
  /** Orchestrator origin or deployment base path; never a controller URL. */
  baseUrl: string;
  jobId: string;
  /** One-time, job-scoped worker capability. */
  uploadGrant: string;
  uploadGrantExpiresAt: string | Date;
}

export interface WindowsEvidenceWorkerBlob {
  sha256: string;
  sizeBytes: number;
  mediaType: string;
  /** Replayable bytes are required because an upload may receive 202 or 503. */
  bytes: Uint8Array;
}

export interface WindowsEvidenceStoredBlob {
  status: "stored" | "already-stored";
  ref: Omit<WindowsEvidenceWorkerBlob, "bytes">;
}

export interface WindowsEvidenceSubmissionReceipt {
  jobId: string;
  packId: string;
  status: "submitted";
}

export interface WindowsEvidenceWorkerClientOptions {
  fetchImpl?: typeof fetch;
  now?: () => number;
  sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
  maxAttemptsPerRequest?: number;
  maxRetryDelayMs?: number;
}

export class WindowsEvidenceWorkerTransportError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "WindowsEvidenceWorkerTransportError";
  }
}

/**
 * Grant-bound transport for an already-issued Windows evidence job.
 *
 * This client intentionally has no controller or validator methods and accepts
 * no tenant, policy, object-store key, signer allowlist, or signing material.
 */
export class WindowsEvidenceWorkerClient {
  private readonly baseUrl: string;
  private readonly jobId: string;
  private readonly uploadGrant: string;
  private readonly expiresAtMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
  private readonly maxAttempts: number;
  private readonly maxRetryDelayMs: number;

  constructor(
    handoff: WindowsEvidenceWorkerHandoff,
    options: WindowsEvidenceWorkerClientOptions = {},
  ) {
    this.baseUrl = validateBaseUrl(handoff.baseUrl);
    if (!JOB_ID.test(handoff.jobId)) {
      throw new WindowsEvidenceWorkerTransportError("Windows evidence worker job ID is invalid");
    }
    if (!UPLOAD_GRANT.test(handoff.uploadGrant)) {
      throw new WindowsEvidenceWorkerTransportError(
        "Windows evidence worker upload grant is invalid",
      );
    }
    this.jobId = handoff.jobId;
    this.uploadGrant = handoff.uploadGrant;
    this.expiresAtMs = parseExpiry(handoff.uploadGrantExpiresAt);
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? abortableSleep;
    this.maxAttempts = positiveInteger(
      options.maxAttemptsPerRequest ?? DEFAULT_MAX_ATTEMPTS,
      "attempt limit",
    );
    this.maxRetryDelayMs = positiveInteger(
      options.maxRetryDelayMs ?? DEFAULT_MAX_RETRY_DELAY_MS,
      "retry delay limit",
    );
    this.requireActiveGrant();
  }

  /** Upload unique blobs in caller order after locally verifying their identities. */
  async uploadBlobs(
    blobs: readonly WindowsEvidenceWorkerBlob[],
    signal?: AbortSignal,
  ): Promise<WindowsEvidenceStoredBlob[]> {
    signal?.throwIfAborted();
    const unique = validateAndDedupeBlobs(blobs);
    const stored: WindowsEvidenceStoredBlob[] = [];
    for (const blob of unique) {
      signal?.throwIfAborted();
      stored.push(await this.uploadBlob(blob, signal));
    }
    return stored;
  }

  async uploadBlob(
    input: WindowsEvidenceWorkerBlob,
    signal?: AbortSignal,
  ): Promise<WindowsEvidenceStoredBlob> {
    const blob = validateBlob(input);
    const path = `/internal/windows-evidence-worker/jobs/${this.jobId}/blobs/${blob.sha256}`;
    const response = await this.requestWithRetry({
      operation: "blob upload",
      path,
      signal,
      makeInit: () => ({
        method: "PUT",
        redirect: "error",
        headers: this.headers({
          "Content-Length": String(blob.sizeBytes),
          "Content-Type": blob.mediaType,
        }),
        body: replayableBody(blob.bytes),
        signal,
      }),
      accept: async (result) => parseStoredBlob(result, blob),
      retryInProgress: true,
    });
    return response;
  }

  /** Submit an already-assembled envelope; schema validation remains contract-owned. */
  async submitEnvelope(
    envelope: unknown,
    signal?: AbortSignal,
  ): Promise<WindowsEvidenceSubmissionReceipt> {
    signal?.throwIfAborted();
    const expectedPackId = envelopePackId(envelope);
    let encoded: string;
    try {
      encoded = JSON.stringify(envelope);
    } catch (error) {
      throw this.safeError("Windows evidence envelope is not JSON-serializable", undefined, error);
    }
    if (typeof encoded !== "string" || encoded.length === 0) {
      throw new WindowsEvidenceWorkerTransportError("Windows evidence envelope is invalid");
    }
    const bytes = new TextEncoder().encode(encoded);
    if (bytes.byteLength > MAX_ENVELOPE_BYTES) {
      throw new WindowsEvidenceWorkerTransportError(
        "Windows evidence envelope exceeds the 256 KiB transport limit",
      );
    }
    const path = `/internal/windows-evidence-worker/jobs/${this.jobId}/submit`;
    return await this.requestWithRetry({
      operation: "envelope submission",
      path,
      signal,
      makeInit: () => ({
        method: "POST",
        redirect: "error",
        headers: this.headers({
          "Content-Length": String(bytes.byteLength),
          "Content-Type": "application/json",
        }),
        body: replayableBody(bytes),
        signal,
      }),
      accept: async (response) => parseSubmission(response, this.jobId, expectedPackId),
      retryInProgress: false,
    });
  }

  private async requestWithRetry<T>(args: {
    operation: string;
    path: string;
    signal?: AbortSignal;
    makeInit(): RequestInit;
    accept(response: Response): Promise<T>;
    retryInProgress: boolean;
  }): Promise<T> {
    let transientFailures = 0;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      args.signal?.throwIfAborted();
      this.requireActiveGrant();
      let response: Response;
      try {
        response = await this.fetchImpl(`${this.baseUrl}${args.path}`, args.makeInit());
      } catch (error) {
        throw this.safeError(`Windows evidence ${args.operation} failed`, undefined, error);
      }

      if (response.status === 200) {
        try {
          return await args.accept(response);
        } catch (error) {
          throw this.safeError(
            `Windows evidence ${args.operation} returned an invalid response`,
            200,
            error,
          );
        }
      }

      const canRetry =
        (args.retryInProgress && response.status === 202) || response.status === 503;
      if (!canRetry) {
        await discardResponseBody(response);
        throw new WindowsEvidenceWorkerTransportError(
          `Windows evidence ${args.operation} was rejected (HTTP ${response.status})`,
          response.status,
        );
      }
      if (response.status === 503) transientFailures += 1;
      if (attempt === this.maxAttempts) {
        await discardResponseBody(response);
        throw new WindowsEvidenceWorkerTransportError(
          `Windows evidence ${args.operation} retry limit reached`,
          response.status,
        );
      }

      const delayMs = retryDelayMs({
        retryAfter: response.headers.get("retry-after"),
        transientFailures,
        nowMs: this.now(),
        maximumMs: this.maxRetryDelayMs,
      });
      await discardResponseBody(response);
      this.requireRetryWindow(delayMs);
      await this.sleep(delayMs, args.signal);
    }
    throw new WindowsEvidenceWorkerTransportError(
      `Windows evidence ${args.operation} retry limit reached`,
    );
  }

  private headers(extra: Record<string, string>): Record<string, string> {
    return {
      Authorization: `Bearer ${this.uploadGrant}`,
      Accept: "application/json",
      "User-Agent": `0sec-cli/${VERSION}`,
      ...extra,
    };
  }

  private requireActiveGrant(): void {
    if (this.now() >= this.expiresAtMs) {
      throw new WindowsEvidenceWorkerTransportError(
        "Windows evidence worker upload grant has expired",
      );
    }
  }

  private requireRetryWindow(delayMs: number): void {
    if (this.now() + delayMs >= this.expiresAtMs) {
      throw new WindowsEvidenceWorkerTransportError(
        "Windows evidence worker upload grant will expire before retry",
      );
    }
  }

  private safeError(
    message: string,
    status?: number,
    cause?: unknown,
  ): WindowsEvidenceWorkerTransportError {
    const detail = cause instanceof Error ? `: ${cause.message}` : "";
    return new WindowsEvidenceWorkerTransportError(
      `${message}${detail}`.split(this.uploadGrant).join("[REDACTED]"),
      status,
    );
  }
}

function validateBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new WindowsEvidenceWorkerTransportError("Windows evidence worker base URL is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new WindowsEvidenceWorkerTransportError("Windows evidence worker base URL is invalid");
  }
  return url.toString().replace(/\/$/, "");
}

function parseExpiry(value: string | Date): number {
  const milliseconds = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new WindowsEvidenceWorkerTransportError(
      "Windows evidence worker grant expiry is invalid",
    );
  }
  return milliseconds;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new WindowsEvidenceWorkerTransportError(`Windows evidence worker ${label} is invalid`);
  }
  return value;
}

function validateBlob(input: WindowsEvidenceWorkerBlob): WindowsEvidenceWorkerBlob {
  if (typeof input.sha256 !== "string" || !SHA256.test(input.sha256)) {
    throw new WindowsEvidenceWorkerTransportError("Windows evidence blob digest is invalid");
  }
  if (!Number.isSafeInteger(input.sizeBytes) || input.sizeBytes < 0) {
    throw new WindowsEvidenceWorkerTransportError("Windows evidence blob size is invalid");
  }
  if (
    typeof input.mediaType !== "string" ||
    input.mediaType.length === 0 ||
    input.mediaType.length > 200 ||
    /[\u0000\r\n]/.test(input.mediaType)
  ) {
    throw new WindowsEvidenceWorkerTransportError("Windows evidence blob media type is invalid");
  }
  if (!(input.bytes instanceof Uint8Array) || input.bytes.byteLength !== input.sizeBytes) {
    throw new WindowsEvidenceWorkerTransportError(
      "Windows evidence blob bytes do not match declared size",
    );
  }
  const observed = createHash("sha256").update(input.bytes).digest("hex");
  if (observed !== input.sha256) {
    throw new WindowsEvidenceWorkerTransportError(
      "Windows evidence blob bytes do not match declared digest",
    );
  }
  return input;
}

function validateAndDedupeBlobs(
  blobs: readonly WindowsEvidenceWorkerBlob[],
): WindowsEvidenceWorkerBlob[] {
  const unique = new Map<string, WindowsEvidenceWorkerBlob>();
  for (const input of blobs) {
    const blob = validateBlob(input);
    const previous = unique.get(blob.sha256);
    if (
      previous !== undefined &&
      (previous.sizeBytes !== blob.sizeBytes || previous.mediaType !== blob.mediaType)
    ) {
      throw new WindowsEvidenceWorkerTransportError(
        "Windows evidence blob digest has conflicting metadata",
      );
    }
    if (previous === undefined) unique.set(blob.sha256, blob);
  }
  return [...unique.values()];
}

async function parseStoredBlob(
  response: Response,
  expected: WindowsEvidenceWorkerBlob,
): Promise<WindowsEvidenceStoredBlob> {
  const value = await response.json() as unknown;
  if (!isRecord(value) || (value.status !== "stored" && value.status !== "already-stored")) {
    throw new Error("invalid persistence status");
  }
  const ref = value.ref;
  if (
    !isRecord(ref) ||
    ref.sha256 !== expected.sha256 ||
    ref.sizeBytes !== expected.sizeBytes ||
    ref.mediaType !== expected.mediaType
  ) {
    throw new Error("stored blob reference mismatch");
  }
  return {
    status: value.status,
    ref: {
      sha256: expected.sha256,
      sizeBytes: expected.sizeBytes,
      mediaType: expected.mediaType,
    },
  };
}

async function parseSubmission(
  response: Response,
  expectedJobId: string,
  expectedPackId: string,
): Promise<WindowsEvidenceSubmissionReceipt> {
  const value = await response.json() as unknown;
  if (
    !isRecord(value) ||
    value.status !== "submitted" ||
    value.jobId !== expectedJobId ||
    value.packId !== expectedPackId
  ) {
    throw new Error("submission receipt mismatch");
  }
  return { jobId: value.jobId, packId: value.packId, status: "submitted" };
}

function envelopePackId(envelope: unknown): string {
  if (!isRecord(envelope) || typeof envelope.packId !== "string" || !SHA256.test(envelope.packId)) {
    throw new WindowsEvidenceWorkerTransportError(
      "Windows evidence envelope pack ID is invalid",
    );
  }
  return envelope.packId;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function replayableBody(bytes: Uint8Array): Blob {
  // Copy into an ArrayBuffer-owned view. Uint8Array may otherwise be backed by
  // SharedArrayBuffer, which is not a valid fetch BlobPart in every runtime.
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return new Blob([copy.buffer]);
}

function retryDelayMs(args: {
  retryAfter: string | null;
  transientFailures: number;
  nowMs: number;
  maximumMs: number;
}): number {
  let requested: number | null = null;
  if (args.retryAfter !== null && /^\d+$/.test(args.retryAfter.trim())) {
    requested = Number(args.retryAfter.trim()) * 1_000;
  } else if (args.retryAfter !== null) {
    const date = Date.parse(args.retryAfter);
    if (Number.isFinite(date)) requested = Math.max(0, date - args.nowMs);
  }
  if (requested === null || !Number.isSafeInteger(requested)) {
    requested = DEFAULT_RETRY_DELAY_MS * 2 ** Math.max(0, args.transientFailures - 1);
  }
  return Math.max(1, Math.min(requested, args.maximumMs));
}

async function abortableSleep(milliseconds: number, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", onAbort);
      reject(signal?.reason);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function discardResponseBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The status is authoritative; best-effort connection cleanup must not
    // turn a bounded retry into an untyped transport failure.
  }
}
