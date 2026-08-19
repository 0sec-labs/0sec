/**
 * Immutable, non-executing receipt contract for XNU fuzz inputs.
 *
 * A receipt binds the exact encoded program and external payload to an intended
 * target model. Replaying a receipt only verifies those bindings and deduplicates
 * them; it never opens a device, boots a VM, or invokes an IOKit method.
 */

import { createHash } from "node:crypto";
import { decodeProgram } from "./program.js";
import type { XnuArtifactReference, XnuTargetReference } from "./types.js";

export const XNU_RECEIPT_SCHEMA_VERSION = 1 as const;

export interface XnuFuzzReceipt {
  schemaVersion: typeof XNU_RECEIPT_SCHEMA_VERSION;
  id: string;
  target: XnuTargetReference;
  program: XnuArtifactReference;
  payload: XnuArtifactReference;
}

export type XnuReceiptReplayOutcome =
  | { status: "accepted"; receipt: XnuFuzzReceipt }
  | { status: "duplicate"; receipt: XnuFuzzReceipt; duplicateOf: string; reason: "receipt-id" | "program-payload" }
  | { status: "rejected"; reason: string };

export interface CreateXnuFuzzReceiptInput {
  target: XnuTargetReference;
  program: { id: string; bytes: Uint8Array };
  payload: { id: string; bytes: Uint8Array };
}

export interface XnuReceiptArtifacts {
  program: Uint8Array;
  payload: Uint8Array;
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SAFE_ID = /^[a-z0-9][a-z0-9._:-]{0,159}$/;

/** Computes the canonical digest used by all XNU receipt references. */
export function xnuArtifactDigest(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function safeId(value: unknown, label: string): string {
  if (typeof value !== "string" || !SAFE_ID.test(value)) {
    throw new Error(`${label} must be a safe lowercase identifier`);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a lowercase sha256 digest`);
  }
  return value;
}

function reference(value: unknown, label: string): XnuArtifactReference {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const raw = value as Record<string, unknown>;
  if (!Number.isSafeInteger(raw.byteLength) || (raw.byteLength as number) < 0) {
    throw new Error(`${label}.byteLength must be a non-negative safe integer`);
  }
  return { id: safeId(raw.id, `${label}.id`), digest: digest(raw.digest, `${label}.digest`), byteLength: raw.byteLength as number };
}

function targetReference(value: unknown): XnuTargetReference {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("receipt.target must be an object");
  const raw = value as Record<string, unknown>;
  return { id: safeId(raw.id, "receipt.target.id"), digest: digest(raw.digest, "receipt.target.digest") };
}

function receiptId(receipt: Omit<XnuFuzzReceipt, "id">): string {
  const canonical = JSON.stringify(receipt);
  return `xnu-receipt:${xnuArtifactDigest(new TextEncoder().encode(canonical)).slice("sha256:".length)}`;
}

/** Creates an immutable receipt after binding ids, lengths, and SHA-256 digests. */
export function createXnuFuzzReceipt(input: CreateXnuFuzzReceiptInput): XnuFuzzReceipt {
  const body: Omit<XnuFuzzReceipt, "id"> = {
    schemaVersion: XNU_RECEIPT_SCHEMA_VERSION,
    target: targetReference(input.target),
    program: { id: safeId(input.program.id, "program.id"), digest: xnuArtifactDigest(input.program.bytes), byteLength: input.program.bytes.byteLength },
    payload: { id: safeId(input.payload.id, "payload.id"), digest: xnuArtifactDigest(input.payload.bytes), byteLength: input.payload.bytes.byteLength },
  };
  return { ...body, id: receiptId(body) };
}

/** Validates receipt shape and its content-derived identity without executing it. */
export function validateXnuFuzzReceipt(value: unknown): XnuFuzzReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("receipt must be an object");
  const raw = value as Record<string, unknown>;
  if (raw.schemaVersion !== XNU_RECEIPT_SCHEMA_VERSION) {
    throw new Error(`receipt.schemaVersion must be ${XNU_RECEIPT_SCHEMA_VERSION}`);
  }
  const body: Omit<XnuFuzzReceipt, "id"> = {
    schemaVersion: XNU_RECEIPT_SCHEMA_VERSION,
    target: targetReference(raw.target),
    program: reference(raw.program, "receipt.program"),
    payload: reference(raw.payload, "receipt.payload"),
  };
  if (safeId(raw.id, "receipt.id") !== receiptId(body)) {
    throw new Error("receipt.id does not match its canonical content digest");
  }
  return { ...body, id: receiptId(body) };
}

function verifyArtifact(reference: XnuArtifactReference, bytes: Uint8Array, label: string): void {
  if (bytes.byteLength !== reference.byteLength) throw new Error(`${label} byte length does not match receipt`);
  if (xnuArtifactDigest(bytes) !== reference.digest) throw new Error(`${label} digest does not match receipt`);
}

/**
 * In-memory replay/dedup gate. It deliberately has no runner or target handle:
 * accepted means "receipt is bound and new", never "program was executed".
 */
export class XnuReceiptReplayer {
  private readonly acceptedById = new Map<string, XnuFuzzReceipt>();
  private readonly acceptedByArtifacts = new Map<string, XnuFuzzReceipt>();

  replay(value: unknown, artifacts: XnuReceiptArtifacts): XnuReceiptReplayOutcome {
    try {
      const receipt = validateXnuFuzzReceipt(value);
      verifyArtifact(receipt.program, artifacts.program, "program");
      verifyArtifact(receipt.payload, artifacts.payload, "payload");
      decodeProgram(artifacts.program);

      const sameId = this.acceptedById.get(receipt.id);
      if (sameId) return { status: "duplicate", receipt, duplicateOf: sameId.id, reason: "receipt-id" };
      const artifactKey = `${receipt.program.digest}:${receipt.payload.digest}`;
      const sameArtifacts = this.acceptedByArtifacts.get(artifactKey);
      if (sameArtifacts) return { status: "duplicate", receipt, duplicateOf: sameArtifacts.id, reason: "program-payload" };

      this.acceptedById.set(receipt.id, receipt);
      this.acceptedByArtifacts.set(artifactKey, receipt);
      return { status: "accepted", receipt };
    } catch (error) {
      return { status: "rejected", reason: error instanceof Error ? error.message : String(error) };
    }
  }
}
