import { describe, expect, it } from "vitest";
import { encodeProgram } from "./program.js";
import {
  createXnuFuzzReceipt,
  xnuArtifactDigest,
  XnuReceiptReplayer,
} from "./receipt.js";

const program = encodeProgram([
  { selector: 4, scalarInput: [7n], structureInput: new Uint8Array([1, 2]), scalarOutCnt: 0, structOutSize: 0 },
]);
const payload = new Uint8Array([0xca, 0xfe]);
const target = { id: "model:iosurface-26", digest: xnuArtifactDigest(new TextEncoder().encode("target-model")) };

function receipt(programId = "program:one", payloadId = "payload:one") {
  return createXnuFuzzReceipt({
    target,
    program: { id: programId, bytes: program },
    payload: { id: payloadId, bytes: payload },
  });
}

describe("XNU receipt replay contract", () => {
  it("accepts an exact program/payload binding once, then deduplicates it", () => {
    const replayer = new XnuReceiptReplayer();
    const first = receipt();
    expect(replayer.replay(first, { program, payload })).toMatchObject({ status: "accepted", receipt: first });
    expect(replayer.replay(first, { program, payload })).toMatchObject({
      status: "duplicate",
      duplicateOf: first.id,
      reason: "receipt-id",
    });

    const sameArtifactsNewReferences = receipt("program:two", "payload:two");
    expect(replayer.replay(sameArtifactsNewReferences, { program, payload })).toMatchObject({
      status: "duplicate",
      duplicateOf: first.id,
      reason: "program-payload",
    });
  });

  it("rejects altered payloads and receipt identities without recording them", () => {
    const replayer = new XnuReceiptReplayer();
    const first = receipt();
    const changedPayload = new Uint8Array([0xca, 0xff]);
    expect(replayer.replay(first, { program, payload: changedPayload })).toMatchObject({
      status: "rejected",
      reason: expect.stringMatching(/payload digest/),
    });
    expect(replayer.replay({ ...first, id: "xnu-receipt:invalid" }, { program, payload })).toMatchObject({
      status: "rejected",
      reason: expect.stringMatching(/canonical content digest/),
    });
    expect(replayer.replay(first, { program, payload })).toMatchObject({ status: "accepted" });
  });

  it("rejects a receipt whose bound program is not a complete wire-format program", () => {
    const malformedProgram = new Uint8Array([0x50, 0x4b, 0x58, 0x46]);
    const malformedReceipt = createXnuFuzzReceipt({
      target,
      program: { id: "program:malformed", bytes: malformedProgram },
      payload: { id: "payload:malformed", bytes: payload },
    });
    expect(new XnuReceiptReplayer().replay(malformedReceipt, { program: malformedProgram, payload })).toMatchObject({
      status: "rejected",
      reason: expect.stringMatching(/truncated program/),
    });
  });
});
