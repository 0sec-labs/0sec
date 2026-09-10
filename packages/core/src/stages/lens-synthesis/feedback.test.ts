import { readFileSync, rmSync, mkdirSync, writeFileSync, symlinkSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { describe, expect, it, beforeEach, afterEach } from "vitest";

import type { RegisteredLens, ValidationFixture } from "./types.js";
import {
  captureObservation,
  listObservations,
  approveObservation,
  rejectObservation,
  observationQueueSummary,
  claimForProcessing,
  markProcessed,
  releaseClaim,
  getObservation,
  observationDigest,
  parseObservationInput,
  parseApprovedObservationShape,
} from "./feedback.js";
import type { CaptureObservationInput } from "./feedback.js";

function tmpStore(): string {
  const dir = resolve(tmpdir(), `0sec-feedback-test-${randomBytes(4).toString("hex")}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return resolve(dir, "observations.json");
}

const POS_FIXTURE: ValidationFixture = {
  id: "pos-001", path: "", expectedCwe: "CWE-918", expectedFile: "pos-001.js", expectedLine: 5,
};
const HO_FIXTURE: ValidationFixture = {
  id: "ho-001", path: "", expectedCwe: "CWE-79", expectedFile: "ho-001.js", expectedLine: 12,
};
const NEG_FIXTURE: ValidationFixture = {
  id: "neg-001", path: "", cleanProvenance: "operator-reviewed fixed-origin fetch; no input influences destination",
};

const SAMPLE_OBSERVATION: CaptureObservationInput = {
  classHint: "CWE-918 SSRF",
  sinkPattern: "fetch(url)",
  exampleFileLine: "src/fetch.ts:42",
  whyMissed: "dynamic URL without host validation",
  source: "confirmed-miss",
  scanId: "scan-001",
  sourceRevisionDigest: "abc123def456",
  evidenceRefs: [],
  consent: true,
};

describe("feedback queue", () => {
  let storePath: string;

  beforeEach(() => {
    storePath = tmpStore();
    for (const fixture of [POS_FIXTURE, HO_FIXTURE, NEG_FIXTURE]) {
      fixture.path = resolve(storePath, "..", `${fixture.id}.js`);
      if (fixture.id === "pos-001") {
        writeFileSync(fixture.path, "const url = request.query.target;\nfetch(url);\n");
      } else if (fixture.id === "ho-001") {
        writeFileSync(fixture.path, "const name = params.get('user');\ndocument.body.innerHTML = name;\n");
      } else {
        writeFileSync(fixture.path, "fetch('https://example.com/fixed');\n");
      }
    }
  });

  afterEach(() => {
    try { rmSync(resolve(storePath, ".."), { recursive: true, force: true }); } catch { /* cleanup */ }
  });

  it("captures an observation with content-addressed id including provenance", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });

    const expectedId = observationDigest(
      SAMPLE_OBSERVATION.classHint,
      SAMPLE_OBSERVATION.sinkPattern,
      SAMPLE_OBSERVATION.exampleFileLine,
      SAMPLE_OBSERVATION.whyMissed,
      SAMPLE_OBSERVATION.sourceRevisionDigest,
      SAMPLE_OBSERVATION.scanId,
      SAMPLE_OBSERVATION.source,
      [],
    );

    expect(entry.id).toBe(expectedId);
    expect(entry.status).toBe("pending");
    expect(entry.consent).toBe(true);
  });

  it("does NOT deduplicate across different source revisions", () => {
    captureObservation(SAMPLE_OBSERVATION, { storePath });
    const v2 = captureObservation(
      { ...SAMPLE_OBSERVATION, sourceRevisionDigest: "v2digest" },
      { storePath },
    );
    expect(listObservations({}, { storePath })).toHaveLength(2);
    expect(v2.sourceRevisionDigest).toBe("v2digest");
  });

  it("deduplicates identical content+provenance", () => {
    captureObservation(SAMPLE_OBSERVATION, { storePath });
    captureObservation(SAMPLE_OBSERVATION, { storePath });
    expect(listObservations({}, { storePath })).toHaveLength(1);
  });

  it("lists observations filtered by status", () => {
    captureObservation(SAMPLE_OBSERVATION, { storePath });
    captureObservation(
      { ...SAMPLE_OBSERVATION, classHint: "CWE-79 XSS", sinkPattern: "innerHTML", exampleFileLine: "src/xss.ts:10" },
      { storePath },
    );
    expect(listObservations({ status: "pending" }, { storePath })).toHaveLength(2);
    expect(listObservations({ status: "approved" }, { storePath })).toHaveLength(0);
  });

  it("approves with required nonempty fixture arrays, persisted consent, and valid fixtures", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });

    const approved = approveObservation(entry.id, {
      positives: [POS_FIXTURE],
      heldOut: [HO_FIXTURE],
      negativeControls: [NEG_FIXTURE],
    }, { storePath });

    expect(approved.status).toBe("approved");
    expect(approved.consent).toBe(true);
    expect(approved.approvedShape?.positives).toHaveLength(1);
    expect(approved.approvedShape?.heldOut).toHaveLength(1);
    expect(approved.approvedShape?.negativeControls).toHaveLength(1);
  });

  it("throws on approve with empty fixture arrays", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    expect(() => approveObservation(entry.id, {
      positives: [],
      heldOut: [HO_FIXTURE],
      negativeControls: [NEG_FIXTURE],
    }, { storePath })).toThrow("no positive fixtures");
  });

  it("throws on approve without consent", () => {
    const entry = captureObservation(
      { ...SAMPLE_OBSERVATION, consent: false },
      { storePath },
    );
    expect(() => approveObservation(entry.id, {
      positives: [POS_FIXTURE],
      heldOut: [HO_FIXTURE],
      negativeControls: [NEG_FIXTURE],
    }, { storePath })).toThrow("consent");
  });

  it("allows approval without capture consent when allowModelSourceAccess is set, and persists consent", () => {
    const entry = captureObservation(
      { ...SAMPLE_OBSERVATION, consent: false },
      { storePath },
    );
    const approved = approveObservation(entry.id, {
      positives: [POS_FIXTURE],
      heldOut: [HO_FIXTURE],
      negativeControls: [NEG_FIXTURE],
    }, { storePath, allowModelSourceAccess: true });
    expect(approved.status).toBe("approved");
    expect(approved.consent).toBe(true); // persisted grant
  });

  it("rejects a pending observation with reason", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    const rejected = rejectObservation(entry.id, "duplicate — already covered by lens ssrf-url-detect", { storePath });
    expect(rejected.status).toBe("rejected");
    expect(rejected.rejectedReason).toBe("duplicate — already covered by lens ssrf-url-detect");
  });

  it("claims approved observations with exclusive token", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE],
      heldOut: [HO_FIXTURE],
      negativeControls: [NEG_FIXTURE],
    }, { storePath });

    const claimed = claimForProcessing({ storePath });
    expect(claimed).toHaveLength(1);
    expect(claimed[0]!.claimToken).toBeTruthy();
    expect(claimed[0]!.id).toBe(entry.id);

    // Second claim returns nothing (already claimed)
    expect(claimForProcessing({ storePath })).toHaveLength(0);
  });

  it("marks processed with token and outcome", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE],
      heldOut: [HO_FIXTURE],
      negativeControls: [NEG_FIXTURE],
    }, { storePath });

    const [claimed] = claimForProcessing({ storePath });
    const ok = markProcessed(entry.id, { registeredLensIds: ["appsec/ssrf-fetch-test"], validatedAt: "2026-09-09T00:00:00Z" }, claimed!.claimToken, { storePath });
    expect(ok).toBe(true);

    const processed = getObservation(entry.id, { storePath })!;
    expect(processed.status).toBe("processed");
    expect(processed.processedOutcome?.registeredLensIds).toEqual(["appsec/ssrf-fetch-test"]);
    expect(processed.claimToken).toBeUndefined();
  });

  it("releases claim and allows re-claim", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE],
      heldOut: [HO_FIXTURE],
      negativeControls: [NEG_FIXTURE],
    }, { storePath });

    const [claimed] = claimForProcessing({ storePath });
    const released = releaseClaim(entry.id, claimed!.claimToken, { storePath });
    expect(released).toBe(true);

    // Re-claim succeeds
    const reClaimed = claimForProcessing({ storePath });
    expect(reClaimed).toHaveLength(1);
  });

  it("reports queue summary", () => {
    const a = captureObservation(SAMPLE_OBSERVATION, { storePath });
    captureObservation(
      { ...SAMPLE_OBSERVATION, classHint: "CWE-79 XSS", exampleFileLine: "src/xss.ts:10" },
      { storePath },
    );
    const c = captureObservation(
      { ...SAMPLE_OBSERVATION, classHint: "CWE-22 Path Traversal", exampleFileLine: "src/path.ts:5" },
      { storePath },
    );

    approveObservation(a.id, { positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE] }, { storePath });
    rejectObservation(c.id, "not actionable", { storePath });

    const summary = observationQueueSummary({ storePath });
    expect(summary.total).toBe(3);
    expect(summary.pending).toBe(1);
    expect(summary.approved).toBe(1);
    expect(summary.rejected).toBe(1);
    expect(summary.processed).toBe(0);
  });

  it("persists observations across load cycles", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath });

    const raw = JSON.parse(readFileSync(storePath, "utf8")) as Array<{ id: string; status: string }>;
    expect(raw).toHaveLength(1);
    expect(raw[0]!.status).toBe("approved");
  });

  it("handles empty store gracefully", () => {
    expect(listObservations({}, { storePath })).toHaveLength(0);
    expect(observationQueueSummary({ storePath })).toMatchObject({
      total: 0, pending: 0, approved: 0, processed: 0, rejected: 0,
    });
    expect(claimForProcessing({ storePath })).toHaveLength(0);
  });

  it("does not claim already-processed observations", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath });
    const [claimed] = claimForProcessing({ storePath });
    markProcessed(entry.id, { registeredLensIds: ["lens-a"], validatedAt: "now" }, claimed!.claimToken, { storePath });
    expect(claimForProcessing({ storePath })).toHaveLength(0);
  });

  it("captures incomplete-coverage observations", () => {
    const entry = captureObservation({
      ...SAMPLE_OBSERVATION,
      sinkPattern: "",
      source: "incomplete-coverage",
      whyMissed: "finder timed out at 120000ms budget",
      consent: false,
    }, { storePath });
    expect(entry.source).toBe("incomplete-coverage");
    expect(entry.consent).toBe(false);

    const filtered = listObservations({ source: "incomplete-coverage" }, { storePath });
    expect(filtered).toHaveLength(1);
  });

  it("parseObservationInput validates required fields", () => {
    const input = parseObservationInput({
      classHint: "CWE-918",
      sinkPattern: "fetch",
      exampleFileLine: "a.ts:1",
      whyMissed: "no validation",
      source: "confirmed-miss",
      scanId: "s1",
      sourceRevisionDigest: "d1",
    });
    expect(input.classHint).toBe("CWE-918");
    expect(() => parseObservationInput({})).toThrow("required");
  });

  it("rejects a curation shape without development positives", () => {
    expect(() => parseApprovedObservationShape({
      positives: [], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    })).toThrow();
  });

  it("throws on approve for non-pending status", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    rejectObservation(entry.id, "not needed", { storePath });
    expect(() => approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath })).toThrow("status is \"rejected\"");
  });

  it("markProcessed requires matching claimToken", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath });
    claimForProcessing({ storePath });

    const ok = markProcessed(entry.id, { registeredLensIds: ["lens"], validatedAt: "now" }, "wrong-token", { storePath });
    expect(ok).toBe(false);
    expect(getObservation(entry.id, { storePath })!.status).toBe("approved");
  });

  it("releaseClaim returns false for wrong token", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath });
    claimForProcessing({ storePath });
    expect(releaseClaim(entry.id, "bad-token", { storePath })).toBe(false);
  });

  it("rejects a missing fixture without approving the observation", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    rmSync(HO_FIXTURE.path);
    expect(() => approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath })).toThrow();
    expect(getObservation(entry.id, { storePath })?.status).toBe("pending");
  });

  it("stamps contentDigest on approved fixtures via prepareValidationCorpus", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    const approved = approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath });
    expect(approved.approvedShape?.positives[0]?.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(approved.approvedShape?.heldOut[0]?.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(approved.approvedShape?.negativeControls[0]?.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    // Paths are canonical absolute after preparation
    expect(approved.approvedShape?.positives[0]?.path).toBe(resolve(POS_FIXTURE.path));
  });

  it("rejects approval when two fixtures share identical content bytes", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    // Write a second positive fixture that is a byte-for-byte copy of the first
    const clonePath = resolve(storePath, "..", "pos-dup.js");
    writeFileSync(clonePath, readFileSync(POS_FIXTURE.path));
    const dupFixture: ValidationFixture = {
      id: "pos-dup", path: clonePath, expectedCwe: "CWE-22", expectedFile: "pos-dup.js", expectedLine: 1,
    };
    expect(() => approveObservation(entry.id, {
      positives: [POS_FIXTURE, dupFixture], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath })).toThrow("duplicate fixture content");
  });

  it("rejects a symlinked queue instead of reading another store", () => {
    captureObservation(SAMPLE_OBSERVATION, { storePath });
    const alias = resolve(storePath, "..", "alias.json");
    symlinkSync(storePath, alias);
    expect(() => listObservations(undefined, { storePath: alias })).toThrow();
  });

  it("captures observation with detector lens provenance and different version produces distinct id", () => {
    const a = captureObservation({
      ...SAMPLE_OBSERVATION, detectorLensId: "ssrf-fetch", detectorLensVersionDigest: "sha256:abc",
    }, { storePath });
    expect(a.detectorLensId).toBe("ssrf-fetch");
    expect(a.detectorLensVersionDigest).toBe("sha256:abc");

    const b = captureObservation({
      ...SAMPLE_OBSERVATION, detectorLensId: "ssrf-fetch", detectorLensVersionDigest: "sha256:xyz",
    }, { storePath });
    expect(b.id).not.toBe(a.id);
  });

  it("markProcessed retains full registered lenses, warnings, and rejected", () => {
    const entry = captureObservation(SAMPLE_OBSERVATION, { storePath });
    approveObservation(entry.id, {
      positives: [POS_FIXTURE], heldOut: [HO_FIXTURE], negativeControls: [NEG_FIXTURE],
    }, { storePath });

    const [claimed] = claimForProcessing({ storePath });
    const registeredLens: RegisteredLens = {
      id: "ssrf-fetch", uid: "ssrf-fetch-v1", validatedAt: "now",
      missRefs: [], lensVersionDigest: "sha256:digest123",
    };

    const ok = markProcessed(entry.id, {
      registeredLensIds: [registeredLens.id],
      registeredLenses: [registeredLens],
      validatedAt: new Date().toISOString(),
      warnings: ["synthesis partial: timeout on archetype B"],
      rejected: [{ id: "candidate-b", reason: "validator rejected no lift" }],
    }, claimed!.claimToken, { storePath });
    expect(ok).toBe(true);

    const processed = getObservation(entry.id, { storePath })!;
    expect(processed.processedOutcome?.registeredLenses).toHaveLength(1);
    expect(processed.processedOutcome?.registeredLenses![0]!.lensVersionDigest).toBe("sha256:digest123");
    expect(processed.processedOutcome?.warnings).toContain("synthesis partial: timeout on archetype B");
    expect(processed.processedOutcome?.rejected).toHaveLength(1);
    expect(processed.processedOutcome?.rejected![0]!.reason).toBe("validator rejected no lift");
  });
});