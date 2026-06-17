import { describe, it, expect } from "vitest";
import {
  DISCLOSURE_STATUSES,
  TERMINAL_STATUSES,
  PUBLIC_STATUSES,
  allowedNextStatuses,
  canTransition,
  createDisclosureRecord,
  transition,
  isPubliclyDisclosed,
  IllegalTransitionError,
  type DisclosureStatus,
} from "./tracking.js";

// Vocabulary parity guard: the engine status set must stay identical to the
// dashboard's findings_disclosure_status_check enum (migration 0045). If the
// dashboard changes, this assertion fails on purpose — update both in lockstep.
const DASHBOARD_DISCLOSURE_STATUS_ENUM = [
  "draft",
  "sent",
  "acknowledged",
  "accepted",
  "cve_assigned",
  "published",
  "rejected",
  "not_applicable",
  "duplicate",
  "withdrawn",
] as const;

describe("disclosure status vocabulary", () => {
  it("matches the dashboard disclosure_status enum verbatim", () => {
    expect([...DISCLOSURE_STATUSES]).toEqual([...DASHBOARD_DISCLOSURE_STATUS_ENUM]);
  });

  it("treats published + the off-ramps as terminal", () => {
    expect([...TERMINAL_STATUSES].sort()).toEqual(
      ["duplicate", "not_applicable", "published", "rejected", "withdrawn"].sort(),
    );
  });

  it("treats only published as publicly disclosed (cve_assigned stays embargoed)", () => {
    expect(PUBLIC_STATUSES.has("published")).toBe(true);
    expect(PUBLIC_STATUSES.has("cve_assigned")).toBe(false);
  });
});

describe("state machine — allowedNextStatuses / canTransition", () => {
  it("walks the full forward path draft → published", () => {
    expect(canTransition("draft", "sent")).toBe(true);
    expect(canTransition("sent", "acknowledged")).toBe(true);
    expect(canTransition("acknowledged", "accepted")).toBe(true);
    expect(canTransition("accepted", "cve_assigned")).toBe(true);
    expect(canTransition("cve_assigned", "published")).toBe(true);
  });

  it("allows accepted → published without a CVE (GHSA-only path)", () => {
    expect(canTransition("accepted", "published")).toBe(true);
  });

  it("forbids skipping draft → published", () => {
    expect(canTransition("draft", "published")).toBe(false);
    expect(canTransition("draft", "accepted")).toBe(false);
  });

  it("forbids going backwards", () => {
    expect(canTransition("sent", "draft")).toBe(false);
    expect(canTransition("published", "accepted")).toBe(false);
  });

  it("offers every off-ramp from a non-terminal status", () => {
    const next = allowedNextStatuses("sent");
    for (const off of ["rejected", "not_applicable", "duplicate", "withdrawn"] as DisclosureStatus[]) {
      expect(next).toContain(off);
    }
  });

  it("reaches nothing from any terminal status", () => {
    for (const s of TERMINAL_STATUSES) {
      expect(allowedNextStatuses(s)).toEqual([]);
    }
  });
});

describe("createDisclosureRecord", () => {
  it("opens in draft with a single initial timeline event and no real-world side effects", () => {
    const rec = createDisclosureRecord("finding-1", { at: "2026-06-17T00:00:00.000Z" });
    expect(rec.status).toBe("draft");
    expect(rec.findingId).toBe("finding-1");
    expect(rec.timeline).toHaveLength(1);
    expect(rec.timeline[0]).toMatchObject({ fromStatus: null, toStatus: "draft", actor: "operator" });
    // No vendor was contacted: these are unset until an operator records `sent`.
    expect(rec.disclosedTo).toBeUndefined();
    expect(rec.disclosedAt).toBeUndefined();
    expect(rec.cveId).toBeUndefined();
  });
});

describe("transition", () => {
  it("is pure — does not mutate the input record", () => {
    const rec = createDisclosureRecord("f", { at: "2026-06-17T00:00:00.000Z" });
    const next = transition(rec, { to: "sent", at: "2026-06-17T01:00:00.000Z" });
    expect(rec.status).toBe("draft");
    expect(rec.timeline).toHaveLength(1);
    expect(next.status).toBe("sent");
    expect(next.timeline).toHaveLength(2);
  });

  it("stamps disclosedTo/disclosedAt only on the draft→sent step", () => {
    const rec = createDisclosureRecord("f", { at: "2026-06-17T00:00:00.000Z" });
    const sent = transition(rec, {
      to: "sent",
      disclosedTo: "security@vendor.com",
      at: "2026-06-17T01:00:00.000Z",
    });
    expect(sent.disclosedTo).toBe("security@vendor.com");
    expect(sent.disclosedAt).toBe("2026-06-17T01:00:00.000Z");
  });

  it("stamps cveId on the *→cve_assigned step", () => {
    let rec = createDisclosureRecord("f", { at: "2026-06-17T00:00:00.000Z" });
    rec = transition(rec, { to: "sent", at: "2026-06-17T01:00:00.000Z" });
    rec = transition(rec, { to: "cve_assigned", cveId: "CVE-2026-12345", at: "2026-06-17T02:00:00.000Z" });
    expect(rec.status).toBe("cve_assigned");
    expect(rec.cveId).toBe("CVE-2026-12345");
  });

  it("throws IllegalTransitionError on an illegal edge and keeps the record intact", () => {
    const rec = createDisclosureRecord("f", { at: "2026-06-17T00:00:00.000Z" });
    expect(() => transition(rec, { to: "published" })).toThrow(IllegalTransitionError);
    // Record unchanged.
    expect(rec.status).toBe("draft");
    expect(rec.timeline).toHaveLength(1);
  });

  it("appends an immutable from→to event with actor + message", () => {
    let rec = createDisclosureRecord("f", { at: "2026-06-17T00:00:00.000Z" });
    rec = transition(rec, {
      to: "sent",
      actor: "doruk",
      message: "emailed maintainer",
      at: "2026-06-17T01:00:00.000Z",
    });
    const ev = rec.timeline[1];
    expect(ev).toMatchObject({
      fromStatus: "draft",
      toStatus: "sent",
      actor: "doruk",
      message: "emailed maintainer",
      at: "2026-06-17T01:00:00.000Z",
    });
  });
});

describe("isPubliclyDisclosed", () => {
  it("is false until published", () => {
    let rec = createDisclosureRecord("f", { at: "2026-06-17T00:00:00.000Z" });
    rec = transition(rec, { to: "sent", at: "2026-06-17T01:00:00.000Z" });
    rec = transition(rec, { to: "accepted", at: "2026-06-17T02:00:00.000Z" });
    expect(isPubliclyDisclosed(rec)).toBe(false);
    rec = transition(rec, { to: "published", at: "2026-06-17T03:00:00.000Z" });
    expect(isPubliclyDisclosed(rec)).toBe(true);
  });
});
