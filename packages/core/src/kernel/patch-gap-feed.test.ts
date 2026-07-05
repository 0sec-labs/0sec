import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { loadVulnsFeedFromDir, parseVulnsCveRecord, type RawVulnsCveRecord } from "./patch-gap-feed.js";

/** A minimal, schema-real published CVE record (trimmed from the real
 * CVE-2026-53356.json fetched off bench's /root/kernel-vulns clone). */
function makeRecord(overrides: Partial<RawVulnsCveRecord> = {}): RawVulnsCveRecord {
  return {
    cveMetadata: { cveId: "CVE-2026-53356", state: "PUBLISHED" },
    containers: {
      cna: {
        title: "drm/i915/gem: Fix phys BO pread/pwrite with offset",
        descriptions: [
          {
            lang: "en",
            value:
              "In the Linux kernel, the following vulnerability has been resolved:\n\n" +
              "drm/i915/gem: fix it\n\n" +
              "(cherry picked from commit 3e49a2f85070b2fb672c1e0fdba281a4ea3aebe6)",
          },
        ],
        affected: [
          {
            product: "Linux",
            programFiles: ["drivers/gpu/drm/i915/gem/i915_gem_phys.c"],
            versions: [
              {
                version: "abc",
                lessThan: "40f738991058eb3e3530c3006a5bd6fd5e29f035",
                status: "affected",
                versionType: "git",
              },
              {
                version: "abc",
                lessThan: "1ec8fc63e9cdb22da54e48e536c9204020416fc6",
                status: "affected",
                versionType: "git",
              },
            ],
          },
        ],
        references: [{ url: "https://git.kernel.org/stable/c/40f738991058eb3e3530c3006a5bd6fd5e29f035" }],
      },
    },
    ...overrides,
  };
}

describe("kernel/patch-gap-feed: parseVulnsCveRecord (pure)", () => {
  it("parses a real-shaped published CVE record", () => {
    const entry = parseVulnsCveRecord(makeRecord());
    expect(entry).not.toBeNull();
    expect(entry?.cve).toBe("CVE-2026-53356");
    expect(entry?.title).toContain("phys BO");
    expect(entry?.files).toEqual(["drivers/gpu/drm/i915/gem/i915_gem_phys.c"]);
    expect(entry?.mainlineSha).toBe("3e49a2f85070b2fb672c1e0fdba281a4ea3aebe6");
    // versions[] SHA + references[] SHA merged and deduped.
    expect(entry?.candidateShas).toContain("40f738991058eb3e3530c3006a5bd6fd5e29f035");
    expect(entry?.candidateShas).toContain("1ec8fc63e9cdb22da54e48e536c9204020416fc6");
    expect(entry?.candidateShas).toHaveLength(2); // dedupe collapsed the shared ref (versions[] + references[] overlap)
  });

  it("rejects a non-PUBLISHED record (e.g. REJECTED / RESERVED)", () => {
    const rec = makeRecord({ cveMetadata: { cveId: "CVE-2026-00000", state: "REJECTED" } });
    expect(parseVulnsCveRecord(rec)).toBeNull();
  });

  it("rejects a record with no CVE id", () => {
    const rec = makeRecord({ cveMetadata: { state: "PUBLISHED" } });
    expect(parseVulnsCveRecord(rec)).toBeNull();
  });

  it("rejects a record with no checkable SHA anywhere (not actionable)", () => {
    const rec = makeRecord();
    rec.containers!.cna!.descriptions = [{ lang: "en", value: "no cherry-pick note here" }];
    rec.containers!.cna!.affected = [{ programFiles: ["fs/foo.c"], versions: [] }];
    rec.containers!.cna!.references = [];
    expect(parseVulnsCveRecord(rec)).toBeNull();
  });

  it("tolerates garbage input without throwing", () => {
    expect(parseVulnsCveRecord(null)).toBeNull();
    expect(parseVulnsCveRecord(undefined)).toBeNull();
    expect(parseVulnsCveRecord("not an object")).toBeNull();
    expect(parseVulnsCveRecord({})).toBeNull();
  });
});

describe("kernel/patch-gap-feed: loadVulnsFeedFromDir (thin IO, real tmp fs — no network)", () => {
  let repo: string;

  afterAll(() => {
    if (repo) rmSync(repo, { recursive: true, force: true });
  });

  it("reads published/<year>/*.json, skips malformed files, sorts newest-first", () => {
    repo = mkdtempSync(join(tmpdir(), "pwnkit-vulnsfeed-"));
    const published = join(repo, "cve", "published");
    mkdirSync(join(published, "2025"), { recursive: true });
    mkdirSync(join(published, "2026"), { recursive: true });

    writeFileSync(
      join(published, "2025", "CVE-2025-00001.json"),
      JSON.stringify(makeRecord({ cveMetadata: { cveId: "CVE-2025-00001", state: "PUBLISHED" } })),
    );
    writeFileSync(
      join(published, "2026", "CVE-2026-53356.json"),
      JSON.stringify(makeRecord()),
    );
    // Malformed JSON — must not abort the whole load.
    writeFileSync(join(published, "2026", "CVE-2026-99999.json"), "{ not valid json");
    // Well-formed JSON but not actionable (no SHA) — parses to null, dropped.
    const notActionable = makeRecord({ cveMetadata: { cveId: "CVE-2026-00002", state: "PUBLISHED" } });
    notActionable.containers!.cna!.descriptions = [{ lang: "en", value: "prose only" }];
    notActionable.containers!.cna!.affected = [];
    notActionable.containers!.cna!.references = [];
    writeFileSync(join(published, "2026", "CVE-2026-00002.json"), JSON.stringify(notActionable));

    const entries = loadVulnsFeedFromDir({ vulnsRepoPath: repo });
    expect(entries.map((e) => e.cve)).toEqual(["CVE-2026-53356", "CVE-2025-00001"]);
  });

  it("filters by sinceYear and respects limit", () => {
    const entries = loadVulnsFeedFromDir({ vulnsRepoPath: repo, sinceYear: 2026 });
    expect(entries.map((e) => e.cve)).toEqual(["CVE-2026-53356"]);

    const limited = loadVulnsFeedFromDir({ vulnsRepoPath: repo, limit: 1 });
    expect(limited).toHaveLength(1);
  });

  it("returns [] for a missing directory rather than throwing", () => {
    expect(loadVulnsFeedFromDir({ vulnsRepoPath: join(tmpdir(), "pwnkit-does-not-exist-xyz") })).toEqual([]);
  });
});
