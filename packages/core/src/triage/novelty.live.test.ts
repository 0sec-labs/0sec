/**
 * LIVE OSV smoke test for the public-advisory novelty gate (issue #851).
 *
 * Unlike publishability-sources.test.ts (fully stubbed/offline), this test
 * REALLY queries the public OSV API (https://api.osv.dev/v1/query) for a
 * known-vulnerable package+version and asserts the structured verdict comes
 * back as `matches-…`. It proves the gate works end-to-end against the real
 * advisory DB, not just against a stubbed response shape.
 *
 * GATED on an env flag so CI / offline `vitest run` never makes a network call:
 *   PWNKIT_LIVE_INTEL_TEST=1 pnpm --filter @pwnkit/core exec \
 *     vitest run src/triage/novelty.live.test.ts
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveNovelty } from "./publishability-sources.js";

const LIVE = !!process.env.PWNKIT_LIVE_INTEL_TEST;

describe("resolveNovelty — LIVE OSV smoke (#851)", () => {
  let cacheDir: string;
  beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-novelty-live-"));
  });
  afterEach(() => {
    rmSync(cacheDir, { recursive: true, force: true });
  });

  it.skipIf(!LIVE)(
    "matches a real published advisory for a known-vulnerable npm version",
    async () => {
      // lodash 4.17.4 is covered by well-known advisories (prototype pollution
      // GHSA-jf85-cpcp-j695 / CVE-2019-10744, command injection
      // GHSA-35jh-r3h4-6jhm / CVE-2021-23337, etc.) — a stable live fixture.
      const result = await resolveNovelty("lodash", "npm", "4.17.4", { cacheDir });
      // eslint-disable-next-line no-console
      console.log("[live-osv] lodash@4.17.4 →", JSON.stringify(result, null, 2));
      expect(result).toBeDefined();
      expect(result?.verdict).toMatch(/^matches-(CVE|GHSA)-/);
      expect(result?.advisoryMatches.length).toBeGreaterThan(0);
      expect(result?.advisoryMatches[0]?.id).toMatch(/^(CVE|GHSA)-/);
    },
    30_000,
  );

  it.skipIf(!LIVE)(
    "a `latest`-pinned known-vulnerable package → possibly-known (+advisories), not a false matches-/novel",
    async () => {
      // #851 fast-follow: `latest` is not OSV-range-matchable, so resolveNovelty
      // drops to a PACKAGE-LEVEL query. lodash has a deep advisory history, so a
      // package-level lookup MUST return advisories → possibly-known (flag for
      // review), never a false `novel` and never an unprovable matches-CVE-….
      const result = await resolveNovelty("lodash", "npm", "latest", { cacheDir });
      // eslint-disable-next-line no-console
      console.log("[live-osv] lodash@latest →", JSON.stringify(result, null, 2));
      expect(result).toBeDefined();
      expect(result?.verdict).toBe("possibly-known");
      expect(result?.advisoryMatches.length).toBeGreaterThan(0);
    },
    30_000,
  );

  it.skipIf(!LIVE)(
    "a known-vulnerable package with NO version → possibly-known (+advisories)",
    async () => {
      const result = await resolveNovelty("lodash", "npm", undefined, { cacheDir });
      // eslint-disable-next-line no-console
      console.log("[live-osv] lodash@<none> →", JSON.stringify(result, null, 2));
      expect(result?.verdict).toBe("possibly-known");
      expect(result?.advisoryMatches.length).toBeGreaterThan(0);
    },
    30_000,
  );

  it.skipIf(!LIVE)(
    "a clean package with no advisories → novel (genuinely no known issues)",
    async () => {
      const result = await resolveNovelty(
        "pwnkit-nonexistent-package-zzz-851",
        "npm",
        "latest",
        { cacheDir },
      );
      // eslint-disable-next-line no-console
      console.log("[live-osv] clean@latest →", JSON.stringify(result, null, 2));
      // Package-level query, zero advisories → novel (the genuine-no-issues case).
      expect(result?.verdict).toBe("novel");
      expect(result?.advisoryMatches).toEqual([]);
    },
    30_000,
  );

  it.skipIf(!LIVE)(
    "returns a verdict (novel | possibly-known) for a clean nonexistent package without throwing",
    async () => {
      const result = await resolveNovelty(
        "pwnkit-nonexistent-package-zzz-851",
        "npm",
        "1.0.0",
        { cacheDir },
      );
      // eslint-disable-next-line no-console
      console.log("[live-osv] nonexistent →", JSON.stringify(result, null, 2));
      expect(result).toBeDefined();
      expect(["novel", "possibly-known"]).toContain(result?.verdict);
    },
    30_000,
  );
});
