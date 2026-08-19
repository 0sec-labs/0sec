// End-to-end CodeWall-chain self-test against a LOCAL vulnerable fixture.
//
// Goal (0sec#923 family): prove the newly-added tools actually find planted
// vulns when CHAINED, exercising the DETERMINISTIC core of each tool directly
// (no LLM loop) so the test is offline-capable and reproducible:
//
//   recon/asset-map  →  js_recon (endpoints + secrets)
//                    →  auth_boundary_probe (unauth endpoint)
//                    →  structural_sqli (JSON-key injection)
//                    →  cloud probe (S3 bucket, mocked fetch)
//
// SAFETY: the fixture binds to 127.0.0.1 ONLY (asserted below). The cloud
// stage uses a mocked fetch — it never touches real AWS. No external host is
// ever contacted.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ScopePolicy } from "../../scope/scope.js";
import { runJsRecon } from "../../recon/js-recon.js";
import type { FetchTextResult } from "../../recon/js-artifacts.js";
import { runAuthBoundaryProbe } from "../../agent/auth-boundary-prober.js";
import {
  runStructuralSqliProbeAsync,
  type ProbeObservation,
  type KeyPayload,
} from "../../agent/structural-sqli.js";
import {
  probeS3Bucket,
  classifyTakeover,
  bucketInScope,
  type CloudFetchLike,
} from "../../agent/cloud-surface.js";
import {
  startVulnerableFixture,
  type FixtureHandle,
  FAKE_AWS_KEY_ID,
  REFERENCED_S3_BUCKET,
} from "./vulnerable-fixture.js";
import { renderEvidencePack, type EvidencePackInput } from "./evidence-pack.js";

let fixture: FixtureHandle;
/** Authorized scope: the local fixture host only. */
let scope: ScopePolicy;

beforeAll(async () => {
  fixture = await startVulnerableFixture();
  // in_scope = the fixture host (127.0.0.1) + the referenced S3 endpoint so the
  // cloud stage's deny-by-default gate can be satisfied by an operator decision.
  scope = ScopePolicy.fromJson({
    in_scope: ["127.0.0.1", `${REFERENCED_S3_BUCKET}.s3.amazonaws.com`],
  });
});

afterAll(async () => {
  await fixture?.close();
});

/** A node-fetch wrapper used by the js-recon stage (returns {status, body}). */
function makeJsFetchText() {
  return async (url: string): Promise<FetchTextResult> => {
    const res = await fetch(url);
    return { status: res.status, body: await res.text() };
  };
}

describe("CodeWall chain — local fixture self-test", () => {
  it("binds the fixture to 127.0.0.1 only (safety rail)", () => {
    expect(fixture.origin.startsWith("http://127.0.0.1:")).toBe(true);
    // The server's bound address must literally be the loopback IP.
    const addr = fixture.server.address();
    expect(addr && typeof addr === "object" ? addr.address : "").toBe("127.0.0.1");
  });

  it("runs the full chain and finds every planted vuln", async () => {
    // ── Stage 1: recon / asset-map ──
    // The entrypoint a `crawl` would surface: the index page references one JS
    // bundle. (We pin the script URL directly to keep the test deterministic —
    // the crawler itself is covered by its own tests.)
    const scriptUrls = [`${fixture.origin}/static/app.js`];

    // ── Stage 2: js_recon — endpoint + secret discovery from public JS ──
    const recon = await runJsRecon({
      scriptUrls,
      scope,
      fetchText: makeJsFetchText(),
    });

    // It fetched the in-scope bundle (scope gate passed).
    expect(recon.scanned).toEqual(scriptUrls);

    // Planted endpoints were pulled out of the bundle.
    const endpointValues = recon.endpoints.map((e) => e.value);
    expect(endpointValues).toContain("GET /api/public/users");
    expect(endpointValues).toContain("POST /api/reports");
    expect(endpointValues).toContain("GET /api/admin/config");

    // Planted hardcoded AWS key was discovered AND redacted (raw never carried).
    const awsHit = recon.secrets.find((s) => s.kind === "aws_access_key_id");
    expect(awsHit, "js_recon should find the planted AKIA key").toBeTruthy();
    expect(awsHit!.confidence).toBe("high");
    expect(awsHit!.match).not.toContain(FAKE_AWS_KEY_ID); // redacted
    expect(awsHit!.match).toContain("AKIA"); // recognizable prefix only

    // The S3 base URL the bundle references became a known API base.
    expect(
      recon.apiBaseUrls.some((b) => b.includes(`${REFERENCED_S3_BUCKET}.s3.amazonaws.com`)),
    ).toBe(true);

    // ── Stage 3: auth_boundary_probe — feed the discovered endpoints in ──
    // The endpoints from stage 2 become the probe list (stage feeds stage).
    const probeEndpoints = recon.endpoints.map((e) => ({
      url: `${fixture.origin}${e.metadata?.path ?? ""}`,
      method: e.metadata?.method ?? "GET",
    }));
    const authReport = await runAuthBoundaryProbe({
      endpoints: probeEndpoints,
      // Supply a bogus-but-present credential so the authed leg runs against
      // the admin endpoint (which gates on ANY Authorization header).
      auth: { type: "bearer", token: "fixture-operator-token" },
    });

    const usersVerdict = authReport.results.find((r) => r.url.endsWith("/api/public/users"));
    const adminVerdict = authReport.results.find((r) => r.url.endsWith("/api/admin/config"));

    // The planted unauth leak is flagged reachable without credentials.
    expect(usersVerdict, "users endpoint should be probed").toBeTruthy();
    expect(usersVerdict!.unauthReachable).toBe(true);
    expect(usersVerdict!.verdict).toBe("unauth-reachable");

    // The admin endpoint's boundary correctly HOLDS (negative control).
    expect(adminVerdict, "admin endpoint should be probed").toBeTruthy();
    expect(adminVerdict!.unauthReachable).toBe(false);
    expect(adminVerdict!.verdict).toBe("auth-required");

    expect(authReport.unauthReachableCount).toBeGreaterThanOrEqual(1);

    // ── Stage 4: structural_sqli — drive the blind refinement loop over HTTP ──
    // Target the /api/reports endpoint discovered in stage 2. The probe sends a
    // JSON body keyed by the injected payload; the fixture concatenates that
    // KEY into ORDER BY, so a broken key errors and a balanced one parses.
    const reportsUrl = `${fixture.origin}/api/reports`;
    const sendKey = async (payload: KeyPayload): Promise<ProbeObservation> => {
      const res = await fetch(reportsUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        // The injectable surface is the JSON KEY name.
        body: JSON.stringify({ [payload.key]: 1 }),
      });
      return { payloadKey: payload.key, responseText: await res.text(), status: res.status };
    };
    const sqli = await runStructuralSqliProbeAsync({ baseKey: "sort", maxIterations: 6 }, sendKey);

    expect(sqli.verdict, "structural SQLi should be confirmed").toBe("confirmed");
    expect(sqli.dialect).toBe("sqlite");

    // ── Stage 5: cloud probe — the bucket js_recon found, with MOCKED fetch ──
    // Deny-by-default scope gate must pass for the (operator-authorized) bucket.
    const inScope = bucketInScope(REFERENCED_S3_BUCKET, scope);
    expect(inScope.allowed, "operator authorized the bucket in scope").toBe(true);

    // Mock S3: GET / → 200 public ListBucketResult, GET /?acl → 200 ACL doc.
    const mockS3Fetch: CloudFetchLike = async (url) => {
      if (url.includes("?acl")) {
        return {
          ok: true,
          status: 200,
          headers: { "content-type": "application/xml" },
          text: async () =>
            `<?xml version="1.0"?><AccessControlPolicy><Owner/></AccessControlPolicy>`,
        };
      }
      return {
        ok: true,
        status: 200,
        headers: { "content-type": "application/xml" },
        text: async () =>
          `<?xml version="1.0"?><ListBucketResult><Name>${REFERENCED_S3_BUCKET}</Name>` +
          `<Contents><Key>exports/2026-q2-customers.csv</Key></Contents>` +
          `<Contents><Key>exports/2026-q2-revenue.csv</Key></Contents></ListBucketResult>`,
      };
    };
    const bucketProbe = await probeS3Bucket(REFERENCED_S3_BUCKET, { fetchImpl: mockS3Fetch });
    expect(bucketProbe.verdict, "mocked bucket is public").toBe("public");
    expect(bucketProbe.severity).toBe("high");
    expect(bucketProbe.aclReadable).toBe(true);
    expect(bucketProbe.sampleKeys).toContain("exports/2026-q2-customers.csv");
    const takeover = classifyTakeover(bucketProbe);
    expect(takeover.takeoverable).toBe(false); // exists → not takeoverable

    // ── Evidence pack — chained output artifact (redacted) ──
    const pack: EvidencePackInput = {
      target: fixture.origin,
      generatedAt: "2026-06-17T00:00:00Z",
      discoveredEndpoints: recon.endpoints,
      secrets: recon.secrets,
      authBoundary: authReport.results,
      sqli,
      cloud: { probe: bucketProbe, takeover },
    };
    const md = renderEvidencePack(pack);

    // The artifact reflects every stage and never carries the raw secret.
    expect(md).toContain("Stage 2 — JS recon");
    expect(md).toContain("Stage 3 — Auth-boundary probe");
    expect(md).toContain("Stage 4 — Structural SQLi probe");
    expect(md).toContain("Stage 5 — Cloud surface probe");
    expect(md).toContain("structural SQLi confirmed");
    expect(md).not.toContain(FAKE_AWS_KEY_ID);

    // Persist a sample evidence pack alongside the test for inspection.
    const { writeFileSync, mkdirSync } = await import("node:fs");
    const { dirname, join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const here = dirname(fileURLToPath(import.meta.url));
    const outDir = join(here, "artifacts");
    mkdirSync(outDir, { recursive: true });
    // Origin port is ephemeral; normalize it so the committed sample is stable.
    const stable = md.replace(
      new RegExp(fixture.origin.replace(/[.]/g, "\\."), "g"),
      "http://127.0.0.1:PORT",
    );
    writeFileSync(join(outDir, "sample-evidence-pack.md"), stable + "\n", "utf-8");
  });

  it("js_recon stays deny-by-default (no scope → no fetch, even against localhost)", async () => {
    let touched = false;
    const res = await runJsRecon({
      scriptUrls: [`${fixture.origin}/static/app.js`],
      // No scope → must not fetch anything (the safety invariant).
      fetchText: async () => {
        touched = true;
        return { status: 200, body: "" };
      },
    });
    expect(touched).toBe(false);
    expect(res.scanned).toHaveLength(0);
  });
});
