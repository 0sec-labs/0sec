import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScanConfig } from "@pwnkit/shared";

// Mock the DNS-backed modules so the pre-pass stays off the wire. The HTTP-
// driven modules (baseline web checks, fingerprint, js-artifacts, framework
// CVE checks) all funnel through the injected/global `fetch`, which we stub
// per-test below.
vi.mock("../recon/dns-email.js", () => ({
  checkEmailPosture: vi.fn(async () => ({
    domain: "example.com",
    spf: { present: true, policy: "-all" as const },
    dmarc: { present: true, policy: "reject" as const },
    dkim: { checkedSelectors: ["default"], found: ["default"] },
    findings: [],
  })),
}));

vi.mock("../recon/subdomains.js", () => ({
  enumerateSubdomains: vi.fn(async () => []),
}));

import { runWebReconPrePass } from "./web-recon-prepass.js";

const BASE = "https://app.example.com";

function makeConfig(): ScanConfig {
  return {
    target: BASE,
    depth: "standard",
    format: "json",
    mode: "web",
  } as ScanConfig;
}

/** Build a Response-like object the pre-pass `fetch` wrapper consumes. */
function res(
  status: number,
  body: string,
  headers: Record<string, string> = {},
): Response {
  const h = new Headers(headers);
  return {
    status,
    headers: h,
    text: async () => body,
  } as unknown as Response;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("runWebReconPrePass", () => {
  it("emits a missing-security-headers finding from the baseline checks", async () => {
    // Root with NO security headers → baseline header finding. Everything
    // else (chunks, source maps) 404s.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === BASE || url === `${BASE}/`) {
          return res(200, "<html><body>hello</body></html>", {
            "content-type": "text/html",
          });
        }
        return res(404, "");
      }),
    );

    const { findings, promptBlock } = await runWebReconPrePass(makeConfig());
    expect(
      findings.some((f) => f.templateId === "web-security-headers"),
    ).toBe(true);
    expect(promptBlock).toContain("Deterministic web recon");
  });

  it("emits a Next.js version → CVE finding when the advisory DB returns a high CVE", async () => {
    // Root advertises Next.js 15.0.0 via the x-powered-by header so the
    // fingerprint carries a version, which drives the version→CVE lookup.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === BASE || url === `${BASE}/`) {
          return res(
            200,
            '<html><head><meta name="generator" content="Next.js 15.0.0"/></head><body></body></html>',
            { "x-powered-by": "Next.js", "content-security-policy": "default-src 'self'" },
          );
        }
        return res(404, "");
      }),
    );

    // Stub the intel layer so the test is deterministic and offline.
    const versionCve = await import("../intel/version-cve.js");
    vi.spyOn(versionCve, "lookupVersionCves").mockResolvedValue([
      {
        id: "CVE-2025-29927",
        severity: "critical",
        summary: "Next.js middleware authorization bypass",
        affectedRange: "<15.2.3",
        fixedVersion: "15.2.3",
        source: "github",
      },
    ]);

    const { findings } = await runWebReconPrePass(makeConfig());
    const cve = findings.find((f) => f.templateId === "web-recon-version-cve");
    expect(cve).toBeDefined();
    expect(cve?.severity).toBe("critical");
    expect(cve?.category).toBe("known-vulnerable-package");
    expect(cve?.title).toContain("Known-vulnerable dependency: next@15.0.0");
    expect(cve?.evidence.analysis).toContain("CVE-2025-29927");
  });

  it("consolidates many version→CVEs for one component into a SINGLE finding", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === BASE || url === `${BASE}/`) {
          return res(
            200,
            '<html><head><meta name="generator" content="Next.js 15.0.7"/></head><body></body></html>',
            { "x-powered-by": "Next.js", "content-security-policy": "default-src 'self'" },
          );
        }
        return res(404, "");
      }),
    );

    // Five HIGH/CRITICAL advisories for the same next@15.0.7 component.
    const versionCve = await import("../intel/version-cve.js");
    vi.spyOn(versionCve, "lookupVersionCves").mockResolvedValue([
      { id: "CVE-2025-0001", severity: "high", summary: "DoS A", fixedVersion: "15.1.0", source: "github" },
      { id: "CVE-2025-0002", severity: "high", summary: "DoS B", fixedVersion: "15.2.0", source: "github" },
      { id: "CVE-2025-29927", severity: "critical", summary: "Middleware auth bypass", fixedVersion: "15.2.3", source: "github" },
      { id: "CVE-2025-0003", severity: "high", summary: "Info leak", fixedVersion: "15.1.5", source: "osv" },
      { id: "CVE-2025-0004", severity: "high", summary: "ReDoS", fixedVersion: "15.2.1", source: "nvd" },
    ]);

    const { findings } = await runWebReconPrePass(makeConfig());
    const scaFindings = findings.filter(
      (f) => f.templateId === "web-recon-version-cve",
    );
    // Exactly ONE consolidated finding for next@15.0.7, not five.
    expect(scaFindings).toHaveLength(1);
    const sca = scaFindings[0]!;
    expect(sca.title).toContain("next@15.0.7");
    expect(sca.title).toContain("(5 published advisories)");
    expect(sca.severity).toBe("critical"); // max among counting CVEs
    // All five CVE ids and the highest fixed version are carried in the evidence.
    for (const id of ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-29927", "CVE-2025-0003", "CVE-2025-0004"]) {
      expect(sca.evidence.analysis).toContain(id);
    }
    expect(sca.evidence.analysis).toContain(">= 15.2.3");
    expect(sca.description).toContain("VERSION-AFFECTED");
  });

  it("down-ranks and annotates a Vercel-edge-mitigated CVE when hosted on Vercel", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === BASE || url === `${BASE}/`) {
          return res(
            200,
            '<html><head><meta name="generator" content="Next.js 15.0.7"/></head><body></body></html>',
            {
              "x-powered-by": "Next.js",
              "content-security-policy": "default-src 'self'",
              // Vercel edge headers.
              server: "Vercel",
              "x-vercel-id": "fra1::abc123",
            },
          );
        }
        return res(404, "");
      }),
    );

    // The ONLY HIGH/CRITICAL advisory is the Vercel-mitigated middleware bypass.
    const versionCve = await import("../intel/version-cve.js");
    vi.spyOn(versionCve, "lookupVersionCves").mockResolvedValue([
      { id: "CVE-2025-29927", severity: "critical", summary: "Middleware auth bypass", fixedVersion: "15.2.3", source: "github" },
    ]);

    const { findings } = await runWebReconPrePass(makeConfig());
    const sca = findings.find((f) => f.templateId === "web-recon-version-cve");
    expect(sca).toBeDefined();
    // Down-ranked: the only counting CVE is Vercel-mitigated, so the rollup
    // falls back below critical.
    expect(sca?.severity).not.toBe("critical");
    expect(sca?.evidence.analysis).toContain("Vercel");
    expect(sca?.evidence.analysis).toMatch(/auto-mitigated at the Vercel edge/);
  });

  it("emits a codex-confirmed-exploitable CVE as its OWN finding and marks it confirmed in the rollup", async () => {
    const PROTECTED = "/dashboard";
    // Root 307-redirects to /login (auth-gated), so the active checks run.
    // The crafted x-middleware-subrequest request returns 200 protected content
    // → CVE-2025-29927 confirmed exploitable.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const u = new URL(url);
        const headers = (init?.headers ?? {}) as Record<string, string>;
        // Crafted middleware-bypass request → 200 protected content (confirms
        // CVE-2025-29927). Checked first so it wins over the bare-"/" gate below.
        if (headers["x-middleware-subrequest"]) {
          return res(200, "<html><body>secret dashboard</body></html>", {
            "content-type": "text/html",
          });
        }
        // RSC variants stay gated.
        if (u.pathname.endsWith(".rsc") || headers["RSC"] || headers["Next-Router-Segment-Prefetch"]) {
          return res(307, "", { location: "/login" });
        }
        // Login page (used for fingerprint generator detection on the root too).
        if (u.pathname === "/login") {
          return res(200, "<form><input type='password'></form>", {
            "content-type": "text/html",
          });
        }
        // Root / protected route: 307-redirect to /login (auth-gated baseline).
        // The body still carries the Next.js generator meta so the fingerprint
        // extracts a version (the active check keys off the 307 status + Location).
        if (u.pathname === "/") {
          return res(
            307,
            '<html><head><meta name="generator" content="Next.js 15.0.7"/></head></html>',
            {
              location: "/login",
              "x-powered-by": "Next.js",
            },
          );
        }
        return res(404, "");
      }),
    );

    const versionCve = await import("../intel/version-cve.js");
    vi.spyOn(versionCve, "lookupVersionCves").mockResolvedValue([
      { id: "CVE-2025-29927", severity: "critical", summary: "Middleware auth bypass", fixedVersion: "15.2.3", source: "github" },
    ]);

    const { findings } = await runWebReconPrePass(makeConfig());
    // The confirmed CVE is its own framework-cve finding.
    const ownFinding = findings.find(
      (f) => f.templateId === "web-recon-framework-cve" && f.title.includes("CVE-2025-29927"),
    );
    expect(ownFinding).toBeDefined();
    expect(["high", "critical"]).toContain(ownFinding?.severity);
    // And it is marked CONFIRMED in the consolidated rollup.
    const sca = findings.find((f) => f.templateId === "web-recon-version-cve");
    expect(sca).toBeDefined();
    expect(sca?.evidence.analysis).toMatch(/CONFIRMED exploitable/);
  });

  it("does NOT emit a secret finding for a public-only key (low confidence)", async () => {
    const chunkUrl = `${BASE}/static/app.js`;
    // Root references one JS chunk; the chunk ships only a public PostHog key.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === BASE || url === `${BASE}/`) {
          return res(
            200,
            `<html><body><script src="/static/app.js"></script></body></html>`,
            { "content-type": "text/html", "content-security-policy": "x", "x-frame-options": "DENY", "x-content-type-options": "nosniff", "strict-transport-security": "max-age=1" },
          );
        }
        if (url === chunkUrl) {
          return res(200, "var k='phc_" + "a".repeat(40) + "';");
        }
        return res(404, "");
      }),
    );

    const { findings } = await runWebReconPrePass(makeConfig());
    expect(
      findings.some((f) => f.templateId === "web-recon-leaked-secret"),
    ).toBe(false);
  });

  it("never throws when every fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );

    await expect(runWebReconPrePass(makeConfig())).resolves.toMatchObject({
      findings: expect.any(Array),
      promptBlock: expect.any(String),
    });
  });
});

import { isInScopeUrl } from "./web-recon-prepass.js";
import { describe as describe2, it as it2, expect as expect2 } from "vitest";
describe2("isInScopeUrl SSRF guard", () => {
  const host = "oki.doky.ch";
  const dom = "doky.ch";
  it2("allows same-host and same-registrable-domain https URLs", () => {
    expect2(isInScopeUrl("https://oki.doky.ch/_next/static/chunks/x.js", host, dom)).toBe(true);
    expect2(isInScopeUrl("https://cdn.doky.ch/a.js", host, dom)).toBe(true);
  });
  it2("blocks cross-origin, internal, and non-http URLs", () => {
    expect2(isInScopeUrl("https://evil.example/a.js", host, dom)).toBe(false);
    expect2(isInScopeUrl("http://169.254.169.254/latest/meta-data/", host, dom)).toBe(false);
    expect2(isInScopeUrl("http://localhost:8080/x", host, dom)).toBe(false);
    expect2(isInScopeUrl("http://10.0.0.5/x", host, dom)).toBe(false);
    expect2(isInScopeUrl("file:///etc/passwd", host, dom)).toBe(false);
  });
});
