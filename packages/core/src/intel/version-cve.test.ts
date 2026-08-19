import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { lookupVersionCves } from "./version-cve.js";

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

// Mirrors the real OSV shape for `next` constrained by version: the
// CVE-2025-29927 middleware-bypass advisory plus an older React2Shell entry.
const NEXT_OSV_RESPONSE = {
  vulns: [
    {
      id: "GHSA-f82v-jwr5-mffw",
      aliases: ["CVE-2025-29927"],
      summary: "Authorization Bypass in Next.js Middleware",
      database_specific: { severity: "CRITICAL" },
      references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-f82v-jwr5-mffw" }],
      affected: [
        {
          package: { ecosystem: "npm", name: "next" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "15.0.0" }, { fixed: "15.2.3" }] }],
        },
      ],
    },
    {
      id: "GHSA-react-2shell",
      aliases: ["CVE-2025-55182"],
      summary: "React2Shell remote code execution in Next.js server actions",
      database_specific: { severity: "CRITICAL" },
      references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-react-2shell" }],
      affected: [
        {
          package: { ecosystem: "npm", name: "next" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "15.1.0" }] }],
        },
      ],
    },
  ],
};

describe("lookupVersionCves", () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-version-cve-test-"));
  });

  afterEach(() => {
    rmSync(cacheDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("maps a detected npm framework version to known CVEs via OSV", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.startsWith("https://api.osv.dev/")) return json(NEXT_OSV_RESPONSE);
      // GitHub advisory enrichment returns nothing here; OSV is the source under test.
      if (url.startsWith("https://api.github.com/advisories")) return json([]);
      if (url.startsWith("https://services.nvd.nist.gov/")) return json({ vulnerabilities: [] });
      if (url.startsWith("https://www.cisa.gov/")) return json({ vulnerabilities: [] });
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const cves = await lookupVersionCves(
      { ecosystem: "npm", name: "next", version: "15.0.7", cacheDir },
      { fetchImpl: fetchMock },
    );

    const ids = cves.map((cve) => cve.id);
    expect(ids).toContain("CVE-2025-29927");
    expect(ids).toContain("CVE-2025-55182");

    const middleware = cves.find((cve) => cve.id === "CVE-2025-29927")!;
    expect(middleware.severity).toBe("critical");
    expect(middleware.summary).toContain("Middleware");
    expect(middleware.fixedVersion).toBe("15.2.3");
    expect(middleware.source).toBe("osv");
  });

  it("sends the version to OSV so results are constrained to the affected build", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.startsWith("https://api.osv.dev/")) {
        const body = JSON.parse(String(init?.body ?? "{}"));
        expect(body.version).toBe("15.0.7");
        expect(body.package).toEqual({ ecosystem: "npm", name: "next" });
        return json(NEXT_OSV_RESPONSE);
      }
      if (url.startsWith("https://api.github.com/advisories")) return json([]);
      if (url.startsWith("https://services.nvd.nist.gov/")) return json({ vulnerabilities: [] });
      if (url.startsWith("https://www.cisa.gov/")) return json({ vulnerabilities: [] });
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    await lookupVersionCves(
      { ecosystem: "npm", name: "next", version: "15.0.7", cacheDir },
      { fetchImpl: fetchMock },
    );
  });

  it("dedups by advisory id when sources overlap", async () => {
    const duplicated = {
      vulns: [NEXT_OSV_RESPONSE.vulns[0], NEXT_OSV_RESPONSE.vulns[0]],
    };
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.startsWith("https://api.osv.dev/")) return json(duplicated);
      if (url.startsWith("https://api.github.com/advisories")) return json([]);
      if (url.startsWith("https://services.nvd.nist.gov/")) return json({ vulnerabilities: [] });
      if (url.startsWith("https://www.cisa.gov/")) return json({ vulnerabilities: [] });
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const cves = await lookupVersionCves(
      { ecosystem: "npm", name: "next", version: "15.0.7", cacheDir },
      { fetchImpl: fetchMock },
    );
    expect(cves.filter((cve) => cve.id === "CVE-2025-29927")).toHaveLength(1);
  });

  it("returns empty for ecosystems OSV does not cover without throwing", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      // toOsvEcosystem returns null for unknown ecosystems, so OSV is skipped.
      if (url.startsWith("https://api.github.com/advisories")) return json([]);
      if (url.startsWith("https://services.nvd.nist.gov/")) return json({ vulnerabilities: [] });
      if (url.startsWith("https://www.cisa.gov/")) return json({ vulnerabilities: [] });
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const cves = await lookupVersionCves(
      { ecosystem: "nuget", name: "Newtonsoft.Json", version: "12.0.0", cacheDir },
      { fetchImpl: fetchMock },
    );
    expect(cves).toEqual([]);
  });
});
