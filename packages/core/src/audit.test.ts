import { describe, expect, it, vi, afterEach } from "vitest";
import { parseOsvAdvisories, queryOsvAdvisories, summarizeKnownAdvisoriesFinding } from "./audit.js";

describe("parseOsvAdvisories", () => {
  it("maps OSV vulnerabilities into NpmAuditFinding shape", () => {
    const findings = parseOsvAdvisories("lodash", {
      vulns: [
        {
          id: "GHSA-35jh-r3h4-6jhm",
          aliases: ["CVE-2021-23337"],
          summary: "Prototype pollution in lodash",
          database_specific: { severity: "HIGH" },
          references: [{ url: "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm" }],
          affected: [
            {
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.21" }],
                },
              ],
            },
          ],
        },
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "lodash",
      severity: "high",
      title: "Prototype pollution in lodash",
      source: "GHSA-35jh-r3h4-6jhm",
      url: "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
      fixAvailable: "4.17.21",
    });
    expect(findings[0].via).toContain("CVE-2021-23337");
    expect(findings[0].range).toContain("introduced:0");
    expect(findings[0].range).toContain("fixed:4.17.21");
  });

  it("defaults severity to medium when OSV does not provide one", () => {
    const findings = parseOsvAdvisories("pkg", {
      vulns: [{ id: "GHSA-test", summary: "Advisory without severity" }],
    });
    expect(findings[0]?.severity).toBe("medium");
  });
});

describe("queryOsvAdvisories", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("returns parsed advisories on a successful response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({
          vulns: [{ id: "GHSA-1", summary: "Root vuln", database_specific: { severity: "critical" } }],
        }),
      })),
    );

    const findings = await queryOsvAdvisories("axios", "0.21.0");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("queries OSV with the PyPI ecosystem when requested", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ vulns: [] }),
    }));
    vi.stubGlobal("fetch", fetchMock);

    await queryOsvAdvisories("requests", "2.32.0", "pypi");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0]!;
    expect(JSON.parse(String(init.body))).toMatchObject({
      package: { ecosystem: "PyPI", name: "requests" },
      version: "2.32.0",
    });
  });

  it("fails closed on network errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("network down");
    }));

    const findings = await queryOsvAdvisories("axios", "0.21.0");
    expect(findings).toEqual([]);
  });
});

describe("summarizeKnownAdvisoriesFinding", () => {
  it("emits a deterministic finding for root-package advisories", () => {
    const finding = summarizeKnownAdvisoriesFinding(
      {
        ecosystem: "npm",
        name: "lodash",
        version: "4.17.20",
        path: "/tmp/pkg",
        tempDir: "/tmp",
      },
      [
        {
          name: "lodash",
          severity: "high",
          title: "Prototype pollution in lodash",
          source: "GHSA-35jh-r3h4-6jhm",
          url: "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
          via: ["CVE-2021-23337"],
          fixAvailable: "4.17.21",
        },
        {
          name: "lodash",
          severity: "medium",
          title: "Command injection in lodash template",
          source: "GHSA-29mw-wpgm-hmr9",
          url: "https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9",
          via: ["CVE-2021-23337"],
          fixAvailable: "4.17.21",
        },
      ],
    );

    expect(finding).toBeTruthy();
    expect(finding?.templateId).toBe("known-package-advisories");
    expect(finding?.severity).toBe("high");
    expect(finding?.title).toContain("lodash@4.17.20");
    expect(finding?.description).toContain("Prototype pollution in lodash");
    expect(finding?.description).toContain("fix: 4.17.21");
  });

  it("returns null when there are no advisories", () => {
    const finding = summarizeKnownAdvisoriesFinding(
      {
        ecosystem: "npm",
        name: "express",
        version: "latest",
        path: "/tmp/pkg",
        tempDir: "/tmp",
      },
      [],
    );
    expect(finding).toBeNull();
  });
});
