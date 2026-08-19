import { describe, expect, it } from "vitest";
import {
  checkEmailPosture,
  parseDmarcPolicy,
  parseSpfPolicy,
  type ResolveTxt,
} from "./dns-email.js";

/**
 * Build a mock `resolveTxt` from a name → records map. Records are given as
 * plain strings and wrapped into the chunked `string[][]` TXT shape. Any name
 * not in the map rejects with ENOTFOUND, the way a real NXDOMAIN would.
 */
function mockResolver(map: Record<string, string[]>): ResolveTxt {
  return async (name: string) => {
    const key = name.toLowerCase().replace(/\.$/, "");
    const records = map[key];
    if (!records) {
      const err = new Error(`queryTxt ENOTFOUND ${name}`) as NodeJS.ErrnoException;
      err.code = "ENOTFOUND";
      throw err;
    }
    return records.map((r) => [r]);
  };
}

describe("parseSpfPolicy", () => {
  it("extracts the all-mechanism qualifier", () => {
    expect(parseSpfPolicy("v=spf1 include:_spf.google.com ~all")).toBe("~all");
    expect(parseSpfPolicy("v=spf1 mx -all")).toBe("-all");
    expect(parseSpfPolicy("v=spf1 ?all")).toBe("?all");
    expect(parseSpfPolicy("v=spf1 +all")).toBe("+all");
  });

  it("defaults a bare `all` to `+all` and returns undefined when absent", () => {
    expect(parseSpfPolicy("v=spf1 mx all")).toBe("+all");
    expect(parseSpfPolicy("v=spf1 redirect=_spf.example.com")).toBeUndefined();
  });
});

describe("parseDmarcPolicy", () => {
  it("extracts the p= policy tag", () => {
    expect(parseDmarcPolicy("v=DMARC1; p=quarantine; rua=mailto:r@x")).toBe("quarantine");
    expect(parseDmarcPolicy("v=DMARC1; p=reject")).toBe("reject");
    expect(parseDmarcPolicy("v=DMARC1;p=none")).toBe("none");
  });

  it("returns undefined when no valid p= tag is present", () => {
    expect(parseDmarcPolicy("v=DMARC1; rua=mailto:r@x")).toBeUndefined();
    expect(parseDmarcPolicy("v=DMARC1; p=bogus")).toBeUndefined();
  });
});

describe("checkEmailPosture — doky.ch pilot records", () => {
  // Real pilot evidence: SPF softfail (`~all`) + DMARC `p=quarantine`.
  const resolveTxt = mockResolver({
    "doky.ch": [
      "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all",
    ],
    "_dmarc.doky.ch": [
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@doky.ch; fo=1",
    ],
    "google._domainkey.doky.ch": [
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
    ],
  });

  it("flags softfail SPF and non-reject DMARC as LOW hardening notes", async () => {
    const posture = await checkEmailPosture({ domain: "doky.ch", resolveTxt });

    expect(posture.spf).toMatchObject({ present: true, policy: "~all" });
    expect(posture.spf.issue).toMatch(/softfail/i);

    expect(posture.dmarc).toMatchObject({ present: true, policy: "quarantine" });
    expect(posture.dmarc.issue).toMatch(/quarantine/i);

    // DKIM present under the `google` selector → no DKIM finding.
    expect(posture.dkim.found).toEqual(["google"]);

    const titles = posture.findings.map((f) => f.title);
    expect(titles).toContain("SPF uses softfail (~all)");
    expect(titles).toContain("DMARC policy is p=quarantine");
    // Every finding here is a LOW hardening note, none MEDIUM.
    expect(posture.findings.every((f) => f.severity === "low")).toBe(true);
    // No missing-record (MEDIUM) findings.
    expect(titles.some((t) => /missing/i.test(t))).toBe(false);
  });
});

describe("checkEmailPosture — grading rules", () => {
  it("grades a hardened domain (-all + p=reject + DKIM) as clean", async () => {
    const resolveTxt = mockResolver({
      "good.test": ["v=spf1 include:_spf.google.com -all"],
      "_dmarc.good.test": ["v=DMARC1; p=reject; rua=mailto:d@good.test"],
      "default._domainkey.good.test": ["v=DKIM1; k=rsa; p=MIGf..."],
    });
    const posture = await checkEmailPosture({ domain: "good.test", resolveTxt });
    expect(posture.spf.policy).toBe("-all");
    expect(posture.dmarc.policy).toBe("reject");
    expect(posture.dkim.found).toEqual(["default"]);
    expect(posture.findings).toHaveLength(0);
  });

  it("flags missing SPF and DMARC as MEDIUM", async () => {
    const resolveTxt = mockResolver({}); // nothing resolves
    const posture = await checkEmailPosture({ domain: "bare.test", resolveTxt });

    expect(posture.spf.present).toBe(false);
    expect(posture.dmarc.present).toBe(false);
    expect(posture.dkim.found).toEqual([]);

    const bySeverity = posture.findings.reduce<Record<string, string[]>>((acc, f) => {
      (acc[f.severity] ??= []).push(f.title);
      return acc;
    }, {});
    expect(bySeverity.medium).toEqual(
      expect.arrayContaining(["Missing SPF record", "Missing DMARC record"]),
    );
    // Missing DKIM is a LOW note, not MEDIUM.
    expect(bySeverity.low).toEqual(
      expect.arrayContaining(["No DKIM key found for common selectors"]),
    );
  });

  it("flags +all SPF as MEDIUM and p=none DMARC as LOW", async () => {
    const resolveTxt = mockResolver({
      "open.test": ["v=spf1 +all"],
      "_dmarc.open.test": ["v=DMARC1; p=none; rua=mailto:d@open.test"],
    });
    const posture = await checkEmailPosture({ domain: "open.test", resolveTxt });
    const spfFinding = posture.findings.find((f) => /SPF permits all/i.test(f.title));
    const dmarcFinding = posture.findings.find((f) => /p=none/i.test(f.title));
    expect(spfFinding?.severity).toBe("medium");
    expect(dmarcFinding?.severity).toBe("low");
  });

  it("probes the configured DKIM selectors and reports which were checked", async () => {
    const resolveTxt = mockResolver({
      "sel.test": ["v=spf1 -all"],
      "_dmarc.sel.test": ["v=DMARC1; p=reject"],
    });
    const posture = await checkEmailPosture({
      domain: "sel.test",
      resolveTxt,
      dkimSelectors: ["s1", "s2"],
    });
    expect(posture.dkim.checkedSelectors).toEqual(["s1", "s2"]);
    expect(posture.dkim.found).toEqual([]);
  });

  it("normalizes a trailing dot and uppercase in the domain", async () => {
    const resolveTxt = mockResolver({
      "norm.test": ["v=spf1 -all"],
      "_dmarc.norm.test": ["v=DMARC1; p=reject"],
    });
    const posture = await checkEmailPosture({ domain: "NORM.test.", resolveTxt });
    expect(posture.domain).toBe("norm.test");
    expect(posture.spf.present).toBe(true);
    expect(posture.dmarc.present).toBe(true);
  });

  it("treats a chunked TXT record as one logical string", async () => {
    const resolveTxt: ResolveTxt = async (name) => {
      if (name === "chunk.test") return [["v=spf1 include:a ", "include:b -all"]];
      throw new Error("ENOTFOUND");
    };
    const posture = await checkEmailPosture({
      domain: "chunk.test",
      resolveTxt,
      dkimSelectors: [],
    });
    expect(posture.spf.record).toBe("v=spf1 include:a include:b -all");
    expect(posture.spf.policy).toBe("-all");
  });
});
