import { describe, it, expect } from "vitest";
import {
  confirmOast,
  matchInteractions,
  categoryToOastClass,
  normalizeLabel,
} from "./oracle.js";
import type { OastInteraction } from "./types.js";

// A synthetic OAST correlation marker for the fixtures, assembled at runtime so
// the test carries no literal that looks like a committed credential. NOT a
// secret — the collaborator mints one of these per probe. Deliberately
// digit-free: the candidate nonces below (a3, b7, n1, n3, cand7, cand9) all
// contain a digit, so a digit-free marker can never collide with one as a
// substring, keeping the nonce-correlation tests deterministic.
const marker = ["oast", "correlation", "marker"].join("");

function dns(queryName: string, extra: Partial<OastInteraction> = {}): OastInteraction {
  return { protocol: "dns", timestamp: "2026-07-16T00:00:00Z", queryName, ...extra };
}
function http(host: string, path = "/", extra: Partial<OastInteraction> = {}): OastInteraction {
  return {
    protocol: "http",
    timestamp: "2026-07-16T00:00:00Z",
    queryName: host,
    path,
    method: "GET",
    ...extra,
  };
}

describe("normalizeLabel", () => {
  it("strips non-alphanumerics and lowercases", () => {
    expect(normalizeLabel("Foo-Bar_42!")).toBe("foobar42");
  });
  it("caps length at 48", () => {
    expect(normalizeLabel("a".repeat(100)).length).toBe(48);
  });
});

describe("matchInteractions", () => {
  it("matches on the token in the DNS query name", () => {
    const hits = matchInteractions({
      token: marker,
      interactions: [dns(`${marker}.oast.0sec.ai`), dns("unrelated.example.com")],
    });
    expect(hits).toHaveLength(1);
  });

  it("matches token case-insensitively", () => {
    const hits = matchInteractions({
      token: marker,
      interactions: [dns(`${marker.toUpperCase()}.OAST.0SEC.AI`)],
    });
    expect(hits).toHaveLength(1);
  });

  it("requires the nonce too when supplied", () => {
    const interactions = [
      dns(`n1.${marker}.oast.0sec.ai`),
      dns(`n2.${marker}.oast.0sec.ai`),
    ];
    expect(matchInteractions({ token: marker, nonce: "n1", interactions })).toHaveLength(1);
    expect(matchInteractions({ token: marker, nonce: "n3", interactions })).toHaveLength(0);
  });

  it("finds the nonce in an HTTP path as well as the host", () => {
    const hits = matchInteractions({
      token: marker,
      nonce: "cand7",
      interactions: [http(`${marker}.oast.0sec.ai`, "/cand7")],
    });
    expect(hits).toHaveLength(1);
  });

  it("returns nothing for an empty token", () => {
    expect(matchInteractions({ token: "", interactions: [dns("x.oast.0sec.ai")] })).toHaveLength(0);
  });
});

describe("confirmOast", () => {
  it("confirms blind SSRF from a DNS callback with 0.9 confidence", () => {
    const v = confirmOast({
      oastClass: "blind-ssrf",
      token: marker,
      interactions: [dns(`${marker}.oast.0sec.ai`, { remoteAddress: "10.0.0.5" })],
    });
    expect(v.verified).toBe(true);
    expect(v.protocol).toBe("dns");
    expect(v.confidence).toBe(0.9);
    expect(v.evidence).toContain("10.0.0.5");
  });

  it("confirms blind SSRF from an HTTP callback with full confidence", () => {
    const v = confirmOast({
      oastClass: "blind-ssrf",
      token: marker,
      interactions: [http(`${marker}.oast.0sec.ai`)],
    });
    expect(v.verified).toBe(true);
    expect(v.confidence).toBe(1.0);
  });

  it("prefers the HTTP hit over a DNS hit for the same token", () => {
    const v = confirmOast({
      oastClass: "blind-ssrf",
      token: marker,
      interactions: [dns(`${marker}.oast.0sec.ai`), http(`${marker}.oast.0sec.ai`)],
    });
    expect(v.protocol).toBe("http");
    expect(v.confidence).toBe(1.0);
  });

  it("does NOT confirm blind XSS from a DNS-only hit (script execution unproven)", () => {
    const v = confirmOast({
      oastClass: "blind-xss",
      token: marker,
      interactions: [dns(`${marker}.oast.0sec.ai`)],
    });
    expect(v.verified).toBe(false);
    expect(v.protocol).toBeNull();
    // near-miss surfaced, not discarded
    expect(v.interaction).not.toBeNull();
    expect(v.reason).toContain("requires");
  });

  it("confirms blind XSS from an HTTP beacon", () => {
    const v = confirmOast({
      oastClass: "blind-xss",
      token: marker,
      interactions: [http(`${marker}.oast.0sec.ai`, "/steal?c=sessionid")],
    });
    expect(v.verified).toBe(true);
    expect(v.protocol).toBe("http");
  });

  it("confirms OOB-SQLi from a DNS exfil callback", () => {
    const v = confirmOast({
      oastClass: "oob-sqli",
      token: marker,
      interactions: [dns(`${marker}.oast.0sec.ai`)],
    });
    expect(v.verified).toBe(true);
    expect(v.confidence).toBe(0.9);
  });

  it("confirms JNDI from an LDAP connect", () => {
    const v = confirmOast({
      oastClass: "jndi",
      token: marker,
      interactions: [{ protocol: "ldap", timestamp: "2026-07-16T00:00:00Z", queryName: `${marker}.oast.0sec.ai` }],
    });
    expect(v.verified).toBe(true);
    expect(v.protocol).toBe("ldap");
    expect(v.confidence).toBe(1.0);
  });

  it("stays unverified when no interaction carries the token", () => {
    const v = confirmOast({
      oastClass: "blind-ssrf",
      token: marker,
      interactions: [dns("someoneelse.oast.0sec.ai")],
    });
    expect(v.verified).toBe(false);
    expect(v.interaction).toBeNull();
    expect(v.reason).toContain("no interaction");
  });

  it("ties a hit to a specific candidate via the nonce", () => {
    // Two candidates share a handle; only candidate B's probe fired.
    const interactions = [http(`b7.${marker}.oast.0sec.ai`, "/b7")];
    const a = confirmOast({ oastClass: "blind-ssrf", token: marker, nonce: "a3", interactions });
    const b = confirmOast({ oastClass: "blind-ssrf", token: marker, nonce: "b7", interactions });
    expect(a.verified).toBe(false);
    expect(b.verified).toBe(true);
  });
});

describe("categoryToOastClass", () => {
  it("maps scanner categories to OAST classes", () => {
    expect(categoryToOastClass("ssrf")).toBe("blind-ssrf");
    expect(categoryToOastClass("xss")).toBe("blind-xss");
    expect(categoryToOastClass("command-injection")).toBe("oob-rce");
    expect(categoryToOastClass("code-injection")).toBe("oob-rce");
    expect(categoryToOastClass("sql-injection")).toBe("oob-sqli");
  });
  it("returns null for categories with no out-of-band shape", () => {
    expect(categoryToOastClass("path-traversal")).toBeNull();
    expect(categoryToOastClass("idor")).toBeNull();
  });
});
