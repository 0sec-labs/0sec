import { describe, it, expect } from "vitest";
import { H1Client } from "./client.js";
import {
  listPrograms,
  getProgram,
  getStructuredScopes,
  automationVerdict,
  summariseScopes,
} from "./programs.js";

function makeClient(fetchImpl: typeof fetch): H1Client {
  return new H1Client({
    identifier: "test",
    token: "tok",
    fetchImpl,
    pageDelayMs: 0,
    sleep: async () => {},
  });
}

describe("listPrograms", () => {
  it("paginates until limit is reached", async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const u = String(url);
      if (u.includes("page%5Bnumber%5D=2")) {
        return new Response(
          JSON.stringify({
            data: [
              { id: "3", type: "program", attributes: { handle: "c", name: "C", offers_bounties: false } },
            ],
            links: {},
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          data: [
            { id: "1", type: "program", attributes: { handle: "a", name: "A", offers_bounties: true } },
            { id: "2", type: "program", attributes: { handle: "b", name: "B", offers_bounties: true } },
          ],
          links: {
            next: "https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2",
          },
        }),
        { status: 200 },
      );
    }) as typeof fetch;
    const client = makeClient(fetchImpl);
    const list = await listPrograms(client, { limit: 2 });
    expect(list.length).toBe(2);
    expect(list.map((p) => p.attributes.handle)).toEqual(["a", "b"]);
  });

  it("filters --bounty / --vdp client-side", async () => {
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          data: [
            { id: "1", type: "program", attributes: { handle: "bb", name: "BB", offers_bounties: true } },
            { id: "2", type: "program", attributes: { handle: "vdp", name: "VDP", offers_bounties: false } },
          ],
          links: {},
        }),
        { status: 200 },
      )) as typeof fetch;
    const client = makeClient(fetchImpl);
    const onlyBounty = await listPrograms(client, { bountyOnly: true });
    expect(onlyBounty.map((p) => p.attributes.handle)).toEqual(["bb"]);
    const onlyVdp = await listPrograms(client, { vdpOnly: true });
    expect(onlyVdp.map((p) => p.attributes.handle)).toEqual(["vdp"]);
  });
});

describe("getProgram", () => {
  it("accepts a bare resource (no data: wrapper)", async () => {
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          id: "1",
          type: "program",
          attributes: { handle: "demo", name: "Demo" },
        }),
        { status: 200 },
      )) as typeof fetch;
    const client = makeClient(fetchImpl);
    const prog = await getProgram(client, "demo");
    expect(prog.attributes.handle).toBe("demo");
  });

  it("also accepts a {data: …} envelope", async () => {
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          data: { id: "1", type: "program", attributes: { handle: "demo", name: "Demo" } },
        }),
        { status: 200 },
      )) as typeof fetch;
    const client = makeClient(fetchImpl);
    const prog = await getProgram(client, "demo");
    expect(prog.attributes.handle).toBe("demo");
  });
});

describe("getStructuredScopes", () => {
  it("collects scopes across pages", async () => {
    let n = 0;
    const fetchImpl = (async () => {
      n += 1;
      if (n === 1) {
        return new Response(
          JSON.stringify({
            data: [
              { id: "1", type: "structured-scope", attributes: { asset_type: "URL", asset_identifier: "a.com" } },
            ],
            links: { next: "https://api.hackerone.com/v1/hackers/programs/x/structured_scopes?page%5Bnumber%5D=2" },
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          data: [
            { id: "2", type: "structured-scope", attributes: { asset_type: "URL", asset_identifier: "b.com" } },
          ],
          links: {},
        }),
        { status: 200 },
      );
    }) as typeof fetch;
    const client = makeClient(fetchImpl);
    const scopes = await getStructuredScopes(client, "x");
    expect(scopes.length).toBe(2);
  });
});

describe("automationVerdict", () => {
  it("returns 'forbidden' on pure banned-tooling boilerplate", () => {
    expect(automationVerdict("Please do not use automated scanners.")).toBe("forbidden");
    // Note: "No automated tools allowed" trips both NEGATIVE_RE and
    // POSITIVE_RE within the same paragraph, so it surfaces as
    // "mixed" — that's the desired safer behaviour: the operator
    // re-reads the policy. See pure-forbidden fixture below for the
    // unambiguous-prohibition case.
    expect(automationVerdict("No automated tools or scanners are allowed. Reports based on scanner output will be closed as N/A.")).toBe("forbidden");
    expect(automationVerdict("gobuster, sqlmap, nikto are not permitted")).toBe("forbidden");
  });

  it("returns 'permitted' on explicit allow text", () => {
    expect(automationVerdict("Automated testing is welcome. Please rate-limit to 10 requests per second.")).toBe("permitted");
    expect(automationVerdict("Automation is acceptable on staging.")).toBe("permitted");
  });

  it("returns 'mixed' when a paragraph mixes prohibition and contrast clause (issue #266)", () => {
    // Flutter UK&I-shaped fixture — leading prohibition, contrast
    // clause re-permits narrow automation.
    const flutter =
      "Don't use common vulnerability scanners. The search for vulnerabilities should be manual, although custom tools with automated requests are allowed if limited to 5 requests per second.";
    expect(automationVerdict(flutter)).toBe("mixed");
  });

  it("returns 'mixed' when policy paragraphs disagree", () => {
    // Paragraph 1: forbidden. Paragraph 2: permitted. Same intent
    // as Flutter, but split across paragraphs.
    const policy = [
      "Common vulnerability scanners are not permitted on production.",
      "",
      "Automated testing on staging is welcome at 5 rps.",
    ].join("\n");
    expect(automationVerdict(policy)).toBe("mixed");
  });

  it("returns 'unclear' on silence", () => {
    expect(automationVerdict("")).toBe("unclear");
    expect(automationVerdict("Welcome researchers.")).toBe("unclear");
    expect(automationVerdict(undefined)).toBe("unclear");
  });
});

describe("summariseScopes", () => {
  it("splits by asset_type and eligible_for_submission", () => {
    const scopes = [
      { id: "1", type: "s", attributes: { asset_type: "URL", asset_identifier: "a.com", eligible_for_submission: true } },
      { id: "2", type: "s", attributes: { asset_type: "URL", asset_identifier: "b.com", eligible_for_submission: true } },
      { id: "3", type: "s", attributes: { asset_type: "DOMAIN", asset_identifier: "x.com", eligible_for_submission: true } },
      { id: "4", type: "s", attributes: { asset_type: "URL", asset_identifier: "c.com", eligible_for_submission: false } },
    ];
    const s = summariseScopes(scopes as Parameters<typeof summariseScopes>[0]);
    expect(s.totalIn).toBe(3);
    expect(s.totalOut).toBe(1);
    expect(s.inScopeByType).toEqual({ URL: 2, DOMAIN: 1 });
    expect(s.outOfScopeByType).toEqual({ URL: 1 });
  });
});
