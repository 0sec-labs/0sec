import { describe, it, expect, vi, afterEach } from "vitest";
import {
  ToolExecutor,
  TOOL_DEFINITIONS,
  getToolsForRole,
  bodySimilarity,
  diffAccessResponses,
} from "./tools.js";
import { SessionEngine } from "./session.js";
import type { ToolContext } from "./types.js";
import type { NamedIdentity } from "@0sec/shared";
import { fetchScoped } from "../http.js";

vi.mock("../http.js", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  fetchScoped: vi.fn(),
}));

afterEach(() => {
  vi.mocked(fetchScoped).mockReset();
});

// ── unit: similarity + diff verdicts (0sec#564) ──

describe("bodySimilarity", () => {
  it("is 1 for identical (whitespace/case-insensitive) bodies", () => {
    expect(bodySimilarity('{"id":1,"name":"Alice"}', '{"id":1,"name":"Alice"}')).toBe(1);
    expect(bodySimilarity("Hello   World", "hello world")).toBe(1);
    expect(bodySimilarity("", "")).toBe(1);
  });

  it("is 0 for fully disjoint bodies", () => {
    expect(bodySimilarity("alpha beta", "gamma delta")).toBe(0);
  });

  it("is between 0 and 1 for partial overlap", () => {
    const s = bodySimilarity("a b c d", "a b x y");
    expect(s).toBeGreaterThan(0);
    expect(s).toBeLessThan(1);
  });
});

describe("diffAccessResponses", () => {
  const body = '{"id":1,"email":"alice@example.com","ssn":"redacted"}';

  it("flags broken object-level auth when B retrieves the SAME resource (BOLA/IDOR)", () => {
    const d = diffAccessResponses(
      { status: 200, body },
      { status: 200, body },
      { baselineRole: "user", comparisonRole: "user", expectDenied: true },
    );
    expect(d.broken).toBe(true);
    expect(d.verdict).toBe("broken_object_level_authorization");
    expect(d.severity).toBe("high");
    expect(d.bodySimilarity).toBe(1);
  });

  it("labels a same-resource break by a lower-priv identity as vertical privesc", () => {
    const d = diffAccessResponses(
      { status: 200, body },
      { status: 200, body },
      { baselineRole: "admin", comparisonRole: "user" },
    );
    expect(d.broken).toBe(true);
    expect(d.verdict).toBe("vertical_privilege_escalation");
  });

  it("treats a 401/403 comparison as properly denied", () => {
    for (const status of [401, 403]) {
      const d = diffAccessResponses({ status: 200, body }, { status, body: "Forbidden" }, {});
      expect(d.broken).toBe(false);
      expect(d.verdict).toBe("properly_denied");
    }
  });

  it("flags BFLA when a lower-priv identity reaches a function it should not (2xx, different body)", () => {
    const d = diffAccessResponses(
      { status: 200, body: '{"admin":"panel"}' },
      { status: 200, body: '{"ok":true}' },
      { baselineRole: "admin", comparisonRole: "user" },
    );
    expect(d.broken).toBe(true);
    expect(d.verdict).toBe("vertical_privilege_escalation");
  });

  it("does NOT flag a distinct resource for a same-tier identity (likely its own data)", () => {
    const d = diffAccessResponses(
      { status: 200, body: '{"id":1}' },
      { status: 200, body: '{"id":2}' },
      { baselineRole: "user", comparisonRole: "user", expectDenied: false },
    );
    expect(d.broken).toBe(false);
    expect(d.verdict).toBe("accessible_distinct_resource");
  });

  it("is inconclusive when the baseline was not itself authorized", () => {
    const d = diffAccessResponses({ status: 404, body: "" }, { status: 200, body }, {});
    expect(d.broken).toBe(false);
    expect(d.verdict).toBe("inconclusive");
  });
});

// ── registry ──

describe("access_control_probe registration", () => {
  it("is a defined tool", () => {
    expect(TOOL_DEFINITIONS.access_control_probe).toBeDefined();
    expect(TOOL_DEFINITIONS.access_control_probe.required).toContain("url");
  });

  it("is exposed to discovery + attack roles", () => {
    for (const role of ["discovery", "attack"]) {
      const names = getToolsForRole(role).map((t) => t.name);
      expect(names).toContain("access_control_probe");
    }
  });
});

// ── integration: probe over stubbed fetch ──

const TARGET = "https://target.example.com";
const RESOURCE = "https://target.example.com/api/users/1";

function ctxWithIdentities(identities: NamedIdentity[]): ToolContext {
  return {
    target: TARGET,
    scanId: "ac-test",
    findings: [],
    attackResults: [],
    targetInfo: {},
    session: new SessionEngine(identities),
    identities,
  };
}

const TWO_IDENTITIES: NamedIdentity[] = [
  { label: "alice", role: "user", auth: { type: "bearer", token: "alice-tok" } },
  { label: "bob", role: "user", auth: { type: "bearer", token: "bob-tok" } },
];

describe("accessControlProbe integration (0sec#564)", () => {
  it("confirms a BOLA finding when identity B retrieves identity A's object", async () => {
    const aliceObject = '{"id":1,"owner":"alice","email":"alice@example.com"}';
    // Vulnerable server: returns alice's object to ANYONE with a valid token.
    vi.mocked(fetchScoped).mockImplementation(async () => new Response(aliceObject, {
      status: 200,
      headers: { "content-type": "application/json" },
    }));

    const ex = new ToolExecutor(ctxWithIdentities(TWO_IDENTITIES), null);
    const result = await ex.execute({
      name: "access_control_probe",
      arguments: {
        url: RESOURCE,
        baseline_identity: "alice",
        compare_identities: ["bob"],
        expect_denied: true,
      },
    });

    expect(result.success).toBe(true);
    const out = result.output as Record<string, any>;
    expect(out.verdict).toBe("broken_access_control");
    expect(out.broken_count).toBe(1);
    expect(out.comparisons[0].identity).toBe("bob");
    expect(out.comparisons[0].broken).toBe(true);
    expect(out.comparisons[0].verdict).toBe("broken_object_level_authorization");
    // A-vs-B evidence is present for the finding.
    expect(out.baseline.evidence.response.bodyPreview).toContain("alice");
    expect(out.comparisons[0].evidence.response.bodyPreview).toContain("alice");
    // Two requests: one as alice (baseline), one as bob.
    expect(fetchScoped).toHaveBeenCalledTimes(2);
  });

  it("reports no break when the server correctly denies identity B", async () => {
    vi.mocked(fetchScoped).mockImplementation(async (url: string, init: RequestInit) => {
      const auth = (init.headers as Record<string, string> | undefined)?.Authorization ?? "";
      if (auth.includes("alice-tok")) {
        return new Response('{"id":1,"owner":"alice"}', {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("Forbidden", { status: 403 });
    });

    const ex = new ToolExecutor(ctxWithIdentities(TWO_IDENTITIES), null);
    const result = await ex.execute({
      name: "access_control_probe",
      arguments: { url: RESOURCE, baseline_identity: "alice", compare_identities: ["bob"] },
    });

    expect(result.success).toBe(true);
    const out = result.output as Record<string, any>;
    expect(out.verdict).toBe("no_break_detected");
    expect(out.broken_count).toBe(0);
    expect(out.comparisons[0].verdict).toBe("properly_denied");
  });

  it("errors out when fewer than 2 identities are configured", async () => {
    const ex = new ToolExecutor(
      ctxWithIdentities([{ label: "solo", auth: { type: "bearer", token: "x" } }]),
      null,
    );
    const result = await ex.execute({
      name: "access_control_probe",
      arguments: { url: RESOURCE },
    });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/at least 2 identities/);
  });

  it("persists a Set-Cookie across http_request calls (stateful session, no manual jar)", async () => {
    const sent: Array<Record<string, string>> = [];
    let call = 0;
    vi.mocked(fetchScoped).mockImplementation(async (_url: string, init: RequestInit) => {
      sent.push({ ...(init.headers as Record<string, string>) });
      call += 1;
      const respHeaders: Record<string, string> = call === 1
        ? { "content-type": "text/html", "set-cookie": "sid=server-issued; Path=/" }
        : { "content-type": "text/html" };
      return new Response("ok", { status: 200, headers: respHeaders });
    });

    const ex = new ToolExecutor(
      ctxWithIdentities([{ label: "alice", auth: { type: "bearer", token: "alice-tok" } }, { label: "bob" }]),
      null,
    );
    // First request (active = alice) captures the Set-Cookie.
    await ex.execute({ name: "http_request", arguments: { url: RESOURCE, method: "GET" } });
    // Second request re-injects the captured cookie automatically.
    await ex.execute({ name: "http_request", arguments: { url: `${TARGET}/api/users/2`, method: "GET" } });

    expect(sent[0].Cookie).toBeUndefined();
    expect(sent[1].Cookie).toBe("sid=server-issued");
    // Static credential still present on both.
    expect(sent[0].Authorization).toBe("Bearer alice-tok");
    expect(sent[1].Authorization).toBe("Bearer alice-tok");
  });

  it("sends each identity its OWN credential when replaying", async () => {
    const seenAuth: string[] = [];
    vi.mocked(fetchScoped).mockImplementation(async (_url: string, init: RequestInit) => {
      seenAuth.push(((init.headers as Record<string, string>)?.Authorization as string) ?? "");
      return new Response('{"id":1}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const ex = new ToolExecutor(ctxWithIdentities(TWO_IDENTITIES), null);
    await ex.execute({
      name: "access_control_probe",
      arguments: { url: RESOURCE, baseline_identity: "alice", compare_identities: ["bob"] },
    });
    expect(seenAuth).toContain("Bearer alice-tok");
    expect(seenAuth).toContain("Bearer bob-tok");
  });
});
