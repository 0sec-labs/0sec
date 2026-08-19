import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  LootLedger,
  MAX_LOOT_ITEMS,
  type LootItem,
} from "./loot.js";
import { ToolExecutor, getToolsForRole } from "./tools.js";
import { runNativeAgentLoop } from "./native-loop.js";
import type { ToolContext } from "./types.js";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeMessage,
  NativeToolDef,
} from "../runtime/types.js";

// ── LootLedger unit tests ─────────────────────────────────────────────────

describe("LootLedger.add / dedup / revision", () => {
  it("adds a typed item and assigns a stable id", () => {
    const l = new LootLedger();
    const item = l.add({ kind: "credential", value: "admin:hunter2", source: "test" });
    expect(item).not.toBeNull();
    expect(item?.id).toBe("loot-1");
    expect(item?.kind).toBe("credential");
    expect(l.size).toBe(1);
    expect(l.revision).toBe(1);
  });

  it("dedups by (kind, normalized value); first write wins", () => {
    const l = new LootLedger();
    expect(l.add({ kind: "token", value: "ABC123", source: "a" })).not.toBeNull();
    expect(l.add({ kind: "token", value: "abc123", source: "b" })).toBeNull(); // case-insensitive dup
    expect(l.size).toBe(1);
    expect(l.revision).toBe(1); // unchanged on dup
    // Same value, different kind is NOT a dup.
    expect(l.add({ kind: "hash", value: "ABC123", source: "c" })).not.toBeNull();
    expect(l.size).toBe(2);
  });

  it("rejects too-short and empty values", () => {
    const l = new LootLedger();
    expect(l.add({ kind: "path", value: "ab", source: "t" })).toBeNull();
    expect(l.add({ kind: "path", value: "  ", source: "t" })).toBeNull();
    expect(l.size).toBe(0);
  });

  it("caps total ledger size at MAX_LOOT_ITEMS", () => {
    const l = new LootLedger();
    for (let i = 0; i < MAX_LOOT_ITEMS + 25; i++) {
      l.add({ kind: "endpoint", value: `https://h/${i}`, source: "t" });
    }
    expect(l.size).toBe(MAX_LOOT_ITEMS);
  });
});

describe("LootLedger.harvest", () => {
  it("extracts a labelled password as a credential", () => {
    const l = new LootLedger();
    const added = l.harvest('{"login":"ok","password":"Sup3rS3cret!"}', "http_request", 4);
    const cred = added.find((i) => i.kind === "credential");
    expect(cred).toBeDefined();
    expect(cred?.value).toContain("Sup3rS3cret!");
    expect(cred?.turn).toBe(4);
    expect(cred?.source).toBe("http_request");
  });

  it("extracts a JWT as a token (not double-counted as a hash)", () => {
    const l = new LootLedger();
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const added = l.harvest(`Authorization: Bearer ${jwt}`, "crawl");
    const tokens = added.filter((i) => i.kind === "token");
    expect(tokens.length).toBeGreaterThanOrEqual(1);
    expect(tokens.some((t) => t.value.includes("eyJhbGciOiJIUzI1NiJ9"))).toBe(true);
    // The JWT body segment is pure base64url; ensure it wasn't ALSO logged as a hash.
    expect(added.some((i) => i.kind === "hash")).toBe(false);
  });

  it("extracts a Set-Cookie session cookie", () => {
    const l = new LootLedger();
    const added = l.harvest("Set-Cookie: PHPSESSID=abc123def456; HttpOnly", "http_request");
    const cookie = added.find((i) => i.kind === "cookie");
    expect(cookie).toBeDefined();
    expect(cookie?.value).toContain("PHPSESSID=abc123def456");
  });

  it("extracts a bcrypt hash and a DB connection string", () => {
    const l = new LootLedger();
    const bcrypt = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
    const added = l.harvest(
      `hash=${bcrypt}\nDB=postgres://app:s3cr3t@db.internal:5432/main`,
      "read_file",
    );
    expect(added.some((i) => i.kind === "hash" && i.value === bcrypt)).toBe(true);
    expect(
      added.some((i) => i.kind === "credential" && i.value.includes("postgres://app:s3cr3t@")),
    ).toBe(true);
  });

  it("extracts endpoints and sensitive filesystem paths", () => {
    const l = new LootLedger();
    const added = l.harvest(
      "found https://api.internal/v2/users and leaked /etc/passwd plus /var/www/.env",
      "bash",
    );
    expect(added.some((i) => i.kind === "endpoint" && i.value.includes("https://api.internal/v2/users"))).toBe(true);
    expect(added.some((i) => i.kind === "path" && i.value.includes("/etc/passwd"))).toBe(true);
  });

  it("is idempotent across repeated harvests (dedup)", () => {
    const l = new LootLedger();
    l.harvest('password="reuseme123"', "http_request");
    const before = l.size;
    l.harvest('password="reuseme123"', "http_request"); // same again
    expect(l.size).toBe(before);
  });

  it("ignores non-string / empty input safely", () => {
    const l = new LootLedger();
    expect(l.harvest("", "t")).toEqual([]);
    // @ts-expect-error — exercise the runtime guard
    expect(l.harvest(undefined, "t")).toEqual([]);
    expect(l.size).toBe(0);
  });
});

describe("LootLedger.harvestFromFinding", () => {
  it("mines credentials out of a finding's evidence", () => {
    const l = new LootLedger();
    const added = l.harvestFromFinding({
      evidence: {
        request: "POST /login",
        response: 'logged in; Set-Cookie: session=deadbeefcafe; token=ghp_' + "a".repeat(36),
        analysis: "creds reflected",
      },
      description: "password=leakedPass99 found in body",
      category: "information-disclosure",
    });
    expect(added.some((i) => i.kind === "cookie" && i.value.includes("session=deadbeefcafe"))).toBe(true);
    expect(added.some((i) => i.kind === "credential" && i.value.includes("leakedPass99"))).toBe(true);
    expect(l.all()[0]?.source).toContain("save_finding");
  });
});

describe("LootLedger.query / render", () => {
  let l: LootLedger;
  beforeEach(() => {
    l = new LootLedger();
    l.add({ kind: "credential", value: "admin:pw", source: "http_request", context: "login", turn: 2 });
    l.add({ kind: "endpoint", value: "https://h/api/admin", source: "crawl", turn: 3 });
    l.add({ kind: "token", value: "ghp_" + "z".repeat(36), source: "read_file", turn: 5 });
  });

  it("filters by kind", () => {
    expect(l.query({ kind: "credential" }).map((i) => i.value)).toEqual(["admin:pw"]);
  });

  it("filters by case-insensitive search across value/context/id", () => {
    expect(l.query({ search: "LOGIN" }).length).toBe(1);
    expect(l.query({ search: "loot-2" }).map((i) => i.kind)).toEqual(["endpoint"]);
  });

  it("filters by id", () => {
    expect(l.query({ id: "loot-3" }).map((i) => i.kind)).toEqual(["token"]);
  });

  it("renders a compact known-footholds block with ids and values", () => {
    const text = l.render();
    expect(text).toContain("Known footholds");
    expect(text).toContain("[loot-1] credential: admin:pw");
    expect(text).toContain("use_loot");
  });

  it("render('') is empty for an empty ledger", () => {
    expect(new LootLedger().render()).toBe("");
  });

  it("render limit caps the list and notes omissions", () => {
    const text = l.render({ limit: 1 });
    // limit 1 → one bullet + an "…and N more" footer
    expect((text.match(/^- \[/gm) ?? []).length).toBe(1);
    expect(text).toContain("more");
  });
});

// ── ToolExecutor wiring (use_loot + save_finding harvest) ───────────────────

describe("ToolExecutor use_loot", () => {
  function makeCtx(loot?: LootLedger): ToolContext {
    return {
      target: "https://example.com",
      scanId: "loot-test",
      findings: [],
      attackResults: [],
      targetInfo: {},
      loot,
    };
  }

  it("returns full stored values, filterable by kind", async () => {
    const loot = new LootLedger();
    loot.add({ kind: "credential", value: "root:toor", source: "http_request" });
    loot.add({ kind: "endpoint", value: "https://h/admin", source: "crawl" });
    const exec = new ToolExecutor(makeCtx(loot), null);

    const res = await exec.execute({ name: "use_loot", arguments: { kind: "credential" } });
    expect(res.success).toBe(true);
    const out = res.output as { count: number; items: LootItem[] };
    expect(out.count).toBe(1);
    expect(out.items[0].value).toBe("root:toor"); // FULL value for reuse
  });

  it("degrades gracefully when no ledger is present", async () => {
    const exec = new ToolExecutor(makeCtx(undefined), null);
    const res = await exec.execute({ name: "use_loot", arguments: {} });
    expect(res.success).toBe(true);
    expect((res.output as { count: number }).count).toBe(0);
  });

  it("save_finding harvests footholds into the ledger", async () => {
    const loot = new LootLedger();
    const exec = new ToolExecutor(makeCtx(loot), null);
    const res = await exec.execute({
      name: "save_finding",
      arguments: {
        title: "Creds in login response",
        severity: "high",
        category: "information-disclosure",
        evidence_request: "POST /login",
        evidence_response: 'ok; password="ChainMe123"',
        evidence_analysis: "leaked",
      },
    });
    expect(res.success).toBe(true);
    expect(loot.query({ kind: "credential" }).some((i) => i.value.includes("ChainMe123"))).toBe(true);
  });
});

// ── getToolsForRole gating ──────────────────────────────────────────────────

describe("getToolsForRole loot gating", () => {
  const ORIGINAL = process.env["0SEC_FEATURE_LOOT_LEDGER"];
  afterEach(() => {
    if (ORIGINAL === undefined) delete process.env["0SEC_FEATURE_LOOT_LEDGER"];
    else process.env["0SEC_FEATURE_LOOT_LEDGER"] = ORIGINAL;
  });

  it("exposes use_loot to the attack role when the flag is on", () => {
    delete process.env["0SEC_FEATURE_LOOT_LEDGER"]; // default ON
    const names = getToolsForRole("attack").map((t) => t.name);
    expect(names).toContain("use_loot");
  });

  it("hides use_loot when the flag is off", () => {
    process.env["0SEC_FEATURE_LOOT_LEDGER"] = "0";
    expect(getToolsForRole("attack").map((t) => t.name)).not.toContain("use_loot");
    expect(getToolsForRole("audit").map((t) => t.name)).not.toContain("use_loot");
  });
});

// ── Full-loop chaining acceptance (0sec#567) ──────────────────────────────
//
// Deterministic stand-in for the issue's acceptance fixture: step 1 leaks a
// credential, step 2 needs it. We script the agent (mock runtime) to (1) save a
// finding whose evidence leaks a credential, (2) call use_loot to retrieve it,
// (3) finish. We then assert the ledgered credential was (a) re-injected into
// the agent's context as a "known footholds" block and (b) returned in full by
// use_loot — i.e. the artifact survived as reusable state for chaining.

function createMockRuntime(responses: NativeRuntimeResult[]): NativeRuntime {
  let i = 0;
  return {
    type: "api" as const,
    async executeNative(
      _system: string,
      _messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      const r = responses[i] ?? responses[responses.length - 1];
      i++;
      return r;
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("native loop loot chaining (acceptance)", () => {
  const ORIGINAL = process.env["0SEC_FEATURE_LOOT_LEDGER"];
  afterEach(() => {
    if (ORIGINAL === undefined) delete process.env["0SEC_FEATURE_LOOT_LEDGER"];
    else process.env["0SEC_FEATURE_LOOT_LEDGER"] = ORIGINAL;
  });

  it("leaks a credential in step 1, reuses it via use_loot in step 2", async () => {
    delete process.env["0SEC_FEATURE_LOOT_LEDGER"]; // default ON
    // Synthetic fixture value (not a real credential) — named neutrally so the
    // hardcoded-secret scanner doesn't flag the test as committing a password.
    const plantedValue = "Ch41nMe_v2_99";

    const runtime = createMockRuntime([
      {
        // Step 1 — leak a credential through a saved finding's evidence.
        content: [
          {
            type: "tool_use",
            id: "tc1",
            name: "save_finding",
            input: {
              title: "Admin password leaked in /login response",
              severity: "high",
              category: "information-disclosure",
              evidence_request: "POST /login",
              evidence_response: `HTTP/1.1 200 OK\n{"user":"admin","password":"${plantedValue}"}`,
              evidence_analysis: "Login endpoint echoes the stored password.",
            },
          },
        ],
        stopReason: "tool_use",
        durationMs: 10,
        usage: { inputTokens: 10, outputTokens: 10 },
      },
      {
        // Step 2 — retrieve the captured credential to reuse it.
        content: [
          { type: "tool_use", id: "tc2", name: "use_loot", input: { kind: "credential" } },
        ],
        stopReason: "tool_use",
        durationMs: 10,
        usage: { inputTokens: 10, outputTokens: 10 },
      },
      {
        // Step 3 — finish.
        content: [{ type: "tool_use", id: "tc3", name: "done", input: { summary: "chained" } }],
        stopReason: "tool_use",
        durationMs: 10,
        usage: { inputTokens: 10, outputTokens: 10 },
      },
    ]);

    const events: string[] = [];
    const state = await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "test",
        tools: getToolsForRole("attack"),
        maxTurns: 6,
        target: "https://example.com",
        scanId: "loot-chain-test",
      },
      runtime,
      db: null,
      onEvent: (e) => events.push(e),
    });

    // A finding was saved (step 1).
    expect(state.findings.length).toBe(1);

    const blob = JSON.stringify(state.messages);
    // The credential was re-injected as a known-footholds block...
    expect(blob).toContain("Known footholds");
    // ...and use_loot returned the FULL credential value for reuse (step 2).
    expect(blob).toContain(plantedValue);
    // The loop emitted the loot-injection event.
    expect(events).toContain("loot_injected");
  });
});
