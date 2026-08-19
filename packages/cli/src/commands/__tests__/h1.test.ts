/**
 * `pwnkit h1` CLI smoke tests. We register the command on a fresh
 * Commander program, install a fake `fetch` global so the action talks
 * to a stubbed H1 API, then `parseAsync` the same argv the user would
 * type. Exit codes are observed via `process.exitCode`; stdout/stderr
 * are captured via spies.
 *
 * This is NOT meant to re-test the H1 client's transport layer (that's
 * `packages/core/src/h1/client.test.ts`). It's the CLI-shape test:
 * argv → exit code → stdout shape → token-leak invariant.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { registerH1Command } from "../h1.js";

const SECRET = "S3CR3T_TOKEN_DO_NOT_LEAK_999";
const ID = "pwnkit-test";

interface CapturedIO {
  stdout: string[];
  stderr: string[];
  exitCode: number | undefined;
}

function setupHomeWithCreds(): string {
  const home = mkdtempSync(join(tmpdir(), "pwnkit-h1-cli-"));
  mkdirSync(join(home, ".pwnkit"), { recursive: true, mode: 0o700 });
  const path = join(home, ".pwnkit", "h1.env");
  writeFileSync(path, `H1_API_IDENTIFIER=${ID}\nH1_API_TOKEN=${SECRET}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return home;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function captureIO(): CapturedIO & { restore: () => void } {
  const captured: CapturedIO = { stdout: [], stderr: [], exitCode: undefined };
  const stdoutSpy = vi.spyOn(console, "log").mockImplementation((...args) => {
    captured.stdout.push(args.map((a) => String(a)).join(" "));
  });
  const stderrSpy = vi.spyOn(console, "error").mockImplementation((...args) => {
    captured.stderr.push(args.map((a) => String(a)).join(" "));
  });
  return {
    ...captured,
    get stdout() {
      return captured.stdout;
    },
    get stderr() {
      return captured.stderr;
    },
    get exitCode() {
      return captured.exitCode;
    },
    restore: () => {
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
    },
  };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerH1Command(program);
  await program.parseAsync(["node", "pwnkit-cli", ...argv]);
}

describe("pwnkit h1 — exit codes", () => {
  let home: string;
  let originalHome: string | undefined;
  let originalEnvId: string | undefined;
  let originalEnvTok: string | undefined;
  let originalFetch: typeof globalThis.fetch;
  let io: ReturnType<typeof captureIO>;

  beforeEach(() => {
    home = setupHomeWithCreds();
    originalHome = process.env.HOME;
    originalEnvId = process.env.H1_API_IDENTIFIER;
    originalEnvTok = process.env.H1_API_TOKEN;
    process.env.HOME = home;
    delete process.env.H1_API_IDENTIFIER;
    delete process.env.H1_API_TOKEN;
    process.exitCode = undefined;
    originalFetch = globalThis.fetch;
    io = captureIO();
  });

  afterEach(() => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalEnvId !== undefined) process.env.H1_API_IDENTIFIER = originalEnvId;
    if (originalEnvTok !== undefined) process.env.H1_API_TOKEN = originalEnvTok;
    globalThis.fetch = originalFetch;
    process.exitCode = undefined;
    io.restore();
  });

  it("auth: prints OK with identifier on 200, exit 0", async () => {
    globalThis.fetch = (async () =>
      jsonResponse({ data: { id: ID, type: "balance", attributes: {} } })) as typeof fetch;
    await runCli(["h1", "auth"]);
    expect(process.exitCode).toBe(0);
    expect(io.stdout.join("\n")).toContain(`OK (identifier=${ID})`);
    expect(io.stdout.join("\n") + io.stderr.join("\n")).not.toContain(SECRET);
  });

  it("auth: exit 2 on 401, stderr does NOT contain token", async () => {
    globalThis.fetch = (async () => new Response("nope", { status: 401 })) as typeof fetch;
    await runCli(["h1", "auth"]);
    expect(process.exitCode).toBe(2);
    expect(io.stderr.join("\n")).toContain("FAIL (HTTP 401)");
    const allOutput = io.stdout.join("\n") + io.stderr.join("\n");
    expect(allOutput).not.toContain(SECRET);
  });

  it("programs list: exit 1 when --bounty and --vdp both set", async () => {
    globalThis.fetch = (async () => jsonResponse({ data: [], links: {} })) as typeof fetch;
    await runCli(["h1", "programs", "list", "--bounty", "--vdp"]);
    expect(process.exitCode).toBe(1);
    expect(io.stderr.join("\n")).toContain("mutually exclusive");
  });

  it("programs list: rejects --limit > 1000", async () => {
    globalThis.fetch = (async () => jsonResponse({ data: [], links: {} })) as typeof fetch;
    await runCli(["h1", "programs", "list", "--limit", "5000"]);
    expect(process.exitCode).toBe(1);
    expect(io.stderr.join("\n")).toMatch(/cannot exceed 1000/);
  });

  it("programs list: --json emits compact JSON, never prints token", async () => {
    globalThis.fetch = (async () =>
      jsonResponse({
        data: [
          {
            id: "1",
            type: "program",
            attributes: { handle: "demo", name: "Demo Inc", state: "public_mode", offers_bounties: true, currency: "USD" },
          },
        ],
        links: {},
      })) as typeof fetch;
    await runCli(["h1", "programs", "list", "--json", "--limit", "5"]);
    expect(process.exitCode).toBe(0);
    const out = io.stdout.join("\n");
    const parsed = JSON.parse(out.match(/\[[\s\S]*\]/)![0]);
    expect(parsed[0].handle).toBe("demo");
    expect(parsed[0].state).toBe("public_mode");
    expect(out + io.stderr.join("\n")).not.toContain(SECRET);
  });

  it("programs show: prints scope summary and automation verdict", async () => {
    let calls = 0;
    globalThis.fetch = (async (url: string | URL | Request) => {
      const u = String(url);
      calls += 1;
      if (u.endsWith("/structured_scopes") || u.includes("/structured_scopes?")) {
        return jsonResponse({
          data: [
            {
              id: "1",
              type: "structured-scope",
              attributes: { asset_type: "URL", asset_identifier: "api.demo.com", eligible_for_submission: true },
            },
          ],
          links: {},
        });
      }
      return jsonResponse({
        data: {
          id: "1",
          type: "program",
          attributes: { handle: "demo", name: "Demo Inc", state: "public_mode", offers_bounties: true, currency: "USD", policy: "no automated scanners" },
        },
      });
    }) as typeof fetch;
    await runCli(["h1", "programs", "show", "demo"]);
    expect(process.exitCode).toBe(0);
    expect(calls).toBeGreaterThanOrEqual(2);
    const out = io.stdout.join("\n");
    expect(out).toContain("Demo Inc");
    expect(out).toContain("Scope summary");
    expect(out).toContain("forbidden");
    expect(out + io.stderr.join("\n")).not.toContain(SECRET);
  });

  // ── Automation-verdict fixtures (issue #266) ──
  //
  // The verdict heuristic over a free-form policy string is the bit
  // operators trust to gate "should I dispatch a scan against this
  // program?". The pre-#266 version stopped at the first negative
  // keyword and over-flagged programs that explicitly carved out a
  // contrast clause re-permitting targeted automation.
  //
  // We exercise four shapes through the full CLI so the test catches
  // breakage in either the core regex OR the CLI's verdict-formatter.
  function stubProgramShow(policyText: string): void {
    globalThis.fetch = (async (url: string | URL | Request) => {
      const u = String(url);
      if (u.endsWith("/structured_scopes") || u.includes("/structured_scopes?")) {
        return jsonResponse({ data: [], links: {} });
      }
      return jsonResponse({
        data: {
          id: "1",
          type: "program",
          attributes: {
            handle: "fixture",
            name: "Fixture Program",
            state: "public_mode",
            offers_bounties: true,
            currency: "USD",
            policy: policyText,
          },
        },
      });
    }) as typeof fetch;
  }

  it("programs show — Flutter UK&I-shaped contrast clause → mixed (#266)", async () => {
    stubProgramShow(
      "Don't use common vulnerability scanners. The search for vulnerabilities should be manual, although custom tools with automated requests are allowed if limited to 5 requests per second.",
    );
    await runCli(["h1", "programs", "show", "fixture"]);
    expect(process.exitCode).toBe(0);
    const out = io.stdout.join("\n");
    expect(out).toContain("Automation verdict");
    expect(out).toContain("mixed");
    // The pre-fix heuristic emitted "forbidden" for this fixture.
    // Make sure we didn't regress.
    expect(out).not.toMatch(/Automation verdict[^\n]*forbidden/);
    // Operators should be told to read the policy in this case.
    expect(out).toMatch(/policy/i);
  });

  it("programs show — pure-forbidden fixture → forbidden", async () => {
    stubProgramShow(
      "No automated tools or scanners are allowed on production. Reports based on scanner output will be closed as N/A.",
    );
    await runCli(["h1", "programs", "show", "fixture"]);
    expect(process.exitCode).toBe(0);
    const out = io.stdout.join("\n");
    expect(out).toMatch(/Automation verdict[^\n]*forbidden/);
  });

  it("programs show — pure-permitted fixture → permitted", async () => {
    stubProgramShow("Automated testing is welcome. Please rate-limit to 10 requests per second.");
    await runCli(["h1", "programs", "show", "fixture"]);
    expect(process.exitCode).toBe(0);
    const out = io.stdout.join("\n");
    expect(out).toMatch(/Automation verdict[^\n]*permitted/);
    expect(out).not.toMatch(/Automation verdict[^\n]*forbidden/);
  });

  it("programs show — silent fixture (no automation keywords) → unclear", async () => {
    stubProgramShow("Welcome researchers. We pay bounties for high-quality reports.");
    await runCli(["h1", "programs", "show", "fixture"]);
    expect(process.exitCode).toBe(0);
    const out = io.stdout.join("\n");
    expect(out).toMatch(/Automation verdict[^\n]*unclear/);
  });

  it("scope dump: writes scope file under custom --out and prints path", async () => {
    globalThis.fetch = (async (url: string | URL | Request) => {
      const u = String(url);
      if (u.endsWith("/structured_scopes") || u.includes("/structured_scopes?")) {
        return jsonResponse({
          data: [
            {
              id: "1",
              type: "structured-scope",
              attributes: { asset_type: "URL", asset_identifier: "api.demo.com", eligible_for_submission: true },
            },
            {
              id: "2",
              type: "structured-scope",
              attributes: { asset_type: "WILDCARD", asset_identifier: "*.demo.com", eligible_for_submission: true },
            },
          ],
          links: {},
        });
      }
      return jsonResponse({
        data: { id: "1", type: "program", attributes: { handle: "demo", name: "Demo" } },
      });
    }) as typeof fetch;
    const out = join(home, "out.json");
    await runCli(["h1", "scope", "dump", "demo", "--out", out]);
    expect(process.exitCode).toBe(0);
    expect(io.stdout.join("\n")).toContain(out);
    // Round-trip the file through loadScope to confirm conformance.
    const { loadScope } = await import("@pwnkit/core");
    const policy = loadScope(out);
    expect(policy.match("https://api.demo.com/").allowed).toBe(true);
    expect(policy.match("https://x.demo.com/").allowed).toBe(true);
  });
});
