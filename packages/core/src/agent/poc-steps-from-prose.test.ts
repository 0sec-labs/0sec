import { describe, it, expect } from "vitest";
import { extractPocStepsFromProse } from "./poc-steps-from-prose.js";

describe("extractPocStepsFromProse", () => {
  // ── HTTP-only path (paperclip-style auth-gap) ───────────────────────────

  it("extracts a 3-step graph from an HTTP request + 200 response + analysis", () => {
    const steps = extractPocStepsFromProse({
      request: "GET /admin/users HTTP/1.1\nHost: target.example",
      response: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n[{\"id\":1}]",
      analysis: "Authenticated admin endpoint exposed without an auth check.",
    });

    expect(steps).toBeDefined();
    expect(steps).toHaveLength(3);
    const [setup, exploit, verify] = steps!;

    expect(setup.kind).toBe("setup");
    expect(setup.action).toEqual({
      type: "note",
      text: "Authenticated admin endpoint exposed without an auth check.",
    });

    expect(exploit.kind).toBe("exploit");
    expect(exploit.action).toEqual({
      type: "http",
      method: "GET",
      url: "/admin/users",
    });

    expect(verify.kind).toBe("verify");
    expect(verify.action).toEqual({
      type: "http",
      method: "GET",
      url: "/admin/users",
    });
    expect(verify.expect).toEqual({ type: "http-status", status: 200 });
  });

  it("handles HTTP request lines without HTTP/1.1 suffix", () => {
    const steps = extractPocStepsFromProse({
      request: "POST /api/login",
      response: "HTTP/1.1 401 Unauthorized",
    });
    expect(steps).toBeDefined();
    expect(steps!.length).toBe(2);
    expect(steps![0].action).toEqual({
      type: "http",
      method: "POST",
      url: "/api/login",
    });
    expect(steps![1].expect).toEqual({ type: "http-status", status: 401 });
  });

  it("classifies prerequisite-flavoured analysis prose as 'prerequisite'", () => {
    const steps = extractPocStepsFromProse({
      request: "GET /admin",
      response: "HTTP/1.1 200 OK",
      analysis: "Requires a valid session cookie from any low-priv user.",
    });
    expect(steps).toBeDefined();
    expect(steps!.find((s) => s.id === "setup")?.kind).toBe("prerequisite");
  });

  // ── Shell-only path (command injection) ─────────────────────────────────

  it("extracts a 2-step graph from a shell snippet + observed output", () => {
    const steps = extractPocStepsFromProse({
      request: "curl http://target/?q=$(id)",
      response: "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    });

    expect(steps).toBeDefined();
    expect(steps).toHaveLength(2);
    const [exploit, verify] = steps!;

    expect(exploit.kind).toBe("exploit");
    expect(exploit.action).toEqual({
      type: "shell",
      cmd: "curl http://target/?q=$(id)",
    });

    expect(verify.kind).toBe("verify");
    expect(verify.expect).toEqual({
      type: "body-contains",
      text: "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    });
  });

  it("strips $ shell prompts from request prose", () => {
    const steps = extractPocStepsFromProse({
      request: "$ curl https://target/exploit",
      response: "flag{abc}",
    });
    expect(steps).toBeDefined();
    expect(steps![0].action).toEqual({
      type: "shell",
      cmd: "curl https://target/exploit",
    });
  });

  // ── Conservative skip cases ─────────────────────────────────────────────

  it("returns undefined for pure-prose findings with no parseable signals", () => {
    const result = extractPocStepsFromProse({
      request: "We checked the page and found a bug.",
      response: "The server returned something interesting.",
      analysis: "We think there's an information leak.",
    });
    expect(result).toBeUndefined();
  });

  it("returns undefined when only analysis prose is present", () => {
    const result = extractPocStepsFromProse({
      analysis: "Some narrative without an exploit or response.",
    });
    expect(result).toBeUndefined();
  });

  it("returns undefined for an empty input", () => {
    expect(extractPocStepsFromProse({})).toBeUndefined();
    expect(extractPocStepsFromProse({ request: "", response: "" })).toBeUndefined();
  });

  it("skips malformed HTTP request lines (no method match)", () => {
    const result = extractPocStepsFromProse({
      request: "GETTING /admin",
      response: "HTTP/1.1 200 OK",
    });
    expect(result).toBeUndefined();
  });

  it("skips HTTP request lines with whitespace in URL", () => {
    const result = extractPocStepsFromProse({
      request: "GET /admin users",
      response: "HTTP/1.1 200 OK",
    });
    expect(result).toBeUndefined();
  });

  it("skips a partial response with no status line", () => {
    // HTTP exploit + response with no parseable status → no verify possible,
    // and a lone exploit is below the 2-step threshold.
    const result = extractPocStepsFromProse({
      request: "GET /admin",
      response: "{\"users\": []}",
    });
    expect(result).toBeUndefined();
  });

  it("skips a sentence that mentions curl but isn't a command", () => {
    const result = extractPocStepsFromProse({
      request: "curl returned 200",
      response: "HTTP/1.1 200 OK",
    });
    expect(result).toBeUndefined();
  });

  it("skips out-of-range status codes", () => {
    const result = extractPocStepsFromProse({
      request: "GET /admin",
      response: "HTTP/1.1 999 Bogus",
    });
    expect(result).toBeUndefined();
  });

  it("skips a shell exploit with no usable observation in response", () => {
    const result = extractPocStepsFromProse({
      request: "curl http://target/x",
      response: "The response showed nothing useful.",
    });
    expect(result).toBeUndefined();
  });

  it("does not synthesise a setup note when no exploit step is found", () => {
    const result = extractPocStepsFromProse({
      analysis: "This setup line should never become a lone note.",
      response: "HTTP/1.1 200 OK",
    });
    expect(result).toBeUndefined();
  });

  it("prefers HTTP request line over shell snippet when both appear", () => {
    const steps = extractPocStepsFromProse({
      request: "GET /admin\ncurl http://target/admin",
      response: "HTTP/1.1 200 OK",
    });
    expect(steps).toBeDefined();
    expect(steps![0].action).toEqual({
      type: "http",
      method: "GET",
      url: "/admin",
    });
  });

  it("truncates very long shell command summaries", () => {
    const longCmd = `curl https://target.example/${"A".repeat(200)}`;
    const steps = extractPocStepsFromProse({
      request: longCmd,
      response: "uid=0",
    });
    expect(steps).toBeDefined();
    expect(steps![0].summary.length).toBeLessThanOrEqual(120);
  });

  it("issues stable step ids (setup/exploit/verify) for screenshot rendering", () => {
    const steps = extractPocStepsFromProse({
      request: "GET /admin",
      response: "HTTP/1.1 200 OK",
      analysis: "Admin page exposed.",
    });
    expect(steps).toBeDefined();
    expect(steps!.map((s) => s.id)).toEqual(["setup", "exploit", "verify"]);
  });
});
