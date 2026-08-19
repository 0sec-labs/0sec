import { describe, it, expect } from "vitest";
import { CookieJar, SessionEngine } from "./session.js";
import type { NamedIdentity } from "@pwnkit/shared";

const URL_A = "https://target.example.com/api/users/1";
const URL_SAME_HOST = "https://target.example.com/admin";

describe("CookieJar (pwnkit#564)", () => {
  it("captures Set-Cookie and re-injects it as a Cookie header for the same host", () => {
    const jar = new CookieJar();
    jar.ingest(["session=abc123; Path=/; HttpOnly"], URL_A);
    expect(jar.header(URL_A)).toBe("session=abc123");
    // same host, different path → still sent (flat host-scoped jar)
    expect(jar.header(URL_SAME_HOST)).toBe("session=abc123");
  });

  it("merges multiple cookies and is last-write-wins per name", () => {
    const jar = new CookieJar();
    jar.ingest(["a=1", "b=2"], URL_A);
    jar.ingest(["a=9"], URL_A);
    const header = jar.header(URL_A);
    expect(header).toContain("a=9");
    expect(header).toContain("b=2");
    expect(header).not.toContain("a=1");
  });

  it("does not leak cookies across hosts", () => {
    const jar = new CookieJar();
    jar.ingest(["session=abc"], URL_A);
    expect(jar.header("https://other.example.org/x")).toBe("");
  });

  it("deletes a cookie when the value is emptied", () => {
    const jar = new CookieJar();
    jar.ingest(["session=abc"], URL_A);
    jar.ingest(["session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"], URL_A);
    expect(jar.header(URL_A)).toBe("");
  });

  it("deletes a cookie on Max-Age=0", () => {
    const jar = new CookieJar();
    jar.ingest(["session=abc"], URL_A);
    jar.ingest(["session=abc; Max-Age=0"], URL_A);
    expect(jar.header(URL_A)).toBe("");
  });

  it("parses a comma-folded multi-cookie Set-Cookie line with an Expires date", () => {
    const jar = new CookieJar();
    // Two cookies folded into one string; the comma inside the Expires date
    // must NOT be treated as a cookie boundary.
    jar.ingest(
      ["sid=xyz; Expires=Wed, 09 Jun 2099 10:18:14 GMT; Path=/, csrf=tok; Path=/"],
      URL_A,
    );
    const names = jar.names(URL_A).sort();
    expect(names).toEqual(["csrf", "sid"]);
    expect(jar.header(URL_A)).toContain("sid=xyz");
    expect(jar.header(URL_A)).toContain("csrf=tok");
  });

  it("clearHost drops only the targeted host", () => {
    const jar = new CookieJar();
    jar.ingest(["session=abc"], URL_A);
    jar.clearHost(URL_A);
    expect(jar.header(URL_A)).toBe("");
  });
});

describe("SessionEngine (pwnkit#564)", () => {
  const identities: NamedIdentity[] = [
    { label: "admin", role: "admin", auth: { type: "bearer", token: "admin-tok" } },
    { label: "alice", role: "user", auth: { type: "cookie", value: "static=alice" } },
    { label: "anon", role: "anonymous" },
  ];

  it("defaults the active identity to the first and exposes labels in order", () => {
    const engine = new SessionEngine(identities);
    expect(engine.activeLabel).toBe("admin");
    expect(engine.labels).toEqual(["admin", "alice", "anon"]);
  });

  it("throws when constructed with no identities", () => {
    expect(() => new SessionEngine([])).toThrow();
  });

  it("builds static auth headers per identity", () => {
    const engine = new SessionEngine(identities);
    expect(engine.headersFor("admin", URL_A)).toEqual({ Authorization: "Bearer admin-tok" });
    expect(engine.headersFor("anon", URL_A)).toEqual({}); // unauthenticated
  });

  it("merges a static Cookie credential with jar-captured cookies", () => {
    const engine = new SessionEngine(identities);
    engine.capture("alice", ["session=fresh"], URL_A);
    const headers = engine.headersFor("alice", URL_A);
    expect(headers.Cookie).toBe("static=alice; session=fresh");
  });

  it("captures cookies per-identity and keeps jars isolated", () => {
    const engine = new SessionEngine(identities);
    engine.capture("admin", ["session=adminsid"], URL_A);
    expect(engine.headersFor("admin", URL_A).Cookie).toBe("session=adminsid");
    // alice never captured a `session` cookie
    expect(engine.headersFor("alice", URL_A).Cookie).toBe("static=alice");
  });

  it("drops stale captured cookies on 401/403 (re-auth to static credential)", () => {
    const engine = new SessionEngine(identities);
    engine.capture("admin", ["session=adminsid"], URL_A);
    const dropped = engine.handleAuthStatus("admin", 401, URL_A);
    expect(dropped).toBe(true);
    // jar cleared → falls back to static bearer only
    expect(engine.headersFor("admin", URL_A)).toEqual({ Authorization: "Bearer admin-tok" });
  });

  it("does nothing on a 2xx/normal status", () => {
    const engine = new SessionEngine(identities);
    engine.capture("admin", ["session=adminsid"], URL_A);
    expect(engine.handleAuthStatus("admin", 200, URL_A)).toBe(false);
    expect(engine.headersFor("admin", URL_A).Cookie).toBe("session=adminsid");
  });

  it("switches the active identity and rejects unknown labels", () => {
    const engine = new SessionEngine(identities);
    engine.activeLabel = "alice";
    expect(engine.activeLabel).toBe("alice");
    expect(() => (engine.activeLabel = "nobody")).toThrow();
  });
});
