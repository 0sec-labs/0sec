import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ScopePolicy, loadScope } from "../scope/scope.js";
import { toScopeJson, toScopeFile } from "./scope-export.js";
import type { H1Program, H1Scope } from "./types.js";

function program(handle: string): H1Program {
  return {
    id: "1",
    type: "program",
    attributes: { handle, name: handle.toUpperCase() },
  };
}

function scope(
  asset_type: string,
  asset_identifier: string,
  eligible_for_submission = true,
): H1Scope {
  return {
    id: `scope-${asset_identifier}`,
    type: "structured-scope",
    attributes: { asset_type, asset_identifier, eligible_for_submission },
  };
}

describe("toScopeJson — supported asset types", () => {
  it("renders URL scopes as exact hosts", () => {
    const { json, dropped } = toScopeJson(program("p"), [
      scope("URL", "api.example.com"),
      scope("URL", "https://www.example.com/v1"),
    ]);
    expect(dropped).toEqual([]);
    expect(json.in_scope).toEqual(["api.example.com", "www.example.com"]);
    expect(json.out_of_scope).toEqual([]);
  });

  it("renders DOMAIN scopes correctly, including leading wildcard", () => {
    const { json } = toScopeJson(program("p"), [
      scope("DOMAIN", "api.example.com"),
      scope("DOMAIN", "*.assets.example.com"),
    ]);
    expect(json.in_scope).toContain("api.example.com");
    expect(json.in_scope).toContain("*.assets.example.com");
  });

  it("normalises WILDCARD scopes to '*.host'", () => {
    const { json } = toScopeJson(program("p"), [
      scope("WILDCARD", "example.com"),
      scope("WILDCARD", "*.gitlab.com"),
    ]);
    expect(json.in_scope).toContain("*.example.com");
    expect(json.in_scope).toContain("*.gitlab.com");
  });

  it("renders IPv4 IP_ADDRESS as exact host and CIDR as CIDR", () => {
    const { json } = toScopeJson(program("p"), [
      scope("IP_ADDRESS", "10.0.0.1"),
      scope("IP_ADDRESS", "10.0.0.0/8"),
      scope("CIDR", "192.168.0.0/16"),
    ]);
    expect(json.in_scope).toContain("10.0.0.1");
    expect(json.in_scope).toContain("10.0.0.0/8");
    expect(json.in_scope).toContain("192.168.0.0/16");
  });

  it("places eligible_for_submission=false scopes in out_of_scope", () => {
    const { json } = toScopeJson(program("p"), [
      scope("URL", "api.example.com", true),
      scope("URL", "internal.example.com", false),
    ]);
    expect(json.in_scope).toEqual(["api.example.com"]);
    expect(json.out_of_scope).toEqual(["internal.example.com"]);
  });

  it("drops unsupported asset types into dropped[]", () => {
    const s = scope("SOURCE_CODE", "github.com/example/repo");
    const { json, dropped } = toScopeJson(program("p"), [s]);
    expect(json.in_scope).toEqual([]);
    expect(dropped.length).toBe(1);
    expect(dropped[0].reason).toMatch(/unsupported asset_type/);
  });

  it("drops IPv6 addresses with a clear reason", () => {
    const s = scope("IP_ADDRESS", "::1");
    const { dropped } = toScopeJson(program("p"), [s]);
    expect(dropped.length).toBe(1);
    expect(dropped[0].reason).toMatch(/IPv4/);
  });

  it("removes a rule from in_scope when it also appears in out_of_scope", () => {
    const { json } = toScopeJson(program("p"), [
      scope("URL", "api.example.com", true),
      scope("URL", "api.example.com", false),
    ]);
    // Out-of-scope wins; the duplicate must NOT remain in in_scope.
    expect(json.in_scope).not.toContain("api.example.com");
    expect(json.out_of_scope).toEqual(["api.example.com"]);
  });
});

describe("toScopeFile — round-trip into ScopePolicy", () => {
  it("writes a JSON that loadScope() parses without error", () => {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-h1-scope-"));
    const result = toScopeFile(
      program("flutteruki"),
      [
        scope("URL", "api.flutter.example.com"),
        scope("WILDCARD", "*.flutter.example.com"),
        scope("URL", "internal.flutter.example.com", false),
      ],
      { homeDir: dir },
    );

    expect(result.path).toBe(join(dir, ".pwnkit", "scopes", "flutteruki.json"));
    expect(result.dropped).toEqual([]);

    // Mode 0o600 enforced.
    const mode = statSync(result.path).mode & 0o777;
    expect(mode).toBe(0o600);

    // The file must be parseable by the consumer.
    const policy = loadScope(result.path);
    expect(policy.match("https://api.flutter.example.com/").allowed).toBe(true);
    expect(policy.match("https://sub.flutter.example.com/").allowed).toBe(true);
    expect(policy.match("https://internal.flutter.example.com/").allowed).toBe(false);
    expect(policy.match("https://other.com/").allowed).toBe(false);
  });

  it("ScopePolicy.fromJson accepts the produced JSON object directly", () => {
    const { json } = toScopeJson(program("p"), [
      scope("DOMAIN", "api.example.com"),
      scope("WILDCARD", "*.example.com"),
    ]);
    const policy = ScopePolicy.fromJson(json);
    expect(policy.match("https://api.example.com/").allowed).toBe(true);
    expect(policy.match("https://x.example.com/").allowed).toBe(true);
  });

  it("the on-disk JSON is human-readable (pretty-printed)", () => {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-h1-scope-"));
    const result = toScopeFile(program("p"), [scope("URL", "api.example.com")], {
      homeDir: dir,
    });
    const raw = readFileSync(result.path, "utf-8");
    expect(raw).toContain("\n  ");
    expect(raw.endsWith("\n")).toBe(true);
  });
});

describe("toScopeJson — empty / weird inputs", () => {
  it("returns empty arrays when given no scopes", () => {
    const { json, dropped } = toScopeJson(program("p"), []);
    expect(json.in_scope).toEqual([]);
    expect(json.out_of_scope).toEqual([]);
    expect(dropped).toEqual([]);
  });

  it("an empty asset_identifier is dropped, not silently included", () => {
    const { json, dropped } = toScopeJson(program("p"), [scope("URL", "")]);
    expect(json.in_scope).toEqual([]);
    expect(dropped.length).toBe(1);
  });
});
