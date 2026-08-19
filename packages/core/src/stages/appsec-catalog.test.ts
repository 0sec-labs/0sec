/**
 * Appsec archetype catalog tests. `loadAppsecArchetypes` /
 * `appsecArchetypeToFinderLens` / `loadAppsecFinderLenses` are pure — no mocks.
 * These assert the REAL data file (`data/appsec-archetypes.json`), so they are
 * the source-of-truth check that the 5 seed classes load with the expected lens
 * ids and map cleanly to FinderLens[]. The CLI's deep-review.test.ts asserts the
 * WIRING (that defaultFinderLenses unions these); this asserts the DATA.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  appsecArchetypeToFinderLens,
  appsecArchetypesPath,
  loadAppsecArchetypes,
  loadAppsecFinderLenses,
} from "./appsec-catalog.js";

/** The 5 seed lens ids — the coverage classes the four generic finder lenses missed. */
const EXPECTED_LENS_IDS = [
  "os-command-injection",
  "method-authz-differential",
  "template-xss-ssti",
  "sso-trust",
  "resource-exhaustion-dos",
];

describe("loadAppsecArchetypes", () => {
  it("loads all 5 appsec archetypes with unique uids under appsec/", () => {
    const archetypes = loadAppsecArchetypes();
    expect(archetypes).toHaveLength(5);
    const uids = new Set(archetypes.map((a) => a.uid));
    expect(uids.size).toBe(5);
    for (const a of archetypes) {
      expect(a.uid.startsWith("appsec/")).toBe(true);
      expect(a.domain).toBe("appsec");
      expect(a.route).toBe("appsec-source-static");
      expect(a.name.length).toBeGreaterThan(0);
      expect(a.cwe.startsWith("CWE-")).toBe(true);
      expect(a.pattern.length).toBeGreaterThan(0);
      expect(a.detectionSignature.length).toBeGreaterThan(0);
      expect(a.challengeHint.length).toBeGreaterThan(0);
      expect(a.grounding.length).toBeGreaterThan(0);
      expect(a.engineLens).toBeNull();
    }
  });

  it("exposes exactly the 5 expected lens ids", () => {
    const ids = loadAppsecArchetypes().map((a) => a.id);
    expect(ids).toEqual(EXPECTED_LENS_IDS);
  });

  it("is cached (repeated calls return the same reference)", () => {
    expect(loadAppsecArchetypes()).toBe(loadAppsecArchetypes());
  });

  it("resolves a data path ending in the bundled JSON", () => {
    expect(appsecArchetypesPath().endsWith("data/appsec-archetypes.json")).toBe(true);
  });

  it("every challengeHint is cross-language (names concrete sinks across ≥2 ecosystems)", () => {
    // The load-bearing property: each hint must cite sink shapes from more than
    // one ecosystem so the finder hunts the class in any language, not just JS.
    // Markers are framework/runtime/sink tokens (not just language names) since
    // some classes are best identified by their per-framework guard/sink shape
    // (e.g. authz cites [Authorize] / @PreAuthorize / middleware).
    const ecosystemMarkers = [
      // runtimes / languages
      "Node", ".NET", "Java", "Python", "PHP", "Ruby",
      // web frameworks / view layers
      "React", "Angular", "Vue", "Spring", "Rails", "Express",
      // authz guard shapes
      "[Authorize]", "@PreAuthorize", "middleware",
      // exec sinks
      "subprocess", "os.system", "Runtime.exec", "ProcessBuilder", "child_process", "Process.Start",
      // template engines
      "Handlebars", "Thymeleaf", "JSP", "Jinja2", "EJS", "Pug", "Mustache", "Freemarker", "Velocity",
      // federation / token
      "SAML", "OIDC", "OAuth2", "JWT",
      // dos sinks
      "Thread.sleep", "setTimeout", "time.sleep", "Task.Delay", "Inflater", "gunzip", "zlib", "ReDoS",
    ];
    for (const a of loadAppsecArchetypes()) {
      const hits = ecosystemMarkers.filter((m) => a.challengeHint.includes(m));
      expect(hits.length, `${a.id} challengeHint should name ≥2 ecosystem/sink tokens`).toBeGreaterThanOrEqual(2);
    }
  });
});

describe("appsecArchetypeToFinderLens / loadAppsecFinderLenses", () => {
  it("maps each archetype id->lens id and challengeHint 1:1", () => {
    const a = loadAppsecArchetypes()[0]!;
    expect(appsecArchetypeToFinderLens(a)).toEqual({ id: a.id, challengeHint: a.challengeHint });
  });

  it("returns a FinderLens[] carrying the 5 seed ids with non-empty challenge hints", () => {
    const lenses = loadAppsecFinderLenses();
    expect(lenses.map((l) => l.id)).toEqual(EXPECTED_LENS_IDS);
    for (const l of lenses) expect(l.challengeHint.length).toBeGreaterThan(0);
  });
});

describe("loadAppsecFinderLenses — runtime lens injection (0SEC_RUNTIME_LENSES)", () => {
  const FLAG = "0SEC_RUNTIME_LENSES_ENABLED";
  const ENV = "0SEC_RUNTIME_LENSES";

  /** A full, well-formed on-disk (snake_case) runtime archetype for `id`. */
  const rawRuntimeArchetype = (id: string) => ({
    uid: `appsec/${id}`,
    id,
    domain: "appsec",
    name: `Runtime lens ${id}`,
    cwe: "CWE-9999",
    subsystem: "runtime-synth",
    pattern: `synthesized pattern for ${id}`,
    detection_signature: `grep shape for ${id}`,
    challenge_hint: `hunt angle for ${id} across Node child_process and Java Runtime.exec`,
    grounding: ["synthesized from a confirmed finder miss"],
    confirmable: "source-static hypothesis for the skeptic + verify quorum",
    engine_lens: null,
    route: "appsec-source-static",
    source: "synthesized",
    validated_at: "2026-07-21T00:00:00Z",
    miss_refs: ["src/app.js:42"],
  });

  beforeEach(() => {
    delete process.env[FLAG];
    delete process.env[ENV];
  });
  afterEach(() => {
    delete process.env[FLAG];
    delete process.env[ENV];
    vi.restoreAllMocks();
  });

  it("(a) flag OFF → byte-identical to baked (even if a runtime blob is present)", () => {
    // Flag unset is the default. A runtime blob without the flag must be ignored.
    process.env[ENV] = JSON.stringify([rawRuntimeArchetype("runtime-a"), rawRuntimeArchetype("runtime-b")]);
    const lenses = loadAppsecFinderLenses();
    expect(lenses).toHaveLength(5);
    expect(lenses.map((l) => l.id)).toEqual(EXPECTED_LENS_IDS);
  });

  it("(b) flag ON + valid blob with 2 new ids → 7 lenses of correct FinderLens shape", () => {
    process.env[FLAG] = "1";
    process.env[ENV] = JSON.stringify([rawRuntimeArchetype("runtime-a"), rawRuntimeArchetype("runtime-b")]);
    const lenses = loadAppsecFinderLenses();
    expect(lenses).toHaveLength(7);
    expect(lenses.map((l) => l.id)).toEqual([...EXPECTED_LENS_IDS, "runtime-a", "runtime-b"]);
    for (const l of lenses) {
      expect(Object.keys(l).sort()).toEqual(["challengeHint", "id"]);
      expect(typeof l.id).toBe("string");
      expect(l.challengeHint.length).toBeGreaterThan(0);
    }
    const injected = lenses.find((l) => l.id === "runtime-a")!;
    expect(injected.challengeHint).toBe(rawRuntimeArchetype("runtime-a").challenge_hint);
  });

  it("(c) flag ON + runtime id colliding with a baked id → baked wins, no duplicate", () => {
    process.env[FLAG] = "true";
    // Collide on a baked id AND add a genuinely new one.
    const collide = { ...rawRuntimeArchetype(EXPECTED_LENS_IDS[0]!), challenge_hint: "MALICIOUS override attempt" };
    process.env[ENV] = JSON.stringify([collide, rawRuntimeArchetype("runtime-new")]);
    const lenses = loadAppsecFinderLenses();
    expect(lenses).toHaveLength(6); // 5 baked + 1 genuinely-new runtime
    const ids = lenses.map((l) => l.id);
    expect(ids.filter((i) => i === EXPECTED_LENS_IDS[0]!)).toHaveLength(1);
    // Baked challengeHint is preserved — the runtime override never lands.
    const baked = loadAppsecArchetypes().find((a) => a.id === EXPECTED_LENS_IDS[0]!)!;
    expect(lenses.find((l) => l.id === EXPECTED_LENS_IDS[0]!)!.challengeHint).toBe(baked.challengeHint);
    expect(ids).toContain("runtime-new");
  });

  it("(d) flag ON + malformed JSON → falls back to baked, no throw", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env[FLAG] = "1";
    process.env[ENV] = "{ this is not valid json";
    let lenses: ReturnType<typeof loadAppsecFinderLenses> = [];
    expect(() => {
      lenses = loadAppsecFinderLenses();
    }).not.toThrow();
    expect(lenses.map((l) => l.id)).toEqual(EXPECTED_LENS_IDS);
    expect(warn).toHaveBeenCalled();
  });

  it("(d′) flag ON + one bad entry among good ones → bad entry skipped, rest injected", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env[FLAG] = "1";
    // Second entry is missing the load-bearing `challenge_hint`.
    const bad = { ...rawRuntimeArchetype("runtime-bad") } as Record<string, unknown>;
    delete bad.challenge_hint;
    process.env[ENV] = JSON.stringify([rawRuntimeArchetype("runtime-ok"), bad]);
    const lenses = loadAppsecFinderLenses();
    expect(lenses.map((l) => l.id)).toEqual([...EXPECTED_LENS_IDS, "runtime-ok"]);
    expect(warn).toHaveBeenCalled();
  });
});
