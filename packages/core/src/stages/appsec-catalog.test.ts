/**
 * Appsec archetype catalog tests. `loadAppsecArchetypes` /
 * `appsecArchetypeToFinderLens` / `loadAppsecFinderLenses` are pure — no mocks.
 * These assert the REAL data file (`data/appsec-archetypes.json`), so they are
 * the source-of-truth check that the 5 seed classes load with the expected lens
 * ids and map cleanly to FinderLens[]. The CLI's deep-review.test.ts asserts the
 * WIRING (that defaultFinderLenses unions these); this asserts the DATA.
 */

import { describe, expect, it } from "vitest";
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
