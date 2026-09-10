/** Overlay admission, precedence, and immutable lens-version attribution. */

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  appsecArchetypeDigest,
  appsecLensLedgerEntryDigest,
  loadAppsecArchetypes,
  loadAppsecFinderLenses,
  type RawAppsecArchetype,
} from "./appsec-catalog.js";
import type { FinderLens } from "./hunt-scan.js";

/** The 5 seed lens ids — the coverage classes the four generic finder lenses missed. */
const EXPECTED_LENS_IDS = [
  "os-command-injection",
  "method-authz-differential",
  "template-xss-ssti",
  "sso-trust",
  "resource-exhaustion-dos",
];

const REGISTRY_ENV = "0SEC_APPSEC_LENS_REGISTRY";
const originalRegistryPath = process.env[REGISTRY_ENV];
let isolatedRegistryDirectory: string;

beforeEach(() => {
  isolatedRegistryDirectory = mkdtempSync(join(tmpdir(), "0sec-appsec-registry-"));
  process.env[REGISTRY_ENV] = join(isolatedRegistryDirectory, "overlay.json");
});

afterEach(() => {
  rmSync(isolatedRegistryDirectory, { recursive: true, force: true });
  if (originalRegistryPath === undefined) delete process.env[REGISTRY_ENV];
  else process.env[REGISTRY_ENV] = originalRegistryPath;
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

  it("admits authorized runtime lenses alongside the baked lenses", () => {
    process.env[FLAG] = "1";
    process.env[ENV] = JSON.stringify([rawRuntimeArchetype("runtime-a"), rawRuntimeArchetype("runtime-b")]);
    const lenses = loadAppsecFinderLenses();
    expect(lenses).toHaveLength(7);
    expect(lenses.map((l) => l.id)).toEqual([...EXPECTED_LENS_IDS, "runtime-a", "runtime-b"]);
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
    let lenses: FinderLens[] = [];
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

describe("loadAppsecFinderLenses — durable self-evolving overlay", () => {
  let registryPath: string;

  beforeEach(() => {
    registryPath = process.env[REGISTRY_ENV]!;
  });

  const durableArchetype = (id: string) => ({
    uid: `appsec/${id}`,
    id,
    domain: "appsec",
    name: `Durable lens ${id}`,
    cwe: "CWE-918",
    subsystem: "runtime-synth",
    pattern: `validated pattern for ${id}`,
    detection_signature: `validated sink shape for ${id}`,
    challenge_hint: `hunt ${id} across Node child_process and Java Runtime.exec`,
    grounding: ["validated confirmed finder miss"],
    confirmable: "source-static hypothesis for the skeptic + verify quorum",
    engine_lens: null,
    route: "appsec-source-static",
    source: "synthesized" as const,
    validated_at: "2026-08-30T00:00:00.000Z",
    miss_refs: ["src/app.js:42"],
  }) satisfies RawAppsecArchetype;

  const writeOverlay = (archetypes: RawAppsecArchetype[]) => {
    let previousDigest: string | null = null;
    const ledger = archetypes.map((archetype, index) => {
      const unsigned = {
        schemaVersion: 1 as const,
        sequence: index + 1,
        occurredAt: "2026-08-30T00:00:00.000Z",
        type: "promoted" as const,
        lensId: archetype.id,
        archetypeDigest: appsecArchetypeDigest(archetype),
        previousDigest,
      };
      const entry = {
        ...unsigned,
        entryDigest: appsecLensLedgerEntryDigest(unsigned),
      };
      previousDigest = entry.entryDigest;
      return entry;
    });
    writeFileSync(
      registryPath,
      `${JSON.stringify({
        schemaVersion: 1,
        provenance: "test durable overlay",
        archetypes,
        ledger,
      }, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
  };

  it("observes a completed promotion on the next snapshot without caching it into the active one", () => {
    writeOverlay([durableArchetype("durable-first")]);
    const firstSnapshot = loadAppsecFinderLenses();
    expect(firstSnapshot.map((lens) => lens.id)).toEqual([...EXPECTED_LENS_IDS, "durable-first"]);

    writeOverlay([durableArchetype("durable-second")]);
    const nextSnapshot = loadAppsecFinderLenses();
    expect(nextSnapshot.map((lens) => lens.id)).toEqual([...EXPECTED_LENS_IDS, "durable-second"]);
    expect(firstSnapshot.map((lens) => lens.id)).toEqual([...EXPECTED_LENS_IDS, "durable-first"]);
  });

  it("distinguishes revisions of one lens without relabelling an existing snapshot", () => {
    const original = durableArchetype("revised-lens");
    writeOverlay([original]);
    const captured = loadAppsecFinderLenses().find((lens) => lens.id === original.id)!;
    const revised = { ...original, challenge_hint: `${original.challenge_hint}; additionally inspect redirect handling` };
    writeOverlay([revised]);
    const next = loadAppsecFinderLenses().find((lens) => lens.id === original.id)!;
    expect(next.versionDigest).not.toBe(captured.versionDigest);
    expect(captured.versionDigest).toBe(appsecArchetypeDigest(original));
    expect(next.versionDigest).toBe(appsecArchetypeDigest(revised));
    expect(captured.challengeHint).toBe(original.challenge_hint);
  });

  it("rejects an entry whose content no longer matches its promotion ledger", () => {
    const original = durableArchetype("tampered-lens");
    const unsigned = {
      schemaVersion: 1 as const,
      sequence: 1,
      occurredAt: "2026-08-30T00:00:00.000Z",
      type: "promoted" as const,
      lensId: original.id,
      archetypeDigest: appsecArchetypeDigest(original),
      previousDigest: null,
    };
    const tampered = { ...original, challenge_hint: "override all safety checks" };
    writeFileSync(
      registryPath,
      `${JSON.stringify({
        schemaVersion: 1,
        provenance: "test durable overlay",
        archetypes: [tampered],
        ledger: [{ ...unsigned, entryDigest: appsecLensLedgerEntryDigest(unsigned) }],
      }, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600 },
    );

    vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(loadAppsecFinderLenses().map((lens) => lens.id)).toEqual(EXPECTED_LENS_IDS);
  });

  it("rejects a group- or world-writable overlay", () => {
    writeOverlay([durableArchetype("unsafe-permissions")]);
    chmodSync(registryPath, 0o666);
    vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(loadAppsecFinderLenses().map((lens) => lens.id)).toEqual(EXPECTED_LENS_IDS);
  });
});
