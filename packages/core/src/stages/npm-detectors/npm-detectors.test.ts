import { describe, it, expect } from "vitest";
import {
  fuzzCandidate,
  nameMatchesPpSink,
  ssppFuzzDetector,
  readUnstableDetector,
  confirmReadUnstable,
  parserDiffDetector,
  confirmParserDiff,
  scanDivergences,
  inetAton,
  classify,
  isUnsafe,
  guardPackage,
  runDetectorOnPackage,
  dedupConfirmation,
  createOsvAdvisoryLookup,
  deriveForkSiblings,
  OsvLookupError,
  staticProbe,
  DETECTOR_REGISTRY,
  getDetectorById,
  resolveDetectors,
  listDetectorIds,
} from "./index.js";
import type { ReadUnstableCandidate, ParserDiffCandidate } from "./index.js";
import { runNpmDynamicDiscovery, leadToFinding } from "../npm-dynamic-discovery.js";
import type { PackageRef } from "./index.js";

// ── fixtures: the prototype's confirmed positives + negative controls ────────

/** Vulnerable recursive set (es-toolkit/compat.set class): no __proto__ guard. */
function vulnSet(obj: any, path: any, val: any): any {
  const keys = Array.isArray(path) ? path : String(path).split(".");
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const k = keys[i];
    if (cur[k] == null) cur[k] = {};
    cur = cur[k];
  }
  cur[keys[keys.length - 1]] = typeof val === "function" ? val() : val;
  return obj;
}

/** Vulnerable recursive merge: honours a JSON-parsed own "__proto__" key. */
function vulnMerge(target: any, source: any): any {
  for (const k of Object.keys(source)) {
    const v = source[k];
    if (v && typeof v === "object") {
      if (!target[k]) target[k] = {};
      vulnMerge(target[k], v);
    } else {
      target[k] = v;
    }
  }
  return target;
}

/** Guarded merge (lodash-class): skips the dangerous keys → clean. */
function guardedMerge(target: any, source: any): any {
  for (const k of Object.keys(source)) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
    const v = source[k];
    if (v && typeof v === "object") {
      if (!target[k]) target[k] = {};
      guardedMerge(target[k], v);
    } else {
      target[k] = v;
    }
  }
  return target;
}

describe("sspp-fuzz detector", () => {
  it("name heuristic matches known PP sink names, rejects unrelated", () => {
    expect(nameMatchesPpSink("set")).toBe(true);
    expect(nameMatchesPpSink("mergeDeep")).toBe(true);
    expect(nameMatchesPpSink("defu")).toBe(true);
    expect(nameMatchesPpSink("renderTemplate")).toBe(false);
    expect(nameMatchesPpSink("")).toBe(false);
  });

  it("CONFIRMS runtime pollution on a vulnerable set (es-toolkit class)", () => {
    const hits = fuzzCandidate(vulnSet as any);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.some((h) => h.objProto)).toBe(true);
    // no leaked pollution after the run
    expect(({} as any).__sspp_leaked__).toBeUndefined();
  });

  it("CONFIRMS on a vulnerable merge via the object-source payloads", () => {
    const hits = fuzzCandidate(vulnMerge as any);
    expect(hits.length).toBeGreaterThan(0);
  });

  it("does NOT confirm on a guarded merge (negative control)", () => {
    const hits = fuzzCandidate(guardedMerge as any);
    expect(hits.length).toBe(0);
  });

  it("identify → confirm end-to-end via a static probe", async () => {
    const probe = staticProbe({ name: "freshmerge" }, { freshmerge: { set: vulnSet } });
    const cands = await ssppFuzzDetector.identifyCandidates(probe);
    expect(cands.length).toBe(1);
    const conf = await ssppFuzzDetector.confirm(cands[0] as any, probe);
    expect(conf.confirmed).toBe(true);
    expect(conf.evidence.observation).toMatch(/prototype polluted/i);
  });

  it("clean package yields a candidate but NO confirmation", async () => {
    const probe = staticProbe({ name: "lodashy" }, { lodashy: { merge: guardedMerge } });
    const cands = await ssppFuzzDetector.identifyCandidates(probe);
    expect(cands.length).toBe(1);
    const conf = await ssppFuzzDetector.confirm(cands[0] as any, probe);
    expect(conf.confirmed).toBe(false);
  });
});

// ── read-unstable ────────────────────────────────────────────────────────────

describe("read-unstable detector", () => {
  it("CONFIRMS a validate-and-return-live-object bypass (class-validator/superstruct class)", () => {
    // Same-object validator: reads clean at validate-time, app reads the live
    // object at use-time.
    const vulnerable: ReadUnstableCandidate = {
      id: "x.validate",
      label: "x.validate",
      field: "role",
      allowed: ["allowed-1", "allowed-2"],
      probe(field) {
        const input: Record<string, unknown> = {};
        field.install(input, "role");
        const observed = input.role; // validate-phase read → clean
        const accepted = ["allowed-1", "allowed-2"].includes(String(observed));
        return { accepted, readAppValue: () => input.role }; // same live object
      },
    };
    const conf = confirmReadUnstable(vulnerable);
    expect(conf.confirmed).toBe(true);
    expect(conf.evidence.observation).toMatch(/ACCEPTED/);
  });

  it("does NOT confirm a materialising validator (joi/zod control)", () => {
    const safe: ReadUnstableCandidate = {
      id: "y.parse",
      label: "y.parse",
      field: "role",
      allowed: ["allowed-1", "allowed-2"],
      probe(field) {
        const input: Record<string, unknown> = {};
        field.install(input, "role");
        const materialized = input.role; // captured at validate-time → clean
        const accepted = ["allowed-1", "allowed-2"].includes(String(materialized));
        return { accepted, readAppValue: () => materialized }; // FRESH value
      },
    };
    const conf = confirmReadUnstable(safe);
    expect(conf.confirmed).toBe(false);
  });

  it("identify matches a superstruct-shaped module and confirms bypass", async () => {
    const superstructStub = {
      enums: (vals: string[]) => ({ __enum: vals }),
      object: (shape: Record<string, { __enum: string[] }>) => ({ __shape: shape }),
      validate: (input: any, schema: any) => {
        for (const k of Object.keys(schema.__shape)) {
          if (!schema.__shape[k].__enum.includes(input[k])) return [new Error("invalid"), undefined];
        }
        return [undefined, input]; // returns the SAME object
      },
    };
    const probe = staticProbe({ name: "superstruct" }, { superstruct: superstructStub });
    const cands = await readUnstableDetector.identifyCandidates(probe);
    expect(cands.length).toBeGreaterThanOrEqual(1);
    const conf = await readUnstableDetector.confirm(cands[0] as any, probe);
    expect(conf.confirmed).toBe(true);
  });

  it("identify matches a zod-shaped module and does NOT confirm (control)", async () => {
    const zodStub = {
      z: {
        enum: (vals: string[]) => ({ __enum: vals }),
        object: (shape: Record<string, { __enum: string[] }>) => ({
          safeParse: (input: any) => {
            const data: Record<string, unknown> = {};
            for (const k of Object.keys(shape)) {
              const v = input[k]; // read once → materialise
              if (!shape[k].__enum.includes(v)) return { success: false };
              data[k] = v;
            }
            return { success: true, data }; // FRESH object
          },
        }),
      },
    };
    const probe = staticProbe({ name: "zod" }, { zod: zodStub });
    const cands = await readUnstableDetector.identifyCandidates(probe);
    expect(cands.length).toBeGreaterThanOrEqual(1);
    const conf = await readUnstableDetector.confirm(cands[0] as any, probe);
    expect(conf.confirmed).toBe(false);
  });
});

// ── parser-diff ──────────────────────────────────────────────────────────────

describe("parser-diff detector", () => {
  it("oracle resolves octal/decimal encodings of loopback + metadata", () => {
    expect(inetAton("0177.0.0.1").dotted).toBe("127.0.0.1");
    expect(inetAton("2130706433").dotted).toBe("127.0.0.1");
    expect(inetAton("0x7f000001").dotted).toBe("127.0.0.1");
    expect(classify(inetAton("169.254.169.254").long!)).toMatch(/metadata/);
    expect(isUnsafe("loopback")).toBe(true);
    expect(isUnsafe("PUBLIC")).toBe(false);
  });

  it("CONFIRMS a filter that treats an encoded loopback as public (ip class)", () => {
    // naive filter: only blocks the literal dotted private/loopback strings
    const vulnerable: ParserDiffCandidate = {
      id: "ip.isPublic",
      label: "ip.isPublic",
      field: "",
      filterVerdict(input) {
        const blocked = /^127\.0\.0\.1$|^10\.|^192\.168\./.test(input);
        return { treatedAsSafe: !blocked, note: blocked ? "blocked" : "ip.isPublic=true" };
      },
    };
    const hits = scanDivergences(vulnerable);
    expect(hits.length).toBeGreaterThan(0);
    const conf = confirmParserDiff(vulnerable);
    expect(conf.confirmed).toBe(true);
    expect(conf.evidence.observation).toMatch(/SSRF|safe|public|127\.0\.0\.1/i);
  });

  it("does NOT confirm a filter that matches the oracle (control)", () => {
    const correct: ParserDiffCandidate = {
      id: "correct.filter",
      label: "correct.filter",
      field: "",
      filterVerdict(input) {
        const o = inetAton(input);
        const safe = !(o.ok && isUnsafe(o.cls));
        return { treatedAsSafe: safe, note: "oracle-aligned" };
      },
    };
    const conf = confirmParserDiff(correct);
    expect(conf.confirmed).toBe(false);
  });
});

// ── base discipline: guards + assume-FP ──────────────────────────────────────

describe("shared discipline (base.ts)", () => {
  it("downloads-floor guard skips low-download packages", () => {
    expect(guardPackage({ name: "a", weeklyDownloads: 50 }, { downloadsFloor: 1000 }).allowed).toBe(false);
    expect(guardPackage({ name: "a", weeklyDownloads: 5000 }, { downloadsFloor: 1000 }).allowed).toBe(true);
    expect(guardPackage({ name: "a" }, { downloadsFloor: 1000 }).allowed).toBe(true); // unknown ≠ skip
  });

  it("freshness guard skips stale packages, keeps unknown-age", () => {
    const now = Date.parse("2026-07-14T00:00:00Z");
    const stale = new Date(now - 400 * 86_400_000).toISOString();
    expect(guardPackage({ name: "a", lastPublishedAt: stale }, { maxAgeDays: 365 }, now).allowed).toBe(false);
    expect(guardPackage({ name: "a" }, { maxAgeDays: 365 }, now).allowed).toBe(true);
  });

  it("assume-FP: a confirm with confirmed=true but empty observation is dropped", async () => {
    const liar = {
      ...ssppFuzzDetector,
      id: "liar",
      identifyCandidates: () => [{ id: "c", label: "c" } as any],
      confirm: () => ({ confirmed: true, evidence: { observation: "" } }),
    };
    const probe = staticProbe({ name: "p" }, {});
    const outcome = await runDetectorOnPackage(liar as any, probe);
    expect(outcome.leads.length).toBe(0);
  });

  it("dedup: prior-report and fork-twin are non-novel; unknown name is novel-offline", async () => {
    const prior = await dedupConfirmation({ name: "es-toolkit", cwe: "CWE-1321", hints: ssppFuzzDetector.dedupHints });
    expect(prior.novel).toBe(false);
    expect(prior.source).toBe("prior-report");
    const twin = await dedupConfirmation({ name: "radash", cwe: "CWE-1321", hints: ssppFuzzDetector.dedupHints });
    expect(twin.source).toBe("fork-cve-twin");
    const fresh = await dedupConfirmation({ name: "freshmerge", cwe: "CWE-1321", hints: ssppFuzzDetector.dedupHints });
    expect(fresh.novel).toBe(true);
    expect(fresh.source).toBe("unknown"); // no live lookup wired
  });

  it("dedup: injected advisory lookup marks a package known", async () => {
    const fresh = await dedupConfirmation({
      name: "somepkg",
      cwe: "CWE-1321",
      advisoryLookup: () => ["CVE-2099-0001"],
    });
    expect(fresh.novel).toBe(false);
    expect(fresh.source).toBe("osv");
  });
});

// ── live OSV advisory lookup (mocked HTTP) ───────────────────────────────────

/** Minimal `fetch` Response stub covering what the OSV client reads. */
function mkResponse(status: number, json: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => json,
  } as unknown as Response;
}

/** A `querybatch` body { results: [...] } with one `vulns` list per query. */
function batch(...perQueryVulnIds: string[][]): unknown {
  return { results: perQueryVulnIds.map((ids) => ({ vulns: ids.map((id) => ({ id })) })) };
}

describe("live OSV advisory lookup", () => {
  it("derives conservative fork/rename siblings, ignores unrelated names", () => {
    expect(deriveForkSiblings("lodash.merge")).toEqual(["lodash"]);
    expect(deriveForkSiblings("lodash.set")).toEqual(["lodash"]);
    expect(deriveForkSiblings("@acme/left-pad")).toEqual(["left-pad"]);
    expect(deriveForkSiblings("@types/node")).toEqual([]); // type stubs, not code twins
    expect(deriveForkSiblings("radash")).toEqual([]); // plain name ⇒ no blind sibling
    expect(deriveForkSiblings("es-toolkit")).toEqual([]);
  });

  it("sends a well-formed querybatch request (ecosystem npm + version)", async () => {
    let seenUrl = "";
    let seenBody: any;
    const fetchImpl = (async (url: string, init: RequestInit) => {
      seenUrl = String(url);
      seenBody = JSON.parse(String(init.body));
      return mkResponse(200, batch([]));
    }) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl });
    await lookup("es-toolkit", "1.39.0", "CWE-1321");
    expect(seenUrl).toContain("api.osv.dev/v1/querybatch");
    expect(seenBody.queries[0]).toEqual({ package: { ecosystem: "npm", name: "es-toolkit" }, version: "1.39.0" });
  });

  it("KNOWN package returns its advisory id → dedup marks it non-novel (osv)", async () => {
    const fetchImpl = (async () => mkResponse(200, batch(["GHSA-aaaa-bbbb-cccc"]))) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl });
    const ids = await lookup("known-pkg", "1.0.0", "CWE-1321");
    expect(ids).toEqual(["GHSA-aaaa-bbbb-cccc"]);
    const verdict = await dedupConfirmation({ name: "known-pkg", version: "1.0.0", cwe: "CWE-1321", advisoryLookup: lookup });
    expect(verdict.novel).toBe(false);
    expect(verdict.source).toBe("osv");
    expect(verdict.advisories).toContain("GHSA-aaaa-bbbb-cccc");
  });

  it("UNKNOWN package returns [] → dedup marks it novel", async () => {
    const fetchImpl = (async () => mkResponse(200, batch([]))) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl });
    const ids = await lookup("truly-fresh", "0.1.0", "CWE-1321");
    expect(ids).toEqual([]);
    const verdict = await dedupConfirmation({ name: "truly-fresh", version: "0.1.0", cwe: "CWE-1321", advisoryLookup: lookup });
    expect(verdict.novel).toBe(true);
    expect(verdict.source).toBe("novel"); // lookup RAN and found nothing ⇒ genuinely novel
  });

  it("fork-twin: sibling carries the advisory even when the fork name has none", async () => {
    // index 0 = primary `lodash.merge` (clean), index 1 = sibling `lodash` (advised)
    const fetchImpl = (async () => mkResponse(200, batch([], ["GHSA-lodash-proto"]))) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl });
    const ids = await lookup("lodash.merge", undefined, "CWE-1321");
    expect(ids).toEqual(["sibling:lodash:GHSA-lodash-proto"]);
    const verdict = await dedupConfirmation({ name: "lodash.merge", cwe: "CWE-1321", advisoryLookup: lookup });
    expect(verdict.novel).toBe(false);
    expect(verdict.source).toBe("osv");
  });

  it("FAILS CLOSED on HTTP error → dedup source=unknown, NOT novel", async () => {
    const fetchImpl = (async () => mkResponse(500, {})) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl, retries: 0 });
    await expect(lookup("boom", "1.0.0", "CWE-1321")).rejects.toBeInstanceOf(OsvLookupError);
    const verdict = await dedupConfirmation({ name: "boom", version: "1.0.0", cwe: "CWE-1321", advisoryLookup: lookup });
    expect(verdict.source).toBe("unknown"); // possibly-known, never a blind-novel
    expect(verdict.source).not.toBe("novel");
  });

  it("FAILS CLOSED on a network/abort error → dedup source=unknown", async () => {
    const fetchImpl = (async () => {
      const err = new Error("aborted");
      err.name = "AbortError";
      throw err;
    }) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl, retries: 0 });
    await expect(lookup("neterr", "1.0.0", "CWE-1321")).rejects.toBeInstanceOf(OsvLookupError);
    const verdict = await dedupConfirmation({ name: "neterr", cwe: "CWE-1321", advisoryLookup: lookup });
    expect(verdict.source).toBe("unknown");
  });

  it("FAILS CLOSED on a malformed response (no `results` key)", async () => {
    const fetchImpl = (async () => mkResponse(200, { unexpected: true })) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl, retries: 0 });
    await expect(lookup("weird", "1.0.0", "CWE-1321")).rejects.toBeInstanceOf(OsvLookupError);
  });

  it("retries a transient 429 then succeeds", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      return calls === 1 ? mkResponse(429, {}) : mkResponse(200, batch(["CVE-2099-9999"]));
    }) as unknown as typeof fetch;
    const lookup = createOsvAdvisoryLookup({ fetchImpl, retries: 1 });
    const ids = await lookup("rate-limited", "1.0.0", "CWE-1321");
    expect(calls).toBe(2);
    expect(ids).toEqual(["CVE-2099-9999"]);
  });
});

// ── registry ─────────────────────────────────────────────────────────────────

describe("detector registry", () => {
  it("registers the three first-class detectors with unique ids", () => {
    const ids = listDetectorIds();
    expect(ids).toEqual(expect.arrayContaining(["sspp-fuzz", "read-unstable", "parser-diff"]));
    expect(new Set(ids).size).toBe(ids.length);
    expect(DETECTOR_REGISTRY.length).toBeGreaterThanOrEqual(3);
  });

  it("getDetectorById + resolveDetectors handle known and unknown ids", () => {
    expect(getDetectorById("sspp-fuzz")?.cwe).toBe("CWE-1321");
    expect(getDetectorById("nope")).toBeUndefined();
    const r = resolveDetectors(["sspp-fuzz", "nope"]);
    expect(r.detectors.map((d) => d.id)).toEqual(["sspp-fuzz"]);
    expect(r.unknown).toEqual(["nope"]);
    expect(resolveDetectors().detectors.length).toBe(DETECTOR_REGISTRY.length);
  });
});

// ── stage end-to-end ─────────────────────────────────────────────────────────

describe("runNpmDynamicDiscovery stage", () => {
  it("sweeps a worklist, emits canonical findings, splits novel vs known", async () => {
    const modules: Record<string, Record<string, unknown>> = {
      freshmerge: { freshmerge: { set: vulnSet } }, // vuln + novel
      "es-toolkit": { "es-toolkit": { set: vulnSet } }, // vuln + prior-report → known
      radash: { radash: { set: vulnSet } }, // vuln + fork-twin → known
      lodashy: { lodashy: { merge: guardedMerge } }, // clean → no finding
    };
    const worklist: PackageRef[] = Object.keys(modules).map((name) => ({ name }));
    const streamed: string[] = [];
    const result = await runNpmDynamicDiscovery({
      worklist,
      detectorIds: ["sspp-fuzz"],
      probeFactory: (pkg) => staticProbe(pkg, modules[pkg.name] ?? {}),
      onConfirmed: (f) => {
        streamed.push(f.title);
      },
    });

    expect(result.scannedPackages).toBe(4);
    expect(result.novel.length).toBe(1);
    expect(result.novel[0].title).toMatch(/freshmerge/);
    expect(result.known.length).toBe(2); // es-toolkit + radash
    // canonical finding shape
    const f = result.novel[0];
    expect(f.status).toBe("discovered");
    expect(f.category).toBe("prototype-pollution");
    expect(f.noveltyVerdict).toBe("novel");
    expect(f.templateId).toBe("npm-dynamic-sspp-fuzz");
    // onConfirmed streams only novel
    expect(streamed).toEqual([f.title]);
  });

  it("records unpreparable packages instead of fabricating findings", async () => {
    const result = await runNpmDynamicDiscovery({
      worklist: [{ name: "cannot-install" }],
      detectorIds: ["sspp-fuzz"],
      probeFactory: () => undefined,
    });
    expect(result.unpreparable).toEqual(["cannot-install"]);
    expect(result.findings.length).toBe(0);
  });

  it("leadToFinding yields a well-formed Finding", () => {
    const f = leadToFinding(
      { name: "demo", version: "1.0.0" },
      ssppFuzzDetector,
      {
        detectorId: "sspp-fuzz",
        candidateId: "set@demo",
        confirmation: { confirmed: true, severity: "high", source: "demo.set", evidence: { observation: "Object.prototype polluted" } },
        dedup: { novel: true, source: "novel", advisories: [] },
      },
    );
    expect(f.severity).toBe("high");
    expect(f.title).toMatch(/demo@1.0.0/);
    expect(f.fingerprint).toContain("npm-dynamic:sspp-fuzz:demo");
  });
});
