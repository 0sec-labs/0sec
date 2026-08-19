/**
 * Hunt evidence ledger (hunt-evidence-ledger.ts) + its bridge into the existing
 * learned-negatives gate (hunt-negatives.ts). Coverage:
 *
 *   - CONCURRENCY: two REAL OS processes appending to one ledger at the same
 *     time lose nothing and tear nothing. Run through actual child processes
 *     rather than `Promise.all` in one process, because `writeFileSync` is
 *     synchronous — an in-process "concurrent" test would serialise itself and
 *     prove nothing about the O_APPEND claim in the module header.
 *   - SHARING: a claim one worker disproves is visible to a second worker, and
 *     reaches the skeptic through the pre-existing `KnownNegative` path.
 *   - STANCE: observations and assumptions stay distinguishable end-to-end, an
 *     observation without a locator is refused, and a terminal status cannot be
 *     reached on assumptions alone.
 *   - APPEND-ONLY / IDEMPOTENCE: history is retained across a status
 *     transition, and re-running identical work does not duplicate the claim.
 */

import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  appendHuntClaim,
  createHuntClaim,
  disprovenHuntClaims,
  loadHuntLedger,
  readHuntLedger,
  resolveHuntLedger,
  staleHuntClaims,
  unresolvedHuntClaims,
  validateHuntClaimRecord,
  type HuntEvidence,
  type RecordHuntClaimInput,
} from "./hunt-evidence-ledger.js";
import { loadKnownNegativesFromLedger, matchNegative, negativeContext } from "./hunt-negatives.js";
import type { Finding } from "@pwnkit/shared";

const HERE = dirname(fileURLToPath(import.meta.url));

// The skeptic-wiring block below drives `makeSkepticVerifier` without a real
// finder — same mock idiom as hunt-negatives.test.ts.
const agenticScanMock = vi.fn();
vi.mock("../agentic-scanner.js", () => ({
  agenticScan: (...args: unknown[]) => agenticScanMock(...args),
}));

let dir: string;
let ledger: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hunt-ledger-"));
  ledger = join(dir, "campaign", "evidence.jsonl");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function observation(statement: string, locator: string, source = "skeptic.gpt-5"): HuntEvidence {
  return { stance: "observation", statement, source, locator };
}

function assumption(statement: string, source = "finder.claude"): HuntEvidence {
  return { stance: "assumption", statement, source };
}

function claim(overrides: Partial<RecordHuntClaimInput> = {}): RecordHuntClaimInput {
  return {
    shape: { path: "drivers/net/wireless/foo.c", bugClass: "CWE-416 use-after-free" },
    statement: "foo_release() frees ctx while the retry timer can still dereference it",
    status: "unresolved",
    evidence: [assumption("the timer looks unsynchronised with release")],
    worker: "finder-1",
    ...overrides,
  };
}

function mkFinding(title: string, analysis: string): Finding {
  return {
    id: "f-1",
    templateId: "ledger-test",
    title,
    description: analysis,
    severity: "high",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
  };
}

describe("concurrent writers", () => {
  it("loses nothing when two real processes append to one ledger at once", async () => {
    // Bundle the module to a standalone .mjs so a child `node` process can
    // import the ACTUAL implementation (the repo's `.js` specifiers point at
    // `.ts` sources, which node cannot resolve directly).
    const esbuild = join(HERE, "..", "..", "..", "..", "node_modules", "esbuild", "bin", "esbuild");
    const bundle = join(dir, "ledger.mjs");
    execFileSync( // foxguard: ignore[js/no-command-injection]
      esbuild,
      [join(HERE, "hunt-evidence-ledger.ts"), "--bundle", "--platform=node", "--format=esm", `--outfile=${bundle}`],
      { stdio: "pipe" },
    );

    const runner = join(dir, "worker.mjs");
    // Each worker rendezvouses with its sibling BEFORE writing, then appends
    // CLAIMS_PER_WORKER distinct claims as fast as it can with a yield between
    // writes. The barrier is what makes this a real concurrency test rather
    // than a hope about the scheduler: a worker that reaches its writes has
    // proven the other process is alive at the same moment (and exits 3 if it
    // never shows up). Whether individual appends then interleave is up to the
    // OS — the property under test is that nothing is lost or torn either way.
    writeFileSync(
      runner,
      [
        `import { appendHuntClaim } from ${JSON.stringify(bundle)};`,
        'import { existsSync, writeFileSync } from "node:fs";',
        "const [ledger, worker, count] = process.argv.slice(2);",
        "const other = worker === 'worker-a' ? 'worker-b' : 'worker-a';",
        "writeFileSync(`${ledger}.ready-${worker}`, '');",
        "const deadline = Date.now() + 30_000;",
        "while (!existsSync(`${ledger}.ready-${other}`)) {",
        "  if (Date.now() > deadline) { console.error('barrier timeout'); process.exit(3); }",
        "  await new Promise((r) => setTimeout(r, 5));",
        "}",
        "for (let i = 0; i < Number(count); i++) {",
        "  appendHuntClaim(ledger, {",
        "    shape: { path: `drivers/net/site-${i}.c`, bugClass: 'CWE-416 use-after-free' },",
        "    statement: `${worker} claims site ${i} frees under the timer`,",
        "    status: 'disproven',",
        "    evidence: [{ stance: 'observation', statement: 'the guard is present', source: worker, locator: `drivers/net/site-${i}.c:41` }],",
        "    worker,",
        "  });",
        "  await new Promise((r) => setImmediate(r));",
        "}",
      ].join("\n"),
      "utf8",
    );

    const CLAIMS_PER_WORKER = 120;
    // The ledger's own parent dir is created lazily by appendHuntClaim, but the
    // barrier files below are written before the first append.
    mkdirSync(dirname(ledger), { recursive: true });
    const run = (worker: string) =>
      new Promise<number>((resolve, reject) => {
        const child = spawn(process.execPath, [runner, ledger, worker, String(CLAIMS_PER_WORKER)], { stdio: "pipe" }); // foxguard: ignore[js/no-command-injection]
        let stderr = "";
        child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
        child.on("error", reject);
        child.on("exit", (code) => (code === 0 ? resolve(code) : reject(new Error(`worker ${worker} exited ${code}: ${stderr}`))));
      });

    await Promise.all([run("worker-a"), run("worker-b")]);

    // Every line must be individually parseable — a torn record would fail here.
    const malformed: string[] = [];
    const records = readHuntLedger(ledger, { onMalformed: (line) => malformed.push(line) });
    expect(malformed).toEqual([]);
    expect(records).toHaveLength(CLAIMS_PER_WORKER * 2);
    expect(records.filter((r) => r.worker === "worker-a")).toHaveLength(CLAIMS_PER_WORKER);
    expect(records.filter((r) => r.worker === "worker-b")).toHaveLength(CLAIMS_PER_WORKER);
    // Every record is intact end-to-end, not merely present: a partially
    // written line would fail its content-digest check in readHuntLedger and
    // land in `malformed` above rather than here.
    expect(new Set(records.map((r) => r.id)).size).toBe(CLAIMS_PER_WORKER * 2);
  }, 60_000);
});

describe("disproven claims are shared", () => {
  it("makes one worker's refutation visible to a second worker", () => {
    // Worker A investigates and refutes.
    appendHuntClaim(ledger, claim({ worker: "finder-1" }));
    appendHuntClaim(
      ledger,
      claim({
        status: "disproven",
        worker: "skeptic-2",
        evidence: [
          observation("ctx is refcounted; foo_release() drops the last ref only after timer_delete_sync()", "drivers/net/wireless/foo.c:812"),
          assumption("the retry path is probably the only other consumer"),
        ],
      }),
    );

    // Worker B, a separate reader, sees the dead end without re-deriving it.
    const resolved = loadHuntLedger(ledger);
    const dead = disprovenHuntClaims(resolved);
    expect(dead).toHaveLength(1);
    expect(dead[0].statement).toContain("foo_release()");
    expect(unresolvedHuntClaims(resolved)).toEqual([]);
  });

  it("reaches the skeptic through the existing KnownNegative path", () => {
    appendHuntClaim(
      ledger,
      claim({
        shape: { path: "drivers/net/wireless/foo.c", bugClass: "CWE-416 use-after-free" },
        status: "disproven",
        worker: "skeptic-2",
        evidence: [observation("timer_delete_sync() runs before kfree(ctx)", "drivers/net/wireless/foo.c:812")],
      }),
    );

    const negatives = loadKnownNegativesFromLedger(ledger);
    expect(negatives).toHaveLength(1);
    expect(negatives[0].candidatePath).toBe("drivers/net/wireless/foo.c");
    expect(negatives[0].provenance).toContain("worker=skeptic-2");

    const match = matchNegative(
      mkFinding("use-after-free in foo_release", "CWE-416: ctx is freed while timer_delete_sync may still run"),
      negatives,
    );
    expect(match).not.toBeNull();
    const context = negativeContext(match!);
    expect(context).toContain("KNOWN PRIOR REFUTE");
    // The quoted reason is the OBSERVATION, not the claim's own prose.
    expect(context).toContain("timer_delete_sync() runs before kfree(ctx)");
    // Still a label, never an auto-dismissal.
    expect(context).toContain("NEW distinguishing fact");
  });

  it("never surfaces a contradicted claim as a dead end", () => {
    appendHuntClaim(
      ledger,
      claim({ status: "disproven", worker: "skeptic-2", evidence: [observation("guard present", "foo.c:812")] }),
    );
    appendHuntClaim(
      ledger,
      claim({ status: "validated", worker: "prover-3", evidence: [observation("KASAN UAF on the retry path", "kasan.log:1")] }),
    );

    const resolved = loadHuntLedger(ledger);
    const entry = [...resolved.values()][0];
    expect(entry.conflicted).toBe(true);
    expect(disprovenHuntClaims(resolved)).toEqual([]);
    expect(loadKnownNegativesFromLedger(ledger)).toEqual([]);
    // A contradicted claim is an open question, not a settled one.
    expect(unresolvedHuntClaims(resolved)).toHaveLength(1);
  });

  it("is inert on a missing ledger", () => {
    expect(readHuntLedger(join(dir, "nope.jsonl"))).toEqual([]);
    expect(loadKnownNegativesFromLedger(join(dir, "nope.jsonl"))).toEqual([]);
  });
});

describe("observations vs assumptions", () => {
  it("keeps the two distinguishable through write, read, and resolve", () => {
    appendHuntClaim(
      ledger,
      claim({
        status: "validated",
        worker: "prover-3",
        evidence: [
          observation("KASAN reports a UAF read at foo_retry+0x40", "kasan.log:17"),
          assumption("the same window probably exists on the resume path"),
        ],
      }),
    );

    const entry = [...loadHuntLedger(ledger).values()][0];
    expect(entry.observations.map((e) => e.statement)).toEqual(["KASAN reports a UAF read at foo_retry+0x40"]);
    expect(entry.assumptions.map((e) => e.statement)).toEqual(["the same window probably exists on the resume path"]);
    expect(entry.observations[0].locator).toBe("kasan.log:17");
    expect(entry.assumptions[0].locator).toBeUndefined();
  });

  it("refuses an observation with no locator", () => {
    expect(() =>
      createHuntClaim(
        claim({
          status: "validated",
          evidence: [{ stance: "observation", statement: "I checked", source: "skeptic.gpt-5" }],
        }),
      ),
    ).toThrow(/observation and must carry a locator/);
  });

  it("refuses to settle a claim on assumptions alone", () => {
    for (const status of ["validated", "disproven"] as const) {
      expect(() =>
        createHuntClaim(claim({ status, evidence: [assumption("it is probably unreachable")] })),
      ).toThrow(/requires at least one observation/);
    }
    // The same evidence is fine for an open claim — recording an assumption is
    // exactly how a later worker learns what to attack first.
    expect(createHuntClaim(claim({ status: "unresolved" })).status).toBe("unresolved");
  });
});

describe("append-only and idempotence", () => {
  it("retains history across a status transition", () => {
    appendHuntClaim(ledger, claim({ worker: "finder-1" }));
    appendHuntClaim(
      ledger,
      claim({ status: "disproven", worker: "skeptic-2", evidence: [observation("guard present", "foo.c:812")] }),
    );

    const entry = [...loadHuntLedger(ledger).values()][0];
    expect(entry.records).toHaveLength(2);
    expect(entry.records.map((r) => r.status)).toEqual(["unresolved", "disproven"]);
    expect(entry.status).toBe("disproven");
    // The earlier record is still byte-present on disk — nothing was rewritten.
    expect(readFileSync(ledger, "utf8").split("\n").filter(Boolean)).toHaveLength(2);
  });

  it("does not duplicate a claim when identical work is re-run", () => {
    const input = claim({
      status: "disproven",
      worker: "skeptic-2",
      evidence: [observation("guard present", "foo.c:812")],
    });
    const first = appendHuntClaim(ledger, input);
    const second = appendHuntClaim(ledger, input);
    expect(second.id).toBe(first.id);

    // The file physically grew (append-only, no read-before-write) …
    expect(readFileSync(ledger, "utf8").split("\n").filter(Boolean)).toHaveLength(2);
    // … but the ledger's view is deduped, so the re-run changed nothing.
    expect(readHuntLedger(ledger)).toHaveLength(1);
    expect(disprovenHuntClaims(loadHuntLedger(ledger))).toHaveLength(1);
  });

  it("treats two workers reaching the same conclusion as corroboration, not a duplicate", () => {
    const evidence = [observation("guard present", "foo.c:812")];
    appendHuntClaim(ledger, claim({ status: "disproven", worker: "skeptic-2", evidence }));
    appendHuntClaim(ledger, claim({ status: "disproven", worker: "skeptic-9", evidence }));

    const records = readHuntLedger(ledger);
    expect(records).toHaveLength(2);
    // Same claim, two independent producers.
    expect(new Set(records.map((r) => r.claimKey)).size).toBe(1);
    expect(records.map((r) => r.worker)).toEqual(["skeptic-2", "skeptic-9"]);
  });

  it("skips a torn line instead of blinding every reader", () => {
    appendHuntClaim(ledger, claim({ worker: "finder-1" }));
    // Simulate a worker killed mid-write.
    writeFileSync(ledger, `${readFileSync(ledger, "utf8")}{"schemaVersion":1,"id":"sha256:aa`, "utf8");
    const malformed: string[] = [];
    expect(readHuntLedger(ledger, { onMalformed: (line) => malformed.push(line) })).toHaveLength(1);
    expect(malformed).toHaveLength(1);
  });

  it("rejects a record whose id no longer matches its content", () => {
    const record = createHuntClaim(claim());
    expect(() => validateHuntClaimRecord({ ...record, statement: "tampered statement" })).toThrow(
      /does not match its canonical/,
    );
  });

  it("refuses a symlinked ledger path", () => {
    const real = join(dir, "real.jsonl");
    writeFileSync(real, "", "utf8");
    const link = join(dir, "link.jsonl");
    symlinkSync(real, link);
    expect(() => appendHuntClaim(link, claim())).toThrow(/symbolic link/);
    expect(() => readHuntLedger(link)).toThrow(/symbolic link/);
    expect(existsSync(real)).toBe(true);
  });
});

describe("makeSkepticVerifier wiring", () => {
  it("records its verdict and lets a LATER verdict in the same run see it", async () => {
    // Worker A refutes: the mocked refute pass returns no findings.
    agenticScanMock.mockReset();
    agenticScanMock.mockResolvedValue({ findings: [] });
    const { makeSkepticVerifier } = await import("./hunt-scan.js");

    const candidate = { path: "drivers/net/wireless/foo.c" };
    const finding = mkFinding(
      "use-after-free in foo_release",
      "CWE-416: ctx freed while timer_delete_sync may still run",
    );

    const workerA = makeSkepticVerifier({
      sourceRoot: dir,
      runtime: "api",
      model: "model-a",
      crossFamilyRefute: false,
      ledgerPath: ledger,
    });
    const verdictA = await workerA(finding, candidate);
    expect(verdictA.confirmed).toBe(false);

    // The refutation is on the ledger, phrased as what it actually is.
    const dead = disprovenHuntClaims(loadHuntLedger(ledger));
    expect(dead).toHaveLength(1);
    expect(dead[0].observations[0].statement).toContain("adversarial refute pass over drivers/net/wireless/foo.c");
    expect(dead[0].assumptions[0].statement).toContain("CWE-416");

    // Worker B, constructed AFTER worker A already ran (the in-run case the
    // end-of-run corpus cannot cover), gets the prior refute in its prompt.
    agenticScanMock.mockClear();
    const workerB = makeSkepticVerifier({
      sourceRoot: dir,
      runtime: "api",
      model: "model-b",
      crossFamilyRefute: false,
      ledgerPath: ledger,
    });
    await workerB(finding, candidate);
    const hint = agenticScanMock.mock.calls.at(-1)?.[0]?.challengeHint as string;
    expect(hint).toContain("KNOWN PRIOR REFUTE");
    expect(hint).toContain("adversarial refute pass over drivers/net/wireless/foo.c");
  });

  it("leaves the prompt untouched and writes nothing when no ledger is configured", async () => {
    agenticScanMock.mockReset();
    agenticScanMock.mockResolvedValue({ findings: [] });
    const { makeSkepticVerifier } = await import("./hunt-scan.js");
    const verifier = makeSkepticVerifier({ sourceRoot: dir, runtime: "api", model: "model-a", crossFamilyRefute: false });
    await verifier(mkFinding("some claim", "analysis"), { path: "a.c" });
    const hint = agenticScanMock.mock.calls.at(-1)?.[0]?.challengeHint as string;
    expect(hint).not.toContain("KNOWN PRIOR REFUTE");
    expect(existsSync(ledger)).toBe(false);
  });

  it("does not let a ledger I/O failure change the verdict", async () => {
    agenticScanMock.mockReset();
    agenticScanMock.mockResolvedValue({ findings: [{ id: "x" }] });
    const { makeSkepticVerifier } = await import("./hunt-scan.js");
    // A directory is not a writable ledger file.
    const verifier = makeSkepticVerifier({
      sourceRoot: dir,
      runtime: "api",
      model: "model-a",
      crossFamilyRefute: false,
      ledgerPath: dir,
    });
    const verdict = await verifier(mkFinding("some claim", "analysis"), { path: "a.c" });
    expect(verdict.confirmed).toBe(true);
  });
});

describe("dependencies", () => {
  it("flags claims resting transitively on a disproven claim", () => {
    const root = appendHuntClaim(
      ledger,
      claim({
        statement: "the retry timer is the only other ctx consumer",
        status: "disproven",
        worker: "skeptic-2",
        evidence: [observation("resume path also holds a ref", "foo.c:640")],
      }),
    );
    const mid = appendHuntClaim(
      ledger,
      claim({
        statement: "therefore the free is unguarded",
        dependsOn: [root.claimKey],
        worker: "finder-1",
      }),
    );
    appendHuntClaim(
      ledger,
      claim({
        statement: "therefore the bug is remotely reachable",
        dependsOn: [mid.claimKey],
        worker: "finder-1",
      }),
    );

    const stale = staleHuntClaims(loadHuntLedger(ledger)).map((c) => c.statement);
    expect(stale).toContain("therefore the free is unguarded");
    expect(stale).toContain("therefore the bug is remotely reachable");
    expect(stale).not.toContain("the retry timer is the only other ctx consumer");
  });

  it("survives a dependency cycle", () => {
    const a = createHuntClaim(claim({ statement: "claim a", worker: "finder-1" }));
    const b = createHuntClaim(claim({ statement: "claim b", dependsOn: [a.claimKey], worker: "finder-1" }));
    const aCyclic = createHuntClaim(claim({ statement: "claim a", dependsOn: [b.claimKey], worker: "finder-1" }));
    const resolved = resolveHuntLedger([a, b, aCyclic]);
    expect(() => staleHuntClaims(resolved)).not.toThrow();
    expect(staleHuntClaims(resolved)).toEqual([]);
  });
});
