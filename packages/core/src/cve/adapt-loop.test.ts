import { beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  adaptAndVerify,
  applyUnifiedDiff,
  renderAdaptationPrompt,
} from "./adapt-loop.js";
import type { AdaptationAgent, AdaptationAgentInput, VerifyKernelFinding } from "./adapt-loop.js";
import type { CveArtifactProvider, CveArtifacts, PocCandidate, FetchedPoc } from "./types.js";
import type { JournalEntry, JournalEntryInput, JournalPaths, JournalWriter } from "../agent/journal/index.js";

// ── Test helpers ────────────────────────────────────────────────────────────

interface RecordingJournal {
  writer: JournalWriter;
  entries: JournalEntry[];
}

function makeJournal(): RecordingJournal {
  const entries: JournalEntry[] = [];
  const paths: JournalPaths = {
    runDir: "/tmp/test-run",
    journalPath: "/tmp/test-run/journal.jsonl",
    artifactsDir: "/tmp/test-run/artifacts",
  };
  const writer: JournalWriter = {
    paths,
    append(input: JournalEntryInput): JournalEntry {
      const entry = {
        schemaVersion: 1,
        id: `id-${entries.length}`,
        runId: "test-run",
        timestamp: new Date(0).toISOString(),
        ...input,
      } as JournalEntry;
      entries.push(entry);
      return entry;
    },
    load() {
      return entries;
    },
  };
  return { writer, entries };
}

function makeArtifacts(candidates: PocCandidate[]): CveArtifacts {
  return {
    cveId: "CVE-2024-1086",
    pocCandidates: candidates,
    writeupText: "Use-after-free in nf_tables; trigger via crafted netlink message.",
    affectedKernelSubsystem: "net/netfilter/nf_tables_api.c",
    expectedSignature: "KASAN: slab-use-after-free",
  };
}

function makeFetcher(cacheRoot: string) {
  return async (candidate: PocCandidate): Promise<FetchedPoc> => {
    const path = join(cacheRoot, `${candidate.url.replace(/[^a-z0-9]+/gi, "_")}.${candidate.language}`);
    if (!existsSync(path)) {
      writeFileSync(path, "int main(void) {\n  return 0;\n}\n", "utf-8");
    }
    return {
      local_path: path,
      language: candidate.language,
      sha256: "deadbeef",
      source_url: candidate.url,
      fetched_at: new Date(0).toISOString(),
    };
  };
}

describe("adaptAndVerify", () => {
  let cacheRoot: string;

  beforeEach(() => {
    cacheRoot = mkdtempSync(join(tmpdir(), "0sec-adapt-test-"));
  });

  it("returns confirmed on first-try reproduction", async () => {
    const candidate: PocCandidate = {
      url: "https://raw.example/CVE.c",
      source: "github-raw",
      language: "c",
      confidence: 0.9,
    };
    const provider: CveArtifactProvider = async () => makeArtifacts([candidate]);
    const runner: VerifyKernelFinding = async () => ({
      status: "reproduced",
      signature: "kasan-uaf",
      dmesg_path: join(cacheRoot, "dmesg.log"),
      build_cache_hit: true,
    });
    // Make sure dmesg_path exists for any potential read.
    writeFileSync(join(cacheRoot, "dmesg.log"), "BUG: KASAN: slab-use-after-free\n", "utf-8");
    const recorder = makeJournal();

    const result = await adaptAndVerify("CVE-2024-1086", {
      kernelTree: "/fake/tree",
      artifactProvider: provider,
      fetcher: makeFetcher(cacheRoot),
      runner,
      journalFactory: () => recorder.writer,
    });

    expect(result.status).toBe("confirmed");
    expect(result.signature).toBe("kasan-uaf");
    expect(result.attempts.length).toBe(1);
    expect(result.attempts[0].verification?.status).toBe("reproduced");

    const summaries = recorder.entries
      .filter((e) => e.kind === "observation")
      .map((e) => (e as { summary: string }).summary);
    expect(summaries).toContain("attempt_started");
    expect(summaries).toContain("poc_fetched");
    expect(summaries).toContain("verify_run");

    const done = recorder.entries.find((e) => e.kind === "done");
    expect(done).toBeDefined();
    expect((done as { status: string }).status).toBe("success");
  });

  it("falls back to the second candidate after the first fails to reproduce", async () => {
    const candA: PocCandidate = { url: "https://raw.example/A.c", source: "github-raw", language: "c", confidence: 0.9 };
    const candB: PocCandidate = { url: "https://raw.example/B.c", source: "github-raw", language: "c", confidence: 0.7 };

    const provider: CveArtifactProvider = async () => makeArtifacts([candA, candB]);

    const seen: string[] = [];
    const runner: VerifyKernelFinding = async (opts) => {
      seen.push(opts.reproducerPath ?? opts.syzProgramPath ?? "");
      const path = opts.reproducerPath ?? "";
      // The fetcher sanitises URLs to filenames (replacing . with _), so the
      // raw URL `https://raw.example/B.c` becomes a cache filename containing
      // `_B_c`. Look for the disambiguator (`_B_` / `_A_`).
      const verdict = /_B_/.test(path) ? "reproduced" : "no_signal";
      return {
        status: verdict,
        signature: verdict === "reproduced" ? "kasan-uaf" : undefined,
        dmesg_path: join(cacheRoot, "dmesg.log"),
        build_cache_hit: true,
      };
    };
    writeFileSync(join(cacheRoot, "dmesg.log"), "no crash\n", "utf-8");

    const recorder = makeJournal();
    const result = await adaptAndVerify("CVE-2024-1086", {
      kernelTree: "/fake/tree",
      artifactProvider: provider,
      fetcher: makeFetcher(cacheRoot),
      runner,
      // No agent → after first candidate fails, loop should advance to candidate B.
      agent: async () => "",
      journalFactory: () => recorder.writer,
    });

    expect(result.status).toBe("confirmed");
    expect(result.signature).toBe("kasan-uaf");
    expect(result.attempts.length).toBe(2);
    expect(seen[0]).toMatch(/_A_/);
    expect(seen[1]).toMatch(/_B_/);
  });

  it("applies an agent-supplied diff and re-runs successfully", async () => {
    const candidate: PocCandidate = {
      url: "https://raw.example/uaf.c",
      source: "github-raw",
      language: "c",
      confidence: 0.9,
    };
    const provider: CveArtifactProvider = async () => makeArtifacts([candidate]);

    // After diff is applied, the file contents change to include "patched".
    const runner: VerifyKernelFinding = async (opts) => {
      const path = opts.reproducerPath ?? "";
      const src = existsSync(path) ? readFileSync(path, "utf-8") : "";
      const reproduced = src.includes("patched");
      return {
        status: reproduced ? "reproduced" : "no_signal",
        signature: reproduced ? "kasan-uaf" : undefined,
        dmesg_path: join(cacheRoot, "dmesg.log"),
        build_cache_hit: true,
      };
    };
    writeFileSync(join(cacheRoot, "dmesg.log"), "no crash\n", "utf-8");

    const agent: AdaptationAgent = async (input: AdaptationAgentInput) => {
      // Canned diff: replace `return 0;` with `return 0; /* patched */`
      // The source produced by makeFetcher is:
      //   int main(void) {\n  return 0;\n}\n
      void input;
      return [
        "--- a/poc.c",
        "+++ b/poc.c",
        "@@ -1,3 +1,3 @@",
        " int main(void) {",
        "-  return 0;",
        "+  return 0; /* patched */",
        " }",
        "",
      ].join("\n");
    };

    const recorder = makeJournal();
    const result = await adaptAndVerify("CVE-2024-1086", {
      kernelTree: "/fake/tree",
      artifactProvider: provider,
      fetcher: makeFetcher(cacheRoot),
      runner,
      agent,
      attempts: 3,
      journalFactory: () => recorder.writer,
    });

    expect(result.status).toBe("confirmed");
    expect(result.attempts.length).toBe(2);
    expect(result.attempts[0].verification?.status).toBe("no_signal");
    expect(result.attempts[1].verification?.status).toBe("reproduced");
    expect(result.attempts[1].diffApplied).toBe(true);

    const adaptEvents = recorder.entries
      .filter((e) => e.kind === "observation")
      .map((e) => (e as { summary: string }).summary);
    expect(adaptEvents).toContain("adapt_diff_applied");
    expect(result.final_poc_path).toBeDefined();
    expect(readFileSync(result.final_poc_path!, "utf-8")).toContain("patched");
  });

  it("returns budget_exhausted when attempts cap fires", async () => {
    const candidate: PocCandidate = {
      url: "https://raw.example/never.c",
      source: "github-raw",
      language: "c",
      confidence: 0.9,
    };
    const provider: CveArtifactProvider = async () => makeArtifacts([candidate]);
    const runner: VerifyKernelFinding = async () => ({
      status: "no_signal",
      dmesg_path: join(cacheRoot, "dmesg.log"),
      build_cache_hit: true,
    });
    writeFileSync(join(cacheRoot, "dmesg.log"), "no crash\n", "utf-8");

    // Agent keeps returning a no-op diff that the loop will accept; loop
    // hits the attempts cap.
    let i = 0;
    const agent: AdaptationAgent = async () => {
      i += 1;
      return [
        "--- a/poc.c",
        "+++ b/poc.c",
        "@@ -1,3 +1,3 @@",
        " int main(void) {",
        `-  return 0;`,
        `+  return ${i};`,
        " }",
        "",
      ].join("\n");
    };

    const recorder = makeJournal();
    const result = await adaptAndVerify("CVE-2024-1086", {
      kernelTree: "/fake/tree",
      artifactProvider: provider,
      fetcher: makeFetcher(cacheRoot),
      runner,
      agent,
      attempts: 2,
      journalFactory: () => recorder.writer,
    });

    expect(result.status).toBe("budget_exhausted");
    expect(result.attempts.length).toBe(2);
  });

  it("returns no_artifact when provider has no candidates", async () => {
    const provider: CveArtifactProvider = async () => makeArtifacts([]);
    const recorder = makeJournal();

    const result = await adaptAndVerify("CVE-2024-XXXX", {
      kernelTree: "/fake/tree",
      artifactProvider: provider,
      fetcher: makeFetcher(cacheRoot),
      runner: async () => ({
        status: "no_signal",
        dmesg_path: "",
        build_cache_hit: false,
      }),
      journalFactory: () => recorder.writer,
    });

    expect(result.status).toBe("no_artifact");
    expect(result.attempts).toEqual([]);
  });

  it("returns no_artifact when the provider itself throws", async () => {
    const provider: CveArtifactProvider = async () => {
      throw new Error("network down");
    };
    const recorder = makeJournal();
    const result = await adaptAndVerify("CVE-2024-1086", {
      kernelTree: "/fake/tree",
      artifactProvider: provider,
      fetcher: makeFetcher(cacheRoot),
      runner: async () => ({
        status: "no_signal",
        dmesg_path: "",
        build_cache_hit: false,
      }),
      journalFactory: () => recorder.writer,
    });
    expect(result.status).toBe("no_artifact");
    const err = recorder.entries.find((e) => e.kind === "error");
    expect(err).toBeDefined();
  });

  it("orders candidates by confidence desc", async () => {
    const low: PocCandidate = { url: "https://raw.example/low.c", source: "github-raw", language: "c", confidence: 0.1 };
    const high: PocCandidate = { url: "https://raw.example/high.c", source: "github-raw", language: "c", confidence: 0.95 };
    const provider: CveArtifactProvider = async () => makeArtifacts([low, high]);

    const seen: string[] = [];
    const runner: VerifyKernelFinding = async (opts) => {
      const path = opts.reproducerPath ?? "";
      seen.push(path);
      // Pretend both are reproduced so only the FIRST tried matters.
      return {
        status: "reproduced",
        signature: "kasan-uaf",
        dmesg_path: join(cacheRoot, "dmesg.log"),
        build_cache_hit: true,
      };
    };
    writeFileSync(join(cacheRoot, "dmesg.log"), "ok\n", "utf-8");

    const recorder = makeJournal();
    await adaptAndVerify("CVE-2024-1086", {
      kernelTree: "/fake/tree",
      artifactProvider: provider,
      fetcher: makeFetcher(cacheRoot),
      runner,
      journalFactory: () => recorder.writer,
    });

    expect(seen.length).toBe(1);
    expect(seen[0]).toContain("high");
    expect(seen[0]).not.toContain("low");
  });
});

describe("applyUnifiedDiff", () => {
  it("applies a simple replacement hunk", () => {
    const source = "alpha\nbeta\ngamma\n";
    const diff = [
      "--- a/x",
      "+++ b/x",
      "@@ -1,3 +1,3 @@",
      " alpha",
      "-beta",
      "+BETA",
      " gamma",
      "",
    ].join("\n");
    const next = applyUnifiedDiff(source.replace(/\n$/, ""), diff);
    expect(next.split("\n")).toEqual(["alpha", "BETA", "gamma"]);
  });

  it("supports pure-add hunks", () => {
    const source = "alpha\nbeta";
    const diff = [
      "--- a/x",
      "+++ b/x",
      "@@ -1,2 +1,3 @@",
      " alpha",
      "+inserted",
      " beta",
      "",
    ].join("\n");
    expect(applyUnifiedDiff(source, diff)).toBe("alpha\ninserted\nbeta");
  });

  it("throws on context mismatch (loud failure)", () => {
    const source = "alpha\nbeta\ngamma";
    const diff = [
      "--- a/x",
      "+++ b/x",
      "@@ -1,3 +1,3 @@",
      " WRONG",
      "-beta",
      "+BETA",
      " gamma",
      "",
    ].join("\n");
    expect(() => applyUnifiedDiff(source, diff)).toThrow(/context mismatch/);
  });

  it("returns source unchanged when diff has no hunks", () => {
    expect(applyUnifiedDiff("a\nb", "--- a/x\n+++ b/x\n")).toBe("a\nb");
  });
});

describe("renderAdaptationPrompt", () => {
  it("includes the PoC source, writeup, and error log", () => {
    const out = renderAdaptationPrompt({
      cveId: "CVE-2024-1086",
      pocSource: "int main(){}",
      pocLanguage: "c",
      writeupText: "writeup text",
      errorLog: "no crash signature observed",
      attemptIndex: 1,
    });
    expect(out).toContain("CVE-2024-1086");
    expect(out).toContain("int main(){}");
    expect(out).toContain("writeup text");
    expect(out).toContain("no crash signature observed");
    expect(out).toContain("unified diff");
  });
});
