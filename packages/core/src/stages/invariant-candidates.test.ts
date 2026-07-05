/**
 * `generateInvariantCandidates` — spec parsing + candidate shaping + the
 * runHuntScan-plug mapping, plus the 2-thread race-PoC template scaffold.
 *
 * Mock-at-module-boundary for `node:fs` (feed source without a real tree) and
 * `../runtime/llm-api.js` (no real LLM / no key needed) — mirrors
 * `variant-candidates.test.ts`'s strategy so CI stays key-free.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const readFileSyncMock = vi.fn();
vi.mock("node:fs", () => ({
  readFileSync: (...args: unknown[]) => readFileSyncMock(...args),
}));

const executeNativeMock = vi.fn();
vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    executeNative(...args: unknown[]) {
      return executeNativeMock(...args);
    }
  },
}));

const { generateInvariantCandidates } = await import("./invariant-candidates.js");
const { renderRaceHarness, makeTemplateRacePocSynth } = await import("./race-poc-synth.js");

const SPEC = {
  lock: "unix_gc_lock",
  guardedFields: ["gc_candidate", "u->inflight", "gc_in_progress"],
  refcountBalance: "each in-flight fd holds one ref on the peer sk; GC drops exactly the inflight refs",
  stateTransitions: ["UNIX_GC_CANDIDATE -> scanned -> collectible -> freed"],
};

/** A well-formed candidate + a malformed one (missing racing pair) to exercise filtering. */
function mockFsAndLlm(): void {
  readFileSyncMock.mockReset().mockImplementation((path: string) => {
    if (String(path).includes("garbage.c")) return "/* unix gc state machine */\nvoid __unix_gc(void) {}\n";
    if (String(path).includes("af_unix.c")) return "/* af_unix */\nint unix_stream_sendmsg(void) { return 0; }\n";
    throw new Error(`ENOENT: ${path}`);
  });
  executeNativeMock.mockReset().mockResolvedValue({
    content: [
      {
        type: "tool_use",
        name: "emit_invariant_analysis",
        input: {
          spec: SPEC,
          candidates: [
            {
              invariant: "gc_in_progress must exclude concurrent inflight mutation",
              racingSyscallPair: { A: "sendmsg(SCM_RIGHTS)", B: "close(fd)" },
              field: "u->inflight",
              hypothesizedPrimitive: "refcount underflow -> UAF on sk",
              site: "net/unix/garbage.c:250",
            },
            {
              invariant: "candidate list is stable during scan",
              racingSyscallPair: { A: "recvmsg", B: "__unix_gc" },
              field: "gc_candidate",
              hypothesizedPrimitive: "UAF",
              // no site -> falls back to first subsystem file
            },
            {
              // malformed: missing racingSyscallPair -> must be dropped
              invariant: "bogus",
              field: "x",
              hypothesizedPrimitive: "OOB",
            },
          ],
        },
      },
    ],
  });
}

beforeEach(() => {
  mockFsAndLlm();
});

describe("generateInvariantCandidates", () => {
  it("parses the invariant spec off the model tool call", async () => {
    const plan = await generateInvariantCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["net/unix/garbage.c", "net/unix/af_unix.c"],
      runtime: "api",
    });
    expect(plan.spec).toEqual(SPEC);
    expect(plan.brief.bugClass).toContain("unix_gc_lock");
    expect(plan.brief.pattern).toContain("u->inflight");
  });

  it("keeps well-formed candidates and drops malformed ones", async () => {
    const plan = await generateInvariantCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["net/unix/garbage.c", "net/unix/af_unix.c"],
      runtime: "api",
    });
    // 3 emitted, 1 malformed dropped.
    expect(plan.invariantCandidates).toHaveLength(2);
    expect(plan.warnings.some((w) => w.includes("dropped 1 malformed"))).toBe(true);
    for (const c of plan.invariantCandidates) {
      expect(typeof c.racingSyscallPair.A).toBe("string");
      expect(typeof c.racingSyscallPair.B).toBe("string");
      expect(c.field).toBeTruthy();
      expect(c.hypothesizedPrimitive).toBeTruthy();
    }
  });

  it("maps candidates to runHuntScan sites (model site when known, else first file)", async () => {
    const plan = await generateInvariantCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["net/unix/garbage.c", "net/unix/af_unix.c"],
      runtime: "api",
    });
    const paths = plan.candidates.map((c) => c.path);
    // Both valid candidates resolve to garbage.c (one via site:line, one via fallback=first file),
    // so they dedupe onto a single site with a merged hint.
    expect(paths).toEqual(["net/unix/garbage.c"]);
    expect(plan.candidates[0].hint).toContain("sendmsg(SCM_RIGHTS)");
    expect(plan.candidates[0].hint).toContain("---"); // merged second hint
  });

  it("respects maxCandidates", async () => {
    const plan = await generateInvariantCandidates({
      sourceRoot: "/src",
      subsystemFiles: ["net/unix/garbage.c"],
      runtime: "api",
      maxCandidates: 1,
    });
    expect(plan.invariantCandidates).toHaveLength(1);
    expect(plan.warnings.some((w) => w.includes("capped candidates"))).toBe(true);
  });

  it("throws when no subsystem file is readable", async () => {
    readFileSyncMock.mockReset().mockImplementation(() => {
      throw new Error("ENOENT");
    });
    await expect(
      generateInvariantCandidates({ sourceRoot: "/src", subsystemFiles: ["nope.c"], runtime: "api" }),
    ).rejects.toThrow(/could not read any subsystemFile/);
  });

  it("throws when the model emits no usable spec", async () => {
    executeNativeMock.mockReset().mockResolvedValue({ content: [{ type: "text", text: "no tool call" }] });
    await expect(
      generateInvariantCandidates({ sourceRoot: "/src", subsystemFiles: ["net/unix/garbage.c"], runtime: "api" }),
    ).rejects.toThrow(/usable invariant spec/);
  });
});

describe("renderRaceHarness / race-poc-synth", () => {
  const candidate = {
    invariant: "gc_in_progress must exclude concurrent inflight mutation",
    racingSyscallPair: { A: "sendmsg(SCM_RIGHTS)", B: "close(fd)" },
    field: "u->inflight",
    hypothesizedPrimitive: "refcount underflow -> UAF on sk",
  };

  it("emits a 2-thread harness pinned to two CPUs with the race-widen knobs", () => {
    const src = renderRaceHarness({ candidate, cpus: [2, 3] });
    // Two threads, pinned to the requested CPUs.
    expect(src).toContain("pthread_create");
    expect(src).toContain("sched_setaffinity");
    expect(src).toContain("pin_to_cpu(2)");
    expect(src).toContain("pin_to_cpu(3)");
    // The PWNKIT_RACE_* widen knobs are wired.
    expect(src).toContain("PWNKIT_RACE_ITERS");
    expect(src).toContain("PWNKIT_RACE_WIDEN");
    expect(src).toContain("PWNKIT_RACE_SPIN");
    // The candidate's syscalls appear as TODO stubs (codegen is a follow-up).
    expect(src).toContain("sendmsg(SCM_RIGHTS)");
    expect(src).toContain("close(fd)");
    expect(src).toContain("TODO(#1113)");
  });

  it("defaults to CPUs 0/1 and produces a C identifier-safe thread name", () => {
    const src = makeTemplateRacePocSynth().synthesize({ candidate });
    expect(src).toContain("pin_to_cpu(0)");
    expect(src).toContain("pin_to_cpu(1)");
    // Non-ident chars in the syscall name are sanitized for the C function name.
    expect(src).toMatch(/thread_sendmsg_SCM_RIGHTS_/);
  });
});
