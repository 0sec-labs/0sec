import { describe, it, expect, afterEach } from "vitest";
import {
  parseCrashOutput,
  runUserspaceFuzzLoop,
} from "./userspace-fuzz-runner.js";
import type { MemSafetyTarget } from "./memsafety-types.js";

// ────────────────────────────────────────────────────────────────────
// parseCrashOutput — raw run output → CrashArtifact.kind / .primitive
// ────────────────────────────────────────────────────────────────────

const ASAN_UAF = `==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x4f9abc
READ of size 4 at 0x602000000010 thread T0
    #0 0x4f9abc in use_after_free /src/foo.c:42:7
    #1 0x4f8000 in main /src/foo.c:60:3
SUMMARY: AddressSanitizer: heap-use-after-free /src/foo.c:42:7 in use_after_free`;

const ASAN_OOB_WRITE = `==2222==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018 at pc 0x401abc
WRITE of size 8 at 0x602000000018 thread T0
    #0 0x401abc in copy_into /src/buf.c:88:5
    #1 0x401000 in main /src/buf.c:120:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/buf.c:88:5 in copy_into`;

const ASAN_OOB_READ = `==3333==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000040 at pc 0x401def
READ of size 4 at 0x602000000040 thread T0
    #0 0x401def in read_past /src/buf.c:200:9
    #1 0x401111 in main /src/buf.c:240:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/buf.c:200:9 in read_past`;

const MIRI_UB = `error: Undefined Behavior: pointer to alloc1234 was dereferenced after this allocation got freed
    --> src/lib.rs:42:18
     |
  42 |     unsafe { *dangling }
     |              ^^^^^^^^^
note: inside \`use_freed\` at src/lib.rs:42:18`;

const RUST_PANIC = `thread 'main' panicked at src/main.rs:10:9:
index out of bounds: the len is 3 but the index is 9
note: run with \`RUST_BACKTRACE=1\` environment variable to display a backtrace
   0: rust_begin_unwind
   1: core::panicking::panic_fmt`;

const BARE_SEGV = `==6666==ERROR: libFuzzer: deadly signal
   1: my_crate::oops
==6666== signal SIGSEGV (segmentation fault)`;

describe("parseCrashOutput", () => {
  it("ASan heap-use-after-free → kind=asan, primitive=use-after-free", () => {
    const c = parseCrashOutput(ASAN_UAF);
    expect(c).not.toBeNull();
    expect(c!.kind).toBe("asan");
    expect(c!.primitive).toBe("use-after-free");
    expect(c!.stack?.length).toBeGreaterThan(0);
  });

  it("ASan heap-buffer-overflow WRITE → primitive=heap-oob-write", () => {
    const c = parseCrashOutput(ASAN_OOB_WRITE);
    expect(c!.kind).toBe("asan");
    expect(c!.primitive).toBe("heap-oob-write");
  });

  it("ASan heap-buffer-overflow READ → primitive=heap-oob-read", () => {
    const c = parseCrashOutput(ASAN_OOB_READ);
    expect(c!.kind).toBe("asan");
    expect(c!.primitive).toBe("heap-oob-read");
  });

  it("Miri UB → kind=miri, primitive=use-after-free", () => {
    const c = parseCrashOutput(MIRI_UB);
    expect(c!.kind).toBe("miri");
    expect(c!.primitive).toBe("use-after-free");
  });

  it("Rust panic (index oob) → kind=panic, primitive=heap-oob-read", () => {
    const c = parseCrashOutput(RUST_PANIC);
    expect(c!.kind).toBe("panic");
    expect(c!.primitive).toBe("heap-oob-read");
  });

  it("bare deadly signal → kind=segfault, primitive=null-deref", () => {
    const c = parseCrashOutput(BARE_SEGV);
    expect(c!.kind).toBe("segfault");
    expect(c!.primitive).toBe("null-deref");
  });

  it("timeout hint with non-crash output → kind=timeout", () => {
    const c = parseCrashOutput("still running... no crash here", { kind: "timeout" });
    expect(c!.kind).toBe("timeout");
    expect(c!.primitive).toBe("unknown");
  });

  it("libFuzzer OOM → kind=oom", () => {
    const c = parseCrashOutput("==1==ERROR: libFuzzer: out-of-memory (rss limit exceeded)");
    expect(c!.kind).toBe("oom");
  });

  it("returns null for empty / benign output (never fabricates a crash)", () => {
    expect(parseCrashOutput("")).toBeNull();
    expect(parseCrashOutput("   \n  ")).toBeNull();
    expect(parseCrashOutput("Done. 1000 iterations, 0 crashes. Everything passed.")).toBeNull();
  });

  it("threads through the inputPath hint", () => {
    const c = parseCrashOutput(ASAN_UAF, { inputPath: "/tmp/crash-abc" });
    expect(c!.inputPath).toBe("/tmp/crash-abc");
  });
});

// ────────────────────────────────────────────────────────────────────
// Signature stability — dedup invariant
// ────────────────────────────────────────────────────────────────────

describe("parseCrashOutput — signature stability", () => {
  it("the same crash text yields the same signature (deterministic)", () => {
    const a = parseCrashOutput(ASAN_UAF);
    const b = parseCrashOutput(ASAN_UAF);
    expect(a!.signature).toBe(b!.signature);
  });

  it("addresses/PIDs differ but the stack is the same → same signature", () => {
    // Same frames, different runtime addresses + report PID. The normalised
    // signature must collapse these to one bug.
    const rerun = ASAN_UAF
      .replace(/0x602000000010/g, "0x701ffffabcd0")
      .replace("==12345==", "==99999==")
      .replace("0x4f9abc", "0xdeadbe");
    const a = parseCrashOutput(ASAN_UAF);
    const b = parseCrashOutput(rerun);
    expect(b!.signature).toBe(a!.signature);
  });

  it("a materially different crash (different frames) → different signature", () => {
    const a = parseCrashOutput(ASAN_UAF);
    const b = parseCrashOutput(ASAN_OOB_WRITE);
    expect(b!.signature).not.toBe(a!.signature);
  });

  it("different crash kinds with no frames still separate by kind", () => {
    const oom = parseCrashOutput("==1==ERROR: libFuzzer: out-of-memory");
    const timeout = parseCrashOutput("hang", { kind: "timeout" });
    expect(oom!.signature).not.toBe(timeout!.signature);
  });
});

// ────────────────────────────────────────────────────────────────────
// runUserspaceFuzzLoop — tooling-absent contract
//
// The whole point of Monty-mode's degrade-when-absent rule: the loop must
// NEVER fabricate a crash or a fake clean pass when the toolchain is
// missing. We force every toolchain probe to fail by emptying PATH so the
// `execFile("cargo"/"clang", ...)` calls hit ENOENT — this makes the test
// deterministic regardless of what is installed on the host CI box.
// ────────────────────────────────────────────────────────────────────

const REAL_PATH = process.env.PATH;

describe("runUserspaceFuzzLoop — tooling-absent contract", () => {
  afterEach(() => {
    process.env.PATH = REAL_PATH;
  });

  function withoutToolchain<T>(fn: () => Promise<T>): Promise<T> {
    // Point PATH at a directory with no executables so every probe ENOENTs.
    process.env.PATH = "/nonexistent-pwnkit-test-path";
    return fn();
  }

  const rustTarget: MemSafetyTarget = {
    language: "rust",
    sourceRoot: "/tmp/pwnkit-no-such-rust-target",
    buildSystem: "cargo",
    harnessEntry: "fuzz_target_1",
  };

  it("Rust target with cargo absent → iterations:0, no crashes, cargo in toolingMissing", async () => {
    const result = await withoutToolchain(() =>
      runUserspaceFuzzLoop({ target: rustTarget, logger: () => {} }),
    );
    expect(result.iterations).toBe(0);
    expect(result.crashes).toHaveLength(0);
    expect(result.toolingMissing).toBeDefined();
    expect(result.toolingMissing).toContain("cargo");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("C/C++ target with clang absent → iterations:0, no crashes, clang missing", async () => {
    const cTarget: MemSafetyTarget = {
      language: "c",
      sourceRoot: "/tmp/pwnkit-no-such-c-target",
      buildSystem: "make",
    };
    const result = await withoutToolchain(() =>
      runUserspaceFuzzLoop({
        target: cTarget,
        // A tier2 artifact is present, so the loop proceeds to the clang probe.
        tier2Artifact: {
          // minimal shape: only the two commands the runner consumes.
          compile_command: "clang -fsanitize=fuzzer,address harness.c -o h",
          run_command: "./h -runs=1000",
        } as never,
        logger: () => {},
      }),
    );
    expect(result.iterations).toBe(0);
    expect(result.crashes).toHaveLength(0);
    expect(result.toolingMissing).toContain("clang");
  });

  it("C/C++ target with NO tier2 artifact → honest empty result, never a fake crash", async () => {
    const cTarget: MemSafetyTarget = {
      language: "c",
      sourceRoot: "/tmp/pwnkit-no-such-c-target",
      buildSystem: "make",
    };
    const result = await runUserspaceFuzzLoop({ target: cTarget, logger: () => {} });
    expect(result.iterations).toBe(0);
    expect(result.crashes).toHaveLength(0);
    // No toolchain was probed (nothing to run), so this is a clean honest zero,
    // not a fabricated pass: crashes is empty and iterations is 0.
  });

  it("never fabricates a crash when tooling is missing", async () => {
    const result = await withoutToolchain(() =>
      runUserspaceFuzzLoop({ target: rustTarget, runMiri: true, logger: () => {} }),
    );
    expect(result.crashes).toEqual([]);
    expect(result.iterations).toBe(0);
    // cargo is the floor; once it is missing the loop bails before miri, so
    // cargo (at least) is reported missing.
    expect(result.toolingMissing).toContain("cargo");
  });
});
