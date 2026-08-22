import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { describe, it, expect, afterEach } from "vitest";
import {
  parseCrashOutput,
  runUserspaceFuzzLoop,
  cargoFuzzRunArgs,
} from "./userspace-fuzz-runner.js";
import type { MemSafetyTarget } from "./memsafety-types.js";

// ────────────────────────────────────────────────────────────────────
// cargoFuzzRunArgs — `--fuzz-dir` routing for non-standard layouts
// ────────────────────────────────────────────────────────────────────

describe("cargoFuzzRunArgs", () => {
  it("omits --fuzz-dir for the conventional fuzz/ layout", () => {
    const args = cargoFuzzRunArgs("string_input_panic", undefined, 60);
    expect(args).not.toContain("--fuzz-dir");
    expect(args).toEqual([
      "fuzz",
      "run",
      "string_input_panic",
      "--",
      "-max_total_time=60",
    ]);
  });

  it("threads --fuzz-dir for non-standard crates (e.g. Monty's crates/fuzz), before the target", () => {
    const args = cargoFuzzRunArgs("string_input_panic", "crates/fuzz", 60);
    const fdIdx = args.indexOf("--fuzz-dir");
    expect(fdIdx).toBeGreaterThanOrEqual(0);
    expect(args[fdIdx + 1]).toBe("crates/fuzz");
    // the dir flag must precede the target name
    expect(fdIdx).toBeLessThan(args.indexOf("string_input_panic"));
  });

  it("floors a fractional timeout into -max_total_time seconds", () => {
    const args = cargoFuzzRunArgs("t", undefined, 60.9);
    expect(args).toContain("-max_total_time=60");
  });
});

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
const fakeCargoDirs: string[] = [];

afterEach(() => {
  process.env.PATH = REAL_PATH;
  for (const dir of fakeCargoDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function useFakeCargo(
  harnesses: string[],
  runOutput = "Done. 1000 iterations, 0 crashes.\n",
): string {
  const fixtureDir = mkdtempSync(join(tmpdir(), "0sec-fake-cargo-"));
  fakeCargoDirs.push(fixtureDir);
  const sourceRoot = join(fixtureDir, "source");
  mkdirSync(sourceRoot);
  mkdirSync(join(sourceRoot, "fuzz"), { recursive: true });
  writeFileSync(
    join(sourceRoot, "fuzz", "Cargo.toml"),
    "[package]\nname = \"fake-fuzz\"\nversion = \"0.0.0\"\n",
    "utf8",
  );
  const harnessOutput = harnesses.length > 0 ? `${harnesses.join("\n")}\n` : "";

  writeFileSync(
    join(fixtureDir, "cargo"),
    `#!${process.execPath}
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--version") process.exit(0);
if (args[0] === "fuzz" && args[1] === "--help") process.exit(0);
if (args[0] === "fuzz" && args[1] === "list") {
  process.stdout.write(${JSON.stringify(harnessOutput)});
  process.exit(0);
}
if (args[0] === "fuzz" && args[1] === "run") {
  process.stdout.write(${JSON.stringify(runOutput)});
  process.exit(0);
}
process.exit(1);
`,
    "utf8",
  );
  chmodSync(join(fixtureDir, "cargo"), 0o755);
  process.env.PATH = fixtureDir;
  return sourceRoot;
}

describe("runUserspaceFuzzLoop — cargo-fuzz harness discovery", () => {
  it("auto-selects and runs the only existing cargo-fuzz harness", async () => {
    const sourceRoot = useFakeCargo(["only_target"]);
    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      logger: () => {},
    });

    expect(result.toolingMissing).toBeUndefined();
    expect(result.executedHarness).toBe("only_target");
    expect(result.iterations).toBe(1);
    expect(result.crashes).toEqual([]);
  });

  it("removes an empty persistent artifact directory after a no-crash run", async () => {
    const sourceRoot = useFakeCargo(["only_target"]);
    const retainedRoot = mkdtempSync(join(tmpdir(), "0sec-retained-artifacts-"));
    fakeCargoDirs.push(retainedRoot);

    await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      artifactDir: retainedRoot,
      logger: () => {},
    });

    expect(readdirSync(retainedRoot)).not.toContainEqual(
      expect.stringMatching(/^0sec-uf-/),
    );
  });

  it("attaches a cargo-fuzz artifact input to a captured Rust crash", async () => {
    const sourceRoot = useFakeCargo(["only_target"], ASAN_OOB_WRITE);
    const sourceArtifactDir = join(
      sourceRoot,
      "fuzz",
      "artifacts",
      "only_target",
    );
    const sourceInputPath = join(sourceArtifactDir, "crash-deadbeef");
    mkdirSync(sourceArtifactDir, { recursive: true });
    writeFileSync(sourceInputPath, "reproducer", "utf8");
    const retainedRoot = mkdtempSync(join(tmpdir(), "0sec-retained-proof-"));
    fakeCargoDirs.push(retainedRoot);

    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      artifactDir: retainedRoot,
      artifactMaxBytes: 128 * 1024,
      logger: () => {},
    });

    expect(result.crashes).toHaveLength(1);
    expect(result.crashes[0]!.kind).toBe("asan");
    expect(result.crashes[0]!.inputPath).toContain(
      `${retainedRoot}/0sec-uf-`,
    );
  });

  it("retains bounded reproducers and crash logs beneath an explicit artifact root", async () => {
    const sourceRoot = useFakeCargo(["only_target"], ASAN_OOB_WRITE);
    const sourceArtifactDir = join(sourceRoot, "fuzz", "artifacts", "only_target");
    const sourceInput = join(sourceArtifactDir, "crash-deadbeef");
    mkdirSync(sourceArtifactDir, { recursive: true });
    writeFileSync(sourceInput, "reproducer", "utf8");
    const retainedRoot = mkdtempSync(join(tmpdir(), "0sec-retained-artifacts-"));
    fakeCargoDirs.push(retainedRoot);

    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      artifactDir: retainedRoot,
      logger: () => {},
    });

    const crash = result.crashes[0]!;
    const runName = readdirSync(retainedRoot).find((name) =>
      name.startsWith("0sec-uf-"),
    )!;
    const reproducerRef = `${runName}/reproducers/${crash.signature}.input`;
    const reproducerPath = join(retainedRoot, reproducerRef);

    expect(readFileSync(reproducerPath, "utf8")).toBe("reproducer");
    expect(crash.inputPath).toBe(reproducerPath);
    expect(crash.artifactRef).toBe(reproducerRef);
    expect(readFileSync(join(retainedRoot, runName, "logs", `${crash.signature}.log`), "utf8"))
      .toContain("AddressSanitizer");
    expect(
      JSON.parse(readFileSync(join(retainedRoot, runName, "manifest.json"), "utf8")),
    ).toMatchObject({
      schema: "0sec-memsafety-artifacts/v1",
      crashes: [
        {
          signature: crash.signature,
          reproducer: { ref: reproducerRef },
        },
      ],
    });
  });

  it("does not follow a source-tree reproducer symlink into retained evidence", async () => {
    const sourceRoot = useFakeCargo(["only_target"], ASAN_OOB_WRITE);
    const sourceArtifactDir = join(sourceRoot, "fuzz", "artifacts", "only_target");
    const outside = join(tmpdir(), `0sec-outside-${Date.now()}`);
    const sourceInput = join(sourceArtifactDir, "crash-deadbeef");
    mkdirSync(sourceArtifactDir, { recursive: true });
    writeFileSync(outside, "must not retain", "utf8");
    symlinkSync(outside, sourceInput);
    const retainedRoot = mkdtempSync(join(tmpdir(), "0sec-retained-artifacts-"));
    fakeCargoDirs.push(retainedRoot, outside);

    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      artifactDir: retainedRoot,
      logger: () => {},
    });

    expect(result.crashes[0]!.artifactRef).toBeUndefined();
    const runName = readdirSync(retainedRoot).find((name) =>
      name.startsWith("0sec-uf-"),
    )!;
    const manifest = JSON.parse(
      readFileSync(join(retainedRoot, runName, "manifest.json"), "utf8"),
    );
    expect(manifest.crashes[0].reproducer).toBeNull();
  });

  it("does not follow a symlinked artifact-directory ancestor into retained evidence", async () => {
    const sourceRoot = useFakeCargo(["only_target"], ASAN_OOB_WRITE);
    const sourceArtifactRoot = join(sourceRoot, "fuzz", "artifacts");
    const outsideDir = mkdtempSync(join(tmpdir(), "0sec-outside-artifacts-"));
    mkdirSync(sourceArtifactRoot, { recursive: true });
    writeFileSync(join(outsideDir, "crash-deadbeef"), "must not retain", "utf8");
    symlinkSync(outsideDir, join(sourceArtifactRoot, "only_target"));
    const retainedRoot = mkdtempSync(join(tmpdir(), "0sec-retained-artifacts-"));
    fakeCargoDirs.push(retainedRoot, outsideDir);

    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      artifactDir: retainedRoot,
      logger: () => {},
    });

    expect(result.crashes[0]!.artifactRef).toBeUndefined();
    const runName = readdirSync(retainedRoot).find((name) =>
      name.startsWith("0sec-uf-"),
    )!;
    const manifest = JSON.parse(
      readFileSync(join(retainedRoot, runName, "manifest.json"), "utf8"),
    );
    expect(manifest.crashes[0].reproducer).toBeNull();
  });

  it("keeps proof copies below the aggregate artifact budget", async () => {
    const sourceRoot = useFakeCargo(["only_target"], ASAN_OOB_WRITE);
    const sourceArtifactDir = join(sourceRoot, "fuzz", "artifacts", "only_target");
    const sourceInput = join(sourceArtifactDir, "crash-deadbeef");
    mkdirSync(sourceArtifactDir, { recursive: true });
    writeFileSync(sourceInput, Buffer.alloc(128 * 1024, 7));
    const retainedRoot = mkdtempSync(join(tmpdir(), "0sec-retained-artifacts-"));
    fakeCargoDirs.push(retainedRoot);

    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      artifactDir: retainedRoot,
      artifactMaxBytes: 64 * 1024,
      logger: () => {},
    });

    const crash = result.crashes[0]!;
    const runName = readdirSync(retainedRoot).find((name) =>
      name.startsWith("0sec-uf-"),
    )!;
    const manifest = JSON.parse(
      readFileSync(join(retainedRoot, runName, "manifest.json"), "utf8"),
    );
    expect(crash.artifactRef).toBeUndefined();
    expect(manifest.crashes[0]).toMatchObject({
      reproducer: null,
      log: null,
    });
  });

  it("does not discover a cargo-fuzz target outside the source root", async () => {
    const sourceRoot = useFakeCargo(["parent_target"]);
    rmSync(join(sourceRoot, "fuzz"), { recursive: true, force: true });
    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      logger: () => {},
    });

    expect(result.executedHarness).toBeUndefined();
    expect(result.iterations).toBe(0);
    expect(result.toolingMissing).toContain("cargo-fuzz-layout");
  });


  it("rejects traversal fuzz directories and harness names before cargo execution", async () => {
    const sourceRoot = useFakeCargo(["only_target"]);
    const traversal = await runUserspaceFuzzLoop({
      target: {
        language: "rust",
        sourceRoot,
        buildSystem: "cargo",
        fuzzDir: "../outside",
      },
      logger: () => {},
    });
    const invalidHarness = await runUserspaceFuzzLoop({
      target: {
        language: "rust",
        sourceRoot,
        buildSystem: "cargo",
        harnessEntry: "../outside",
      },
      logger: () => {},
    });

    expect(traversal.iterations).toBe(0);
    expect(traversal.toolingMissing).toContain("cargo-fuzz-layout");
    expect(invalidHarness.iterations).toBe(0);
    expect(invalidHarness.toolingMissing).toContain("cargo-fuzz-layout");
  });

  it("supports an ordinary non-standard in-root fuzz directory", async () => {
    const sourceRoot = useFakeCargo(["only_target"]);
    const fuzzDir = join(sourceRoot, "crates", "fuzz");
    mkdirSync(fuzzDir, { recursive: true });

    const result = await runUserspaceFuzzLoop({
      target: {
        language: "rust",
        sourceRoot,
        buildSystem: "cargo",
        fuzzDir: "crates/fuzz",
        harnessEntry: "only_target",
      },
      logger: () => {},
    });

    expect(result.toolingMissing).toBeUndefined();

    expect(result.executedHarness).toBe("only_target");
    expect(result.iterations).toBe(1);
  });
  it("fails closed when cargo-fuzz has no harnesses", async () => {
    const sourceRoot = useFakeCargo([]);
    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      logger: () => {},
    });

    expect(result.executedHarness).toBeUndefined();
    expect(result.iterations).toBe(0);
    expect(result.crashes).toEqual([]);
    expect(result.toolingMissing).toContain("cargo-fuzz-harness");
  });

  it("fails closed instead of choosing among multiple cargo-fuzz harnesses", async () => {
    const sourceRoot = useFakeCargo(["parser", "network"]);
    const result = await runUserspaceFuzzLoop({
      target: { language: "rust", sourceRoot, buildSystem: "cargo" },
      logger: () => {},
    });

    expect(result.executedHarness).toBeUndefined();
    expect(result.iterations).toBe(0);
    expect(result.crashes).toEqual([]);
    expect(result.toolingMissing).toContain("cargo-fuzz-harness");
  });
});

describe("runUserspaceFuzzLoop — tooling-absent contract", () => {

  function withoutToolchain<T>(fn: () => Promise<T>): Promise<T> {
    // Point PATH at a directory with no executables so every probe ENOENTs.
    process.env.PATH = "/nonexistent-0sec-test-path";
    return fn();
  }

  const rustTarget: MemSafetyTarget = {
    language: "rust",
    sourceRoot: "/tmp/0sec-no-such-rust-target",
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
      sourceRoot: "/tmp/0sec-no-such-c-target",
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
      sourceRoot: "/tmp/0sec-no-such-c-target",
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

// ────────────────────────────────────────────────────────────────────
// Env isolation: cargo-fuzz builds and RUNS target-derived code (a hostile
// crate's build.rs / the fuzzed code can read process.env). The fuzz child
// must therefore never inherit the harness's provider/cloud credentials.
// ────────────────────────────────────────────────────────────────────

/**
 * Like useFakeCargo, but the `fuzz run` branch dumps the child's own view of a
 * representative credential + PATH to `dumpPath` so the test can assert what
 * the fuzz subprocess actually received in its environment.
 */
function useEnvDumpingCargo(dumpPath: string): string {
  const fixtureDir = mkdtempSync(join(tmpdir(), "0sec-envdump-cargo-"));
  fakeCargoDirs.push(fixtureDir);
  const sourceRoot = join(fixtureDir, "source");
  mkdirSync(join(sourceRoot, "fuzz"), { recursive: true });
  writeFileSync(
    join(sourceRoot, "fuzz", "Cargo.toml"),
    "[package]\nname = \"fake-fuzz\"\nversion = \"0.0.0\"\n",
    "utf8",
  );
  writeFileSync(
    join(fixtureDir, "cargo"),
    `#!${process.execPath}
const fs = require("fs");
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--version") process.exit(0);
if (args[0] === "fuzz" && args[1] === "--help") process.exit(0);
if (args[0] === "fuzz" && args[1] === "list") { process.stdout.write("only_target\\n"); process.exit(0); }
if (args[0] === "fuzz" && args[1] === "run") {
  fs.writeFileSync(${JSON.stringify(dumpPath)}, JSON.stringify({
    anthropic: process.env.ANTHROPIC_API_KEY || "ABSENT",
    github: process.env.GITHUB_TOKEN || "ABSENT",
    path: process.env.PATH ? "SET" : "ABSENT",
  }));
  process.stdout.write("Done. 1000 iterations, 0 crashes.\\n");
  process.exit(0);
}
process.exit(1);
`,
    "utf8",
  );
  chmodSync(join(fixtureDir, "cargo"), 0o755);
  process.env.PATH = fixtureDir;
  return sourceRoot;
}

describe("runUserspaceFuzzLoop — env isolation", () => {
  it("does not expose harness credentials to the fuzz child, but keeps PATH", async () => {
    const prevAnthropic = process.env.ANTHROPIC_API_KEY;
    const prevGithub = process.env.GITHUB_TOKEN;
    process.env.ANTHROPIC_API_KEY = "sk-ant-should-not-leak";
    process.env.GITHUB_TOKEN = "ghp_should_not_leak";
    const dumpDir = mkdtempSync(join(tmpdir(), "0sec-fuzz-envdump-"));
    fakeCargoDirs.push(dumpDir);
    const dumpPath = join(dumpDir, "child-env.json");
    try {
      const sourceRoot = useEnvDumpingCargo(dumpPath);
      const result = await runUserspaceFuzzLoop({
        target: { language: "rust", sourceRoot, buildSystem: "cargo" },
        logger: () => {},
      });
      expect(result.executedHarness).toBe("only_target");
      const seen = JSON.parse(readFileSync(dumpPath, "utf8"));
      expect(seen.anthropic).toBe("ABSENT");
      expect(seen.github).toBe("ABSENT");
      expect(seen.path).toBe("SET");
    } finally {
      if (prevAnthropic === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = prevAnthropic;
      if (prevGithub === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = prevGithub;
    }
  });
});
