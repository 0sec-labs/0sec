/**
 * Shared contract for the userspace / Rust memory-safety pipeline
 * ("Monty-mode"). See docs/pwnkit-rust-memsafety-pipeline.md.
 *
 * Track B owns this file; Tracks A and C import from it.
 */

/** A userspace / Rust build under test. */
export interface MemSafetyTarget {
  language: "c" | "cpp" | "rust";
  sourceRoot: string;
  buildSystem: "cargo" | "cmake" | "autotools" | "meson" | "make";
  /** libFuzzer / cargo-fuzz target name, when known. */
  harnessEntry?: string;
  /**
   * Non-standard cargo-fuzz directory, relative to `sourceRoot`, for projects
   * that don't keep their fuzz crate at the conventional `fuzz/` (e.g. Monty
   * uses `crates/fuzz`). Passed to `cargo fuzz` as `--fuzz-dir` and used to
   * locate the corpus. Defaults to `fuzz` when omitted.
   */
  fuzzDir?: string;
}

/** Memory-safety primitive classes (userspace analogue of KernelPrimitive). */
export type MemPrimitive =
  | "use-after-free"
  | "double-free"
  | "heap-oob-read"
  | "heap-oob-write"
  | "stack-oob"
  | "type-confusion"
  | "uninit-read"
  | "null-deref"
  | "integer-overflow"
  | "unknown";

/** A single crash captured from a fuzz/run iteration. */
export interface CrashArtifact {
  kind:
    | "asan"
    | "ubsan"
    | "msan"
    | "miri"
    | "panic"
    | "segfault"
    | "timeout"
    | "oom";
  /** Dedup hash over the normalised stack. */
  signature: string;
  /** Raw sanitizer / miri / panic text. */
  rawOutput: string;
  /** Path to the reproducing input, when one was saved. */
  inputPath?: string;
  /** Symbolised stack frames, when available. */
  stack?: string[];
  primitive?: MemPrimitive;
}

/** Result of one closed fuzz loop run. */
export interface FuzzLoopResult {
  iterations: number;
  /** Deduped by signature. */
  crashes: CrashArtifact[];
  corpusSize: number;
  durationMs: number;
  /** Tooling that was required but absent, e.g. ["cargo-fuzz","miri"]. */
  toolingMissing?: string[];
}

/** Exploitability assessment for a crash (assist-scoped — not a synthesised exploit). */
export interface ExploitabilityVerdict {
  primitive: MemPrimitive;
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Attacker-controlled offset / value? */
  controllable: boolean;
  readWrite: "read" | "write" | "exec" | "none";
  rationale: string;
}
