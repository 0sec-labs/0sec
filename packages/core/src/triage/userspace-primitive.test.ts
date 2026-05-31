import { describe, it, expect } from "vitest";
import {
  classifyUserspacePrimitive,
  sniffMemPrimitive,
  describeExploitabilityVerdict,
  maxMemSeverity,
} from "./userspace-primitive.js";
import type { CrashArtifact, MemPrimitive } from "./memsafety-types.js";

// ────────────────────────────────────────────────────────────────────
// Realistic raw sanitizer / Miri / panic fixtures
//
// These are trimmed-but-faithful copies of the text the respective tools
// emit. We feed them in as `rawOutput` WITHOUT a pre-set `crash.primitive`
// so the classifier exercises its own `sniffMemPrimitive` path (an
// upstream-supplied `primitive` would short-circuit the sniff).
// ────────────────────────────────────────────────────────────────────

const ASAN_UAF = `==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x0000004f9abc bp 0x7ffd bp sp 0x7ffd
READ of size 4 at 0x602000000010 thread T0
    #0 0x4f9abc in use_after_free /src/foo.c:42:7
    #1 0x4f8000 in main /src/foo.c:60:3
0x602000000010 is located 0 bytes inside of 16-byte region [0x602000000010,0x602000000020)
freed by thread T0 here:
    #0 0x4d1234 in free
SUMMARY: AddressSanitizer: heap-use-after-free /src/foo.c:42:7 in use_after_free`;

const ASAN_HEAP_OOB_WRITE = `==2222==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018 at pc 0x000000401abc
WRITE of size 8 at 0x602000000018 thread T0
    #0 0x401abc in copy_into /src/buf.c:88:5
    #1 0x401000 in main /src/buf.c:120:3
0x602000000018 is located 0 bytes to the right of 8-byte region
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/buf.c:88:5 in copy_into`;

const ASAN_HEAP_OOB_READ = `==3333==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000040 at pc 0x000000401def
READ of size 4 at 0x602000000040 thread T0
    #0 0x401def in read_past /src/buf.c:200:9
    #1 0x401111 in main /src/buf.c:240:3
0x602000000040 is located 0 bytes to the right of 32-byte region
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/buf.c:200:9 in read_past`;

const ASAN_DOUBLE_FREE = `==4444==ERROR: AddressSanitizer: attempting double-free on 0x602000000010 in thread T0:
    #0 0x4d1234 in free
    #1 0x401abc in dealloc_twice /src/df.c:33:3
    #2 0x401000 in main /src/df.c:50:3
SUMMARY: AddressSanitizer: double-free /src/df.c:33:3 in dealloc_twice`;

const UBSAN_INT_OVERFLOW = `/src/math.c:17:23: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/math.c:17:23`;

const MSAN_UNINIT = `==5555==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x401abc in compute /src/m.c:12:5
    #1 0x401000 in main /src/m.c:20:3
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/m.c:12:5 in compute`;

const MIRI_UB_UAF = `error: Undefined Behavior: pointer to alloc1234 was dereferenced after this allocation got freed
    --> src/lib.rs:42:18
     |
  42 |     unsafe { *dangling }
     |              ^^^^^^^^^ pointer to alloc1234 was dereferenced after this allocation got freed
     |
     = help: this indicates a bug in the program: it performed an invalid operation
note: inside \`use_freed\` at src/lib.rs:42:18`;

const RUST_PANIC = `thread 'main' panicked at src/main.rs:10:9:
assertion failed: x > 0
note: run with \`RUST_BACKTRACE=1\` environment variable to display a backtrace`;

const RAW_SEGFAULT = `==6666==ERROR: libFuzzer: deadly signal
    #0 0x401abc in crashy /src/c.c:5:3
==6666== ERROR: SEGV on unknown address 0x000000000010
SUMMARY: AddressSanitizer: SEGV /src/c.c:5:3`;

const UNRECOGNISED = `Hello from the program. Everything is fine. Exited with code 0.
No sanitizer, no panic, nothing crash-like in this blob at all.`;

/** Build a CrashArtifact with only kind + rawOutput so the classifier sniffs. */
function crash(
  kind: CrashArtifact["kind"],
  rawOutput: string,
  extra: Partial<CrashArtifact> = {},
): CrashArtifact {
  return { kind, signature: "sig", rawOutput, ...extra };
}

// ────────────────────────────────────────────────────────────────────
// sniffMemPrimitive — the raw-text → primitive map
// ────────────────────────────────────────────────────────────────────

describe("sniffMemPrimitive", () => {
  const cases: Array<[string, string, MemPrimitive | undefined]> = [
    ["ASan heap-use-after-free", ASAN_UAF, "use-after-free"],
    ["ASan heap-buffer-overflow WRITE", ASAN_HEAP_OOB_WRITE, "heap-oob-write"],
    ["ASan heap-buffer-overflow READ", ASAN_HEAP_OOB_READ, "heap-oob-read"],
    ["ASan double-free", ASAN_DOUBLE_FREE, "double-free"],
    ["UBSan integer overflow", UBSAN_INT_OVERFLOW, "integer-overflow"],
    ["MSan uninitialised value", MSAN_UNINIT, "uninit-read"],
    ["Miri dangling-pointer UB", MIRI_UB_UAF, "use-after-free"],
    ["unrecognised blob", UNRECOGNISED, undefined],
  ];

  it.each(cases)("classifies %s", (_label, raw, expected) => {
    expect(sniffMemPrimitive(raw)).toBe(expected);
  });

  it("returns undefined for a plain Rust panic (no corruption vocabulary)", () => {
    expect(sniffMemPrimitive(RUST_PANIC)).toBeUndefined();
  });
});

// ────────────────────────────────────────────────────────────────────
// classifyUserspacePrimitive — primitive + ExploitabilityVerdict
// ────────────────────────────────────────────────────────────────────

describe("classifyUserspacePrimitive", () => {
  it("ASan heap-use-after-free (READ) → use-after-free, high, read, controllable", () => {
    const v = classifyUserspacePrimitive(crash("asan", ASAN_UAF));
    expect(v.primitive).toBe("use-after-free");
    expect(v.readWrite).toBe("read");
    expect(v.severity).toBe("high");
    expect(v.controllable).toBe(true);
  });

  it("ASan heap-buffer-overflow WRITE → heap-oob-write, critical, write", () => {
    const v = classifyUserspacePrimitive(crash("asan", ASAN_HEAP_OOB_WRITE));
    expect(v.primitive).toBe("heap-oob-write");
    expect(v.readWrite).toBe("write");
    expect(v.severity).toBe("critical");
    expect(v.controllable).toBe(true);
  });

  it("ASan heap-buffer-overflow READ → heap-oob-read, read, medium", () => {
    const v = classifyUserspacePrimitive(crash("asan", ASAN_HEAP_OOB_READ));
    expect(v.primitive).toBe("heap-oob-read");
    expect(v.readWrite).toBe("read");
    expect(v.severity).toBe("medium");
  });

  it("ASan double-free → double-free, write, high, controllable", () => {
    const v = classifyUserspacePrimitive(crash("asan", ASAN_DOUBLE_FREE));
    expect(v.primitive).toBe("double-free");
    expect(v.readWrite).toBe("write");
    expect(v.severity).toBe("high");
    expect(v.controllable).toBe(true);
  });

  it("UBSan integer overflow → integer-overflow, low, not controllable", () => {
    const v = classifyUserspacePrimitive(crash("ubsan", UBSAN_INT_OVERFLOW));
    expect(v.primitive).toBe("integer-overflow");
    expect(v.severity).toBe("low");
    expect(v.controllable).toBe(false);
    expect(v.readWrite).toBe("none");
  });

  it("MSan uninitialised read → uninit-read, read, medium info-leak", () => {
    const v = classifyUserspacePrimitive(crash("msan", MSAN_UNINIT));
    expect(v.primitive).toBe("uninit-read");
    expect(v.readWrite).toBe("read");
    expect(v.severity).toBe("medium");
    expect(v.controllable).toBe(false);
  });

  it("Miri UB tag (dangling pointer) → use-after-free", () => {
    const v = classifyUserspacePrimitive(crash("miri", MIRI_UB_UAF));
    expect(v.primitive).toBe("use-after-free");
  });

  it("Rust panic with no sanitizer signature → unknown, low, availability bug", () => {
    const v = classifyUserspacePrimitive(crash("panic", RUST_PANIC));
    expect(v.primitive).toBe("unknown");
    expect(v.severity).toBe("low");
    expect(v.controllable).toBe(false);
    expect(v.readWrite).toBe("none");
    expect(v.rationale).toMatch(/panic/i);
  });

  it("raw SIGSEGV / segfault text → null-deref, low DoS", () => {
    // No ASan ERROR header here; just a bare deadly-signal blob with a segfault hint.
    const v = classifyUserspacePrimitive(
      crash("segfault", "Program received signal SIGSEGV, segmentation fault."),
    );
    expect(v.primitive).toBe("null-deref");
    expect(v.severity).toBe("low");
    expect(v.readWrite).toBe("none");
  });

  it("unrecognised blob → unknown, info, undetermined", () => {
    const v = classifyUserspacePrimitive(crash("timeout", UNRECOGNISED));
    expect(v.primitive).toBe("unknown");
    expect(v.severity).toBe("info");
    expect(v.controllable).toBe(false);
  });

  it("trusts an upstream-supplied crash.primitive over the text sniff", () => {
    // rawOutput screams panic, but the producer already classified it.
    const v = classifyUserspacePrimitive(
      crash("asan", RUST_PANIC, { primitive: "heap-oob-write" }),
    );
    expect(v.primitive).toBe("heap-oob-write");
    expect(v.severity).toBe("critical");
  });

  it("controllability heuristic: OOB read flips controllable when index/offset is tainted", () => {
    const tainted = `==7==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x602000000040 thread T0
    #0 0x401def in idx /src/buf.c:200:9 ; attacker-controlled index past length
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/buf.c:200:9 in idx`;
    const controlled = classifyUserspacePrimitive(crash("asan", tainted));
    const uncontrolled = classifyUserspacePrimitive(crash("asan", ASAN_HEAP_OOB_READ));
    expect(controlled.primitive).toBe("heap-oob-read");
    expect(controlled.controllable).toBe(true);
    expect(uncontrolled.controllable).toBe(false);
  });

  it("a write primitive ranks more severe than a read primitive", () => {
    const write = classifyUserspacePrimitive(crash("asan", ASAN_HEAP_OOB_WRITE));
    const read = classifyUserspacePrimitive(crash("asan", ASAN_HEAP_OOB_READ));
    expect(maxMemSeverity(write.severity, read.severity)).toBe(write.severity);
    // critical (write) strictly outranks medium (read)
    expect(write.severity).toBe("critical");
    expect(read.severity).toBe("medium");
  });
});

// ────────────────────────────────────────────────────────────────────
// maxMemSeverity — worst-of ordering
// ────────────────────────────────────────────────────────────────────

describe("maxMemSeverity", () => {
  it("picks the worst severity", () => {
    expect(maxMemSeverity("low", "critical")).toBe("critical");
    expect(maxMemSeverity("critical", "low")).toBe("critical");
    expect(maxMemSeverity("medium", "high")).toBe("high");
    expect(maxMemSeverity("info", "low")).toBe("low");
  });

  it("is idempotent on equal inputs and never downgrades", () => {
    expect(maxMemSeverity("high", "high")).toBe("high");
    expect(maxMemSeverity("medium", "info")).toBe("medium");
  });
});

// ────────────────────────────────────────────────────────────────────
// describeExploitabilityVerdict — human-readable rendering
// ────────────────────────────────────────────────────────────────────

describe("describeExploitabilityVerdict", () => {
  it("returns a non-empty, informative human string", () => {
    const v = classifyUserspacePrimitive(crash("asan", ASAN_HEAP_OOB_WRITE));
    const lines = describeExploitabilityVerdict(v);
    expect(Array.isArray(lines)).toBe(true);
    expect(lines.length).toBeGreaterThan(0);
    const text = lines.join("\n");
    expect(text.trim().length).toBeGreaterThan(0);
    expect(text).toContain("heap-oob-write");
    expect(text).toMatch(/critical/);
    // the rationale line is present
    expect(text).toMatch(/controllable=true/);
  });
});
