/**
 * Userspace / Rust crash-to-primitive classification (pwnkit#698, Track C).
 *
 * The userspace analogue of `kernel-primitive.ts`. An ASan/UBSan/MSan report, a
 * Miri UB diagnostic, a Rust panic or a bare segfault proves a *bug* fired — but
 * not what an attacker can *do* with it. This module bridges that gap: from a
 * captured {@link CrashArtifact} it parses/symbolises the sanitizer / Miri /
 * panic text, labels the underlying memory-safety {@link MemPrimitive}
 * (use-after-free, heap-oob-write, ...), applies a controllability heuristic,
 * and emits an {@link ExploitabilityVerdict} the severity layer can fold in.
 *
 * Design notes (mirroring kernel-primitive.ts):
 *   - The classifier is pure and deterministic — it reads a `CrashArtifact` and
 *     returns an `ExploitabilityVerdict`. No I/O, no fuzz loop. Cheap to run on
 *     every captured crash and trivial to unit-test.
 *   - This is ASSIST-SCOPED. It labels a primitive and rates exploitability; it
 *     does NOT synthesise a working exploit, and labelling a primitive is a
 *     *hypothesis* about exploitability, not proof of it. The verify path
 *     (`pov-gate.ts`) is what flips a hypothesis to confirmed, and only when a
 *     PoC actually reproduces under the sanitizer build — the same skeptical,
 *     assume-false discipline the rest of the pipeline uses.
 */

import type {
  CrashArtifact,
  ExploitabilityVerdict,
  MemPrimitive,
} from "./memsafety-types.js";

// ── Severity ordering helpers ──────────────────────────────────────────────

type MemSeverity = ExploitabilityVerdict["severity"];

const SEVERITY_ORDER: MemSeverity[] = ["info", "low", "medium", "high", "critical"];

function severityRank(sev: MemSeverity): number {
  return SEVERITY_ORDER.indexOf(sev);
}

/** Return the higher of two severities (never downgrades). */
export function maxMemSeverity(a: MemSeverity, b: MemSeverity): MemSeverity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

// ── Classification ──────────────────────────────────────────────────────────

/**
 * Sniff the memory-safety primitive from the raw crash text. Mirrors the
 * `sniffCrashType` helper in `kernel-primitive.ts` — pattern-matches the
 * sanitizer / Miri / panic vocabulary. Returns `undefined` when nothing in the
 * text maps to a known primitive, so the caller can fall back to the crash
 * `kind`.
 */
export function sniffMemPrimitive(raw: string): MemPrimitive | undefined {
  // ASan / sanitizer phrasing.
  if (/heap-use-after-free|use-after-free|use of (deallocated|freed)/i.test(raw)) {
    return "use-after-free";
  }
  if (/double-free|attempting double-free|free of (already-freed|untracked)/i.test(raw)) {
    return "double-free";
  }
  if (/stack-buffer-overflow|stack-use-after-(return|scope)|stack-oob/i.test(raw)) {
    return "stack-oob";
  }
  if (/heap-buffer-overflow|global-buffer-overflow|dynamic-stack-buffer-overflow/i.test(raw)) {
    // Direction (read vs write) is decided by the access sniff below.
    return /\bWRITE of size\b/i.test(raw) ? "heap-oob-write" : "heap-oob-read";
  }
  // Miri undefined-behaviour tags.
  if (/uninitialized (memory|bytes|value)|use of uninitialized|msan|memorysanitizer|conjuring an instance/i.test(raw)) {
    return "uninit-read";
  }
  if (/dangling (reference|pointer)|pointer to .* was dereferenced after/i.test(raw)) {
    return "use-after-free";
  }
  if (/out-of-bounds|out of bounds|index out of bounds/i.test(raw)) {
    return /\bWRITE of size\b|writing|store/i.test(raw) ? "heap-oob-write" : "heap-oob-read";
  }
  // UBSan / arithmetic.
  if (/signed integer overflow|unsigned integer overflow|integer overflow|shift .* out of range/i.test(raw)) {
    return "integer-overflow";
  }
  if (/(member|downcast|wrong type|type mismatch|invalid (vtable|downcast)).*type|type confusion|misaligned/i.test(raw)) {
    return "type-confusion";
  }
  if (/null pointer|null-deref|dereferenc(e|ing) (a )?null|SEGV on unknown address 0x0+\b/i.test(raw)) {
    return "null-deref";
  }
  return undefined;
}

/**
 * Map a crash `kind` to a primitive when the text sniff yields nothing — the
 * conservative fallback (mirrors how `classifyPrimitiveFromDmesg` defaults to
 * `unknown`). Most kinds are ambiguous on their own, so this is intentionally
 * coarse.
 */
function primitiveFromKind(kind: CrashArtifact["kind"]): MemPrimitive {
  switch (kind) {
    case "segfault":
      // A bare segfault with no symbolised access reads as a null/faulting deref
      // unless the text said otherwise.
      return "null-deref";
    case "ubsan":
      return "integer-overflow";
    case "msan":
      return "uninit-read";
    default:
      return "unknown";
  }
}

/** Sniff the dominant memory operation the crash exercised. */
function sniffAccess(raw: string): "read" | "write" | "exec" | "none" {
  if (/\bWRITE of size\b|\bwriting\b|\bstore\b|wild pointer write/i.test(raw)) return "write";
  if (/\bREAD of size\b|\breading\b|\bload\b/i.test(raw)) return "read";
  if (/\bexecute\b|\bPC\b.*invalid|control flow|return address/i.test(raw)) return "exec";
  return "none";
}

/**
 * Primitives whose natural memory operation is a write (the strongest
 * single-primitive levers). Mirrors `WRITE_PRIMITIVE_KINDS` in
 * `kernel-primitive.ts`.
 */
const WRITE_PRIMITIVES = new Set<MemPrimitive>([
  "use-after-free",
  "heap-oob-write",
  "stack-oob",
  "double-free",
]);

/**
 * Classify the exploitation primitive a userspace / Rust crash exposes and rate
 * its exploitability. Pure + deterministic.
 *
 * Inputs that drive the result:
 *   - `crash.primitive`  — an upstream-supplied label is trusted as the strongest
 *     signal (the producer may already have parsed it).
 *   - `crash.rawOutput`  — sniffed for the sanitizer / Miri / panic vocabulary.
 *   - `crash.kind`       — the conservative fallback when text says nothing.
 *   - access direction (read/write) — write primitives are far more exploitable.
 */
export function classifyUserspacePrimitive(
  crash: CrashArtifact,
): ExploitabilityVerdict {
  const raw = crash.rawOutput ?? "";
  const primitive: MemPrimitive =
    crash.primitive ?? sniffMemPrimitive(raw) ?? primitiveFromKind(crash.kind);
  const access = sniffAccess(raw);

  let severity: MemSeverity;
  let controllable: boolean;
  let readWrite: ExploitabilityVerdict["readWrite"];
  let rationale: string;

  switch (primitive) {
    case "use-after-free": {
      readWrite = access === "read" ? "read" : "write";
      controllable = true;
      severity = readWrite === "write" ? "critical" : "high";
      rationale =
        `Use-after-free grants a dangling reference; a ${readWrite} after free is` +
        ` the lever — reclaim the freed allocation with a controlled object to` +
        ` turn it into ${readWrite === "write" ? "an object overwrite" : "an info-leak"}.`;
      break;
    }
    case "double-free": {
      readWrite = "write";
      controllable = true;
      severity = "high";
      rationale =
        "Double-free confuses the allocator freelist, enabling overlapping" +
        " allocations and downstream object overwrite.";
      break;
    }
    case "heap-oob-write": {
      readWrite = "write";
      controllable = true;
      severity = "critical";
      rationale =
        "Heap out-of-bounds write corrupts an adjacent allocation — a" +
        " write-what-where candidate once the neighbouring object is groomed.";
      break;
    }
    case "heap-oob-read": {
      readWrite = "read";
      // OOB read controllability hinges on attacker-influenced index/length.
      controllable = /attacker|user-?controlled|tainted|index|offset|length/i.test(raw);
      severity = "medium";
      rationale =
        "Heap out-of-bounds read leaks adjacent allocation contents — an" +
        " info-leak candidate useful for defeating ASLR.";
      break;
    }
    case "stack-oob": {
      readWrite = access === "read" ? "read" : "write";
      controllable = true;
      // Stack OOB write is powerful but canaries / layout cut control.
      severity = readWrite === "write" ? "high" : "medium";
      rationale =
        "Stack out-of-bounds access; write variants can target saved registers" +
        " / return addresses subject to stack-canary mitigation.";
      break;
    }
    case "type-confusion": {
      readWrite = "write";
      controllable = true;
      severity = "high";
      rationale =
        "Type confusion treats one object layout as another, enabling" +
        " controlled reads/writes through mismatched fields (e.g. a fake vtable).";
      break;
    }
    case "uninit-read": {
      readWrite = "read";
      controllable = false;
      severity = "medium";
      rationale =
        "Uninitialised read returns stale memory — an info-leak building block;" +
        " exploitability depends on whether the leaked bytes reach an attacker.";
      break;
    }
    case "integer-overflow": {
      readWrite = "none";
      controllable = false;
      severity = "low";
      rationale =
        "Integer overflow rarely yields a direct memory primitive on its own;" +
        " treat as a building block (e.g. an undersized allocation) pending" +
        " further analysis.";
      break;
    }
    case "null-deref": {
      readWrite = "none";
      controllable = false;
      severity = "low";
      rationale =
        "Null / faulting dereference is typically a denial-of-service in" +
        " userspace unless a controlled offset reaches a mapped page.";
      break;
    }
    default: {
      readWrite = access;
      controllable = false;
      severity = "info";
      rationale =
        `Crash kind ${crash.kind} did not map to a known memory-safety primitive;` +
        " treat as undetermined pending symbolisation.";
    }
  }

  // A Rust panic / timeout / OOM that didn't sniff into a corruption primitive
  // is a robustness bug, not a memory-corruption lever — never escalate it.
  if (
    (crash.kind === "panic" || crash.kind === "timeout" || crash.kind === "oom") &&
    primitive === "unknown"
  ) {
    return {
      primitive: "unknown",
      severity: crash.kind === "panic" ? "low" : "info",
      controllable: false,
      readWrite: "none",
      rationale:
        crash.kind === "panic"
          ? "Rust panic with no sanitizer signature — a safe-abort / availability" +
            " bug, not a memory-corruption primitive."
          : `${crash.kind} with no corruption signature — an availability bug.`,
    };
  }

  return { primitive, severity, controllable, readWrite, rationale };
}

/**
 * Render a verdict into compact lines for `evidence.analysis`. Mirrors
 * `describeKernelPrimitive`.
 */
export function describeExploitabilityVerdict(
  verdict: ExploitabilityVerdict,
): string[] {
  return [
    `Primitive: ${verdict.primitive} (op=${verdict.readWrite})`,
    `Severity: ${verdict.severity} (controllable=${verdict.controllable})`,
    `- ${verdict.rationale}`,
  ];
}
