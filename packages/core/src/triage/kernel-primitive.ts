/**
 * Kernel bug-to-exploit primitive synthesis (pwnkit#569).
 *
 * A KASAN/UBSAN crash report proves a *bug* fired, but not what an attacker
 * can *do* with it. This module bridges that gap: from the parsed crash type,
 * the access (read/write + size), and the KASAN alloc/free provenance, it
 * labels the underlying exploitation **primitive** (use-after-free,
 * out-of-bounds-write, double-free, ...), proposes a single **bounded
 * control-demonstration step** (a concrete, falsifiable next action — NOT a
 * full weaponised exploit), and emits an `exploitability` score that the
 * severity layer folds into the finding.
 *
 * Design notes:
 *   - The classifier is pure and deterministic — it reads a `CrashReport` and
 *     returns a `KernelPrimitive`. No I/O, no QEMU. That keeps it cheap to run
 *     on every ingested crash and trivial to unit-test.
 *   - The control-demo step is a *candidate* by default (`demonstrated:false`).
 *     We are deliberately honest here: labelling a primitive is a hypothesis
 *     about exploitability, not proof of it. `attemptControlDemo` lets a caller
 *     plug in an oracle (QEMU probe runner) to flip `demonstrated:true` only
 *     when a bounded probe actually confirms the control — mirroring the
 *     skeptical, assume-false discipline the rest of the kernel pipeline uses.
 */

import type { CrashReport, CrashType, Severity } from "@pwnkit/shared";

// ── Public types ──────────────────────────────────────────────────────────

/**
 * The exploitation primitive a crash exposes. This is the "what can the
 * attacker do" label, distinct from the KASAN bug *type* (`CrashType`).
 */
export type KernelPrimitiveKind =
  | "use-after-free"
  | "out-of-bounds-write"
  | "out-of-bounds-read"
  | "double-free"
  | "invalid-free"
  | "null-deref"
  | "uninitialized-access"
  | "unknown";

/** The dominant memory operation the primitive grants the attacker. */
export type PrimitiveControl = "write" | "read" | "free" | "none";

/**
 * A single, bounded step that would *demonstrate* attacker control over the
 * primitive — short of a full exploit. e.g. for a write-UAF: reclaim the freed
 * object with an attacker-sized spray and observe the controlled bytes land.
 */
export interface ControlDemoStep {
  /** The class of demonstration the primitive admits. */
  kind:
    | "object-overwrite"      // reclaim freed/oob object, write controlled bytes
    | "write-what-where"      // controlled OOB write of controlled data
    | "oob-read-leak"         // controlled OOB/UAF read to leak adjacent memory
    | "free-confusion"        // double/invalid free → allocator state confusion
    | "none";
  /** Human-readable, bounded next action a verifier could run. */
  description: string;
  /** What the attacker is hypothesised to control going in. */
  controlledInput?: string;
  /**
   * Whether a bounded oracle probe actually confirmed this control. Defaults
   * to false — labelling is a hypothesis until a probe proves it.
   */
  demonstrated: boolean;
  /** Populated by `attemptControlDemo` when a probe runs. */
  evidence?: string;
}

export interface KernelPrimitive {
  kind: KernelPrimitiveKind;
  control: PrimitiveControl;
  /** Exploitability in [0,1] — how much attacker leverage the primitive gives. */
  exploitability: number;
  /** Confidence in the *classification itself* in [0,1]. */
  confidence: number;
  /** Bounded control-demonstration step (candidate by default). */
  controlDemo: ControlDemoStep;
  /** Short reasoning lines, surfaced into the finding analysis. */
  rationale: string[];
  /** The allocation object / cache the primitive operates on, when derivable. */
  objectHint?: string;
}

// ── Severity ordering helpers ──────────────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

function severityRank(sev: Severity): number {
  return SEVERITY_ORDER.indexOf(sev);
}

/** Return the higher of two severities (never downgrades). */
export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

// ── Classification ──────────────────────────────────────────────────────────

const WRITE_PRIMITIVE_KINDS = new Set<KernelPrimitiveKind>([
  "use-after-free",
  "out-of-bounds-write",
]);

/**
 * Classify the exploitation primitive a kernel crash exposes.
 *
 * Inputs that drive the result:
 *   - `crashType`   — the KASAN/UBSAN bug class.
 *   - `accessType`  — read vs write (write primitives are far more exploitable).
 *   - `accessSize`  — controlled width hints at controllability.
 *   - `allocSite` / `freeSite` — present means we know the object lifecycle,
 *     which both raises classification confidence and unlocks the reclaim/
 *     overwrite demonstration for UAF / double-free.
 */
export function classifyKernelPrimitive(report: CrashReport): KernelPrimitive {
  const rationale: string[] = [];
  const hasAlloc = Boolean(report.allocSite);
  const hasFree = Boolean(report.freeSite);
  const isWrite = report.accessType === "write";
  const isRead = report.accessType === "read";

  let kind: KernelPrimitiveKind;
  let control: PrimitiveControl;
  let exploitability: number;
  let confidence: number;

  switch (report.crashType) {
    case "kasan-uaf":
    case "kasan-wild": {
      kind = "use-after-free";
      control = isWrite ? "write" : isRead ? "read" : "write";
      // A write-UAF with a known alloc+free pair is the strongest single
      // primitive a fuzzer crash typically yields: reclaim + overwrite.
      exploitability = control === "write" ? 0.85 : 0.55;
      confidence = report.crashType === "kasan-wild" ? 0.5 : 0.8;
      rationale.push(
        `Use-after-free grants an attacker a dangling reference; a ${control}` +
          ` after free is the lever.`,
      );
      if (hasAlloc && hasFree) {
        exploitability = Math.min(1, exploitability + 0.05);
        confidence = Math.min(1, confidence + 0.1);
        rationale.push(
          "Both KASAN allocation and free sites are known — the object" +
            " lifecycle is pinned, so a reclaim window can be targeted.",
        );
      }
      break;
    }
    case "kasan-oob": {
      kind = isWrite ? "out-of-bounds-write" : "out-of-bounds-read";
      control = isWrite ? "write" : "read";
      exploitability = isWrite ? 0.8 : 0.45;
      confidence = 0.8;
      rationale.push(
        isWrite
          ? "Heap out-of-bounds write corrupts an adjacent allocation —" +
              " a write-what-where candidate."
          : "Heap out-of-bounds read leaks adjacent allocation contents —" +
              " an info-leak candidate.",
      );
      break;
    }
    case "kasan-stack-oob": {
      kind = isWrite ? "out-of-bounds-write" : "out-of-bounds-read";
      control = isWrite ? "write" : "read";
      // Stack OOB write is powerful but stack canaries / layout cut control.
      exploitability = isWrite ? 0.7 : 0.4;
      confidence = 0.75;
      rationale.push(
        "Stack out-of-bounds access; write variants can target saved" +
          " registers / return addresses subject to canary mitigation.",
      );
      break;
    }
    case "kasan-double-free": {
      kind = "double-free";
      control = "free";
      exploitability = 0.6;
      confidence = 0.8;
      rationale.push(
        "Double-free confuses the slab allocator freelist, enabling cache" +
          " poisoning toward an overlapping allocation.",
      );
      if (hasFree) {
        confidence = Math.min(1, confidence + 0.1);
        rationale.push("KASAN free site is known — the double-free path is pinned.");
      }
      break;
    }
    case "kasan-invalid-free": {
      kind = "invalid-free";
      control = "free";
      exploitability = 0.5;
      confidence = 0.75;
      rationale.push(
        "Invalid-free passes an attacker-influenced pointer to the freer," +
          " a potential arbitrary-free primitive.",
      );
      break;
    }
    case "kasan-null":
    case "kernel-oops":
    case "kernel-panic":
    case "kernel-bug":
    case "general-protection": {
      kind = "null-deref";
      control = "none";
      exploitability = 0.1;
      confidence = 0.6;
      rationale.push(
        "Null / faulting dereference is typically a denial-of-service unless" +
          " low-address mmap is permitted (mmap_min_addr=0).",
      );
      break;
    }
    case "ubsan":
    case "ubsan-shift":
    case "ubsan-overflow":
    case "ubsan-bounds":
    case "ubsan-alignment": {
      kind = "uninitialized-access";
      control = "none";
      exploitability = 0.15;
      confidence = 0.5;
      rationale.push(
        "UBSAN undefined behaviour rarely yields a direct memory primitive on" +
          " its own; treat as a building block pending further analysis.",
      );
      break;
    }
    default: {
      kind = "unknown";
      control = "none";
      exploitability = 0.1;
      confidence = 0.3;
      rationale.push(
        `Crash type ${report.crashType} does not map to a known memory primitive.`,
      );
    }
  }

  // Width of a controlled write/read is a (small) controllability signal.
  if (report.accessSize && (control === "write" || control === "read")) {
    rationale.push(`Access width ${report.accessSize} byte(s) bounds the per-step control.`);
    if (report.accessSize >= 8) {
      // A pointer-width-or-wider access is enough to overwrite a pointer field.
      exploitability = Math.min(1, exploitability + 0.05);
    }
  }

  const objectHint = report.allocSite ?? report.freeSite ?? undefined;

  return {
    kind,
    control,
    exploitability: Number(exploitability.toFixed(2)),
    confidence: Number(confidence.toFixed(2)),
    controlDemo: buildControlDemo(kind, control, report),
    rationale,
    objectHint,
  };
}

/**
 * Propose a single, bounded control-demonstration step for a primitive. The
 * step is a *candidate* (`demonstrated:false`) — a concrete action a verifier
 * could run next, phrased so it is falsifiable.
 */
export function buildControlDemo(
  kind: KernelPrimitiveKind,
  control: PrimitiveControl,
  report: CrashReport,
): ControlDemoStep {
  const sizeHint = report.accessSize ? `${report.accessSize}-byte` : "controlled-width";
  const objectHint = report.allocSite ?? report.faultingFunction;

  switch (kind) {
    case "use-after-free":
      if (control === "write") {
        return {
          kind: "object-overwrite",
          description:
            `After the free in ${report.freeSite ?? "the freed path"}, spray heap` +
            ` objects of the victim cache to reclaim the freed slot, then trigger` +
            ` the dangling ${sizeHint} write and confirm attacker bytes land in` +
            ` the reclaimed object (${objectHint}).`,
          controlledInput: "heap-spray contents reclaiming the freed object",
          demonstrated: false,
        };
      }
      return {
        kind: "oob-read-leak",
        description:
          `Reclaim the freed object (${objectHint}) with a marker payload, then` +
          ` trigger the dangling read and confirm the marker bytes leak back to` +
          ` userspace.`,
        controlledInput: "reclaiming object marker bytes",
        demonstrated: false,
      };
    case "out-of-bounds-write":
      return {
        kind: "write-what-where",
        description:
          `Place a target object immediately after the overflowed allocation` +
          ` (${objectHint}) via heap grooming, then drive the ${sizeHint} OOB` +
          ` write and confirm a controlled field of the neighbour is overwritten.`,
        controlledInput: "overflow payload + neighbouring object layout",
        demonstrated: false,
      };
    case "out-of-bounds-read":
      return {
        kind: "oob-read-leak",
        description:
          `Groom a secret-bearing object after the under-sized allocation` +
          ` (${objectHint}), trigger the ${sizeHint} OOB read, and confirm` +
          ` adjacent bytes are returned to userspace.`,
        controlledInput: "adjacent object placement",
        demonstrated: false,
      };
    case "double-free":
      return {
        kind: "free-confusion",
        description:
          `Allocate a victim object between the two frees of ${objectHint} so the` +
          ` second free poisons the freelist, then confirm two live allocations` +
          ` alias the same slot.`,
        controlledInput: "intervening allocation timing",
        demonstrated: false,
      };
    case "invalid-free":
      return {
        kind: "free-confusion",
        description:
          `Influence the pointer passed to the freer in ${report.faultingFunction}` +
          ` and confirm a non-allocated / attacker-chosen address is handed to` +
          ` the slab allocator.`,
        controlledInput: "the freed pointer value",
        demonstrated: false,
      };
    default:
      return {
        kind: "none",
        description:
          "No bounded control demonstration is proposed for this primitive;" +
          " it reads as denial-of-service or an undetermined building block.",
        demonstrated: false,
      };
  }
}

/**
 * Optionally confirm a control-demo step against an injected probe oracle.
 *
 * We do NOT author a generic kernel exploit here — instead the caller supplies
 * a `probe` that runs a bounded experiment (e.g. a spray+overwrite reproducer
 * in QEMU) and reports whether attacker control was observed. On success the
 * returned step is flipped to `demonstrated:true` with the probe's evidence;
 * otherwise the candidate is returned unchanged. This keeps the assume-false
 * discipline: a primitive is only "demonstrated" when a probe proves it.
 */
export async function attemptControlDemo(
  primitive: KernelPrimitive,
  probe: (step: ControlDemoStep) => Promise<{ controlled: boolean; evidence?: string }>,
): Promise<KernelPrimitive> {
  if (primitive.controlDemo.kind === "none") return primitive;
  const result = await probe(primitive.controlDemo);
  if (!result.controlled) {
    return {
      ...primitive,
      controlDemo: {
        ...primitive.controlDemo,
        demonstrated: false,
        evidence: result.evidence,
      },
    };
  }
  return {
    ...primitive,
    // A demonstrated control is hard exploitability evidence.
    exploitability: Math.min(1, primitive.exploitability + 0.1),
    controlDemo: {
      ...primitive.controlDemo,
      demonstrated: true,
      evidence: result.evidence,
    },
  };
}

// ── Severity surfacing ──────────────────────────────────────────────────────

/**
 * Fold a primitive's exploitability into a base severity. Only ever escalates
 * (callers keep the existing `crashSeverity` heuristic as the floor):
 *   - demonstrated write/free control, or exploitability ≥ 0.8 with write → critical
 *   - exploitability ≥ 0.6 → at least high
 *   - exploitability ≥ 0.4 → at least medium
 */
export function exploitabilityAdjustedSeverity(
  baseSeverity: Severity,
  primitive: KernelPrimitive,
): Severity {
  let floor: Severity = "info";

  if (primitive.controlDemo.demonstrated && WRITE_PRIMITIVE_KINDS.has(primitive.kind)) {
    floor = "critical";
  } else if (primitive.exploitability >= 0.8 && primitive.control === "write") {
    floor = "critical";
  } else if (primitive.exploitability >= 0.6) {
    floor = "high";
  } else if (primitive.exploitability >= 0.4) {
    floor = "medium";
  }

  return maxSeverity(baseSeverity, floor);
}

/**
 * Render a primitive into compact lines for `evidence.analysis`.
 */
export function describeKernelPrimitive(primitive: KernelPrimitive): string[] {
  const lines = [
    `Primitive: ${primitive.kind} (control=${primitive.control})`,
    `Exploitability: ${primitive.exploitability.toFixed(2)} (classifier confidence=${primitive.confidence.toFixed(2)})`,
    `Control demo [${primitive.controlDemo.kind}${primitive.controlDemo.demonstrated ? ", demonstrated" : ", candidate"}]: ${primitive.controlDemo.description}`,
  ];
  if (primitive.controlDemo.evidence) {
    lines.push(`Control demo evidence: ${primitive.controlDemo.evidence}`);
  }
  if (primitive.objectHint) {
    lines.push(`Object hint: ${primitive.objectHint}`);
  }
  for (const r of primitive.rationale) lines.push(`- ${r}`);
  return lines;
}

/**
 * Classify a primitive directly from raw dmesg / KASAN text (verify path),
 * where we have the reproduced crash but not a fully-parsed `CrashReport`.
 * Builds a minimal report from `detectedCrashType` and a write/read sniff,
 * then defers to `classifyKernelPrimitive`.
 */
export function classifyPrimitiveFromDmesg(
  dmesg: string,
  detectedCrashType?: string,
): KernelPrimitive {
  const crashType = (detectedCrashType ?? sniffCrashType(dmesg) ?? "unknown") as CrashType;
  const accessMatch = dmesg.match(/(Read|Write)\s+of\s+size\s+(\d+)/i);
  const report: CrashReport = {
    rawText: dmesg,
    crashType,
    faultingFunction: "unknown",
    callStack: [],
    subsystem: "unknown",
    accessType: accessMatch ? (accessMatch[1]!.toLowerCase() as "read" | "write") : undefined,
    accessSize: accessMatch ? parseInt(accessMatch[2]!, 10) : undefined,
    allocSite: /Allocated by task/i.test(dmesg) ? "alloc" : undefined,
    freeSite: /Freed by task/i.test(dmesg) ? "free" : undefined,
  };
  return classifyKernelPrimitive(report);
}

function sniffCrashType(dmesg: string): CrashType | undefined {
  if (/use-after-free/i.test(dmesg)) return "kasan-uaf";
  if (/out-of-bounds/i.test(dmesg)) return "kasan-oob";
  if (/double-free/i.test(dmesg)) return "kasan-double-free";
  if (/invalid-free/i.test(dmesg)) return "kasan-invalid-free";
  if (/null pointer|null-ptr-deref/i.test(dmesg)) return "kasan-null";
  return undefined;
}
