/**
 * Detector: `read-unstable` — validation read-stability TOCTOU (CWE-367).
 *
 * Ported from the proven prototype `scratchpad/primitive-abuse/` (found the
 * "read-unstable input defeats validate-and-return-live-object" CLASS in
 * class-validator + superstruct; disclosed + blogged, 2026-07-14).
 *
 * The class: a validator reads a property to check it against an allowlist, then
 * hands the SAME live object back to the app (or validates a class instance the
 * app keeps using). If the property is a getter whose value CHANGES between the
 * validator's read and the app's read, the app uses an unvalidated value — an
 * allowlist bypass. Materialising validators (joi, zod) read once and hand back
 * a FRESH value, so they are safe — they are the negative controls.
 *
 * Deterministic confirm: a phased getter returns the allowed value during the
 * validate phase and a forbidden value during the use phase; CONFIRMED only when
 * the validator ACCEPTED and the app-observed value is the forbidden one.
 */

import type {
  Detector,
  DetectorCandidate,
  DetectorConfirmation,
  PackageProbe,
  PackageRef,
} from "./types.js";

// ── phased-getter harness (the deterministic dispose) ────────────────────────

/** Sentinel forbidden value — never a member of a candidate allowlist. */
const EVIL = "__0sec_toctou_forbidden__";

/**
 * A property whose reads return `clean` during the validate phase and `evil`
 * during the use phase. The harness controls the phase flip, so the confirm is
 * independent of how many times the validator reads the field.
 */
export interface PhasedField {
  clean: string;
  evil: string;
  /** Install the phased getter as `target[prop]`. */
  install(target: object, prop: string): void;
  /** Flip from validate phase to use phase. */
  useNow(): void;
}

export function makePhasedField(clean: string, evil: string = EVIL): PhasedField {
  let phase: "validate" | "use" = "validate";
  return {
    clean,
    evil,
    install(target: object, prop: string): void {
      Object.defineProperty(target, prop, {
        enumerable: true,
        configurable: true,
        get() {
          return phase === "validate" ? clean : evil;
        },
      });
    },
    useNow(): void {
      phase = "use";
    },
  };
}

/** What a candidate reports after driving its validator against a phased field. */
export interface ValidatorProbeResult {
  /** The validator accepted the input (no error / empty error list). */
  accepted: boolean;
  /** Lazily read the value the application would use for the field afterward. */
  readAppValue: () => unknown;
}

export interface ReadUnstableCandidate extends DetectorCandidate {
  /** The property under test. */
  field: string;
  /** The allowlist the synthesized schema enforces; `clean` is `allowed[0]`. */
  allowed: string[];
  /** Drive the validator against a harness-controlled phased field. */
  probe(field: PhasedField): ValidatorProbeResult;
}

/** Run the deterministic confirm for one candidate. */
export function confirmReadUnstable(candidate: ReadUnstableCandidate): DetectorConfirmation {
  const field = makePhasedField(candidate.allowed[0] ?? "allowed-1");
  let accepted = false;
  let appValue: unknown;
  try {
    const res = candidate.probe(field);
    accepted = res.accepted;
    field.useNow();
    appValue = res.readAppValue();
  } catch {
    return { confirmed: false, evidence: { observation: "" } };
  }
  const bypass = accepted && appValue === field.evil;
  if (!bypass) return { confirmed: false, evidence: { observation: "" } };
  return {
    confirmed: true,
    severity: "high",
    source: candidate.label,
    evidence: {
      observation: `validator ACCEPTED input yet app-observed ${candidate.field}="${String(appValue)}" (∉ allowlist [${candidate.allowed.join(",")}])`,
      payload: `getter on '${candidate.field}' returns '${field.clean}' at validate-time, '${field.evil}' at use-time`,
      analysis: [
        `${candidate.label} validates then returns/keeps the SAME live object, so a getter-backed`,
        `(or Proxy / mutable-derived) property that changes between the validator's read and the`,
        `app's read yields an unvalidated value the app trusts. TOCTOU allowlist bypass (CWE-367).`,
      ].join(" "),
    },
  };
}

// ── validation-library adapters (candidate proposal) ─────────────────────────
//
// Each adapter recognises a validation library by exported shape and knows how
// to build a minimal enum-allowlist schema + drive validate/assert against a
// harness-controlled phased field. The confirm harness above is fully generic;
// adding a new library = adding one adapter (this is the recipe in miniature —
// see docs/operations/detector-from-finding.md).

const ALLOWED = ["allowed-1", "allowed-2"];

interface ValidationAdapter {
  id: string;
  /** Recognise the library from its package name and loaded module shape. */
  matches(pkgName: string, mod: Record<string, unknown>): boolean;
  /** Build 0+ candidates (e.g. a `validate` and an `assert` variant). */
  candidates(pkgName: string, mod: Record<string, unknown>): ReadUnstableCandidate[];
}

function fn(mod: Record<string, unknown>, key: string): ((...a: unknown[]) => unknown) | undefined {
  const v = mod[key];
  return typeof v === "function" ? (v as (...a: unknown[]) => unknown) : undefined;
}

const ADAPTERS: ValidationAdapter[] = [
  // superstruct: validate(input, Schema) → [err, output]; output === input.
  {
    id: "superstruct",
    matches: (name, mod) => name === "superstruct" || (!!fn(mod, "object") && !!fn(mod, "enums") && !!fn(mod, "validate")),
    candidates(name, mod) {
      const object = fn(mod, "object");
      const enums = fn(mod, "enums");
      const validate = fn(mod, "validate");
      const assert = fn(mod, "assert");
      if (!object || !enums || !validate) return [];
      const Schema = object({ role: enums(ALLOWED) });
      const out: ReadUnstableCandidate[] = [
        {
          id: `${name}.validate`,
          label: `${name}.validate`,
          field: "role",
          allowed: ALLOWED,
          probe(field) {
            const input: Record<string, unknown> = {};
            field.install(input, "role");
            const res = validate(input, Schema) as [unknown, Record<string, unknown>];
            const err = Array.isArray(res) ? res[0] : undefined;
            const output = Array.isArray(res) ? res[1] : input;
            return { accepted: !err, readAppValue: () => (output ?? input)["role"] };
          },
        },
      ];
      if (assert) {
        out.push({
          id: `${name}.assert`,
          label: `${name}.assert`,
          field: "role",
          allowed: ALLOWED,
          probe(field) {
            const input: Record<string, unknown> = {};
            field.install(input, "role");
            let ok = false;
            try {
              assert(input, Schema);
              ok = true;
            } catch {
              ok = false;
            }
            return { accepted: ok, readAppValue: () => input["role"] };
          },
        });
      }
      return out;
    },
  },
  // class-validator: validates class INSTANCES; getter accessors are idiomatic.
  {
    id: "class-validator",
    matches: (name, mod) => name === "class-validator" || (!!fn(mod, "IsIn") && !!fn(mod, "validateSync")),
    candidates(name, mod) {
      const IsIn = fn(mod, "IsIn");
      const validateSync = fn(mod, "validateSync");
      if (!IsIn || !validateSync) return [];
      return [
        {
          id: `${name}.validateSync`,
          label: `${name}.validateSync`,
          field: "role",
          allowed: ALLOWED,
          probe(field) {
            class UserDto {}
            const decorate = IsIn(ALLOWED) as (target: object, prop: string) => void;
            decorate((UserDto as unknown as { prototype: object }).prototype, "role");
            const u = new UserDto();
            field.install(u, "role");
            const errors = validateSync(u) as unknown[];
            return { accepted: Array.isArray(errors) && errors.length === 0, readAppValue: () => (u as Record<string, unknown>)["role"] };
          },
        },
      ];
    },
  },
  // joi (control): materialises a fresh value → SAFE. Kept so the detector
  // proves it does NOT false-positive on read-stable validators.
  {
    id: "joi",
    matches: (name, mod) => name === "joi" || (!!fn(mod, "object") && !!fn(mod, "string")),
    candidates(name, mod) {
      const object = fn(mod, "object");
      const string = fn(mod, "string");
      if (!object || !string) return [];
      return [
        {
          id: `${name}.validate`,
          label: `${name}.validate`,
          field: "role",
          allowed: ALLOWED,
          probe(field) {
            const input: Record<string, unknown> = {};
            field.install(input, "role");
            const schema = object({ role: (string() as { valid: (...a: string[]) => unknown }).valid(...ALLOWED) }) as {
              validate: (v: unknown) => { error?: unknown; value?: Record<string, unknown> };
            };
            const res = schema.validate(input);
            return { accepted: !res.error, readAppValue: () => res.value?.["role"] };
          },
        },
      ];
    },
  },
  // zod (control): safeParse materialises → SAFE.
  {
    id: "zod",
    matches: (name, mod) => name === "zod" || !!fn(mod, "z") || !!fn(mod, "object"),
    candidates(name, mod) {
      const z = (mod["z"] as Record<string, unknown> | undefined) ?? mod;
      const object = fn(z, "object");
      const zenum = fn(z, "enum");
      if (!object || !zenum) return [];
      return [
        {
          id: `${name}.safeParse`,
          label: `${name}.safeParse`,
          field: "role",
          allowed: ALLOWED,
          probe(field) {
            const input: Record<string, unknown> = {};
            field.install(input, "role");
            const schema = object({ role: zenum(ALLOWED) }) as {
              safeParse: (v: unknown) => { success: boolean; data?: Record<string, unknown> };
            };
            const res = schema.safeParse(input);
            return { accepted: res.success, readAppValue: () => res.data?.["role"] };
          },
        },
      ];
    },
  },
];

// ── the detector ─────────────────────────────────────────────────────────────

export const readUnstableDetector: Detector<ReadUnstableCandidate> = {
  id: "read-unstable",
  title: "Validation Read-Stability TOCTOU",
  cwe: "CWE-367",
  category: "toctou",
  severityFloor: "high",
  description:
    "Confirms the validate-and-return-live-object read-stability class: a phased getter (allowed at validate-time, forbidden at use-time) that the validator accepts but the app then reads as forbidden. Materialising validators (joi/zod) are the negative controls.",
  appliesTo(_pkg: PackageRef): boolean {
    // Adapter matching in identify is the real filter; cheap to over-schedule.
    return true;
  },
  identifyCandidates(probe: PackageProbe): ReadUnstableCandidate[] {
    const mod = probe.load(probe.pkg.name);
    if (mod === undefined || (typeof mod !== "object" && typeof mod !== "function")) {
      probe.note?.(`read-unstable: could not load ${probe.pkg.name}`);
      return [];
    }
    const modRec = mod as Record<string, unknown>;
    const out: ReadUnstableCandidate[] = [];
    // Collapse duplicate leads that would confirm the SAME class on the SAME
    // field via the same library — e.g. superstruct's `validate` and `assert`
    // both exercise the identical validate-and-return-live-object semantics on
    // `role`, yielding two near-identical findings. Fingerprint by
    // adapter+field+allowlist so distinct libraries (which legitimately share a
    // field name) are never merged.
    const seen = new Set<string>();
    for (const adapter of ADAPTERS) {
      let matched = false;
      try {
        matched = adapter.matches(probe.pkg.name, modRec);
      } catch {
        matched = false;
      }
      if (!matched) continue;
      try {
        for (const c of adapter.candidates(probe.pkg.name, modRec)) {
          const fp = `${adapter.id}:${c.field}:${c.allowed.join(",")}`;
          if (seen.has(fp)) {
            probe.note?.(`read-unstable: collapsed duplicate candidate ${c.id} (fingerprint ${fp})`);
            continue;
          }
          seen.add(fp);
          out.push(c);
        }
      } catch (e) {
        probe.note?.(`read-unstable: adapter ${adapter.id} failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    return out;
  },
  confirm(candidate: ReadUnstableCandidate): DetectorConfirmation {
    return confirmReadUnstable(candidate);
  },
  dedupHints: {
    priorReports: ["class-validator", "superstruct"],
  },
};
