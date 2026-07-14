/**
 * Detector: `sspp-fuzz` — server-side prototype pollution (CWE-1321), with an
 * optional PP→RCE escalation via the NODE_OPTIONS gadget.
 *
 * Ported from the proven prototype `scratchpad/sspp-miner/lib/{identify,fuzzer,
 * gadget}.js` (found the es-toolkit/compat class, GHSA-42qw-4cfm-q8jq; 28 novel
 * long-tail PP→RCE across 505 pkgs). LLM-proposes / harness-disposes: name
 * heuristics + export walking PROPOSE candidate recursive-write functions; a
 * deterministic dynamic battery DISPOSES — a bug is CONFIRMED only when
 * `Object.prototype` / `Array.prototype` is observed polluted AT RUNTIME.
 *
 * The candidate carries the resolved function so `confirm` is self-contained and
 * hermetically testable (see `npm-detectors.test.ts`), while the real ecosystem
 * path resolves those functions inside the sandbox probe.
 */

import type {
  Detector,
  DetectorCandidate,
  DetectorConfirmation,
  PackageProbe,
  PackageRef,
} from "./types.js";

// ── identify (candidate proposal) ────────────────────────────────────────────

// Property/function names that historically host prototype-pollution sinks.
const NAME_RE = new RegExp(
  "^(" +
    [
      "merge", "mergeWith", "mergeAll", "mergeDeep", "mergeDeepRight", "mergeDeepLeft",
      "deepmerge", "deepMerge", "mergeObjects", "mergeAnything",
      "set", "setWith", "setWithIn", "setProperty", "setValue", "safeSet", "deepSet", "dset",
      "update", "updateWith", "unset",
      "defaults", "defaultsDeep", "defaultsdeep", "defu", "defuFn",
      "assign", "assignIn", "assignInWith", "assignWith", "assignDeep", "extend", "extendDeep",
      "deepExtend", "deepAssign", "mixin", "mixinDeep",
      "clone", "cloneDeep",
      // NB: recursive-WRITE/merge sinks only. Deliberately NOT `parse*` — a
      // validator's `parse`/`parseAsync` (e.g. zod) is a read/validate export,
      // not a merge sink, and matching it both over-flags and (for the async
      // variant) floats a rejected Promise through the sync fuzz loop.
      "expand",
    ].join("|") +
    ")",
  "i",
);
const FRAGMENTS = ["merge", "deep", "assign", "extend", "defaults", "setwith", "mixin", "defu"];

export function nameMatchesPpSink(key: string): boolean {
  if (typeof key !== "string" || !key) return false;
  if (NAME_RE.test(key)) return true;
  const lk = key.toLowerCase();
  return FRAGMENTS.some((f) => lk.includes(f));
}

type AnyFn = (...args: unknown[]) => unknown;

export interface SsppCandidate extends DetectorCandidate {
  /** The resolved recursive-write function to fuzz. */
  fn: AnyFn;
  /** Provenance label, e.g. `es-toolkit/compat.set`. */
  via: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && (typeof v === "object" || typeof v === "function");
}

/** Walk a module object one level deep, collecting name-matching functions. */
function collectFromModule(mod: unknown, via: string, out: SsppCandidate[], seen: Set<AnyFn>): void {
  if (!isRecord(mod)) return;
  const push = (key: string, val: unknown, viaLabel: string): void => {
    if (typeof val !== "function") return;
    if (!nameMatchesPpSink(key)) return;
    const fn = val as AnyFn;
    if (seen.has(fn)) return;
    seen.add(fn);
    out.push({ id: `${key}@${viaLabel}`, label: `${viaLabel}.${key}`, fn, via: viaLabel });
  };
  for (const key of Object.keys(mod)) {
    let val: unknown;
    try {
      val = (mod as Record<string, unknown>)[key];
    } catch {
      continue;
    }
    push(key, val, via);
  }
  if (typeof mod === "function" && (mod as AnyFn).name) push((mod as AnyFn).name, mod, `${via}(default-fn)`);
  for (const nsKey of ["default", "compat", "fp", "object", "lodash"]) {
    let ns: unknown;
    try {
      ns = (mod as Record<string, unknown>)[nsKey];
    } catch {
      ns = undefined;
    }
    if (isRecord(ns) && ns !== mod) {
      for (const key of Object.keys(ns)) {
        let val: unknown;
        try {
          val = (ns as Record<string, unknown>)[key];
        } catch {
          continue;
        }
        push(key, val, `${via}.${nsKey}`);
      }
      if (typeof ns === "function" && (ns as AnyFn).name) push((ns as AnyFn).name, ns, `${via}.${nsKey}(fn)`);
    }
  }
}

/** Candidate module ids to probe: the package, its subpath exports, and `/compat`. */
function subpathCandidates(probe: PackageProbe): string[] {
  const name = probe.pkg.name;
  const subs = new Set<string>([name]);
  const pj = probe.load(`${name}/package.json`);
  if (isRecord(pj) && isRecord((pj as Record<string, unknown>).exports)) {
    for (const k of Object.keys((pj as { exports: Record<string, unknown> }).exports)) {
      if (k === "." || k === "./package.json") continue;
      if (k.startsWith("./") && !k.includes("*")) subs.add(name + k.slice(1));
    }
  }
  subs.add(`${name}/compat`);
  return [...subs];
}

// ── fuzz battery (deterministic dispose) ─────────────────────────────────────

let markerCounter = 0;
function freshMarker(): string {
  markerCounter += 1;
  return `__sspp_${process.pid}_${Date.now().toString(36)}_${markerCounter}__`;
}

/** Is `marker` visible on Object.prototype / Array.prototype via inherited read? */
export function pollutionSnapshot(marker: string): { objHit: boolean; arrHit: boolean; any: boolean } {
  const objHit =
    ({} as Record<string, unknown>)[marker] !== undefined ||
    Object.prototype.hasOwnProperty.call(Object.prototype, marker);
  const arrHit =
    ([] as unknown as Record<string, unknown>)[marker] !== undefined ||
    Object.prototype.hasOwnProperty.call(Array.prototype, marker);
  return { objHit, arrHit, any: objHit || arrHit };
}

function cleanup(marker: string): void {
  try {
    delete (Object.prototype as Record<string, unknown>)[marker];
  } catch {
    /* ignore */
  }
  try {
    delete (Array.prototype as unknown as Record<string, unknown>)[marker];
  } catch {
    /* ignore */
  }
}

interface Payload {
  label: string;
  make: (marker: string) => unknown[];
}

function buildBattery(): Payload[] {
  const battery: Payload[] = [];
  const objStyle = [
    { tag: "src.__proto__", build: (m: string) => JSON.parse(`{"__proto__":{"${m}":"polluted"}}`) as unknown },
    { tag: "src.constructor.prototype", build: (m: string) => JSON.parse(`{"constructor":{"prototype":{"${m}":"polluted"}}}`) as unknown },
    { tag: "src.nested.__proto__", build: (m: string) => JSON.parse(`{"a":{"b":{"__proto__":{"${m}":"polluted"}}}}`) as unknown },
  ];
  for (const p of objStyle) {
    battery.push({ label: `obj:${p.tag}:merge(target,src)`, make: (m) => [{}, p.build(m)] });
    battery.push({ label: `obj:${p.tag}:fn(src)`, make: (m) => [p.build(m)] });
    battery.push({ label: `obj:${p.tag}:merge(target,{},src)`, make: (m) => [{}, {}, p.build(m)] });
  }
  const paths = [
    { tag: "path.str.constructor.prototype", p: (m: string) => `constructor.prototype.${m}` },
    { tag: "path.arr.constructor.prototype", p: (m: string) => ["constructor", "prototype", m] },
    { tag: "path.str.__proto__", p: (m: string) => `__proto__.${m}` },
    { tag: "path.arr.__proto__", p: (m: string) => ["__proto__", m] },
    { tag: "path.str.prototype", p: (m: string) => `prototype.${m}` },
  ];
  for (const pp of paths) {
    battery.push({ label: `set:${pp.tag}:set(obj,path,val)`, make: (m) => [{}, pp.p(m), "polluted"] });
    battery.push({ label: `set:${pp.tag}:update(obj,path,fn)`, make: (m) => [{}, pp.p(m), () => "polluted"] });
  }
  return battery;
}

const BATTERY = buildBattery();

export interface SsppHit {
  payload: string;
  objProto: boolean;
  arrProto: boolean;
}

/** Fuzz a single candidate function; returns runtime-confirmed pollution hits. */
export function fuzzCandidate(fn: AnyFn, timeBudgetMs = 4000): SsppHit[] {
  const started = Date.now();
  const hits: SsppHit[] = [];
  for (const payload of BATTERY) {
    if (Date.now() - started > timeBudgetMs) break;
    const marker = freshMarker();
    cleanup(marker);
    try {
      const ret = fn(...payload.make(marker));
      // A candidate may (mis)resolve to an async function — e.g. a validator's
      // `parseAsync` — that returns a REJECTED promise. This loop is synchronous
      // and ignores the return value, so an un-awaited rejection would float and
      // crash the host (unhandled rejection → exit 1, fatal under
      // `--unhandled-rejections=strict`). Neutralise any returned thenable; we
      // only observe the prototype, never the return value.
      if (ret !== null && (typeof ret === "object" || typeof ret === "function") && typeof (ret as { then?: unknown }).then === "function") {
        void (ret as Promise<unknown>).then(undefined, () => {});
      }
    } catch {
      /* fn rejecting the shape is fine; we only care about the prototype */
    }
    const p = pollutionSnapshot(marker);
    if (p.any) hits.push({ payload: payload.label, objProto: p.objHit, arrProto: p.arrHit });
    cleanup(marker);
  }
  return hits;
}

// ── the detector ─────────────────────────────────────────────────────────────

export const ssppFuzzDetector: Detector<SsppCandidate> = {
  id: "sspp-fuzz",
  title: "Server-Side Prototype Pollution (dynamic fuzz)",
  cwe: "CWE-1321",
  category: "prototype-pollution",
  severityFloor: "high",
  description:
    "LLM-proposes / harness-disposes SSPP miner: name-heuristic candidate recursive-write fns, confirmed ONLY on runtime Object/Array.prototype pollution; optional NODE_OPTIONS gadget escalates to RCE.",
  appliesTo(_pkg: PackageRef): boolean {
    // Any package can host a merge/set sink; the identify walk is the real
    // filter. Conservative = true (never hide a real bug on a missing tag).
    return true;
  },
  identifyCandidates(probe: PackageProbe): SsppCandidate[] {
    const out: SsppCandidate[] = [];
    const seen = new Set<AnyFn>();
    for (const id of subpathCandidates(probe)) {
      const mod = probe.load(id);
      if (mod === undefined) {
        probe.note?.(`sspp-fuzz: could not load ${id}`);
        continue;
      }
      collectFromModule(mod, id, out, seen);
    }
    return out;
  },
  confirm(candidate: SsppCandidate): DetectorConfirmation {
    const hits = fuzzCandidate(candidate.fn);
    if (hits.length === 0) {
      return { confirmed: false, evidence: { observation: "" } };
    }
    const first = hits[0];
    const which = first.objProto ? "Object.prototype" : "Array.prototype";
    return {
      confirmed: true,
      severity: "high",
      source: candidate.label,
      evidence: {
        observation: `${which} polluted at runtime via ${candidate.label} (payload ${first.payload})`,
        payload: first.payload,
        analysis: [
          `Function ${candidate.via} recursively writes attacker-controlled keys without guarding`,
          `__proto__ / constructor.prototype. ${hits.length} payload(s) fired; a truly empty {} then`,
          `inherits the planted marker. SSPP/High; escalate to RCE only if a NODE_OPTIONS gadget`,
          `fires in a spawned Node subprocess (sandbox-gated escalation, assume-FP otherwise).`,
        ].join(" "),
        escalation: { kind: "NODE_OPTIONS→RCE", achieved: false, note: "gadget not attempted in confirm (sandbox-gated)" },
      },
    };
  },
  dedupHints: {
    // 0sec prior filing for this exact class.
    priorReports: ["es-toolkit"],
    // Fork-twin the prototype learned the hard way: npm audit gave a false
    // all-clear because the advisory lives under the maintained fork's name.
    forkTwins: {
      radash:
        "CVE-2025-48054 / GHSA-2xv9-ghh9-xc69 (disclosed in fork `radashi`; no GHSA under `radash` → live advisory lookup misses it)",
    },
  },
};
