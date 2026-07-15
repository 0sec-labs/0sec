/**
 * Bench manifest — scan-level pass@k corpus definition (pwnkit#556).
 *
 * The bench harness turns our per-finding verification oracles into a
 * scan-level, third-party-defensible capability/FP number. A manifest is a
 * list of cases, each pairing a runnable target (a dockerized web app or a
 * kernel reproducer case) with a PROGRAMMATIC objective — a deterministic
 * success predicate (file-read, file-write, db-access, admin-login,
 * ssrf-callback, kasan-hit). This is the same idea CVE-Bench uses: an
 * auto-verifying eval server, not a human-graded rubric.
 *
 * ── Corpus discipline ────────────────────────────────────────────────
 * Per the disclosure embargo rules, the actual uncontaminated/post-cutoff
 * corpus (vulnerable app source, exploits, private reproducers) is NEVER
 * committed here. A manifest carries *references only* — a Docker image
 * ref, a compose directory path, a reproducer artifact id — that resolve
 * to content stored outside the public repo. `bench/example-manifest.json`
 * demonstrates the shape with public/placeholder references and contains
 * no exploit material.
 *
 * The loader is intentionally dependency-light (zod only, already a core
 * dep) so it can run in CI without Docker present — provisioning is a
 * separate, injectable concern (see runner.ts).
 */

import { z } from "zod";

// ── Programmatic objectives ──────────────────────────────────────────
//
// Each objective is a deterministic predicate the oracle can grade against
// a scan's emitted evidence. The `marker` / `token` fields are unique,
// per-target strings injected into the target at build time (exactly like
// the XBOW runner injects a random `FLAG{…}`): observing the marker in the
// scan's evidence is *proof* the objective was met, not an inference.

/** Read a protected file — proof is the injected marker appearing in evidence. */
export const FileReadObjectiveSchema = z.object({
  type: z.literal("file-read"),
  /** Unique marker planted in the protected file; its presence proves a read. */
  marker: z.string().min(4),
  /** Optional path hint, surfaced in notes only. */
  path: z.string().optional(),
});

/** Write to a location the unprivileged user shouldn't reach. */
export const FileWriteObjectiveSchema = z.object({
  type: z.literal("file-write"),
  marker: z.string().min(4),
  path: z.string().optional(),
});

/** Read a row/secret out of the backing database. */
export const DbAccessObjectiveSchema = z.object({
  type: z.literal("db-access"),
  /** Unique token seeded into a DB row; exfiltrating it proves db-access. */
  marker: z.string().min(4),
});

/** Authenticate (or escalate) into an admin-only surface. */
export const AdminLoginObjectiveSchema = z.object({
  type: z.literal("admin-login"),
  /** Marker rendered only on the admin surface (e.g. an admin-panel flag). */
  marker: z.string().min(4),
});

/** Make the target issue a server-side request to an attacker-controlled host. */
export const SsrfCallbackObjectiveSchema = z.object({
  type: z.literal("ssrf-callback"),
  /** OAST/callback token the target must echo back to prove the SSRF fired. */
  token: z.string().min(4),
});

/** Trigger a KASAN/UBSAN/crash signature in a kernel reproducer case. */
export const KasanHitObjectiveSchema = z.object({
  type: z.literal("kasan-hit"),
  /**
   * Optional crash-signature substring to require (e.g.
   * "slab-use-after-free"). When omitted, any recognized crash signature
   * (KASAN/UBSAN/BUG/GPF) counts as a hit.
   */
  signature: z.string().optional(),
});

/**
 * Match a static source-audit finding by vuln class + sink location.
 *
 * Unlike the runtime objectives above (which grade against a marker the
 * exploit must surface), a source-audit case has no runnable target to plant
 * a marker in — the "proof" is the scanner emitting a finding of the right
 * CLASS at the right SINK. Grading stays deterministic and never LLM-judged:
 * the oracle requires a finding whose `category` matches `vulnClass` AND
 * whose evidence text contains at least one `sinkMarkers` substring (a real
 * file path / function / symbol named in the disclosure as the sink).
 */
export const FindingMatchObjectiveSchema = z.object({
  type: z.literal("finding-match"),
  /**
   * The AttackCategory the scanner must report (e.g. "sql-injection",
   * "prototype-pollution"). Kept as a free string here so the bench schema
   * doesn't hard-couple to the engine's category enum; the oracle matches it
   * (with a small synonym map) against the emitted finding's `category`.
   */
  vulnClass: z.string().min(1),
  /**
   * Literal sink substrings (file path / function / symbol) drawn from the
   * ground-truth disclosure. A positive grade requires an in-class finding
   * whose evidence contains at least ONE of these — pinning the match to the
   * actual sink, not just any finding of the same class anywhere in the pkg.
   */
  sinkMarkers: z.array(z.string().min(2)).min(1),
});

export const BenchObjectiveSchema = z.discriminatedUnion("type", [
  FileReadObjectiveSchema,
  FileWriteObjectiveSchema,
  DbAccessObjectiveSchema,
  AdminLoginObjectiveSchema,
  SsrfCallbackObjectiveSchema,
  KasanHitObjectiveSchema,
  FindingMatchObjectiveSchema,
]);

export type BenchObjective = z.infer<typeof BenchObjectiveSchema>;
export type BenchObjectiveType = BenchObjective["type"];

// ── Target provisioning references ────────────────────────────────────
//
// References ONLY — never the content. A web target resolves to a Docker
// image or a compose directory; a kernel case resolves to a reproducer
// artifact id the kernel oracle knows how to fetch. The provisioner
// (runner.ts) decides how to turn these into a runnable target.

export const WebTargetSchema = z.object({
  kind: z.literal("web"),
  /** Docker image ref, e.g. "ghcr.io/0sec-labs/bench-web-001:pinned-sha". */
  image: z.string().optional(),
  /** Alternatively, a docker-compose directory (relative to corpusRoot). */
  composeDir: z.string().optional(),
  /** Container port the app listens on; the provisioner maps it to localhost. */
  port: z.number().int().positive().optional(),
  /** Extra hint surfaced to the scan agent (challenge description, etc.). */
  hint: z.string().optional(),
});

export const KernelTargetSchema = z.object({
  kind: z.literal("kernel"),
  /** Reproducer artifact id the kernel oracle resolves outside the repo. */
  reproducerRef: z.string(),
  /** Ecosystem hint, e.g. "kernel-tree" / "linux-kernel". */
  ecosystem: z.string().optional(),
  /** Free-text hint surfaced to the scan agent. */
  hint: z.string().optional(),
});

export const SourceAuditTargetSchema = z.object({
  kind: z.literal("source-audit"),
  /** Package name as published, e.g. "sequelize" or "@cloudflare/workers-sdk". */
  package: z.string().min(1),
  /**
   * Pinned package version the case is labeled against, e.g. "6.37.8". This
   * is a public registry coordinate (npm/pypi/cargo) — NOT exploit material —
   * so it lives in the manifest directly; the engine `npm install`s it at run
   * time. No out-of-repo corpus is needed for a source-audit case.
   */
  version: z.string().min(1),
  /** Registry the package is fetched from. The engine's PackageEcosystem. */
  ecosystem: z.enum(["npm", "pypi", "cargo", "oci"]).default("npm"),
  /** Free-text hint surfaced to the audit agent. */
  hint: z.string().optional(),
});

export const BenchTargetSchema = z.discriminatedUnion("kind", [
  WebTargetSchema,
  KernelTargetSchema,
  SourceAuditTargetSchema,
]);

export type BenchTarget = z.infer<typeof BenchTargetSchema>;

// ── Objective ↔ target-kind pairing ───────────────────────────────────
//
// Each objective type is only meaningful against exactly one target kind.
// The runtime-marker objectives grade a live web target; kasan-hit grades a
// kernel reproducer; finding-match grades a static source-audit. The case
// schema enforces this pairing at load time (see superRefine below).

const OBJECTIVE_TARGET_KIND: Record<BenchObjectiveType, BenchTarget["kind"]> = {
  "file-read": "web",
  "file-write": "web",
  "db-access": "web",
  "admin-login": "web",
  "ssrf-callback": "web",
  "kasan-hit": "kernel",
  "finding-match": "source-audit",
};

// ── Case + manifest ───────────────────────────────────────────────────

export const BenchCaseSchema = z
  .object({
    /** Stable, unique id within the manifest. */
    id: z.string().min(1),
    /** Human label. */
    name: z.string().optional(),
    target: BenchTargetSchema,
    objective: BenchObjectiveSchema,
    /**
     * Known-negative (non-vulnerable) target. A "verified" verdict against a
     * known-negative is a FALSE POSITIVE and feeds the scorecard's fpRate.
     * Defaults to false.
     */
    knownNegative: z.boolean().default(false),
    /**
     * Include this case in the fast CI subset. The CI gate runs only
     * `ci: true` cases and fails the build below threshold.
     */
    ci: z.boolean().default(false),
    /** Per-case pass@k override. Falls back to the run-level passAtK. */
    passAtK: z.number().int().positive().optional(),
    /** Per-case turn budget override. Falls back to the run-level budget. */
    maxTurns: z.number().int().positive().optional(),
    /** Free-form tags for slicing the scorecard. */
    tags: z.array(z.string()).default([]),
  })
  .superRefine((c, ctx) => {
    // Each objective type is only meaningful against one target kind. Catch a
    // mismatch (e.g. a finding-match objective on a web target, or a kasan-hit
    // on a source-audit target) at load time rather than at grade time.
    const expected = OBJECTIVE_TARGET_KIND[c.objective.type];
    if (expected !== c.target.kind) {
      // Preserve the legacy kasan/kernel diagnostic for any mismatch touching
      // the kernel pairing, so existing callers/tests grepping for it keep
      // working; emit a generic message for the other pairings.
      const message =
        c.objective.type === "kasan-hit" || c.target.kind === "kernel"
          ? `case "${c.id}": kasan-hit objective requires a kernel target and vice versa (objective=${c.objective.type}, target=${c.target.kind})`
          : `case "${c.id}": ${c.objective.type} objective requires a ${expected} target (got target=${c.target.kind})`;
      ctx.addIssue({ code: z.ZodIssueCode.custom, message });
    }
  });

export type BenchCase = z.infer<typeof BenchCaseSchema>;

export const BenchManifestSchema = z.object({
  /** Stable manifest id (surfaced in the scorecard). */
  id: z.string().min(1),
  /** Manifest schema/version label, for forward-compat. */
  version: z.literal(1).default(1),
  /**
   * Root the provisioner resolves relative `composeDir` references against.
   * Points OUTSIDE the repo at the private corpus checkout. Optional so a
   * manifest that only uses absolute image refs needs no root.
   */
  corpusRoot: z.string().optional(),
  cases: z.array(BenchCaseSchema).min(1),
});

export type BenchManifest = z.infer<typeof BenchManifestSchema>;

// ── Loader ────────────────────────────────────────────────────────────

/**
 * Parse + validate a manifest from a raw JS object (already JSON-parsed).
 * Throws a ZodError with a readable message on the first invalid case.
 * Also enforces case-id uniqueness, which zod can't express structurally.
 */
export function parseManifest(raw: unknown): BenchManifest {
  const manifest = BenchManifestSchema.parse(raw);
  const seen = new Set<string>();
  for (const c of manifest.cases) {
    if (seen.has(c.id)) {
      throw new Error(`bench manifest "${manifest.id}": duplicate case id "${c.id}"`);
    }
    seen.add(c.id);
  }
  return manifest;
}

/**
 * Load + validate a manifest from a JSON file on disk.
 *
 * Kept as a thin wrapper over `parseManifest` so unit tests can validate
 * the schema without touching the filesystem. Node `fs`/`path` are imported
 * lazily so importing this module in a browser-ish/test context that never
 * calls `loadManifest` stays cheap.
 */
export async function loadManifest(path: string): Promise<BenchManifest> {
  const { readFile } = await import("node:fs/promises");
  const text = await readFile(path, "utf8");
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(
      `bench manifest at ${path} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseManifest(raw);
}

/** All cases flagged for the fast CI subset. */
export function selectCiCases(manifest: BenchManifest): BenchCase[] {
  return manifest.cases.filter((c) => c.ci);
}

/**
 * Build a validated, ordered manifest slice for sealed development/held-out/
 * negative-control runs. Unknown and duplicate ids fail closed so a typo can
 * never silently shrink an experiment corpus.
 */
export function subsetManifest(
  manifest: BenchManifest,
  caseIds: string[],
  id: string,
): BenchManifest {
  if (caseIds.length === 0) throw new Error("bench manifest subset must not be empty");
  if (new Set(caseIds).size !== caseIds.length) {
    throw new Error("bench manifest subset contains duplicate case ids");
  }
  const byId = new Map(manifest.cases.map((c) => [c.id, c]));
  const cases = caseIds.map((caseId) => {
    const c = byId.get(caseId);
    if (!c) throw new Error(`bench manifest "${manifest.id}": unknown case id "${caseId}"`);
    return c;
  });
  return parseManifest({
    id,
    version: manifest.version,
    corpusRoot: manifest.corpusRoot,
    cases,
  });
}

/** Cases partitioned into positive (real-vuln) and known-negative buckets. */
export function partitionCases(cases: BenchCase[]): {
  positives: BenchCase[];
  knownNegatives: BenchCase[];
} {
  return {
    positives: cases.filter((c) => !c.knownNegative),
    knownNegatives: cases.filter((c) => c.knownNegative),
  };
}
