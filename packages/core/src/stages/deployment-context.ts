/**
 * Deployment-context classification for candidate findings — the mechanical
 * path heuristic and severity-downgrade rule (#1215, deep-review postmortem).
 *
 * Every finding flowing through `leadToCandidateFinding` gets a deterministic
 * deployment-context tag based on its candidate file path. Dev/test/build-only
 * findings are severity-capped at low/info unless the evidence shows a
 * trust-boundary bypass from production (the HackerOne rule).
 *
 * A production-exposed ML-powered verify lens (the `deployment-context` lens
 * in `defaultVerifyLenses`) may overlap — the mechanical heuristic always wins
 * on conflict.
 */

import type { Finding, DeploymentContext, Severity } from "@0sec/shared";

// ── Path patterns ────────────────────────────────────────────────────────────

/**
 * Path segments and patterns indicating DEV-ONLY code: dev servers, seeds,
 * fixtures, migration tooling, environment config, and scaffolding that only
 * runs during local development.
 */
const DEV_ONLY_PATTERNS: RegExp[] = [
  // Named dev scripts / entry points
  /\/dev[-_]/,               // dev-server, dev.ts, dev.js
  /run[-_]dev/,              // run-dev, run_dev
  /\bdev\.(ts|js|tsx|jsx|mjs|cjs)$/,
  // Dev environment config
  /\/\.dev\.vars/,           // Cloudflare .dev.vars
  /\/\.env\.local/,          // local-only env
  /\.env\.development/,      // dev env
  /\/env\.ts$/,
  // Seeds, fixtures, factories
  /\/seed[s]?\//,            // seeds/, seed/
  /\/fixture[s]?\//,         // fixtures/
  /\/factory[/s]?\//,        // factories/
  // Dev-only setup / scaffolding
  /\/scripts\//,             // scripts/ (dev scripts)
  /\/bin\//,                 // local bin scripts
  /\/docker-compose/,        // Docker Compose (local dev)
  /\/Dockerfile/,            // Dockerfile (dev build)
  /\/docker-entrypoint/,     // entrypoint scripts
  /Vagrantfile/,
  /\/\.tool-versions/,
  /\/\.nvmrc/,
  /\/\.node-version/,
  /\/\.python-version/,
];

/**
 * Path patterns indicating TEST-ONLY code: test files, mocks, stubs,
 * integration test fixtures, e2e tests, and test runners.
 */
const TEST_ONLY_PATTERNS: RegExp[] = [
  // Standard test directories
  /\/test[s]?\//,            // tests/, test/
  /\/__tests__\//,           // Jest/TS test dirs
  /\/spec\//,                // spec/
  /\/e2e\//,                 // e2e/
  /\/integration\//,         // integration/
  // Test file name patterns
  /\.test\.(ts|js|tsx|jsx|py|go|rs|rb|java|kt)$/i,
  /\.spec\.(ts|js|tsx|jsx|py|go|rs|rb|java|kt)$/i,
  /\/__mocks__\//,
  /\/mock[s]?\//,
  /\/stub[s]?\//,
  /\/__snapshots__\//,
  // Cypress / Playwright
  /\/cypress\//,
  /\/playwright\//,
  /\/__fixtures__\//,
  // Benchmark files (benchmarks are test-like — not prod)
  /\.bench\.(ts|js|tsx|jsx|py|go|rs)$/i,
  /\/benchmark[s]?\//,
  // Load test scripts
  /\/k6\//,
  /\/artillery\//,
  /\/locustfile/,
];

/**
 * Path patterns indicating BUILD-ONLY code: package manifests, build
 * configuration, generated code, vendored dependencies, CI tooling, and
 * any file whose runtime is the build pipeline, not production.
 */
const BUILD_ONLY_PATTERNS: RegExp[] = [
  // Package manifests (runtime: package manager)
  /\/package\.json$/,
  /\/package-lock\.json$/,
  /\/yarn\.lock$/,
  /\/pnpm-lock\.yaml$/,
  /\/Cargo\.toml$/,
  /\/Cargo\.lock$/,
  /\/go\.mod$/,
  /\/go\.sum$/,
  /\/Gemfile$/,
  /\/Gemfile\.lock$/,
  /\/Pipfile$/,
  /\/Pipfile\.lock$/,
  /\/requirements.*\.txt$/,
  /\/build\.gradle/,
  /\/pom\.xml$/,
  // Build tooling config
  /\/webpack\.config/,
  /\/vite\.config/,
  /\/rollup\.config/,
  /\/esbuild\./,
  /\/tsconfig\./,
  /\/babel\.config/,
  /\/\.babelrc/,
  /\/postcss\.config/,
  /\/tailwind\.config/,
  /\/next\.config/,
  /\/nuxt\.config/,
  /\/svelte\.config/,
  /\/eslint\.config/,
  /\/prettier\.config/,
  // CI
  /\/\.github\//,
  /\/\.gitlab/,
  /\/Jenkinsfile/,
  /\/\.circleci\//,
  /\/\.gitlab-ci\./,
  // Build output / generated
  /\/dist\//,
  /\/build\//,
  /\/out\//,
  /\/target\//,              // Rust build output
  /\/\.next\//,
  /\/\.nuxt\//,
  /\/\.cache\//,
  /\/coverage\//,
  /\/generated\//,
  /\/\.gen\//,
  /\/_gen\//,
  // Vendored / third-party
  /\/node_modules\//,
  /\/vendor\//,
  /\/\.pnp\..+/,
  /\.min\.(js|css)$/,
  // Makefile / build scripts
  /\/Makefile$/,
  /\/Makefile\./,
  /\/CMakeLists\.txt$/,
  /\/meson\.build$/,
];

// ── Pattern helpers ──────────────────────────────────────────────────────────

/** Specific-enough patterns that alone determine test-only context. */
const STRONG_TEST_PATTERNS: RegExp[] = [
  /\.test\.(ts|js|tsx|jsx|py|go|rs|rb|java|kt)$/i,
  /\.spec\.(ts|js|tsx|jsx|py|go|rs|rb|java|kt)$/i,
  /\/__tests__\//,
  /\/__mocks__\//,
  /\/__snapshots__\//,
];

/** Specific-enough patterns that alone determine dev-only context. */
const STRONG_DEV_PATTERNS: RegExp[] = [
  /\/\.dev\.vars/,
  /\/seed[s]?\//,
  /\/dev[-_]/,
  /run[-_]dev/,
];

/** Specific-enough patterns that alone determine build-only context. */
const STRONG_BUILD_PATTERNS: RegExp[] = [
  /\/node_modules\//,
  /\/dist\//,
  /\/build\//,
  /\/\.next\//,
  /\/package\.json$/,
  /\/Cargo\.toml$/,
  /\/go\.mod$/,
];

/**
 * Check if a path matches ANY pattern in a list.
 */
function matchesAny(path: string, patterns: RegExp[]): boolean {
  const normalized = path.replace(/\\/g, "/");
  return patterns.some((p) => p.test(normalized));
}

// ── Classification ──────────────────────────────────────────────────────────

/**
 * Classify a candidate file's deployment context from its path alone.
 *
 * Priority order (first match wins):
 *   1. STRONG test patterns → `test_only`
 *   2. STRONG dev patterns → `dev_only`
 *   3. STRONG build patterns → `build_only`
 *   4. Complete test set → `test_only`
 *   5. Complete dev set → `dev_only`
 *   6. Complete build set → `build_only`
 *   7. No match → `prod_reachable` (default/unknown)
 *
 * The strong-patterns-first order ensures that e.g. a test file under a
 * `scripts/` directory is still classified as `test_only`, not `dev_only`.
 */
export function classifyDeploymentContext(candidatePath: string): DeploymentContext {
  const path = candidatePath.replace(/\\/g, "/");

  // Strong test patterns (highest priority — a *.test.* file is test_only
  // even if it lives under scripts/).
  if (matchesAny(path, STRONG_TEST_PATTERNS)) return "test_only";

  // Strong dev patterns
  if (matchesAny(path, STRONG_DEV_PATTERNS)) return "dev_only";

  // Strong build patterns
  if (matchesAny(path, STRONG_BUILD_PATTERNS)) return "build_only";

  // Full pattern sets (broader, e.g. a file under a generic tests/ dir)
  if (matchesAny(path, TEST_ONLY_PATTERNS)) return "test_only";
  if (matchesAny(path, DEV_ONLY_PATTERNS)) return "dev_only";
  if (matchesAny(path, BUILD_ONLY_PATTERNS)) return "build_only";

  // Default — no dev/test/build evidence found
  return "prod_reachable";
}

// ── Severity cap ────────────────────────────────────────────────────────────

/**
 * Severity cap map for each non-prod deployment context.
 *
 * - `dev_only` → info (local-only, not a real exploitation surface)
 * - `test_only` → low (test code can affect CI but not real users)
 * - `build_only` → info (build tooling, transitive dep issues)
 * - `prod_reachable` → no cap (pass through as-is)
 */
const DEPLOYMENT_CONTEXT_CAP: Record<DeploymentContext, Severity | null> = {
  prod_reachable: null,   // no cap
  dev_only: "info",
  test_only: "low",
  build_only: "info",
};

/** Severity ranking — higher number = more severe. */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Check whether a finding's evidence suggests a trust-boundary bypass from
 * production (the HackerOne rule) — i.e. the finding describes an attack path
 * that crosses from a prod endpoint into a dev/test/build code path. This is a
 * cheap heuristic that looks for keywords in the evidence text; the model lens
 * provides the authoritative assessment.
 *
 * The H1 rule: a test-only finding is still valid if the attacker can reach it
 * from a production endpoint (e.g. a staging endpoint that accepts prod
 * traffic, a feature-flag-gated code path accessible to all users).
 */
export function hasTrustBoundaryBypass(finding: Pick<Finding, "title" | "description" | "evidence">): boolean {
  const text = [
    finding.title,
    finding.description,
    finding.evidence?.analysis ?? "",
    finding.evidence?.request ?? "",
    finding.evidence?.response ?? "",
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  // Look for evidence of production-reachable dev/test code
  const signals = [
    /trust.boundary/i,
    /prod.*bypass/i,
    /bypass.*prod/i,
    /reachable.*prod/i,
    /prod.*reach/i,
    /production.*reachable/i,
    /staging.*prod/i,
    /prod.*traffic/i,
    /flag.gated.*prod/i,
    /env=.*prod/i,
    /deployed.*prod/i,
    /\bprod\b.*\broute\b/i,
    /\broute\b.*\bprod\b/i,
    /affects.*all.*users/i,
    /no.*auth.*required/i,
    /public.*endpoint.*dev/i,
    /attacker.*controlled.*path/i,
    /trust.boundary.*cross/i,
  ];

  return signals.some((s) => s.test(text));
}

/**
 * Apply the deployment-context severity cap to a finding. Returns a new
 * severity value (or the original if no cap applies).
 *
 * Rule: dev_only / test_only / build_only findings are downgraded (severity
 * capped at low/info per {@link DEPLOYMENT_CONTEXT_CAP}) UNLESS the finding
 * evidence shows a trust-boundary bypass from production (the HackerOne rule).
 *
 * The mechanical path tag is the deterministic floor — a model lens may
 * disagree, but the heuristic wins on conflict.
 */
export function applyDeploymentContextCap(
  finding: Pick<Finding, "title" | "description" | "evidence" | "deploymentContext" | "severity">,
): Severity {
  const ctx = finding.deploymentContext;
  if (!ctx || ctx === "prod_reachable") return finding.severity;

  // HackerOne rule: if there is evidence of a prod trust-boundary bypass,
  // keep the original severity (don't cap).
  if (hasTrustBoundaryBypass(finding)) return finding.severity;

  const cap = DEPLOYMENT_CONTEXT_CAP[ctx];
  if (cap === null) return finding.severity;

  const currentRank = SEVERITY_RANK[finding.severity] ?? 2; // default: medium
  const capRank = SEVERITY_RANK[cap];

  return currentRank > capRank ? cap : finding.severity;
}

/**
 * Stamp the deployment context on a finding and apply the severity cap.
 * Convenience wrapper for the pipeline call sites.
 *
 * @returns The original `finding` mutated in place — the pipeline creates fresh
 *   plain objects for candidacy, so mutation is safe. Returns the same object
 *   for chaining.
 */
export function stampDeploymentContext(
  finding: Finding,
  candidatePath: string | undefined,
): Finding {
  if (!candidatePath) return finding;

  const ctx = classifyDeploymentContext(candidatePath);
  finding.deploymentContext = ctx;

  const capped = applyDeploymentContextCap(finding);
  if (capped !== finding.severity) {
    const original = finding.severity;
    finding.severity = capped;
    // Append a note to the evidence analysis so the audit trail is clear
    const note = `[deployment-context] severity capped from ${original} to ${capped} ` +
      `(${ctx} — only prod-reachable findings exceed this tier; ` +
      `report a trust-boundary bypass to override)`;
    finding.evidence = {
      ...finding.evidence,
      analysis: finding.evidence.analysis
        ? `${finding.evidence.analysis}\n\n${note}`
        : note,
    };
  }

  return finding;
}