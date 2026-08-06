/**
 * Deployment-context classification tests (issue #1215, deep-review postmortem).
 *
 * Tests the mechanical path heuristic (classification table), the severity cap
 * for dev/test/build-only findings, and the trust-boundary bypass override.
 */

import { describe, expect, it, vi } from "vitest";
import {
  classifyDeploymentContext,
  applyDeploymentContextCap,
  hasTrustBoundaryBypass,
} from "./deployment-context.js";
import type { Finding, DeploymentContext, Severity } from "@pwnkit/shared";

// ── Classification table ────────────────────────────────────────────────────

interface ClassifyCase {
  path: string;
  expected: DeploymentContext;
  label: string;
}

const CLASSIFY_CASES: ClassifyCase[] = [
  // ── prod_reachable (no dev/test/build patterns) ──
  { path: "/app/src/routes/api.ts", expected: "prod_reachable", label: "plain source file" },
  { path: "/app/src/components/Button.tsx", expected: "prod_reachable", label: "UI component" },
  { path: "/app/lib/utils.js", expected: "prod_reachable", label: "lib utility" },
  { path: "/app/main.go", expected: "prod_reachable", label: "Go entrypoint" },
  { path: "/app/Cargo.toml", expected: "build_only", label: "Cargo.toml" },

  // ── dev_only patterns ──
  { path: "/app/.dev.vars", expected: "dev_only", label: ".dev.vars" },
  { path: "/app/seeds/init.ts", expected: "dev_only", label: "seeds directory" },
  { path: "/app/seed/data.json", expected: "dev_only", label: "seed file" },
  { path: "/app/dev-server.ts", expected: "dev_only", label: "dev-server.ts" },
  { path: "/app/scripts/setup.ts", expected: "dev_only", label: "scripts directory" },
  { path: "/app/scripts/deploy.ts", expected: "dev_only", label: "deploy script" },
  { path: "/app/bin/migrate.ts", expected: "dev_only", label: "bin directory" },
  { path: "/app/docker-compose.yml", expected: "dev_only", label: "docker-compose" },
  { path: "/app/Dockerfile", expected: "dev_only", label: "Dockerfile" },
  { path: "/app/.env.local", expected: "dev_only", label: ".env.local" },

  // ── test_only patterns ──
  { path: "/app/tests/api.test.ts", expected: "test_only", label: "tests/api.test.ts" },
  { path: "/app/test/routes.test.ts", expected: "test_only", label: "test directory" },
  { path: "/app/__tests__/auth.spec.ts", expected: "test_only", label: "__tests__" },
  { path: "/app/spec/auth.spec.ts", expected: "test_only", label: "spec directory" },
  { path: "/app/e2e/login.spec.ts", expected: "test_only", label: "e2e tests" },
  { path: "/app/integration/db.test.ts", expected: "test_only", label: "integration tests" },
  { path: "/app/src/utils.test.ts", expected: "test_only", label: ".test.ts inline" },
  { path: "/app/src/helper.spec.ts", expected: "test_only", label: ".spec.ts inline" },
  { path: "/app/__mocks__/db.ts", expected: "test_only", label: "__mocks__" },
  { path: "/app/mocks/request.ts", expected: "test_only", label: "mocks directory" },
  { path: "/app/__snapshots__/test.js.snap", expected: "test_only", label: "__snapshots__" },
  { path: "/app/cypress/e2e/login.cy.ts", expected: "test_only", label: "Cypress e2e" },
  { path: "/app/playwright/login.spec.ts", expected: "test_only", label: "Playwright" },

  // ── build_only patterns ──
  { path: "/app/node_modules/express/index.js", expected: "build_only", label: "node_modules" },
  { path: "/app/dist/bundle.js", expected: "build_only", label: "dist output" },
  { path: "/app/build/artifacts", expected: "build_only", label: "build output" },
  { path: "/app/.next/server/pages", expected: "build_only", label: ".next build" },
  { path: "/app/package.json", expected: "build_only", label: "package.json" },
  { path: "/app/Cargo.toml", expected: "build_only", label: "Cargo.toml" },
  { path: "/app/go.mod", expected: "build_only", label: "go.mod" },
  { path: "/app/webpack.config.js", expected: "build_only", label: "webpack config" },
  { path: "/app/vite.config.ts", expected: "build_only", label: "vite config" },
  { path: "/app/tsconfig.json", expected: "build_only", label: "tsconfig" },
  { path: "/app/.github/workflows/ci.yml", expected: "build_only", label: "GitHub Actions" },
  { path: "/app/target/debug/main", expected: "build_only", label: "Rust target" },
  { path: "/app/coverage/lcov.info", expected: "build_only", label: "coverage output" },

  // ── Priority: strong patterns win over broader categories ──
  // A .test.ts file under scripts/ should still be test_only (strong test wins)
  { path: "/app/scripts/utils.test.ts", expected: "test_only", label: "test under scripts (strong wins)" },
  // A .dev.vars file under tests/ should still be dev_only (strong dev wins)
  { path: "/app/tests/.dev.vars", expected: "dev_only", label: ".dev.vars under tests (strong dev wins)" },
  // A node_modules test file is still build_only (strong build wins)
  { path: "/app/node_modules/pkg/test/test.js", expected: "build_only", label: "test in node_modules (strong build wins)" },
];

describe("classifyDeploymentContext — path heuristics", () => {
  for (const { path, expected, label } of CLASSIFY_CASES) {
    it(`classifies "${label}" as ${expected}`, () => {
      expect(classifyDeploymentContext(path)).toBe(expected);
    });
  }

  it("handles Windows backslash paths", () => {
    expect(classifyDeploymentContext("C:\\app\\tests\\api.test.ts")).toBe("test_only");
    expect(classifyDeploymentContext("C:\\app\\.dev.vars")).toBe("dev_only");
    expect(classifyDeploymentContext("C:\\app\\node_modules\\pkg\\index.js")).toBe("build_only");
    expect(classifyDeploymentContext("C:\\app\\src\\routes.ts")).toBe("prod_reachable");
  });

  it("returns prod_reachable for an unknown path", () => {
    expect(classifyDeploymentContext("/app/unknown/file.xyz")).toBe("prod_reachable");
    expect(classifyDeploymentContext("")).toBe("prod_reachable");
  });
});

// ── Severity cap tests ───────────────────────────────────────────────────────

describe("applyDeploymentContextCap — severity downgrade", () => {
  function mkFinding(
    severity: Severity,
    deploymentContext: DeploymentContext | undefined,
    evidenceText?: string,
  ): Pick<Finding, "title" | "description" | "evidence" | "deploymentContext" | "severity"> {
    return {
      severity,
      deploymentContext,
      title: "Test finding",
      description: "A finding for testing",
      evidence: { request: "", response: "", analysis: evidenceText ?? "" },
    };
  }

  describe("passes prod_reachable through unchanged", () => {
    for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
      it(`keeps ${sev} for prod_reachable`, () => {
        expect(applyDeploymentContextCap(mkFinding(sev, "prod_reachable"))).toBe(sev);
      });
    }
  });

  describe("caps dev_only to info", () => {
    it("downgrades critical to info", () => {
      expect(applyDeploymentContextCap(mkFinding("critical", "dev_only"))).toBe("info");
    });
    it("downgrades high to info", () => {
      expect(applyDeploymentContextCap(mkFinding("high", "dev_only"))).toBe("info");
    });
    it("downgrades medium to info", () => {
      expect(applyDeploymentContextCap(mkFinding("medium", "dev_only"))).toBe("info");
    });
    it("passes info through unchanged", () => {
      expect(applyDeploymentContextCap(mkFinding("info", "dev_only"))).toBe("info");
    });
  });

  describe("caps test_only to low", () => {
    it("downgrades critical to low", () => {
      expect(applyDeploymentContextCap(mkFinding("critical", "test_only"))).toBe("low");
    });
    it("downgrades high to low", () => {
      expect(applyDeploymentContextCap(mkFinding("high", "test_only"))).toBe("low");
    });
    it("downgrades medium to low", () => {
      expect(applyDeploymentContextCap(mkFinding("medium", "test_only"))).toBe("low");
    });
    it("passes low through unchanged", () => {
      expect(applyDeploymentContextCap(mkFinding("low", "test_only"))).toBe("low");
    });
    it("passes info through unchanged", () => {
      expect(applyDeploymentContextCap(mkFinding("info", "test_only"))).toBe("info");
    });
  });

  describe("caps build_only to info", () => {
    it("downgrades critical to info", () => {
      expect(applyDeploymentContextCap(mkFinding("critical", "build_only"))).toBe("info");
    });
    it("downgrades high to info", () => {
      expect(applyDeploymentContextCap(mkFinding("high", "build_only"))).toBe("info");
    });
    it("downgrades medium to info", () => {
      expect(applyDeploymentContextCap(mkFinding("medium", "build_only"))).toBe("info");
    });
    it("passes info through unchanged", () => {
      expect(applyDeploymentContextCap(mkFinding("info", "build_only"))).toBe("info");
    });
  });

  describe("undefined deployment context passes through", () => {
    for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
      it(`keeps ${sev} when context is undefined`, () => {
        expect(applyDeploymentContextCap(mkFinding(sev, undefined))).toBe(sev);
      });
    }
  });
});

// ── Trust-boundary bypass override ──────────────────────────────────────────

describe("hasTrustBoundaryBypass — HackerOne rule", () => {
  function mkFindingWithEvidence(text: string) {
    return {
      title: "Test",
      description: "Description",
      evidence: { request: "", response: "", analysis: text },
    };
  }

  it("detects trust boundary in evidence", () => {
    expect(hasTrustBoundaryBypass(mkFindingWithEvidence("crosses trust boundary from prod endpoint"))).toBe(true);
  });

  it("detects prod reachable", () => {
    expect(hasTrustBoundaryBypass(mkFindingWithEvidence("reachable from production traffic"))).toBe(true);
  });

  it("detects prod bypass", () => {
    expect(hasTrustBoundaryBypass(mkFindingWithEvidence("attacker bypasses prod routing to reach dev code"))).toBe(true);
  });

  it("detects no auth required", () => {
    expect(hasTrustBoundaryBypass(mkFindingWithEvidence("affects all users, no auth required"))).toBe(true);
  });

  it("returns false when no bypass signal is present", () => {
    expect(hasTrustBoundaryBypass(mkFindingWithEvidence("dev-only seed initialization"))).toBe(false);
  });

  it("returns false for empty evidence", () => {
    expect(hasTrustBoundaryBypass(mkFindingWithEvidence(""))).toBe(false);
  });
});

describe("applyDeploymentContextCap — trust-boundary bypass override", () => {
  function mkFinding(
    severity: Severity,
    deploymentContext: DeploymentContext,
    evidenceText: string,
  ): Pick<Finding, "title" | "description" | "evidence" | "deploymentContext" | "severity"> {
    return {
      severity,
      deploymentContext,
      title: "Test",
      description: "Description",
      evidence: { request: "", response: "", analysis: evidenceText },
    };
  }

  it("keeps high severity for test_only with trust-boundary bypass evidence", () => {
    const f = mkFinding("high", "test_only", "attacker-controlled path from prod endpoint reaches test helper");
    expect(applyDeploymentContextCap(f)).toBe("high");
  });

  it("keeps critical severity for dev_only with trust-boundary bypass evidence", () => {
    const f = mkFinding("critical", "dev_only", "critical trust boundary bypass from production");
    expect(applyDeploymentContextCap(f)).toBe("critical");
  });

  it("still caps dev_only without bypass evidence", () => {
    const f = mkFinding("high", "dev_only", "dev-only seed file is unauthenticated");
    expect(applyDeploymentContextCap(f)).toBe("info");
  });
});