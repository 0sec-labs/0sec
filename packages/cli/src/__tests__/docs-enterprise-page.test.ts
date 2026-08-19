import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Guard test for the enterprise readiness checklist page introduced in #379.
 *
 * The page at `docs/src/content/docs/enterprise.md` is the single source of
 * truth for enterprise capability claims. Sales decks and procurement
 * responses link to it. If the file is renamed, deleted, or one of the seven
 * required section headers is removed, this test fails so the regression is
 * caught before it reaches a customer-facing surface.
 *
 * The seven required section headers correspond directly to the issue body
 * acceptance criteria: Auth, Models, Deployment, Data, Audit, SLA, Compliance.
 */

// Walk up from this test file to the repo root, then into the docs tree.
// __dirname-style resolution via import.meta.url keeps the test independent of
// the working directory `pnpm --filter @pwnkit/cli test` runs from.
const here = new URL(".", import.meta.url).pathname;
const REPO_ROOT = join(here, "..", "..", "..", "..");
const ENTERPRISE_PAGE = join(
  REPO_ROOT,
  "docs",
  "src",
  "content",
  "docs",
  "enterprise.md",
);

const REQUIRED_SECTION_HEADERS = [
  "## Auth",
  "## Models / BYOK",
  "## Deployment",
  "## Data",
  "## Audit",
  "## SLA",
  "## Compliance",
] as const;

describe("docs/enterprise.md (#379) — enterprise readiness checklist", () => {
  it("exists at the canonical path", () => {
    expect(existsSync(ENTERPRISE_PAGE)).toBe(true);
  });

  it("has a parseable frontmatter block with title + description", () => {
    const body = readFileSync(ENTERPRISE_PAGE, "utf8");
    expect(body.startsWith("---\n")).toBe(true);
    const closingIdx = body.indexOf("\n---", 4);
    expect(closingIdx).toBeGreaterThan(0);
    const frontmatter = body.slice(4, closingIdx);
    expect(frontmatter).toMatch(/^title:\s*Enterprise readiness/m);
    expect(frontmatter).toMatch(/^description:\s*.+/m);
    // The owner field is required so an internal human owns the freshness of
    // the status badges. Until assigned it must be the placeholder so the
    // pre-merge review catches it.
    expect(frontmatter).toMatch(/^owner:\s*OWNER_TBD\s*$/m);
  });

  it("contains each of the seven required section headers", () => {
    const body = readFileSync(ENTERPRISE_PAGE, "utf8");
    for (const header of REQUIRED_SECTION_HEADERS) {
      expect(
        body.includes(`\n${header}\n`),
        `enterprise.md must contain a "${header}" section header (#379 acceptance criteria)`,
      ).toBe(true);
    }
  });

  it("declares itself the single source of truth for enterprise claims", () => {
    // Belt-and-suspenders against someone silently deleting the SSoT note,
    // which is the whole point of the page existing.
    const body = readFileSync(ENTERPRISE_PAGE, "utf8");
    expect(body).toMatch(/single source of truth/i);
  });

  it("points at enterprise@0sec.ai as the contact channel", () => {
    const body = readFileSync(ENTERPRISE_PAGE, "utf8");
    expect(body).toContain("enterprise@0sec.ai");
  });
});
