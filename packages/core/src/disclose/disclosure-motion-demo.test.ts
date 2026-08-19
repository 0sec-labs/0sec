/**
 * Coordinated-disclosure GTM-motion demo harness.
 *
 * This is a DEMO/TEST harness — it exercises the existing `disclose/` module
 * end-to-end to prove the coordinated-disclosure + research-writeup motion
 * produces good DRAFTS, and only drafts. It does NOT modify the product code.
 *
 * Everything here is DRAFT-ONLY and operator-gated. The module is a pure
 * library: no I/O, no network, no auto-send (see the module headers in
 * tracking.ts / evidence-pack.ts / writeup.ts and `disclosure/AGENTS.md`).
 * This harness:
 *   1. Builds a synthetic-but-realistic reproduced-PoC finding (a CodeWall-style
 *      unauthenticated SQL endpoint) with a session token + cookie baked into
 *      the PoC, so we can prove redaction.
 *   2. Drives a `DisclosureRecord` through the full timeline
 *      draft → sent → acknowledged → accepted → cve_assigned → published, and
 *      asserts illegal transitions are rejected.
 *   3. Assembles the vendor-notification draft (`assembleEvidencePack` +
 *      `renderVendorNotificationMarkdown`) and asserts the NOT-SENT banner +
 *      secret redaction.
 *   4. Generates the research writeup (`generateWriteup`): asserts it REFUSES
 *      for an embargoed/unpublished finding, then renders (carrying the DRAFT
 *      banner + PII redaction) once the operator has marked it published.
 *   5. Writes the two sample artifacts into `__demo_artifacts__/` so the
 *      quality can be eyeballed. These are committed sample drafts, not live
 *      disclosure content — they never touch `disclosure/`.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, PocStep, LayerVerdict } from "@0sec/shared";

import {
  createDisclosureRecord,
  transition,
  isPubliclyDisclosed,
  IllegalTransitionError,
  type DisclosureRecord,
} from "./tracking.js";
import {
  assembleEvidencePack,
  renderVendorNotificationMarkdown,
} from "./evidence-pack.js";
import {
  parseDisclosure,
  generateWriteup,
  EmbargoedFindingError,
} from "./writeup.js";

// ── Demo output path (committed, for human eyeballing) ──────────────────────
const DEMO_DIR = join(
  fileURLToPath(new URL(".", import.meta.url)),
  "__demo_artifacts__",
);

// ── Secrets baked into the synthetic PoC, to prove redaction ────────────────
// A long fake JWT (≥80 chars so the JWT sweep fires) and a session cookie.
const FAKE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gT3BlcmF0b3IiLCJpYXQiOjE1MTYyMzkwMjJ9." +
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const FAKE_COOKIE = "session=abc123-operator-session-do-not-leak; csrftoken=zzz";

/**
 * Synthetic CodeWall-style finding: an unauthenticated SQL endpoint with a
 * reproduced PoC. Carries a reproducing layer verdict so
 * `evidenceKindForFinding` classifies it `reproduced-poc` (the safe-to-notify
 * gate). The PoC + evidence embed an operator session token and cookie on
 * purpose, so the redaction guarantee is testable.
 */
function reproducingLayerVerdict(): LayerVerdict {
  return {
    layer: "pov_gate",
    verdict: "pass",
    reason: "PoC reproduced in isolated sandbox — dumped users table",
    durationMs: 1820,
    costUsd: 0,
  };
}

function pocSteps(): PocStep[] {
  return [
    {
      id: "setup-1",
      kind: "setup",
      summary: "Stand up the CodeWall demo target",
      action: { type: "shell", cmd: "docker compose -f codewall/docker-compose.yml up -d" },
    },
    {
      id: "exploit-1",
      kind: "exploit",
      summary: "Inject a boolean-based SQL payload into the unauthenticated /api/reports filter",
      action: {
        type: "http",
        method: "GET",
        url: "https://demo.codewall.example/api/reports?org=1%27%20OR%20%271%27%3D%271",
        // These header values MUST be redacted in every emitted draft.
        headers: {
          Authorization: `Bearer ${FAKE_JWT}`,
          Cookie: FAKE_COOKIE,
          "X-Api-Key": "AKIAIOSFODNN7EXAMPLE",
        },
      },
      expect: { type: "body-contains", text: '"users"' },
    },
    {
      id: "verify-1",
      kind: "verify",
      summary: "Confirm the response leaks rows from a table the org should not see",
      action: { type: "note", text: "Response returns rows for every org, not just org=1 — confirms unauthenticated cross-tenant SQLi." },
    },
  ];
}

function codewallFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-codewall-sqli-001",
    templateId: "sql-injection-template",
    title: "Unauthenticated SQL injection in CodeWall /api/reports org filter",
    description:
      "The `/api/reports` endpoint interpolates the `org` query parameter " +
      "directly into a SQL WHERE clause with no authentication and no " +
      "parameterisation. An unauthenticated attacker can read arbitrary rows " +
      "across all tenants (cross-tenant data exposure) and enumerate the schema.",
    severity: "critical",
    category: "sql-injection",
    status: "verified",
    evidence: {
      request:
        "GET /api/reports?org=1' OR '1'='1 HTTP/1.1\n" +
        "Host: demo.codewall.example\n" +
        `Authorization: Bearer ${FAKE_JWT}\n` +
        `Cookie: ${FAKE_COOKIE}`,
      response:
        'HTTP/1.1 200 OK\nContent-Type: application/json\n\n' +
        '{"rows":[{"org":1,"user":"alice"},{"org":2,"user":"bob"}],"table":"users"}',
      analysis:
        "Boolean-based SQLi confirmed: `org=1' OR '1'='1` returns rows from " +
        "every org. The query is built by string concatenation in " +
        "reports.controller.ts.",
    },
    pocSteps: pocSteps(),
    layerVerdicts: [reproducingLayerVerdict()],
    remediation: {
      summary: "Use parameterised queries and require authentication on /api/reports.",
      steps: [
        "Replace string concatenation with a parameterised query / prepared statement.",
        "Require an authenticated, org-scoped session before serving /api/reports.",
        "Add an org-scoping predicate so a session can only read its own org's rows.",
      ],
      references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    timestamp: 1735689600,
    ...overrides,
  };
}

// A disclosure markdown file as it would live in `disclosure/` once the finding
// is being coordinated. The writeup generator reads this shape (frontmatter +
// body). The frontmatter `status` uses the disclosure-file vocabulary
// (published-cve / patched-no-cve / wontfix / maintainer-rejected), which is
// SEPARATE from the tracking.ts status machine — the operator marking the
// tracking record `published` is the signal to flip this file's status to
// `published-cve`. The Timeline embeds a personal maintainer email to prove
// the PII sweep.
function disclosureFile(status: string): string {
  return `---
package: codewall
short_name: api-reports-sqli
vuln_class: sql-injection
status: ${status}
severity_estimate: critical
cve_id: ${status === "published-cve" ? "CVE-2026-12345" : "null"}
ghsa_id: null
date_found: 2026-06-10
date_published: ${status === "published-cve" ? "2026-06-17" : "null"}
---

# Unauthenticated SQL injection in CodeWall /api/reports

> Status: ${status}.

## Summary

The CodeWall \`/api/reports\` endpoint concatenates the \`org\` query
parameter into a SQL WHERE clause with no authentication. An unauthenticated
attacker reads arbitrary rows across every tenant.

## Reproduction

Send \`GET /api/reports?org=1' OR '1'='1\`. The response returns rows for
every org, not just the requested one.

\`\`\`http
GET /api/reports?org=1' OR '1'='1 HTTP/1.1
Authorization: Bearer ${FAKE_JWT}
Cookie: ${FAKE_COOKIE}
\`\`\`

## Timeline

- 2026-06-10 — Reported to security@codewall.example.
- 2026-06-12 — Maintainer (jane.doe@personal-mail.example) acknowledged.
- 2026-06-17 — Fix shipped; CVE-2026-12345 assigned; advisory published.

## Recommended fix

Use parameterised queries and require an authenticated, org-scoped session.

## Next step

Internal: chase the bounty payout. (This heading should NOT leak into the writeup.)
`;
}

describe("coordinated-disclosure GTM motion (demo harness)", () => {
  beforeAll(() => {
    mkdirSync(DEMO_DIR, { recursive: true });
  });

  it("drives the full disclosure timeline and validates transitions", () => {
    const finding = codewallFinding();
    const t0 = "2026-06-10T09:00:00.000Z";

    // Open the record (draft). Records intent only — sends nothing.
    let rec: DisclosureRecord = createDisclosureRecord(finding.id, {
      actor: "doruk",
      at: t0,
      message: "Confirmed reproduced-poc SQLi; opening coordinated disclosure.",
    });
    expect(rec.status).toBe("draft");
    expect(rec.timeline).toHaveLength(1);
    expect(rec.timeline[0].fromStatus).toBeNull();

    // Illegal jump: draft → published must be refused.
    expect(() => transition(rec, { to: "published" })).toThrow(IllegalTransitionError);
    // Embargo gate: a draft record is NOT publicly disclosed.
    expect(isPubliclyDisclosed(rec)).toBe(false);

    // Walk the legal forward path.
    rec = transition(rec, {
      to: "sent",
      actor: "doruk",
      at: "2026-06-10T10:00:00.000Z",
      disclosedTo: "security@codewall.example",
      message: "First-contact email sent by operator.",
    });
    expect(rec.status).toBe("sent");
    expect(rec.disclosedTo).toBe("security@codewall.example");
    expect(rec.disclosedAt).toBe("2026-06-10T10:00:00.000Z");

    rec = transition(rec, { to: "acknowledged", at: "2026-06-12T08:00:00.000Z" });
    rec = transition(rec, { to: "accepted", at: "2026-06-13T08:00:00.000Z" });
    expect(isPubliclyDisclosed(rec)).toBe(false); // accepted is still embargoed

    rec = transition(rec, {
      to: "cve_assigned",
      at: "2026-06-15T08:00:00.000Z",
      cveId: "CVE-2026-12345",
    });
    expect(rec.cveId).toBe("CVE-2026-12345");
    // cve_assigned does NOT lift the writeup embargo (CVE can be reserved pre-publish).
    expect(isPubliclyDisclosed(rec)).toBe(false);

    rec = transition(rec, { to: "published", at: "2026-06-17T08:00:00.000Z" });
    expect(rec.status).toBe("published");
    expect(isPubliclyDisclosed(rec)).toBe(true);

    // Terminal: no further transitions.
    expect(() => transition(rec, { to: "withdrawn" })).toThrow(IllegalTransitionError);

    // Append-only timeline captured every step in order.
    expect(rec.timeline.map((e) => e.toStatus)).toEqual([
      "draft", "sent", "acknowledged", "accepted", "cve_assigned", "published",
    ]);
  });

  it("assembles a redacted vendor-notification draft carrying the NOT-SENT banner", () => {
    const finding = codewallFinding();
    const draft = assembleEvidencePack(finding, {
      target: "codewall",
      affectedRef: "v3.4.0",
    });

    expect(draft.reproduced).toBe(true);

    const md = renderVendorNotificationMarkdown(draft);

    // NOT-SENT / DRAFT banner is mandatory and load-bearing.
    expect(md).toContain("DRAFT — NOT SENT.");
    expect(md).toContain("Nothing here is transmitted to a vendor by 0sec.");

    // Redaction: no secret survives into the draft.
    expect(md).not.toContain(FAKE_JWT);
    expect(md).not.toContain("abc123-operator-session-do-not-leak");
    expect(md).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(md).toContain("<REDACTED-Authorization>");
    expect(md).toContain("<REDACTED-Cookie>");

    // Structure: the what/where/impact/repro/remediation spine is present.
    expect(md).toContain("## What");
    expect(md).toContain("## Where");
    expect(md).toContain("## Impact");
    expect(md).toContain("## Reproduction");
    expect(md).toContain("## Suggested remediation");

    writeFileSync(join(DEMO_DIR, "vendor-notification-draft.md"), md, "utf8");
  });

  it("refuses to render the research writeup while the finding is embargoed", () => {
    // While coordination is in flight, the disclosure file is still embargoed
    // (status not in PUBLISHABLE_STATUSES). The writeup generator must refuse.
    const parsed = parseDisclosure(disclosureFile("reported"));
    expect(() => generateWriteup(parsed)).toThrow(EmbargoedFindingError);

    // The embargo override still produces a draft, but flags it as not-public.
    const staged = generateWriteup(parsed, { allowEmbargoed: true });
    expect(staged.embargoed).toBe(true);
    expect(staged.markdown).toContain("not yet in a public/terminal status");
  });

  it("renders a sanitised, DRAFT-banner research writeup once published", () => {
    // Operator has driven the tracking record to `published`, so the
    // disclosure file's status is flipped to `published-cve` — now cleared.
    const parsed = parseDisclosure(disclosureFile("published-cve"));
    const writeup = generateWriteup(parsed, {
      generatedAt: new Date("2026-06-17T12:00:00.000Z"),
    });

    expect(writeup.embargoed).toBe(false);

    // DRAFT banner present, embargo reminder present.
    expect(writeup.markdown).toContain("DRAFT — sanitised writeup");
    expect(writeup.markdown).toContain("disclosure/AGENTS.md");

    // Secret + PII redaction.
    expect(writeup.markdown).not.toContain(FAKE_JWT);
    expect(writeup.markdown).not.toContain("abc123-operator-session-do-not-leak");
    expect(writeup.markdown).not.toContain("jane.doe@personal-mail.example");
    expect(writeup.markdown).toContain("<REDACTED-EMAIL>");
    // Public vendor security inbox is intentionally preserved.
    expect(writeup.markdown).toContain("security@codewall.example");

    // Internal-only heading must NOT leak into the public writeup.
    expect(writeup.markdown).not.toContain("chase the bounty payout");
    expect(writeup.markdown).not.toContain("Next step");

    // Canonical narrative sections present.
    expect(writeup.sectionsPresent).toContain("Summary");
    expect(writeup.sectionsPresent).toContain("How we found it");
    expect(writeup.sectionsPresent).toContain("Timeline");
    expect(writeup.sectionsPresent).toContain("Remediation");

    writeFileSync(join(DEMO_DIR, writeup.filename), writeup.markdown, "utf8");
    // Stable copy under a fixed name so the demo path is predictable to eyeball.
    writeFileSync(join(DEMO_DIR, "research-writeup-draft.md"), writeup.markdown, "utf8");
  });

  it("refuses to assemble a vendor draft for an unreproduced finding (CoC trip-wire)", () => {
    // Strip the reproducing layer verdict → evidenceKind becomes source-only.
    const unreproduced = codewallFinding({ layerVerdicts: [] });
    expect(() => assembleEvidencePack(unreproduced, { target: "codewall" })).toThrow(
      /no reproduced PoC/i,
    );
    // The override stages an internal draft, flagged not-reproduced.
    const draft = assembleEvidencePack(unreproduced, {
      target: "codewall",
      allowUnreproduced: true,
    });
    expect(draft.reproduced).toBe(false);
    const md = renderVendorNotificationMarkdown(draft);
    expect(md).toContain("did **not** reproduce");
  });
});
