/**
 * #777 — "how we hacked X" writeup generator.
 *
 * Covers the two load-bearing behaviours: (1) redaction of secrets + PII before
 * content lands in the draft, and (2) section assembly — frontmatter parsing,
 * heading-alias mapping onto the canonical Summary/PoC/Timeline/Remediation
 * spine, and the embargo gate.
 */

import { describe, it, expect } from "vitest";
import {
  parseDisclosure,
  generateWriteup,
  extractSections,
  sanitizeWriteup,
  redactPii,
  EmbargoedFindingError,
} from "./index.js";

// A representative disclosure file with embedded secrets + PII across the
// reproduction and timeline sections, plus an internal-only "Next step".
const SAMPLE = `---
package: acme-widget
short_name: auth-bypass
vuln_class: prototype-pollution
status: published-cve
severity_estimate: high
cve_id: CVE-2026-99999
date_found: 2026-05-01
date_published: 2026-05-30
---

# acme-widget — auth bypass via prototype pollution

> Status: 2026-05-30. Internal triage staging.

## Summary

A polluted \`Object.prototype\` flips an internal flag and bypasses auth.

## Reproduction

\`\`\`sh
curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' http://t/api
\`\`\`

Operator key AKIAIOSFODNN7EXAMPLE was used during the run.

## Next step

Email the maintainer privately before going public.

## Recommended fix

Use \`Object.create(null)\` for the options clone.

## Timeline

- 2026-05-01 — discovered; emailed alice.smith@example.com and security@acme.io.
- 2026-05-30 — CVE-2026-99999 published.
`;

describe("parseDisclosure", () => {
  it("splits frontmatter from body", () => {
    const { frontmatter, body } = parseDisclosure(SAMPLE);
    expect(frontmatter.package).toBe("acme-widget");
    expect(frontmatter.status).toBe("published-cve");
    expect(frontmatter.cve_id).toBe("CVE-2026-99999");
    expect(body.startsWith("# acme-widget")).toBe(true);
    expect(body).not.toContain("package: acme-widget");
  });

  it("tolerates a file with no frontmatter", () => {
    const { frontmatter, body } = parseDisclosure("# Just a body\n\ntext");
    expect(frontmatter).toEqual({});
    expect(body).toContain("Just a body");
  });
});

describe("redactPii", () => {
  it("masks personal emails but keeps vendor security inboxes", () => {
    const out = redactPii("emailed alice.smith@example.com and security@acme.io");
    expect(out).toContain("<REDACTED-EMAIL>");
    expect(out).not.toContain("alice.smith@example.com");
    expect(out).toContain("security@acme.io");
  });
});

describe("sanitizeWriteup", () => {
  it("strips JWTs, AWS keys, auth headers, and personal emails together", () => {
    const dirty =
      "Authorization: Bearer x\n" +
      "key AKIAIOSFODNN7EXAMPLE\n" +
      "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n" +
      "ping bob@gmail.com";
    const out = sanitizeWriteup(dirty);
    expect(out).toContain("<REDACTED-Authorization>");
    expect(out).toContain("<REDACTED-AWS-KEY>");
    expect(out).toContain("<REDACTED-JWT>");
    expect(out).toContain("<REDACTED-EMAIL>");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).not.toContain("bob@gmail.com");
  });
});

describe("extractSections — alias mapping", () => {
  it("maps disclosure headings onto canonical sections", () => {
    const { body } = parseDisclosure(SAMPLE);
    const s = extractSections(body);
    expect(s.Summary.join("")).toContain("polluted");
    expect(s["How we found it"].join("")).toContain("curl");
    expect(s.Remediation.join("")).toContain("Object.create(null)");
    expect(s.Timeline.join("")).toContain("2026-05-30");
  });

  it("drops internal-only headings like 'Next step'", () => {
    const { body } = parseDisclosure(SAMPLE);
    const s = extractSections(body);
    const all = [...s.Summary, ...s["How we found it"], ...s.Timeline, ...s.Remediation].join("\n");
    expect(all).not.toContain("Email the maintainer privately");
  });
});

describe("generateWriteup — assembly + gate", () => {
  const at = new Date("2026-06-02T00:00:00Z");

  it("emits a sanitised draft for a published finding", () => {
    const w = generateWriteup(parseDisclosure(SAMPLE), { generatedAt: at });
    // Section order + headings.
    expect(w.markdown).toContain("# How we hacked acme-widget");
    expect(w.markdown.indexOf("## Summary")).toBeLessThan(w.markdown.indexOf("## How we found it"));
    expect(w.markdown.indexOf("## How we found it")).toBeLessThan(w.markdown.indexOf("## Timeline"));
    expect(w.markdown.indexOf("## Timeline")).toBeLessThan(w.markdown.indexOf("## Remediation"));
    expect(w.sectionsPresent).toEqual(["Summary", "How we found it", "Timeline", "Remediation"]);
    // Redaction applied in the body. The JWT here lives inside an
    // `Authorization: Bearer ...` curl header, so the header mask redacts the
    // whole value (it never reaches the standalone JWT pass) — assert the raw
    // token is gone rather than the specific placeholder.
    expect(w.markdown).toContain("<REDACTED-Authorization>");
    expect(w.markdown).not.toContain("eyJhbGciOiJIUzI1NiJ9");
    expect(w.markdown).toContain("<REDACTED-AWS-KEY>");
    expect(w.markdown).toContain("<REDACTED-EMAIL>");
    expect(w.markdown).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(w.markdown).not.toContain("alice.smith@example.com");
    // Internal-only content + private channels stay out.
    expect(w.markdown).not.toContain("Email the maintainer privately");
    // Attribution per disclosure/AGENTS.md hard rule #6 (0sec.ai, not pwnkit repo).
    expect(w.markdown).toContain("0sec.ai");
    // Public-safe metadata present.
    expect(w.markdown).toContain("CVE-2026-99999");
    expect(w.embargoed).toBe(false);
    expect(w.filename).toBe("acme-widget-auth-bypass-2026-06-02.md");
  });

  it("refuses an embargoed finding by default", () => {
    const embargoed = SAMPLE.replace("status: published-cve", "status: pending-disclosure");
    expect(() => generateWriteup(parseDisclosure(embargoed))).toThrow(EmbargoedFindingError);
  });

  it("stages an embargoed draft under the override, marked do-not-publish", () => {
    const embargoed = SAMPLE.replace("status: published-cve", "status: pending-disclosure");
    const w = generateWriteup(parseDisclosure(embargoed), { allowEmbargoed: true, generatedAt: at });
    expect(w.embargoed).toBe(true);
    expect(w.markdown).toContain("do not publish");
    expect(w.markdown).toContain("pending-disclosure");
    // Redaction still applies on the override path.
    expect(w.markdown).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });
});
