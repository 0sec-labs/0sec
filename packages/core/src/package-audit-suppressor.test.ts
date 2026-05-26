import { describe, expect, it } from "vitest";
import type { Finding, Severity, AttackCategory } from "@pwnkit/shared";
import { postProcessPackageAuditFindings } from "./package-audit-suppressor.js";

function makeFinding(
  title: string,
  description: string,
  severity: Severity = "high",
  category: AttackCategory = "code-injection",
): Finding {
  return {
    id: title,
    templateId: "audit-agent",
    title,
    description,
    severity,
    category,
    status: "discovered",
    evidence: {
      request: "src/index.js",
      response: description,
      analysis: "Agent finding",
    },
    timestamp: Date.now(),
  };
}

describe("postProcessPackageAuditFindings", () => {
  it("suppresses documented extension-hook findings", () => {
    const findings = [
      makeFinding(
        "AJV code.process callback RCE",
        "AJV lets applications provide code.process for custom code generation, which can run arbitrary logic during standalone compilation.",
      ),
    ];

    expect(postProcessPackageAuditFindings(findings)).toEqual([]);
  });

  it("downgrades caller-controlled regex surfaces to info", () => {
    const findings = [
      makeFinding(
        "Joi object.pattern() ReDoS",
        "The package runs a caller-controlled regex supplied through object.pattern(), so schema authors can attach an expensive pattern.",
        "high",
        "regex-dos",
      ),
    ];

    const out = postProcessPackageAuditFindings(findings);

    expect(out).toHaveLength(1);
    expect(out[0]?.severity).toBe("info");
    expect(out[0]?.triageStatus).toBe("accepted");
    expect(out[0]?.triageNote).toContain("caller-controlled regex surface");
  });

  it("suppresses pure CLI self-DoS findings", () => {
    const findings = [
      makeFinding(
        "Nanoid CLI --size self-DoS",
        "The command-line CLI accepts an oversized --size value, causing local CPU exhaustion and a self-DoS for the caller.",
        "medium",
        "regex-dos",
      ),
    ];

    expect(postProcessPackageAuditFindings(findings)).toEqual([]);
  });

  it("suppresses generic install-hook findings with no suspicious matches", () => {
    const findings = [
      makeFinding(
        "Package executes 1 install-time hook (postinstall)",
        "A package defines a postinstall hook. No suspicious patterns matched in the script content. Manual review still recommended.",
        "medium",
        "supply-chain" as AttackCategory,
      ),
    ];

    expect(postProcessPackageAuditFindings(findings)).toEqual([]);
  });

  it("suppresses esbuild's known binary-bootstrap install hook pattern", () => {
    const findings = [
      makeFinding(
        "Package executes 1 install-time hook (postinstall)",
        "`esbuild` defines install-time scripts that execute on every `npm install`.\n\n" +
          "**Hooks declared:**\n" +
          "- `postinstall` → `node install.js`\n\n" +
          "**Suspicious patterns matched:**\n" +
          "- `install.js` — child_process spawned in install hook\n" +
          "- `install.js` — exec/spawn family in install hook\n" +
          "- `install.js` — outbound HTTP request in install hook\n" +
          "- `install.js` — fetch() in install hook",
        "high",
        "supply-chain" as AttackCategory,
      ),
    ];

    expect(postProcessPackageAuditFindings(findings)).toEqual([]);
  });

  it("keeps likely real package findings intact", () => {
    const findings = [
      makeFinding(
        "Sequelize SQL injection in Sequelize.prototype.set",
        "A crafted attribute path can reach SQL generation and produce attacker-controlled SQL fragments.",
        "critical",
        "sql-injection",
      ),
      makeFinding(
        "node-forge forge.form.serialize prototype pollution",
        "forge.form.serialize writes attacker-controlled keys into object graphs and can reach Object.prototype.",
        "high",
        "prototype-pollution",
      ),
    ];

    const out = postProcessPackageAuditFindings(findings);

    expect(out).toHaveLength(2);
    expect(out[0]?.severity).toBe("critical");
    expect(out[0]?.triageNote).toBeUndefined();
    expect(out[1]?.severity).toBe("high");
    expect(out[1]?.triageNote).toBeUndefined();
  });

  it("keeps object-scoped prototype mutation findings but downgrades severity", () => {
    const findings = [
      makeFinding(
        "Joi object.rename() template destination reaches __proto__ on returned object",
        "A rename template can write __proto__ onto the returned validated object, mutating the result object without polluting Object.prototype globally.",
        "high",
        "prototype-pollution",
      ),
    ];

    const out = postProcessPackageAuditFindings(findings);

    expect(out).toHaveLength(1);
    expect(out[0]?.severity).toBe("medium");
    expect(out[0]?.triageStatus).toBe("accepted");
    expect(out[0]?.triageNote).toContain("object-scoped prototype mutation");
  });
});
