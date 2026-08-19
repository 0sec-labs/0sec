import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  foxguardFindingToKernelVariantFinding,
  runKernelVariantHunt,
} from "./variant-hunt.js";

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-kernel-variant-test-"));
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

function makeSarif(): string {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        results: [
          {
            ruleId: "kernel/dirty-frag-class/skb-inplace-aead-no-cow",
            level: "error",
            message: {
              text: "in-place AEAD decrypt on shared skb frag without skb_cow_data",
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "net/ipv4/esp4.c" },
                  region: { startLine: 512, endLine: 520 },
                },
              },
            ],
          },
        ],
      },
    ],
  });
}

describe("foxguardFindingToKernelVariantFinding", () => {
  it("maps dirty-frag foxguard hits into pwnkit findings with kernel provenance", () => {
    const finding = foxguardFindingToKernelVariantFinding({
      finding: {
        ruleId: "kernel/dirty-frag-class/skb-inplace-aead-no-cow",
        level: "error",
        message: "in-place AEAD decrypt on shared skb frag without skb_cow_data",
        file: "net/ipv4/esp4.c",
        startLine: 512,
      },
      tree: "/linux",
      advisory: "dirty-frag.md",
      rules: "/foxguard/rules/kernel/dirty-frag-class",
    });

    expect(finding.templateId).toContain("kernel-variant-dirty-frag");
    expect(finding.title).toContain("net/ip");
    expect(finding.severity).toBe("high");
    expect(finding.category).toBe("information-disclosure");
    expect(finding.status).toBe("discovered");
    expect(finding.triageStatus).toBe("new");
    expect(finding.fingerprint).toMatch(/^[a-f0-9]{16}$/);
    expect(finding.evidence.analysis).toContain("Variant status: suspect");
  });

  it("treats page-cache write primitive candidates as high severity", () => {
    const finding = foxguardFindingToKernelVariantFinding({
      finding: {
        ruleId: "kernel/page-cache-write/no-ownership-check",
        level: "warning",
        message: "filemap_get_folio page-cache page written via kmap_local_page+memcpy without page_count or copy_highpage ownership/COW proof",
        file: "mm/filemap.c",
        startLine: 1204,
      },
      tree: "/linux",
      advisory: "copy-fail.md",
      rules: "/foxguard/rules/kernel/page-cache-write",
    });

    expect(finding.templateId).toContain("kernel-variant-copy-fail");
    expect(finding.title).toContain("mm");
    expect(finding.severity).toBe("high");
    expect(finding.category).toBe("other");
    expect(finding.evidence.analysis).toContain("Rule: kernel/page-cache-write/no-ownership-check");
    expect(finding.evidence.analysis).toContain("Category: other");
  });
});

describe("runKernelVariantHunt", () => {
  it("uses pre-produced SARIF and returns pwnkit findings", async () => {
    const tree = join(tmpRoot, "linux");
    mkdirSync(tree);
    const sarifPath = join(tmpRoot, "foxguard.sarif");
    writeFileSync(sarifPath, makeSarif(), "utf8");

    const report = await runKernelVariantHunt({
      tree,
      advisory: "https://www.openwall.com/lists/oss-security/2026/05/07/8",
      sarifPath,
    });

    expect(report.tree).toBe(tree);
    expect(report.foxguardFindings).toHaveLength(1);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.evidence.request).toContain("foxguard scan");
    expect(report.warnings.map((w) => w.message)).toContain(
      "Used pre-produced SARIF; foxguard was not invoked in this run.",
    );
  });

  it("invokes foxguard with rule root and tolerates non-zero exit when SARIF exists", async () => {
    const tree = join(tmpRoot, "linux");
    const rules = join(tmpRoot, "rules", "kernel", "dirty-frag-class");
    const foxguard = join(tmpRoot, "foxguard");
    mkdirSync(tree, { recursive: true });
    mkdirSync(rules, { recursive: true });
    writeFileSync(foxguard, "#!/bin/sh\n", "utf8");

    let observedArgs: string[] = [];
    const report = await runKernelVariantHunt({
      tree,
      rules,
      foxguardPath: foxguard,
      runner: async (_file, args) => {
        observedArgs = args;
        const outIndex = args.indexOf("--output");
        expect(outIndex).toBeGreaterThan(0);
        const outPath = args[outIndex + 1]!;
        writeFileSync(outPath, makeSarif(), "utf8");
        throw new Error("foxguard exits non-zero when findings are present");
      },
    });

    expect(observedArgs).toEqual([
      "scan",
      tree,
      "--rules",
      rules,
      "--format",
      "sarif",
      "--output",
      expect.any(String),
    ]);
    expect(report.findings).toHaveLength(1);
    expect(existsSync(foxguard)).toBe(true);
  });

  it("rejects a missing kernel tree before invoking foxguard", async () => {
    await expect(
      runKernelVariantHunt({
        tree: join(tmpRoot, "missing-linux"),
        foxguardPath: join(tmpRoot, "foxguard"),
      }),
    ).rejects.toThrow(/kernel tree not found/);
  });
});
