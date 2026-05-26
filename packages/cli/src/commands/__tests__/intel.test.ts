import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

const searchAdvisoriesMock = vi.fn();
const lookupCveMock = vi.fn();
const searchSimilarMock = vi.fn();
const buildIntelDossierMock = vi.fn();
const searchTargetHistoryMock = vi.fn();

vi.mock("@pwnkit/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pwnkit/core")>();
  return {
    ...actual,
    searchAdvisories: searchAdvisoriesMock,
    lookupCve: lookupCveMock,
    searchSimilar: searchSimilarMock,
    buildIntelDossier: buildIntelDossierMock,
    searchTargetHistory: searchTargetHistoryMock,
  };
});

const { registerIntelCommand } = await import("../intel.js");

function captureIO() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const stdoutSpy = vi.spyOn(console, "log").mockImplementation((...args) => {
    stdout.push(args.map(String).join(" "));
  });
  const stderrSpy = vi.spyOn(console, "error").mockImplementation((...args) => {
    stderr.push(args.map(String).join(" "));
  });
  return {
    stdout,
    stderr,
    restore: () => {
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
    },
  };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerIntelCommand(program);
  await program.parseAsync(["node", "pwnkit-cli", ...argv]);
}

describe("pwnkit intel", () => {
  let io: ReturnType<typeof captureIO>;

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.clearAllMocks();
    io.restore();
  });

  it("search passes package-version and ecosystem to core", async () => {
    searchAdvisoriesMock.mockResolvedValue({ advisories: [], graph: { nodes: [], edges: [] } });
    await runCli(["intel", "search", "formidable", "--ecosystem", "npm", "--package-version", "3.5.2", "--json"]);
    expect(searchAdvisoriesMock).toHaveBeenCalledWith({
      ecosystem: "npm",
      packageName: "formidable",
      version: "3.5.2",
      enrich: true,
      offline: undefined,
      cacheDir: undefined,
    });
    expect(io.stdout.join("\n")).toBe("[]");
  });

  it("dossier forwards package context and renders JSON", async () => {
    buildIntelDossierMock.mockResolvedValue({
      package: { ecosystem: "npm", name: "zipper" },
      version: "1.0.0",
      generatedAt: "2026-05-25T00:00:00.000Z",
      summary: {
        advisoryCount: 0,
        variantLeadCount: 0,
        playbookCount: 1,
        criticalCount: 0,
        highCount: 0,
        kevCount: 0,
        cweCount: 0,
        topSeverity: "info",
        riskScore: 0,
        riskLevel: "none",
        recommendedFocus: [],
      },
      advisories: [],
      variantLeads: [],
      playbooks: [
        {
          id: "playbook:path-traversal",
          bugClass: "Path traversal / archive extraction escape",
          cwes: ["CWE-22"],
          priorVulnerabilityIds: ["CVE-2024-0001"],
          relevance: "Prior traversal shape",
          steps: [],
        },
      ],
      auditGraph: { entrypointNodeIds: [], nodes: [], edges: [] },
      graph: { nodes: [], edges: [] },
      provenance: { sources: [] },
    });

    await runCli([
      "intel",
      "dossier",
      "zipper",
      "--ecosystem",
      "npm",
      "--package-version",
      "1.0.0",
      "--keywords",
      "zip slip,path traversal",
      "--similar-limit",
      "7",
      "--json",
    ]);

    expect(buildIntelDossierMock).toHaveBeenCalledWith({
      ecosystem: "npm",
      packageName: "zipper",
      version: "1.0.0",
      keywords: ["zip slip", "path traversal"],
      similarLimit: 7,
      includeSimilar: true,
      offline: undefined,
      cacheDir: undefined,
    });
    expect(JSON.parse(io.stdout.join("\n")).package.name).toBe("zipper");
  });

  it("search supports --ver alias and --no-enrich", async () => {
    searchAdvisoriesMock.mockResolvedValue({ advisories: [], graph: { nodes: [], edges: [] } });
    await runCli(["intel", "search", "formidable", "--ver", "3.5.2", "--no-enrich", "--json"]);
    expect(searchAdvisoriesMock).toHaveBeenCalledWith({
      ecosystem: "npm",
      packageName: "formidable",
      version: "3.5.2",
      enrich: false,
      offline: undefined,
      cacheDir: undefined,
    });
  });

  it("cve renders lookup result as JSON", async () => {
    lookupCveMock.mockResolvedValue({
      id: "CVE-2024-0001",
      aliases: ["CVE-2024-0001"],
      source: "nvd",
      sources: ["nvd"],
      affectedRanges: [],
      fixedVersions: [],
      severity: "high",
      cwes: ["CWE-22"],
      references: [],
      fetchedAt: "2024-01-01T00:00:00.000Z",
    });
    await runCli(["intel", "cve", "CVE-2024-0001", "--json"]);
    expect(lookupCveMock).toHaveBeenCalledWith({
      cveId: "CVE-2024-0001",
      offline: undefined,
      cacheDir: undefined,
    });
    expect(JSON.parse(io.stdout.join("\n")).id).toBe("CVE-2024-0001");
  });

  it("similar splits keyword CSV", async () => {
    searchSimilarMock.mockResolvedValue({ advisories: [], graph: { nodes: [], edges: [] } });
    await runCli(["intel", "similar", "--cwe", "CWE-22", "--keywords", "zip slip,path traversal", "--limit", "5"]);
    expect(searchSimilarMock).toHaveBeenCalledWith({
      cwe: "CWE-22",
      ecosystem: undefined,
      keywords: ["zip slip", "path traversal"],
      limit: 5,
      offline: undefined,
      cacheDir: undefined,
    });
  });

  it("target-history forwards target hints and renders JSON", async () => {
    searchTargetHistoryMock.mockResolvedValue({
      target: {
        target: undefined,
        repository: "org/zipper",
        ecosystem: "npm",
        packageName: "zipper",
        product: "zipper",
        vendor: undefined,
        keywords: ["archive extraction"],
      },
      generatedAt: "2026-05-25T00:00:00.000Z",
      summary: {
        advisoryCount: 1,
        playbookCount: 1,
        criticalCount: 0,
        highCount: 1,
        kevCount: 0,
        cweCount: 1,
        topSeverity: "high",
        matchedHints: ["org/zipper", "zipper"],
      },
      advisories: [],
      playbooks: [],
      auditGraph: { entrypointNodeIds: [], nodes: [], edges: [] },
      graph: { nodes: [], edges: [] },
      provenance: { sources: ["nvd"] },
    });

    await runCli([
      "intel",
      "target-history",
      "--repository",
      "org/zipper",
      "--ecosystem",
      "npm",
      "--package",
      "zipper",
      "--product",
      "zipper",
      "--keywords",
      "archive extraction",
      "--limit",
      "5",
      "--json",
    ]);

    expect(searchTargetHistoryMock).toHaveBeenCalledWith({
      target: undefined,
      repoPath: undefined,
      repository: "org/zipper",
      ecosystem: "npm",
      packageName: "zipper",
      product: "zipper",
      vendor: undefined,
      keywords: ["archive extraction"],
      limit: 5,
      offline: undefined,
      cacheDir: undefined,
    });
    expect(JSON.parse(io.stdout.join("\n")).summary.advisoryCount).toBe(1);
  });

  it("target-history accepts repo-path inference", async () => {
    searchTargetHistoryMock.mockResolvedValue({
      target: {
        target: undefined,
        repoPath: "/tmp/repo",
        repository: "org/zipper",
        ecosystem: "npm",
        packageName: "@org/zipper",
        product: "zipper",
        vendor: "org",
        keywords: [],
      },
      generatedAt: "2026-05-25T00:00:00.000Z",
      summary: {
        advisoryCount: 0,
        playbookCount: 0,
        criticalCount: 0,
        highCount: 0,
        kevCount: 0,
        cweCount: 0,
        topSeverity: "info",
        matchedHints: ["org/zipper", "zipper"],
      },
      advisories: [],
      playbooks: [],
      auditGraph: { entrypointNodeIds: [], nodes: [], edges: [] },
      graph: { nodes: [], edges: [] },
      provenance: { sources: [] },
    });

    await runCli(["intel", "target-history", "--repo-path", "/tmp/repo", "--json"]);

    expect(searchTargetHistoryMock).toHaveBeenCalledWith({
      target: undefined,
      repoPath: "/tmp/repo",
      repository: undefined,
      ecosystem: undefined,
      packageName: undefined,
      product: undefined,
      vendor: undefined,
      keywords: undefined,
      limit: 20,
      offline: undefined,
      cacheDir: undefined,
    });
  });

  it("similar caps limit at 50 and rejects invalid limits", async () => {
    searchSimilarMock.mockResolvedValue({ advisories: [], graph: { nodes: [], edges: [] } });
    await runCli(["intel", "similar", "--keywords", "zip slip", "--limit", "999"]);
    expect(searchSimilarMock).toHaveBeenCalledWith({
      cwe: undefined,
      ecosystem: undefined,
      keywords: ["zip slip"],
      limit: 50,
      offline: undefined,
      cacheDir: undefined,
    });

    await runCli(["intel", "similar", "--keywords", "zip slip", "--limit", "0"]);
    expect(process.exitCode).toBe(1);
  });
});
