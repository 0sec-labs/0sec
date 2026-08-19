import { describe, expect, it } from "vitest";
import type { Finding } from "@0sec/shared";
import {
  emitFindingsAsPRs,
  buildBranchName,
  buildPrTitle,
  buildPrBody,
  buildHypothesesMarkdown,
  buildReproReadme,
  isReproduced,
  type GhClient,
  type GitClient,
  type FsClient,
  type EvidenceArtifact,
} from "../pr-emitter.js";

// ── Test doubles ─────────────────────────────────────────────────────────────

interface CallRecord {
  argv: string[];
  cwd?: string;
}

function makeFakeGit(): { client: GitClient; calls: CallRecord[] } {
  const calls: CallRecord[] = [];
  return {
    calls,
    client: {
      async run(args, opts) {
        calls.push({ argv: args, cwd: opts?.cwd });
        return { stdout: "", stderr: "" };
      },
    },
  };
}

function makeFakeGh(opts: {
  authenticated?: boolean;
  prCreateUrl?: string;
} = {}): { client: GhClient; calls: CallRecord[] } {
  const calls: CallRecord[] = [];
  return {
    calls,
    client: {
      async isAuthenticated() {
        return opts.authenticated ?? true;
      },
      async run(args, runOpts) {
        calls.push({ argv: args, cwd: runOpts?.cwd });
        return {
          stdout: opts.prCreateUrl ?? "https://github.com/example/repo/pull/1",
          stderr: "",
        };
      },
    },
  };
}

interface InMemoryFs {
  client: FsClient;
  files: Map<string, string>;
  dirs: Set<string>;
  copies: Array<{ src: string; dest: string }>;
}

function makeFakeFs(seedFiles: Record<string, string> = {}): InMemoryFs {
  const files = new Map(Object.entries(seedFiles));
  const dirs = new Set<string>();
  const copies: InMemoryFs["copies"] = [];
  return {
    files,
    dirs,
    copies,
    client: {
      async mkdir(path) {
        dirs.add(path);
      },
      async writeFile(path, content) {
        files.set(path, content);
      },
      async copyFile(src, dest) {
        if (!files.has(src)) {
          throw new Error(`missing fixture: ${src}`);
        }
        files.set(dest, files.get(src)!);
        copies.push({ src, dest });
      },
      async exists(path) {
        return files.has(path) || dirs.has(path);
      },
    },
  };
}

// ── Finding factory ──────────────────────────────────────────────────────────

interface ReproducedExtras {
  verificationStatus?: "reproduced" | "not_reproduced" | "inconclusive";
  evidenceArtifacts?: EvidenceArtifact[];
}

function mkFinding(
  id: string,
  category: Finding["category"],
  extras: Partial<Finding> & ReproducedExtras = {},
): Finding {
  const { verificationStatus, evidenceArtifacts, ...rest } = extras;
  const base: Finding & Record<string, unknown> = {
    id,
    templateId: "tpl",
    title: `Finding ${id}`,
    description: `Issue at src/file.ts:10`,
    severity: "high",
    category,
    status: "verified",
    evidence: { request: "GET /", response: "200", analysis: "src/file.ts:10" },
    timestamp: 0,
    ...rest,
  };
  if (verificationStatus) {
    (base as Record<string, unknown>).verification_result = { status: verificationStatus };
  }
  if (evidenceArtifacts) {
    (base as Record<string, unknown>).evidence_artifacts = evidenceArtifacts;
  }
  return base;
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("isReproduced", () => {
  it("returns true for verification_result.status === 'reproduced'", () => {
    expect(isReproduced(mkFinding("a", "xss", { verificationStatus: "reproduced" }))).toBe(true);
  });
  it("returns false for any other status", () => {
    expect(isReproduced(mkFinding("a", "xss", { verificationStatus: "not_reproduced" }))).toBe(false);
    expect(isReproduced(mkFinding("a", "xss", { verificationStatus: "inconclusive" }))).toBe(false);
    expect(isReproduced(mkFinding("a", "xss"))).toBe(false);
  });
  it("accepts camelCase variant", () => {
    const f = mkFinding("a", "xss");
    (f as unknown as Record<string, unknown>).verificationResult = { status: "reproduced" };
    expect(isReproduced(f)).toBe(true);
  });
});

describe("buildBranchName", () => {
  it("sanitizes finding id to a safe ref", () => {
    expect(buildBranchName(mkFinding("abc-123", "xss"))).toBe("0sec/finding-abc123");
  });
  it("truncates long ids", () => {
    const f = mkFinding("0123456789abcdefghij", "xss");
    expect(buildBranchName(f)).toBe("0sec/finding-0123456789ab");
  });
});

describe("buildPrTitle / buildPrBody", () => {
  it("title carries severity badge", () => {
    expect(buildPrTitle(mkFinding("a", "xss", { severity: "critical", title: "RCE" }))).toBe("[CRITICAL] RCE");
  });

  it("body includes severity reasoning, repro pointer, finding id", () => {
    const f = mkFinding("fnd-1", "xss", {
      verificationStatus: "reproduced",
      cvssScore: 7.5,
      cvssVector: "CVSS:3.1/AV:N",
    });
    const body = buildPrBody(f, {});
    expect(body).toContain("## Summary");
    expect(body).toContain("## Severity reasoning");
    expect(body).toContain("CVSS:** 7.5 (CVSS:3.1/AV:N)");
    expect(body).toContain(".0sec/findings/fnd1/");
    expect(body).toContain("`reproduced`");
    expect(body).toContain("Finding ID: `fnd-1`");
  });

  it("body links the hypotheses md when provided", () => {
    const body = buildPrBody(mkFinding("a", "xss"), { hypothesesLink: "hypotheses.md" });
    expect(body).toContain("hypotheses.md");
  });
});

describe("buildHypothesesMarkdown", () => {
  it("renders an empty marker when there are none", () => {
    expect(buildHypothesesMarkdown([])).toContain("No unverified findings");
  });
  it("renders each finding with status badge", () => {
    const md = buildHypothesesMarkdown([
      mkFinding("a", "xss", { verificationStatus: "not_reproduced" }),
      mkFinding("b", "ssrf"),
    ]);
    expect(md).toContain("## [HIGH] Finding a");
    expect(md).toContain("**Verification status:** `not_reproduced`");
    expect(md).toContain("**Verification status:** `unknown`");
  });
});

describe("buildReproReadme", () => {
  it("lists artifacts by basename + kind", () => {
    const f = mkFinding("a", "xss", {
      evidenceArtifacts: [
        { path: "/tmp/sanitizer.log", kind: "sanitizer-log" },
        { path: "/abs/screenshot.png", kind: "screenshot", caption: "alert fired" },
      ],
    });
    const md = buildReproReadme(f);
    expect(md).toContain("`sanitizer.log` — sanitizer-log");
    expect(md).toContain("`screenshot.png` — screenshot: alert fired");
  });
});

// ── End-to-end via fakes ─────────────────────────────────────────────────────

describe("emitFindingsAsPRs", () => {
  it("emits one PR per reproduced finding and skips hypotheses", async () => {
    const findings = [
      mkFinding("rep1", "information-disclosure", {
        verificationStatus: "reproduced",
        description: "Hard-coded secret at src/cfg.ts:5",
        evidence: { request: "", response: "", analysis: "src/cfg.ts:5" },
      }),
      mkFinding("rep2", "missing-validation", {
        verificationStatus: "reproduced",
        description: "Missing validation on parameter id at src/h.ts:12",
        evidence: { request: "", response: "", analysis: "src/h.ts:12" },
      }),
      mkFinding("hyp1", "xss", { verificationStatus: "not_reproduced" }),
    ];

    const git = makeFakeGit();
    const gh = makeFakeGh({ authenticated: true });
    const fs = makeFakeFs();
    const logs: string[] = [];

    const report = await emitFindingsAsPRs(findings, {
      repoRoot: "/repo",
      baseBranch: "main",
      outDir: "/out",
      gitClient: git.client,
      ghClient: gh.client,
      fsClient: fs.client,
      log: (l) => logs.push(l),
    });

    expect(report.forcedDryRun).toBe(false);
    expect(report.results.map((r) => r.outcome)).toEqual([
      "pr_created",
      "pr_created",
      "skipped_unreproduced",
    ]);
    expect(report.results[0]!.prUrl).toContain("github.com");

    // gh pr create called exactly twice
    expect(gh.calls.filter((c) => c.argv[0] === "pr").length).toBe(2);
    // each pr-create call carries --base main
    for (const call of gh.calls.filter((c) => c.argv[0] === "pr")) {
      expect(call.argv).toContain("--base");
      expect(call.argv).toContain("main");
      expect(call.argv).toContain("--title");
    }

    // hypotheses.md written
    expect(report.hypothesesMdPath).toBe("/out/hypotheses.md");
    expect(fs.files.get("/out/hypotheses.md")).toContain("Finding hyp1");

    // repro README + suggested patch landed for the secret finding
    expect(fs.files.get("/repo/.0sec/findings/rep1/README.md")).toContain("Finding rep1");
    expect(fs.files.get("/repo/.0sec/findings/rep1/suggested-fix.patch")).toContain("process.env.");

    // missing-validation finding got a guard patch
    expect(fs.files.get("/repo/.0sec/findings/rep2/suggested-fix.patch")).toContain("starter guard");
  });

  it("dry-run prints commands and does not invoke gh", async () => {
    const finding = mkFinding("rep1", "information-disclosure", {
      verificationStatus: "reproduced",
      description: "Secret at src/x.ts:1",
      evidence: { request: "", response: "", analysis: "src/x.ts:1" },
    });
    const git = makeFakeGit();
    const gh = makeFakeGh({ authenticated: true });
    const fs = makeFakeFs();
    const logs: string[] = [];

    const report = await emitFindingsAsPRs([finding], {
      repoRoot: "/repo",
      dryRun: true,
      gitClient: git.client,
      ghClient: gh.client,
      fsClient: fs.client,
      log: (l) => logs.push(l),
    });

    expect(report.results[0]!.outcome).toBe("pr_dry_run");
    expect(report.results[0]!.commands?.some((c) => c.startsWith("gh pr create"))).toBe(true);
    expect(gh.calls.length).toBe(0); // never executed
    expect(git.calls.length).toBe(0); // never executed
    expect(logs.some((l) => l.includes("DRY RUN"))).toBe(true);
  });

  it("falls back to dry-run when gh is unauthenticated", async () => {
    const finding = mkFinding("rep1", "information-disclosure", {
      verificationStatus: "reproduced",
      description: "Secret at src/x.ts:1",
      evidence: { request: "", response: "", analysis: "src/x.ts:1" },
    });
    const git = makeFakeGit();
    const gh = makeFakeGh({ authenticated: false });
    const fs = makeFakeFs();
    const logs: string[] = [];

    const report = await emitFindingsAsPRs([finding], {
      repoRoot: "/repo",
      gitClient: git.client,
      ghClient: gh.client,
      fsClient: fs.client,
      log: (l) => logs.push(l),
    });

    expect(report.forcedDryRun).toBe(true);
    expect(report.results[0]!.outcome).toBe("pr_dry_run");
    expect(gh.calls.length).toBe(0);
    expect(logs.some((l) => l.includes("gh auth status"))).toBe(true);
  });

  it("copies evidence_artifacts into the repro tree", async () => {
    const finding = mkFinding("rep1", "information-disclosure", {
      verificationStatus: "reproduced",
      description: "Secret at src/x.ts:1",
      evidence: { request: "", response: "", analysis: "src/x.ts:1" },
      evidenceArtifacts: [{ path: "/fixtures/sanitizer.log", kind: "sanitizer-log" }],
    });
    const git = makeFakeGit();
    const gh = makeFakeGh({ authenticated: true });
    const fs = makeFakeFs({ "/fixtures/sanitizer.log": "AddressSanitizer: heap-buffer-overflow" });

    await emitFindingsAsPRs([finding], {
      repoRoot: "/repo",
      gitClient: git.client,
      ghClient: gh.client,
      fsClient: fs.client,
    });

    expect(fs.copies).toContainEqual({
      src: "/fixtures/sanitizer.log",
      dest: "/repo/.0sec/findings/rep1/sanitizer.log",
    });
  });

  it("falls back to a .missing.txt stub when an artifact is unreadable", async () => {
    const finding = mkFinding("rep1", "information-disclosure", {
      verificationStatus: "reproduced",
      description: "Secret at src/x.ts:1",
      evidence: { request: "", response: "", analysis: "src/x.ts:1" },
      evidenceArtifacts: [{ path: "/nope/nothing.log", kind: "sanitizer-log" }],
    });
    const git = makeFakeGit();
    const gh = makeFakeGh({ authenticated: true });
    const fs = makeFakeFs(); // empty — copyFile will throw

    await emitFindingsAsPRs([finding], {
      repoRoot: "/repo",
      gitClient: git.client,
      ghClient: gh.client,
      fsClient: fs.client,
    });

    expect(fs.files.get("/repo/.0sec/findings/rep1/nothing.log.missing.txt")).toContain(
      "/nope/nothing.log",
    );
  });

  it("dedupes a duplicate branch from two findings with colliding ids", async () => {
    const f1 = mkFinding("rep1", "information-disclosure", {
      verificationStatus: "reproduced",
      description: "Secret at src/a.ts:1",
      evidence: { request: "", response: "", analysis: "src/a.ts:1" },
    });
    const f2 = mkFinding("rep1", "information-disclosure", {
      verificationStatus: "reproduced",
      description: "Same id, different finding",
      evidence: { request: "", response: "", analysis: "src/b.ts:1" },
    });
    const git = makeFakeGit();
    const gh = makeFakeGh({ authenticated: true });
    const fs = makeFakeFs();

    const report = await emitFindingsAsPRs([f1, f2], {
      repoRoot: "/repo",
      gitClient: git.client,
      ghClient: gh.client,
      fsClient: fs.client,
    });

    expect(report.results.map((r) => r.outcome)).toEqual(["pr_created", "skipped_dedup"]);
  });

  it("issues git branch + commit args in the right shape", async () => {
    const finding = mkFinding("rep1", "information-disclosure", {
      verificationStatus: "reproduced",
      description: "Secret at src/x.ts:1",
      evidence: { request: "", response: "", analysis: "src/x.ts:1" },
    });
    const git = makeFakeGit();
    const gh = makeFakeGh({ authenticated: true });
    const fs = makeFakeFs();

    await emitFindingsAsPRs([finding], {
      repoRoot: "/repo",
      baseBranch: "develop",
      gitClient: git.client,
      ghClient: gh.client,
      fsClient: fs.client,
    });

    // Sequence should be: checkout develop, checkout -b branch, add, commit,
    // add, commit (for the fix-template patch).
    const argvs = git.calls.map((c) => c.argv.join(" "));
    expect(argvs[0]).toBe("checkout develop");
    expect(argvs[1]).toMatch(/^checkout -b 0sec\/finding-rep1$/);
    expect(argvs.some((a) => a.startsWith("commit -m 0sec(information-disclosure)"))).toBe(true);
  });
});
