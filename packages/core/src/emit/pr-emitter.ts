// PR-shaped finding output (pwnkit#377).
//
// `emitFindingsAsPRs` turns reproduced findings into one GitHub PR each,
// containing:
//   - A minimal repro under `.pwnkit/findings/<id>/` (evidence + README)
//   - An optional second commit applying a starter fix-template patch
//   - A PR body assembled from finding metadata
//
// Non-reproduced findings (hypotheses) are collected into a single
// `hypotheses.md` rolled-up report instead — emitting separate PRs for
// unverified findings is exactly the "AI-generated low-quality" trigger
// H1's CoC penalises, so we hard-gate it.
//
// All `git` and `gh` calls go through injectable `GitClient` / `GhClient`
// interfaces so unit tests can assert on argv without touching disk.

import type { Finding } from "@pwnkit/shared";
import {
  FixTemplateRegistry,
  createDefaultFixTemplateRegistry,
  renderUnifiedDiff,
  type UnifiedDiff,
} from "./fix-templates.js";

// ─── Injectable interfaces ───────────────────────────────────────────────────

/**
 * Minimal `git` interface the emitter needs. Only the operations we use here
 * are declared — keeping the surface small means a test fake can implement
 * the whole thing in ~20 lines.
 */
export interface GitClient {
  /** Run a git command with the given args. Throws on non-zero exit. */
  run(args: string[], opts?: { cwd?: string }): Promise<{ stdout: string; stderr: string }>;
}

/** Minimal `gh` interface the emitter needs. */
export interface GhClient {
  /** Returns true if `gh auth status` exits 0 — i.e. there's a usable token. */
  isAuthenticated(): Promise<boolean>;
  /** Run a `gh` command with the given args. Throws on non-zero exit. */
  run(args: string[], opts?: { cwd?: string }): Promise<{ stdout: string; stderr: string }>;
}

/** Filesystem operations the emitter uses. Default impl wraps node:fs. */
export interface FsClient {
  mkdir(path: string, opts?: { recursive?: boolean }): Promise<void>;
  writeFile(path: string, content: string): Promise<void>;
  copyFile(src: string, dest: string): Promise<void>;
  exists(path: string): Promise<boolean>;
}

// ─── Public types ────────────────────────────────────────────────────────────

export interface EmitFindingsAsPRsOptions {
  /** Absolute path to the target repo. PRs are opened against this repo. */
  repoRoot: string;
  /** Base branch to fork PR branches from. Defaults to "main". */
  baseBranch?: string;
  /**
   * When true, no `git` or `gh` mutating commands run — the emitter only
   * prints what it WOULD run to stdout (or returns it in the result). Used
   * automatically when `gh auth status` fails.
   */
  dryRun?: boolean;
  /** Registry of fix templates. Defaults to the three #377 starters. */
  fixTemplateRegistry?: FixTemplateRegistry;
  /** Output directory for the rolled-up hypotheses.md. */
  outDir?: string;
  /** Injected git client. Default: node:child_process. */
  gitClient?: GitClient;
  /** Injected gh client. Default: node:child_process. */
  ghClient?: GhClient;
  /** Injected fs client. Default: node:fs/promises. */
  fsClient?: FsClient;
  /** Hook for stdout — tests assert on captured lines. Defaults to console.log. */
  log?: (line: string) => void;
}

export type PrEmitOutcome =
  | "pr_created"
  | "pr_dry_run"
  | "skipped_unreproduced"
  | "skipped_no_anchor"
  | "skipped_dedup";

export interface PrEmitResult {
  finding: Finding;
  outcome: PrEmitOutcome;
  /** Branch name created (or that would have been created in --dry-run). */
  branch: string;
  /** PR URL when actually opened. */
  prUrl?: string;
  /** Commands the dry-run path would have executed. */
  commands?: string[];
  /** The starter patch we applied, if any. */
  fixDiff?: UnifiedDiff;
}

export interface EmitFindingsAsPRsReport {
  results: PrEmitResult[];
  /** Path of the rolled-up hypotheses.md, when written. */
  hypothesesMdPath?: string;
  /** True when emitter dropped to dry-run because `gh` was unauthenticated. */
  forcedDryRun: boolean;
}

// ─── Finding helpers (the verification_result and evidence_artifacts fields
// from #193/#376 land on findings as additive properties; we duck-type to
// avoid a schema change) ──────────────────────────────────────────────────────

/** Optional, schema-additive verification result tag. */
interface MaybeVerificationResult {
  verification_result?: { status?: string };
  verificationResult?: { status?: string };
}

/** Optional, schema-additive evidence-artifact list. */
interface MaybeEvidenceArtifacts {
  evidence_artifacts?: EvidenceArtifact[];
  evidenceArtifacts?: EvidenceArtifact[];
}

export interface EvidenceArtifact {
  /** Repo-relative or absolute source path of the artifact. */
  path: string;
  /** Logical label, e.g. "sanitizer-log", "screenshot", "test-fixture". */
  kind: string;
  /** Optional short caption. */
  caption?: string;
}

/**
 * True iff the finding is "reproduced" per the #193 verification schema.
 * Defensive: we accept either snake_case or camelCase since the schema is
 * additive and some producers will land it either way.
 */
export function isReproduced(finding: Finding): boolean {
  const v = (finding as unknown as MaybeVerificationResult);
  const status =
    v.verification_result?.status ??
    v.verificationResult?.status ??
    null;
  return status === "reproduced";
}

function evidenceArtifacts(finding: Finding): EvidenceArtifact[] {
  const v = finding as unknown as MaybeEvidenceArtifacts;
  return v.evidence_artifacts ?? v.evidenceArtifacts ?? [];
}

// ─── Default node-backed clients ─────────────────────────────────────────────

function defaultGitClient(): GitClient {
  return {
    async run(args, opts) {
      const { spawn } = await import("node:child_process");
      return new Promise((resolveProm, rejectProm) => {
        const child = spawn("git", args, { cwd: opts?.cwd });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (d) => (stdout += d.toString()));
        child.stderr?.on("data", (d) => (stderr += d.toString()));
        child.on("close", (code) => {
          if (code === 0) resolveProm({ stdout, stderr });
          else rejectProm(new Error(`git ${args.join(" ")} exited ${code}: ${stderr}`));
        });
        child.on("error", rejectProm);
      });
    },
  };
}

function defaultGhClient(): GhClient {
  return {
    async isAuthenticated() {
      const { spawn } = await import("node:child_process");
      return new Promise((resolveProm) => {
        const child = spawn("gh", ["auth", "status"], { stdio: "ignore" });
        child.on("close", (code) => resolveProm(code === 0));
        child.on("error", () => resolveProm(false));
      });
    },
    async run(args, opts) {
      const { spawn } = await import("node:child_process");
      return new Promise((resolveProm, rejectProm) => {
        const child = spawn("gh", args, { cwd: opts?.cwd });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (d) => (stdout += d.toString()));
        child.stderr?.on("data", (d) => (stderr += d.toString()));
        child.on("close", (code) => {
          if (code === 0) resolveProm({ stdout, stderr });
          else rejectProm(new Error(`gh ${args.join(" ")} exited ${code}: ${stderr}`));
        });
        child.on("error", rejectProm);
      });
    },
  };
}

function defaultFsClient(): FsClient {
  return {
    async mkdir(path, opts) {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(path, { recursive: opts?.recursive ?? true });
    },
    async writeFile(path, content) {
      const { writeFile } = await import("node:fs/promises");
      await writeFile(path, content, "utf-8");
    },
    async copyFile(src, dest) {
      const { copyFile } = await import("node:fs/promises");
      await copyFile(src, dest);
    },
    async exists(path) {
      const { access } = await import("node:fs/promises");
      try {
        await access(path);
        return true;
      } catch {
        return false;
      }
    },
  };
}

// ─── Body assembly ───────────────────────────────────────────────────────────

function shortFindingId(finding: Finding): string {
  // Strip non-alphanumeric and take first 12 chars. Branch names need to be
  // safe for git refs (no `@`, `~`, `..`, etc.).
  const cleaned = finding.id.replace(/[^a-zA-Z0-9]/g, "").slice(0, 12);
  return cleaned || "finding";
}

export function buildBranchName(finding: Finding): string {
  return `pwnkit/finding-${shortFindingId(finding)}`;
}

export function buildPrTitle(finding: Finding): string {
  const sev = finding.severity.toUpperCase();
  return `[${sev}] ${finding.title}`;
}

export function buildPrBody(finding: Finding, opts: { fixApplied?: UnifiedDiff; hypothesesLink?: string }): string {
  const lines: string[] = [];

  lines.push(`## Summary`);
  lines.push(finding.description);
  lines.push("");

  lines.push(`## Severity reasoning`);
  lines.push(`- **Severity:** ${finding.severity}`);
  lines.push(`- **Category:** ${finding.category}`);
  if (finding.cvssScore !== undefined) {
    lines.push(`- **CVSS:** ${finding.cvssScore}${finding.cvssVector ? ` (${finding.cvssVector})` : ""}`);
  }
  if (finding.confidence !== undefined) {
    lines.push(`- **Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
  }
  lines.push("");

  lines.push(`## Reproduction`);
  lines.push(
    `The full repro lives under \`.pwnkit/findings/${shortFindingId(finding)}/\` on this branch.`,
  );
  lines.push("");
  if (finding.pocSteps && finding.pocSteps.length > 0) {
    lines.push(`### Steps`);
    for (const [idx, step] of finding.pocSteps.entries()) {
      lines.push(`${idx + 1}. **${step.kind}** — ${step.summary}`);
    }
    lines.push("");
  } else if (finding.evidence?.request) {
    lines.push("```");
    lines.push(finding.evidence.request);
    lines.push("```");
    lines.push("");
  }

  lines.push(`## Verification`);
  const vrStatus =
    ((finding as unknown as MaybeVerificationResult).verification_result?.status ??
      (finding as unknown as MaybeVerificationResult).verificationResult?.status ??
      "unknown");
  lines.push(`- **Status:** \`${vrStatus}\` (per pwnkit#193)`);
  if (finding.evidence?.analysis) {
    lines.push("");
    lines.push(`> ${finding.evidence.analysis.split("\n").slice(0, 4).join("\n> ")}`);
  }
  lines.push("");

  if (opts.fixApplied) {
    lines.push(`## Suggested patch`);
    lines.push(`${opts.fixApplied.summary}.`);
    lines.push("");
    lines.push(
      `**This is a starter patch.** Review it carefully — the template is`,
      ` deliberately conservative and may need adaptation to project style.`,
    );
    lines.push("");
  }

  if (opts.hypothesesLink) {
    lines.push(`## Other findings`);
    lines.push(
      `Unreproduced hypotheses from this scan are collected in [\`${opts.hypothesesLink}\`](./${opts.hypothesesLink}).`,
    );
    lines.push("");
  }

  lines.push(`---`);
  lines.push(`*Emitted by [pwnkit](https://github.com/0sec-labs/0sec) \`--emit pr\` | Finding ID: \`${finding.id}\`*`);

  return lines.join("\n");
}

export function buildReproReadme(finding: Finding): string {
  const lines: string[] = [];
  lines.push(`# Repro: ${finding.title}`);
  lines.push("");
  lines.push(`- **Finding ID:** \`${finding.id}\``);
  lines.push(`- **Category:** ${finding.category}`);
  lines.push(`- **Severity:** ${finding.severity}`);
  lines.push("");
  lines.push(`## Description`);
  lines.push(finding.description);
  lines.push("");
  if (finding.pocSteps && finding.pocSteps.length > 0) {
    lines.push(`## Steps`);
    for (const [idx, step] of finding.pocSteps.entries()) {
      lines.push(`${idx + 1}. **${step.kind}** — ${step.summary}`);
    }
    lines.push("");
  }
  const arts = evidenceArtifacts(finding);
  if (arts.length > 0) {
    lines.push(`## Artifacts`);
    for (const a of arts) {
      lines.push(`- \`${basename(a.path)}\` — ${a.kind}${a.caption ? `: ${a.caption}` : ""}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function basename(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}

export function buildHypothesesMarkdown(findings: Finding[]): string {
  const lines: string[] = [];
  lines.push(`# Unverified hypotheses`);
  lines.push("");
  lines.push(
    `These findings were produced by pwnkit but did NOT reproduce under the`,
    ` verification step (per pwnkit#193). They are collected here for human`,
    ` review rather than emitted as PRs — auto-filing unverified findings is`,
    ` the H1 CoC "AI low-quality" tripwire we explicitly avoid.`,
  );
  lines.push("");
  if (findings.length === 0) {
    lines.push(`_No unverified findings in this run._`);
    return lines.join("\n");
  }
  for (const f of findings) {
    const vrStatus =
      ((f as unknown as MaybeVerificationResult).verification_result?.status ??
        (f as unknown as MaybeVerificationResult).verificationResult?.status ??
        "unknown");
    lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push("");
    lines.push(`- **ID:** \`${f.id}\``);
    lines.push(`- **Category:** ${f.category}`);
    lines.push(`- **Verification status:** \`${vrStatus}\``);
    if (f.confidence !== undefined) {
      lines.push(`- **Confidence:** ${(f.confidence * 100).toFixed(0)}%`);
    }
    lines.push("");
    lines.push(f.description);
    lines.push("");
    lines.push(`---`);
    lines.push("");
  }
  return lines.join("\n");
}

// ─── Main entry point ────────────────────────────────────────────────────────

/**
 * Emit each reproduced finding as a GitHub PR. Hypotheses (non-reproduced)
 * are aggregated into a single `hypotheses.md` instead.
 *
 * Workflow per reproduced finding:
 *   1. branch `pwnkit/finding-<short-id>` from `baseBranch`
 *   2. commit `.pwnkit/findings/<id>/{evidence...,README.md}`
 *   3. if a fix template matches, commit the patch as a second commit
 *   4. `gh pr create` with assembled body
 *
 * `dryRun: true` (or auto-fallback when gh is unauthenticated) prints the
 * git / gh commands instead of running them.
 */
export async function emitFindingsAsPRs(
  findings: Finding[],
  options: EmitFindingsAsPRsOptions,
): Promise<EmitFindingsAsPRsReport> {
  const baseBranch = options.baseBranch ?? "main";
  const registry = options.fixTemplateRegistry ?? createDefaultFixTemplateRegistry();
  const git = options.gitClient ?? defaultGitClient();
  const gh = options.ghClient ?? defaultGhClient();
  const fs = options.fsClient ?? defaultFsClient();
  const log = options.log ?? ((line: string) => console.log(line));

  let dryRun = options.dryRun ?? false;
  let forcedDryRun = false;
  if (!dryRun) {
    const authed = await gh.isAuthenticated();
    if (!authed) {
      dryRun = true;
      forcedDryRun = true;
      log(
        "[emit pr] `gh auth status` failed; dropping to --dry-run. " +
          "Run `gh auth login` to enable PR emission.",
      );
    }
  }

  const reproduced = findings.filter((f) => isReproduced(f));
  const hypotheses = findings.filter((f) => !isReproduced(f));

  const results: PrEmitResult[] = [];
  const seenBranches = new Set<string>();

  // Hypotheses.md is written BEFORE per-finding PRs so we can link it in
  // the first PR body. If no PRs are emitted we still write the file and
  // log its path.
  let hypothesesMdPath: string | undefined;
  if (options.outDir) {
    const path = `${options.outDir.replace(/\/+$/, "")}/hypotheses.md`;
    if (!dryRun) {
      await fs.mkdir(options.outDir, { recursive: true });
      await fs.writeFile(path, buildHypothesesMarkdown(hypotheses));
    } else {
      log(`[emit pr] would write hypotheses.md to ${path}`);
    }
    hypothesesMdPath = path;
  }

  for (const finding of findings) {
    if (!isReproduced(finding)) {
      results.push({
        finding,
        outcome: "skipped_unreproduced",
        branch: buildBranchName(finding),
      });
      continue;
    }
    const branch = buildBranchName(finding);
    if (seenBranches.has(branch)) {
      results.push({
        finding,
        outcome: "skipped_dedup",
        branch,
      });
      continue;
    }
    seenBranches.add(branch);

    const fixDiff = registry.apply(finding);
    const commands: string[] = [];
    const reproDir = `.pwnkit/findings/${shortFindingId(finding)}`;

    const execGit = async (args: string[]): Promise<void> => {
      commands.push(`git ${args.join(" ")}`);
      if (!dryRun) {
        await git.run(args, { cwd: options.repoRoot });
      }
    };

    // Step 1 — create branch from base.
    await execGit(["checkout", baseBranch]);
    await execGit(["checkout", "-b", branch]);

    // Step 2 — write repro tree.
    if (!dryRun) {
      await fs.mkdir(`${options.repoRoot}/${reproDir}`, { recursive: true });
      await fs.writeFile(
        `${options.repoRoot}/${reproDir}/README.md`,
        buildReproReadme(finding),
      );
      for (const artifact of evidenceArtifacts(finding)) {
        const dest = `${options.repoRoot}/${reproDir}/${basename(artifact.path)}`;
        try {
          await fs.copyFile(artifact.path, dest);
        } catch {
          // Artifact missing — fall back to a stub note so the repro tree is
          // self-contained. This matches the "be conservative" stance: we
          // never want to silently drop evidence.
          await fs.writeFile(
            `${dest}.missing.txt`,
            `Original artifact not found at: ${artifact.path}\nKind: ${artifact.kind}\n`,
          );
        }
      }
    } else {
      log(`[emit pr] would write repro tree at ${options.repoRoot}/${reproDir}/`);
    }

    await execGit(["add", reproDir]);
    await execGit([
      "commit",
      "-m",
      `pwnkit(${finding.category}): add repro for ${shortFindingId(finding)}`,
    ]);

    // Step 3 — apply fix-template diff (if any) as a second commit.
    if (fixDiff) {
      const diffPath = `${reproDir}/suggested-fix.patch`;
      const rendered = renderUnifiedDiff(fixDiff);
      if (!dryRun) {
        await fs.writeFile(`${options.repoRoot}/${diffPath}`, rendered);
      } else {
        log(`[emit pr] would write suggested-fix.patch to ${options.repoRoot}/${diffPath}`);
      }
      // We intentionally do NOT run `git apply` on the patch — too easy to
      // produce an apply-failing diff. Reviewers see the suggested patch in
      // the PR body and the committed file, and apply it themselves.
      await execGit(["add", diffPath]);
      await execGit([
        "commit",
        "-m",
        `pwnkit(${finding.category}): suggested patch — ${fixDiff.summary}`,
      ]);
    }

    // Step 4 — open the PR.
    const title = buildPrTitle(finding);
    const hypLink = hypothesesMdPath && results.length === 0 ? "hypotheses.md" : undefined;
    const body = buildPrBody(finding, { fixApplied: fixDiff ?? undefined, hypothesesLink: hypLink });
    const ghArgs = [
      "pr",
      "create",
      "--base",
      baseBranch,
      "--head",
      branch,
      "--title",
      title,
      "--body",
      body,
    ];
    commands.push(`gh ${ghArgs.join(" ")}`);

    if (dryRun) {
      log(`[emit pr] --- DRY RUN for ${finding.id} (${finding.category}) ---`);
      for (const c of commands) log(`[emit pr]   ${c}`);
      results.push({
        finding,
        outcome: "pr_dry_run",
        branch,
        commands,
        fixDiff: fixDiff ?? undefined,
      });
    } else {
      const { stdout } = await gh.run(ghArgs, { cwd: options.repoRoot });
      const url = stdout.trim().split(/\s+/).find((tok) => tok.startsWith("http")) ?? stdout.trim();
      results.push({
        finding,
        outcome: "pr_created",
        branch,
        prUrl: url,
        commands,
        fixDiff: fixDiff ?? undefined,
      });
    }
  }

  if (hypothesesMdPath && results.every((r) => r.outcome !== "pr_created" && r.outcome !== "pr_dry_run")) {
    log(`[emit pr] no PRs emitted; hypotheses.md at ${hypothesesMdPath}`);
  }

  return { results, hypothesesMdPath, forcedDryRun };
}
