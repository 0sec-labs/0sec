import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Command } from "commander";
import type { Finding } from "@pwnkit/shared";

function print(value: unknown): void {
  process.stdout.write(JSON.stringify(value, null, 2) + "\n");
}

export function registerResearchCommand(program: Command): void {
  const research = program
    .command("research")
    .description("Run target-specific engines through the shared evidence research plane");

  research
    .command("pipeline")
    .description("Run the existing web/AI/source/package pipeline through the shared evidence plane")
    .requiredOption("--target <target>", "URL, local path, repository, package, or image")
    .option("--target-type <type>", "url, web-app, source-code, npm-package, pypi-package, cargo-package, or oci-image")
    .option("--profile <profile>", "Source review profile")
    .option("--depth <depth>", "quick, default, or deep", "default")
    .option("--runtime <runtime>", "auto, api, claude, codex, gemini, or ollama", "auto")
    .option("--artifact-root <path>", "Research artifact root", ".pwnkit-research")
    .action(async (opts: { target: string; targetType?: string; profile?: string; depth: string; runtime: string; artifactRoot: string }) => {
      const { UnifiedPipelineResearchAdapter, postFinding, runResearch } = await import("@pwnkit/core");
      const allowedTypes = new Set(["url", "web-app", "source-code", "npm-package", "pypi-package", "cargo-package", "oci-image"]);
      if (opts.targetType && !allowedTypes.has(opts.targetType)) throw new Error(`unsupported --target-type ${opts.targetType}`);
      print(await runResearch(
        new UnifiedPipelineResearchAdapter(),
        {
          kind: "pipeline.unified",
          id: `pipeline:${opts.target}`,
          location: opts.target,
          config: {
            options: {
              depth: opts.depth as "quick" | "default" | "deep",
              format: "json",
              runtime: opts.runtime as "auto" | "api" | "claude" | "codex" | "gemini" | "ollama",
              ...(opts.targetType ? { targetType: opts.targetType as "url" | "web-app" | "source-code" | "npm-package" | "pypi-package" | "cargo-package" | "oci-image" } : {}),
              ...(opts.profile ? { reviewProfile: opts.profile as "default" } : {}),
            },
          },
        },
        { artifactRoot: resolve(opts.artifactRoot), emitFinding: postFinding, log: (message) => process.stderr.write(message + "\n") },
      ));
    });

  research
    .command("mobile")
    .description("Run passive mobile intake; indicators remain hypotheses and only scoped adapters may hand off targets")
    .requiredOption("--target <path>", "Extracted APK/IPA directory or metadata file")
    .option("--artifact-root <path>", "Research artifact root", ".pwnkit-research")
    .action(async (opts: { target: string; artifactRoot: string }) => {
      const { MobileStaticResearchAdapter, postFinding, runResearch } = await import("@pwnkit/core");
      const targetPath = resolve(opts.target);
      print(await runResearch(
        new MobileStaticResearchAdapter(),
        { kind: "mobile.static-intake", id: `mobile:${targetPath}`, location: targetPath, config: {} },
        { artifactRoot: resolve(opts.artifactRoot), emitFinding: postFinding, log: (message) => process.stderr.write(message + "\n") },
      ));
    });

  research
    .command("linux-matrix")
    .description("Import externally executed vulnerable-vs-patched boot logs; pwnkit validates and hashes them but does not execute boots")
    .requiredOption("--matrix <path>", "Versioned external boot-matrix manifest JSON")
    .requiredOption("--finding <path>", "Existing Finding JSON to bind the proof to")
    .option("--artifact-root <path>", "Research artifact root", ".pwnkit-research")
    .action(async (opts: { matrix: string; finding: string; artifactRoot: string }) => {
      const { LinuxBootMatrixImportAdapter, postFinding, runResearch } = await import("@pwnkit/core");
      const matrix = resolve(opts.matrix);
      const finding = JSON.parse(readFileSync(resolve(opts.finding), "utf8")) as Finding;
      print(await runResearch(
        new LinuxBootMatrixImportAdapter(),
        { kind: "linux.kernel-boot-matrix-import", id: `linux-matrix:${finding.id}`, location: matrix, config: { finding } },
        { artifactRoot: resolve(opts.artifactRoot), emitFinding: postFinding, log: (message) => process.stderr.write(message + "\n") },
      ));
    });

  research
    .command("linux")
    .description("Run a supplied Linux kernel reproducer through the shared N-boot evidence gate")
    .requiredOption("--kernel-tree <path>", "Linux source tree")
    .requiredOption("--reproducer <path>", "C reproducer or syzkaller .syz program")
    .requiredOption("--finding <path>", "Existing Finding JSON to bind the proof to")
    .option("--boots <n>", "Fresh boots", "3")
    .option("--min-hits <n>", "Required reproducing boots", "2")
    .option("--artifact-root <path>", "Research artifact root", ".pwnkit-research")
    .action(async (opts: { kernelTree: string; reproducer: string; finding: string; boots: string; minHits: string; artifactRoot: string }) => {
      const { LinuxKernelResearchAdapter, postFinding, runResearch } = await import("@pwnkit/core");
      const kernelTree = resolve(opts.kernelTree);
      const reproducer = resolve(opts.reproducer);
      const finding = JSON.parse(readFileSync(resolve(opts.finding), "utf8")) as Finding;
      const boots = Number.parseInt(opts.boots, 10);
      const minHits = Number.parseInt(opts.minHits, 10);
      if (!Number.isFinite(boots) || boots < 1 || !Number.isFinite(minHits) || minHits < 1 || minHits > boots) {
        throw new Error("--boots and --min-hits must be positive, with min-hits <= boots");
      }
      const verify = reproducer.endsWith(".syz")
        ? { syzProgramPath: reproducer, boots, minHits }
        : { reproducerPath: reproducer, boots, minHits };
      print(await runResearch(
        new LinuxKernelResearchAdapter(),
        {
          kind: "linux.kernel-reproducer",
          id: `linux:${finding.id}`,
          location: kernelTree,
          config: { finding, verify },
        },
        { artifactRoot: resolve(opts.artifactRoot), emitFinding: postFinding, log: (message) => process.stderr.write(message + "\n") },
      ));
    });
}
