import type { Command } from "commander";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import chalk from "chalk";
import { loadScope, runMobileStaticIntake } from "@0sec/core";

const VALID_OUTPUT_FORMATS = ["terminal", "json"] as const;
type MobileOutputFormat = (typeof VALID_OUTPUT_FORMATS)[number];

interface MobileIntakeOpts {
  scope?: string;
  output: string;
  maxFileBytes?: string;
}

interface MobileUnpackOpts {
  out?: string;
  force?: boolean;
  intake?: boolean;
  scope?: string;
  output: string;
  maxFileBytes?: string;
}

export function registerMobileCommand(program: Command): void {
  const mobile = program
    .command("mobile")
    .description("Passive mobile app intake workflows");

  mobile
    .command("doctor")
    .description("Show local mobile testing tool availability")
    .option("-o, --output <format>", "Output format: terminal | json", "terminal")
    .action((opts: { output: string }) => {
      try {
        const output = opts.output as MobileOutputFormat;
        if (!VALID_OUTPUT_FORMATS.includes(output)) {
          throw new Error(
            `Invalid output format '${opts.output}'. Valid: ${VALID_OUTPUT_FORMATS.join(", ")}`,
          );
        }
        const tools = [
          checkTool("jadx", "static decompilation"),
          checkTool("apktool", "resource/smali decode"),
          checkTool("adb", "device/emulator control"),
          checkTool("emulator", "Android emulator"),
          checkTool("mitmproxy", "traffic capture proxy"),
          checkTool("frida", "runtime instrumentation"),
          checkTool("objection", "runtime exploration"),
        ];
        if (output === "json") {
          console.log(JSON.stringify({ tools }, null, 2));
        } else {
          console.log(chalk.white.bold("Mobile tool availability"));
          for (const tool of tools) {
            const mark = tool.available ? chalk.green("ok") : chalk.red("missing");
            console.log(`  ${mark} ${tool.name.padEnd(10)} ${chalk.gray(tool.purpose)}${tool.path ? ` ${chalk.gray(tool.path)}` : ""}`);
          }
        }
        process.exitCode = 0;
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 1;
      }
    });

  mobile
    .command("intake")
    .description("Extract mobile metadata and endpoint indicators from a local APK/IPA extraction tree")
    .argument("<path>", "Local .apk/.aab/.ipa file or extracted app directory")
    .option("--scope <path>", "0sec scope JSON for passive in/out-of-scope classification")
    .option("--max-file-bytes <n>", "Maximum text file size to inspect", "1048576")
    .option("-o, --output <format>", "Output format: terminal | json", "terminal")
    .action((targetPath: string, opts: MobileIntakeOpts) => {
      try {
        const output = opts.output as MobileOutputFormat;
        if (!VALID_OUTPUT_FORMATS.includes(output)) {
          throw new Error(
            `Invalid output format '${opts.output}'. Valid: ${VALID_OUTPUT_FORMATS.join(", ")}`,
          );
        }

        const maxFileBytes = parsePositiveInteger(opts.maxFileBytes, "--max-file-bytes");
        const scope = opts.scope ? loadScope(opts.scope) : undefined;
        const report = runMobileStaticIntake(targetPath, { scope, maxFileBytes });

        if (output === "json") {
          console.log(JSON.stringify(report, null, 2));
        } else {
          renderTerminal(report);
        }
        process.exitCode = 0;
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 1;
      }
    });

  mobile
    .command("unpack")
    .description("Decompile an Android APK with jadx, then optionally run passive mobile intake")
    .argument("<apk>", "Local Android .apk file or HTTPS APK URL")
    .option("--out <dir>", "Output directory for decompiled sources")
    .option("--force", "Remove the output directory first when it already exists", false)
    .option("--intake", "Run passive endpoint/metadata intake after decompilation", false)
    .option("--scope <path>", "0sec scope JSON for passive in/out-of-scope classification")
    .option("--max-file-bytes <n>", "Maximum text file size to inspect during --intake", "1048576")
    .option("-o, --output <format>", "Output format: terminal | json", "terminal")
    .action((apkInput: string, opts: MobileUnpackOpts) => {
      try {
        const output = opts.output as MobileOutputFormat;
        if (!VALID_OUTPUT_FORMATS.includes(output)) {
          throw new Error(
            `Invalid output format '${opts.output}'. Valid: ${VALID_OUTPUT_FORMATS.join(", ")}`,
          );
        }
        const preparedApk = prepareApkInput(apkInput);
        const apkPath = preparedApk.path;
        if (!existsSync(apkPath)) {
          throw new Error(`APK not found: ${apkPath}`);
        }

        const outDir = resolve(opts.out ?? join(process.cwd(), `${basename(apkPath, ".apk")}-jadx`));
        if (existsSync(outDir)) {
          if (!opts.force) {
            throw new Error(`Output directory already exists: ${outDir} (pass --force to replace it)`);
          }
          rmSync(outDir, { recursive: true, force: true });
        }
        mkdirSync(outDir, { recursive: true });
        const warnings: string[] = [];
        try {
          execFileSync("jadx", ["-d", outDir, apkPath], { stdio: output === "json" ? "pipe" : "inherit" });
        } catch (err) {
          if (!directoryHasFiles(outDir)) {
            throw err;
          }
          warnings.push(`jadx exited non-zero but wrote a partial decompilation to ${outDir}`);
        }

        const unpackResult: Record<string, unknown> = {
          source: apkInput,
          apk: apkPath,
          outDir,
          tool: "jadx",
          warnings,
        };

        if (opts.intake) {
          const maxFileBytes = parsePositiveInteger(opts.maxFileBytes, "--max-file-bytes");
          const scope = opts.scope ? loadScope(opts.scope) : undefined;
          unpackResult.intake = runMobileStaticIntake(outDir, { scope, maxFileBytes });
        }

        if (output === "json") {
          console.log(JSON.stringify(unpackResult, null, 2));
        } else {
          console.log(chalk.green(`Decompiled APK to ${outDir}`));
          for (const warning of warnings) console.log(chalk.yellow(`Warning: ${warning}`));
          if (opts.intake) renderTerminal(unpackResult.intake as ReturnType<typeof runMobileStaticIntake>);
        }
        process.exitCode = 0;
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 1;
      }
    });
}

function prepareApkInput(input: string): { path: string } {
  if (!/^https?:\/\//i.test(input)) {
    return { path: input };
  }

  const dir = mkdtempSync(join(tmpdir(), "0sec-mobile-apk-"));
  const fileName = apkFileNameFromUrl(input);
  const outputPath = join(dir, fileName);
  execFileSync("curl", ["-L", "--fail", "--silent", "--show-error", "-o", outputPath, input], {
    stdio: "pipe",
  });
  return { path: outputPath };
}

function apkFileNameFromUrl(input: string): string {
  try {
    const parsed = new URL(input);
    const name = basename(parsed.pathname);
    return name.toLowerCase().endsWith(".apk") ? name : "app.apk";
  } catch {
    return "app.apk";
  }
}

function checkTool(name: string, purpose: string): { name: string; purpose: string; available: boolean; path?: string } {
  try {
    const path = execFileSync("which", [name], { encoding: "utf8" }).trim();
    return { name, purpose, available: path.length > 0, path: path || undefined };
  } catch {
    return { name, purpose, available: false };
  }
}

function directoryHasFiles(path: string): boolean {
  try {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      if (entry.isFile()) return true;
      if (entry.isDirectory() && directoryHasFiles(join(path, entry.name))) return true;
    }
  } catch {
    return false;
  }
  return false;
}

function parsePositiveInteger(value: string | undefined, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid ${label} '${value}'; expected a positive integer`);
  }
  return parsed;
}

function renderTerminal(report: ReturnType<typeof runMobileStaticIntake>): void {
  console.log(chalk.blue(`Mobile static intake: ${report.target}`));
  console.log(chalk.gray(`Platform: ${report.platform}`));

  if (report.android) {
    if (report.android.packageName) console.log(`Package: ${report.android.packageName}`);
    if (report.android.versionName) console.log(`Version: ${report.android.versionName}`);
    if (report.android.permissions.length > 0) console.log(`Permissions: ${report.android.permissions.length}`);
    if (report.android.exportedComponents.length > 0) console.log(`Exported components: ${report.android.exportedComponents.length}`);
    if (report.android.deepLinks.length > 0) console.log(`Deep links: ${report.android.deepLinks.length}`);
  }

  if (report.ios) {
    if (report.ios.bundleId) console.log(`Bundle: ${report.ios.bundleId}`);
    if (report.ios.version) console.log(`Version: ${report.ios.version}`);
    if (report.ios.urlSchemes.length > 0) console.log(`URL schemes: ${report.ios.urlSchemes.join(", ")}`);
    if (report.ios.associatedDomains.length > 0) console.log(`Associated domains: ${report.ios.associatedDomains.length}`);
  }

  if (report.warnings.length > 0) {
    for (const warning of report.warnings) console.log(chalk.yellow(`Warning: ${warning}`));
  }

  if (report.risks.length > 0) {
    console.log("");
    console.log(chalk.white.bold("Passive risk indicators"));
    for (const risk of report.risks) {
      console.log(`  ${risk.severity.padEnd(6)} ${risk.title}`);
      for (const evidence of risk.evidence.slice(0, 5)) {
        console.log(chalk.gray(`         ${evidence}`));
      }
      if (risk.evidence.length > 5) {
        console.log(chalk.gray(`         ... ${risk.evidence.length - 5} more`));
      }
    }
  }

  const inScope = report.endpoints.filter((endpoint) => endpoint.scope?.allowed === true).length;
  const outOfScope = report.endpoints.filter((endpoint) => endpoint.scope?.allowed === false).length;
  console.log("");
  console.log(chalk.white.bold("Endpoint indicators"));
  console.log(`  total: ${report.endpoints.length}`);
  if (inScope || outOfScope) {
    console.log(`  in-scope: ${inScope}`);
    console.log(`  out-of-scope: ${outOfScope}`);
  }
  const sortedEndpoints = [...report.endpoints].sort((a, b) =>
    priorityWeight(a.priority) - priorityWeight(b.priority)
    || a.value.localeCompare(b.value),
  );
  for (const endpoint of sortedEndpoints.slice(0, 25)) {
    const scopeLabel = endpoint.scope
      ? endpoint.scope.allowed ? chalk.green("in") : chalk.red("out")
      : chalk.gray("unscoped");
    const tags = endpoint.tags.length > 0 ? chalk.gray(` [${endpoint.tags.join(",")}]`) : "";
    console.log(`  ${scopeLabel} ${endpoint.priority.padEnd(6)} ${endpoint.kind.padEnd(4)} ${endpoint.value}${tags}`);
  }
  if (sortedEndpoints.length > 25) {
    console.log(chalk.gray(`  ... ${sortedEndpoints.length - 25} more`));
  }
}

function priorityWeight(priority: "high" | "medium" | "low"): number {
  return priority === "high" ? 0 : priority === "medium" ? 1 : 2;
}
