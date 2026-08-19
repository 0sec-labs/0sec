import type { Command } from "commander";
import chalk from "chalk";
import { getRuntimeAvailability } from "../utils.js";

export function registerDoctorCommand(program: Command): void {
  program
    .command("doctor")
    .description("Check local runtime prerequisites and suggest the next command")
    .action(async () => {
      const { isBunRuntime, canUseOpenTui } = await import("../tui/runtime.js");
      if (isBunRuntime() && canUseOpenTui()) {
        const { showOpenTuiDoctor } = await import("../tui/run.js");
        await showOpenTuiDoctor();
        return;
      }

      const { hasApiKey, availableRuntimes, apiRuntime } = await getRuntimeAvailability();
      const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
      const hasSupportedNode = nodeMajor >= 20;

      console.log("");
      console.log(chalk.red.bold("  ◆ 0sec") + chalk.gray(" doctor"));
      console.log("");
      console.log(`  Node.js       ${hasSupportedNode ? chalk.green("ok") : chalk.red("bad")}  ${process.version}`);
      const apiStatus = hasApiKey
        ? `${chalk.green("ok")}  ${apiRuntime.providerLabel}`
        : apiRuntime.configured
          ? `${chalk.red("bad")}  ${apiRuntime.providerLabel}`
          : `${chalk.yellow("missing")}  not configured`;
      console.log(`  API runtime   ${apiStatus}`);
      console.log(`  CLI runtimes  ${availableRuntimes.length > 0 ? chalk.green("ok") : chalk.yellow("missing")}  ${availableRuntimes.join(", ") || "none"}`);
      console.log("");

      if (!hasSupportedNode) {
        console.log(chalk.red("  Upgrade to Node 20+ before running 0sec."));
      } else if (apiRuntime.configured && !apiRuntime.valid && apiRuntime.error) {
        console.log(chalk.red("  API runtime is configured but unusable."));
        console.log(chalk.gray(`  ${apiRuntime.error.split("\n").join("\n  ")}`));
      } else if (hasApiKey || availableRuntimes.length > 0) {
        console.log(chalk.green("  Ready to scan."));
        console.log(chalk.gray("  Try one of:"));
        console.log(chalk.gray("    0sec scan --target https://example.com --mode web"));
        console.log(chalk.gray("    0sec review ."));
        console.log(chalk.gray("    0sec audit express"));
      } else {
        console.log(chalk.yellow("  Next step: install Claude/Codex/Gemini CLI or set an API key."));
      }
      console.log("");
    });
}
