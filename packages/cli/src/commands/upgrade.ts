/**
 * `0sec upgrade` — fetches and installs a 0sec binary via the canonical
 * install.sh script. Delegates to the shared {@link performAutoUpdate}
 * helper so that both manual `upgrade` and automatic policy use the same
 * single installer path.
 *
 * Windows support: install.sh does not target Windows, so we print the
 * download URL and tell the user to refresh manually.
 */

import type { Command } from "commander";
import chalk from "chalk";
import { performAutoUpdate } from "../utils/update-check.js";

const RELEASES_URL = "https://github.com/0sec-labs/0sec/releases/latest";

interface UpgradeOptions {
  version?: string;
  installDir?: string;
}

export function registerUpgradeCommand(program: Command): void {
  program
    .command("upgrade")
    .description("Fetch and install the latest 0sec binary (re-runs install.sh)")
    .option("--version <tag>", "Pin a specific release tag (e.g. v0.10.0)")
    .option("--install-dir <path>", "Override the install directory (default: ~/.0sec/bin)")
    .action(async (opts: UpgradeOptions) => {
      if (process.platform === "win32") {
        console.log("");
        console.log(`  ${chalk.bold("0sec upgrade")} doesn't support Windows yet.`);
        console.log("");
        console.log(`  Download the latest ${chalk.cyan("0sec-windows-x64.exe")} from:`);
        console.log(`    ${chalk.cyan(RELEASES_URL)}`);
        console.log("");
        console.log(`  Replace your current binary in place. Auto-upgrade is tracked in issue #46.`);
        console.log("");
        process.exit(1);
      }

      console.log("");
      console.log(`  ${chalk.bold("0sec upgrade")} — fetching the latest binary\u2026`);
      if (opts.version) console.log(`    ${chalk.dim(`tag=${opts.version}`)}`);
      if (opts.installDir) console.log(`    ${chalk.dim(`install_dir=${opts.installDir}`)}`);

      const result = await performAutoUpdate({
        version: opts.version,
        installDir: opts.installDir,
      });

      if (result.signal) {
        process.kill(process.pid, result.signal);
        return;
      }

      if (result.success) {
        console.log("");
        console.log(
          `  ${chalk.green("\u2713")} ${chalk.bold("upgraded.")}` +
            ` run ${chalk.cyan("0sec --version")} to confirm.`,
        );
        console.log("");
        process.exit(0);
      } else {
        console.error(chalk.red(`upgrade failed: ${result.error ?? "unknown error"}`));
        process.exit(result.exitCode ?? 1);
      }
    });
}