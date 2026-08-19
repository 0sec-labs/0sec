/**
 * `pwnkit upgrade` — re-runs install.sh to fetch the latest binary.
 *
 * Convenience wrapper around the canonical install path:
 *
 *   curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
 *
 * When run from inside an installed pwnkit binary, this re-fetches the
 * matching binary for the host platform and writes it into
 * `$PWNKIT_INSTALL_DIR` (default `~/.pwnkit/bin/`), overwriting the
 * current binary atomically.
 *
 * Windows is intentionally not supported by install.sh — print the
 * download URL and tell the user to refresh manually.
 */

import type { Command } from "commander";
import { spawn } from "node:child_process";
import chalk from "chalk";

const INSTALL_URL = "https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh";
const RELEASES_URL = "https://github.com/0sec-labs/0sec/releases/latest";

interface UpgradeOptions {
  version?: string;
  installDir?: string;
}

export function registerUpgradeCommand(program: Command): void {
  program
    .command("upgrade")
    .description("Fetch and install the latest pwnkit binary (re-runs install.sh)")
    .option("--version <tag>", "Pin a specific release tag (e.g. v0.10.0)")
    .option("--install-dir <path>", "Override the install directory (default: ~/.pwnkit/bin)")
    .action(async (opts: UpgradeOptions) => {
      if (process.platform === "win32") {
        console.log("");
        console.log(`  ${chalk.bold("pwnkit upgrade")} doesn't support Windows yet.`);
        console.log("");
        console.log(`  Download the latest ${chalk.cyan("pwnkit-windows-x64.exe")} from:`);
        console.log(`    ${chalk.cyan(RELEASES_URL)}`);
        console.log("");
        console.log(`  Replace your current binary in place. Auto-upgrade is tracked in #234.`);
        console.log("");
        process.exit(1);
      }

      // We pipe the install script into bash, mirroring the curl|bash one-
      // liner from the README. Set up the env so install.sh picks up the
      // requested overrides.
      const env: NodeJS.ProcessEnv = { ...process.env };
      if (opts.version) env.PWNKIT_VERSION = opts.version;
      if (opts.installDir) env.PWNKIT_INSTALL_DIR = opts.installDir;

      console.log("");
      console.log(`  ${chalk.bold("pwnkit upgrade")} — fetching the latest binary…`);
      console.log(`    ${chalk.dim(`curl -fsSL ${INSTALL_URL} | bash`)}`);
      if (opts.version) console.log(`    ${chalk.dim(`PWNKIT_VERSION=${opts.version}`)}`);
      if (opts.installDir) console.log(`    ${chalk.dim(`PWNKIT_INSTALL_DIR=${opts.installDir}`)}`);
      console.log("");

      // Use sh -c so we can pipe curl into bash without writing a temp
      // file. install.sh itself is bash-shebanged, so passing it via stdin
      // to `bash` is fine on every supported platform (macOS, Linux).
      const cmd = `set -e; curl -fsSL "${INSTALL_URL}" | bash`;
      const child = spawn("sh", ["-c", cmd], { stdio: "inherit", env });
      child.on("error", (e) => {
        console.error(chalk.red(`upgrade failed: ${e.message}`));
        process.exit(1);
      });
      child.on("exit", (code, signal) => {
        if (signal) {
          process.kill(process.pid, signal);
          return;
        }
        if (code === 0) {
          console.log("");
          console.log(`  ${chalk.green("✓")} ${chalk.bold("upgraded.")} run ${chalk.cyan("pwnkit --version")} to confirm.`);
          console.log("");
        }
        process.exit(code ?? 0);
      });
    });
}
