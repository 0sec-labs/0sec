import type { Command } from "commander";
import chalk from "chalk";

type TuiOptions = {
  dbPath?: string;
  refreshMs?: string;
};

export function registerTuiCommand(program: Command): void {
  program
    .command("tui")
    .alias("watch")
    .description("Open the operator mission control TUI (Bun-only)")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--refresh-ms <n>", "Refresh interval in milliseconds", "4000")
    .action(async (opts: TuiOptions) => {
      const refreshMs = Number.parseInt(opts.refreshMs ?? "4000", 10);
      const { isBunRuntime } = await import("../tui/runtime.js");
      if (isBunRuntime()) {
        const { showOpenTuiOps } = await import("../tui/run.js");
        await showOpenTuiOps({ dbPath: opts.dbPath, refreshMs });
        return;
      }

      // Node fallback: the legacy Ink mission control was removed in v0.9.0.
      // OpenTUI needs Bun's runtime, so point users at the binary install.
      console.log("");
      console.log(`  ${chalk.bold("0sec tui")} — operator mission control needs Bun.`);
      console.log("");
      console.log(`  ${chalk.dim("Install the standalone binary (Bun runtime baked in):")}`);
      console.log(`    curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash`);
      console.log("");
      console.log(`  ${chalk.dim("Or via Bun directly:")}`);
      console.log(`    bun add -g 0sec-cli  &&  0sec-cli tui`);
      console.log("");
      process.exit(1);
    });
}
