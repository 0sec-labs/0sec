import type { Command } from "commander";
import chalk from "chalk";

type HistoryOptions = {
  dbPath?: string;
  limit?: string;
};

export function registerHistoryCommand(program: Command): void {
  program
    .command("history")
    .description("Show past scan history from the SQLite database")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--limit <n>", "Number of scans to show", "10")
    .action(async (opts: HistoryOptions) => {
      const limit = Number.parseInt(opts.limit ?? "10", 10);
      const { isBunRuntime, canUseOpenTui } = await import("../tui/runtime.js");
      if (isBunRuntime() && canUseOpenTui()) {
        const { showOpenTuiHistory } = await import("../tui/run.js");
        await showOpenTuiHistory({ dbPath: opts.dbPath, limit });
        return;
      }

      const { osecDB } = await import("@0sec/db");
      const db = new osecDB(opts.dbPath);
      const scans = db.listScans(limit);
      db.close();

      if (scans.length === 0) {
        console.log(chalk.gray("No scan history found."));
        return;
      }

      console.log("");
      console.log(chalk.red.bold("  \u25C6 0sec") + chalk.gray(" scan history"));
      console.log("");

      for (const s of scans) {
        const status =
          s.status === "completed"
            ? chalk.green("done")
            : s.status === "failed"
              ? chalk.red("fail")
              : chalk.yellow("run");
        const summary = s.summary ? JSON.parse(s.summary) : null;
        const findings = summary?.totalFindings ?? "?";
        const duration = s.durationMs ? `${(s.durationMs / 1000).toFixed(1)}s` : "-";
        const resumeHint =
          s.status === "completed"
            ? ""
            : ` ${chalk.gray(`resume:${s.id.slice(0, 8)}`)}`;

        console.log(
          `  ${status} ${chalk.white(s.target)} ${chalk.gray(`[${s.depth}]`)} ${chalk.gray(duration)} ${chalk.yellow(`${findings} findings`)} ${chalk.gray(s.startedAt)}${resumeHint}`
        );
      }
      console.log("");
    });
}
