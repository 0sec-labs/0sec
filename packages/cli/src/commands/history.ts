import type { Command } from "commander";
import { existsSync } from "node:fs";
import chalk from "chalk";
import {
  listOsecRunDatabasePaths,
  osecDB,
  resolveOsecDbPath,
} from "@0sec/db";

type HistoryOptions = {
  dbPath?: string;
  limit?: string;
};

export function registerHistoryCommand(program: Command): void {
  program
    .command("history")
    .description("Show past scan history from run-local SQLite databases")
    .option("--db-path <path>", "Path to one SQLite database")
    .option("--limit <n>", "Number of scans to show", "10")
    .action(async (opts: HistoryOptions) => {
      const limit = Number.parseInt(opts.limit ?? "10", 10);
      const { isBunRuntime, canUseOpenTui } = await import("../tui/runtime.js");
      if (opts.dbPath && isBunRuntime() && canUseOpenTui()) {
        const { showOpenTuiHistory } = await import("../tui/run.js");
        await showOpenTuiHistory({ dbPath: opts.dbPath, limit });
        return;
      }


      const dbPaths = opts.dbPath
        ? [opts.dbPath]
        : listOsecRunDatabasePaths();
      const legacyDbPath = resolveOsecDbPath();
      if (!opts.dbPath && existsSync(legacyDbPath) && !dbPaths.includes(legacyDbPath)) {
        dbPaths.push(legacyDbPath);
      }

      const scans = dbPaths
        .flatMap((dbPath) => {
          const db = new osecDB(dbPath);
          try {
            return db.listScans(limit);
          } finally {
            db.close();
          }
        })
        .sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))
        .slice(0, limit);

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
