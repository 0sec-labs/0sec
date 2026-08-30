import type { Command } from "commander";
import chalk from "chalk";


export function registerTuiCommand(program: Command): void {
  program
    .command("tui")
    .alias("watch")
    .description("Open the unified engagement control plane (Bun-only)")
    .action(async () => {
      const { isBunRuntime } = await import("../tui/runtime.js");
      if (isBunRuntime()) {
        // OpenTUI is Bun-specific; defer this module on Node so the fallback
        // remains usable in a plain npm install.
        const { showOpenTuiHome } = await import("../tui/run.js");
        await showOpenTuiHome();
        return;
      }

      // Node cannot host the OpenTUI control plane.
      console.log("");
      console.log(`  ${chalk.bold("0sec tui")} — the engagement control plane needs Bun.`);
      console.log("");
      console.log(`  ${chalk.dim("Install the standalone binary (Bun runtime baked in):")}`);
      console.log(`    curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash`);
      console.log("");
      process.exit(1);
    });
}
