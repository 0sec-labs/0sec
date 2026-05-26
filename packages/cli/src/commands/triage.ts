import type { Command } from "commander";
import chalk from "chalk";

type TriageMemoryAddOptions = {
  dbPath?: string;
  finding: string;
  reason: string;
  scope?: "global" | "target" | "package";
  scopeValue?: string;
};

type TriageMemoryListOptions = {
  dbPath?: string;
  scope?: "global" | "target" | "package";
  category?: string;
};

type TriageMarkFpOptions = {
  dbPath?: string;
  reason: string;
  scope?: "global" | "target" | "package";
  scopeValue?: string;
};

interface FindingRow {
  id: string;
  scanId: string;
  title: string;
  category: string;
  fingerprint?: string | null;
  description: string;
  severity: string;
  status: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  timestamp: number;
}

function resolveFindingByPrefix(rows: FindingRow[], id: string): FindingRow | undefined {
  const exact = rows.find((row) => row.id === id);
  if (exact) return exact;
  const matches = rows.filter((row) => row.id.startsWith(id));
  if (matches.length > 1) {
    throw new Error(`Finding prefix '${id}' is ambiguous (${matches.length} matches).`);
  }
  return matches[0];
}

/**
 * Convert a DB finding row (from @pwnkit/db listFindings) into the shared
 * Finding shape that @pwnkit/core's MemoryStore expects. The evidence fields
 * are folded into the nested `evidence` object and defaults are applied to
 * optional properties.
 */
function rowToFinding(row: FindingRow): import("@pwnkit/shared").Finding {
  return {
    id: row.id,
    templateId: "",
    title: row.title,
    description: row.description,
    severity: row.severity as import("@pwnkit/shared").Severity,
    category: row.category as import("@pwnkit/shared").AttackCategory,
    status: row.status as import("@pwnkit/shared").FindingStatus,
    evidence: {
      request: row.evidenceRequest,
      response: row.evidenceResponse,
      analysis: row.evidenceAnalysis ?? undefined,
    },
    fingerprint: row.fingerprint ?? undefined,
    timestamp: row.timestamp,
  };
}

async function openStore(dbPath?: string) {
  const { MemoryStore } = await import("@pwnkit/core");
  return new MemoryStore(dbPath);
}

async function loadFinding(dbPath: string | undefined, findingId: string): Promise<FindingRow> {
  const { pwnkitDB } = await import("@pwnkit/db");
  const db = new pwnkitDB(dbPath);
  try {
    const rows = db.listFindings({ limit: 5000 }) as FindingRow[];
    const row = resolveFindingByPrefix(rows, findingId);
    if (!row) {
      throw new Error(`Finding '${findingId}' not found.`);
    }
    return row;
  } finally {
    db.close();
  }
}

async function runMemoryAdd(opts: TriageMemoryAddOptions): Promise<void> {
  const row = await loadFinding(opts.dbPath, opts.finding);
  const finding = rowToFinding(row);
  const store = await openStore(opts.dbPath);
  try {
    const memory = await store.recordFp(
      finding,
      opts.reason,
      opts.scope ?? "target",
      opts.scopeValue,
    );
    console.log(
      `${chalk.green("Added memory")} ${chalk.gray(memory.id.slice(0, 8))} ${chalk.gray(`scope:${memory.scope}${memory.scopeValue ? `(${memory.scopeValue})` : ""}`)} ${chalk.gray(`category:${memory.category}`)}`,
    );
    console.log(`  ${chalk.gray("pattern:")} ${memory.pattern}`);
    console.log(`  ${chalk.gray("reason :")} ${memory.reasoning}`);
  } finally {
    await store.close();
  }
}

async function runMemoryList(opts: TriageMemoryListOptions): Promise<void> {
  const store = await openStore(opts.dbPath);
  try {
    const memories = await store.listAll();
    const filtered = memories
      .filter((m) => (opts.scope ? m.scope === opts.scope : true))
      .filter((m) => (opts.category ? m.category === opts.category : true));
    if (filtered.length === 0) {
      console.log(chalk.gray("No triage memories found."));
      return;
    }
    console.log("");
    console.log(chalk.red.bold("  ◆ pwnkit") + chalk.gray(` triage memories (${filtered.length})`));
    console.log("");
    for (const m of filtered) {
      const scopeLabel =
        m.scope === "global" ? "global" : `${m.scope}:${m.scopeValue ?? "?"}`;
      console.log(
        `  ${chalk.cyan(m.id.slice(0, 8))} ${chalk.gray(scopeLabel.padEnd(30))} ${chalk.yellow(m.category.padEnd(18))} ${chalk.gray(`applied:${m.appliedCount}`)}`,
      );
      console.log(`    ${chalk.white(m.pattern)}`);
      console.log(`    ${chalk.dim(m.reasoning)}`);
      console.log("");
    }
  } finally {
    await store.close();
  }
}

async function runMemoryRemove(id: string, dbPath?: string): Promise<void> {
  const store = await openStore(dbPath);
  try {
    const ok = await store.remove(id);
    if (!ok) {
      console.error(chalk.red(`No memory with id '${id}' found.`));
      process.exitCode = 1;
      return;
    }
    console.log(`${chalk.green("Removed memory")} ${chalk.gray(id.slice(0, 8))}`);
  } finally {
    await store.close();
  }
}

async function runMarkFp(findingId: string, opts: TriageMarkFpOptions): Promise<void> {
  // 1. Flip the finding's triage status to suppressed.
  // 2. Auto-create a memory from the finding + reason.
  const row = await loadFinding(opts.dbPath, findingId);
  const finding = rowToFinding(row);

  const { pwnkitDB } = await import("@pwnkit/db");
  const db = new pwnkitDB(opts.dbPath);
  try {
    db.updateFindingTriage(row.id, "suppressed", opts.reason);
  } finally {
    db.close();
  }

  const store = await openStore(opts.dbPath);
  try {
    const memory = await store.recordFp(
      finding,
      opts.reason,
      opts.scope ?? "target",
      opts.scopeValue,
    );
    console.log(
      `${chalk.green("Marked FP")} ${chalk.gray(row.id.slice(0, 8))} ${chalk.gray("and recorded memory")} ${chalk.gray(memory.id.slice(0, 8))}`,
    );
  } finally {
    await store.close();
  }
}

export function registerTriageCommand(program: Command): void {
  const triage = program.command("triage").description("Triage findings and manage learned FP memories");

  const memory = triage.command("memory").description("Manage Semgrep-style triage memories");

  memory
    .command("add")
    .description("Create a memory from an existing finding")
    .requiredOption("--finding <id>", "Finding ID (full or prefix) to derive the memory from")
    .requiredOption("--reason <text>", "Why this finding is a false positive")
    .option("--scope <scope>", "Memory scope: global | target | package", "target")
    .option("--scope-value <value>", "Scope identifier (target URL or package name)")
    .option("--db-path <path>", "Path to SQLite database")
    .action(async (opts: TriageMemoryAddOptions) => {
      try {
        await runMemoryAdd(opts);
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 1;
      }
    });

  memory
    .command("list")
    .description("List all triage memories")
    .option("--scope <scope>", "Filter by scope: global | target | package")
    .option("--category <category>", "Filter by vulnerability category")
    .option("--db-path <path>", "Path to SQLite database")
    .action(async (opts: TriageMemoryListOptions) => {
      try {
        await runMemoryList(opts);
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 1;
      }
    });

  memory
    .command("remove")
    .description("Delete a memory by id")
    .argument("<id>", "Memory ID")
    .option("--db-path <path>", "Path to SQLite database")
    .action(async (id: string, opts: { dbPath?: string }) => {
      try {
        await runMemoryRemove(id, opts.dbPath);
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 1;
      }
    });

  triage
    .command("mark-fp")
    .description("Mark a finding as false positive and auto-create a memory")
    .argument("<finding-id>", "Finding ID (full or prefix)")
    .requiredOption("--reason <text>", "Why this finding is a false positive")
    .option("--scope <scope>", "Memory scope: global | target | package", "target")
    .option("--scope-value <value>", "Scope identifier (target URL or package name)")
    .option("--db-path <path>", "Path to SQLite database")
    .action(async (findingId: string, opts: TriageMarkFpOptions) => {
      try {
        await runMarkFp(findingId, opts);
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 1;
      }
    });
}
