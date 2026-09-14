// `0sec login`, `0sec models`, `0sec balance` — 0sec Cloud hosted
// inference CLI commands.
//
// Subcommands:
//   - login        alias for `0sec auth login` (opens browser/polls)
//   - models       list qualified 0sec Cloud models and server-provided
//                  supplier-cost estimates
//   - balance      show subscription allowance across its shared monthly,
//                  weekly and five-hour limits, plus legacy credit availability
//
// All use CloudClient from @0sec/core, which reads scoped creds from
// env or ~/.0sec/cloud.env. 401 → clear auth error, not silent fallback.
//
// SECURITY: the token is never printed. Error messages include status +
// path + host, never the Authorization header.

import type { Command } from "commander";
import chalk from "chalk";
import { consolePresentationOutput } from "../presentation/process-output.js";
import {
  loadCloudCredentials,
  CloudAuthMissingError,
  CloudClient,
  CloudUnauthorizedError,
  CloudForbiddenError,
  CloudNetworkError,
  CloudError,
  DEFAULT_CLOUD_HOST,
  type HostedAllowanceOverview,
} from "@0sec/core";
import { runLogin } from "./auth.js";

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;
const EXIT_AUTH = 2;
const EXIT_NET = 3;

export function registerHostedCommand(program: Command): void {
  // ── 0sec login (alias for 0sec auth login) ──
  program
    .command("login")
    .description("Sign in to 0sec Cloud (optional for your own provider)")
    .option("--host <url>", `Cloud host (default ${DEFAULT_CLOUD_HOST})`)
    .option("--token <value>", "Skip the browser flow and persist this token directly")
    .action(async (opts: { host?: string; token?: string }) => {
      await runLogin(opts);
    });

  // ── 0sec models ──
  program
    .command("models")
    .description("List qualified 0sec Cloud models and server-provided supplier-cost estimates")
    .option("--json", "Output raw JSON instead of a formatted table")
    .action(async (opts: { json?: boolean }) => {
      await runModels(opts);
    });

  // ── 0sec balance ──
  program
    .command("balance")
    .description("Show subscription allowance across its shared monthly, weekly and five-hour limits")
    .option("--json", "Output raw account JSON instead of formatted allowance details")
    .action(async (opts: { json?: boolean }) => {
      await runBalance(opts);
    });
}

// ── implementations ──

async function loadClient(): Promise<CloudClient> {
  let creds: { host: string; token: string };
  try {
    const c = loadCloudCredentials();
    creds = { host: c.host, token: c.token };
  } catch (err) {
    if (err instanceof CloudAuthMissingError) {
      consolePresentationOutput.stderr(chalk.red(err.message), "hosted.creds-missing");
      process.exitCode = EXIT_AUTH;
      throw err;
    }
    consolePresentationOutput.stderr(
      chalk.red(err instanceof Error ? err.message : String(err)),
      "hosted.creds-error",
    );
    process.exitCode = EXIT_USER_ERROR;
    throw err;
  }
  return new CloudClient(creds);
}

function handleApiError(err: unknown): void {
  if (err instanceof CloudUnauthorizedError) {
    consolePresentationOutput.stderr(
      chalk.red("Authentication failed (HTTP 401). Run `0sec login` to refresh."),
      "hosted.unauthorized",
    );
    process.exitCode = EXIT_AUTH;
    return;
  }
  if (err instanceof CloudForbiddenError) {
    consolePresentationOutput.stderr(
      chalk.red("Access denied (HTTP 403). Check your token scopes and organization access."),
      "hosted.forbidden",
    );
    process.exitCode = EXIT_AUTH;
    return;
  }
  if (err instanceof CloudNetworkError) {
    consolePresentationOutput.stderr(
      chalk.red(`Network error: ${err.message}`),
      "hosted.network-error",
    );
    process.exitCode = EXIT_NET;
    return;
  }
  if (err instanceof CloudError) {
    consolePresentationOutput.stderr(
      chalk.red(`API error (HTTP ${err.status ?? "?"}): ${err.message}`),
      "hosted.api-error",
    );
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  consolePresentationOutput.stderr(
    chalk.red(err instanceof Error ? err.message : String(err)),
    "hosted.error",
  );
  process.exitCode = EXIT_USER_ERROR;
}

async function runModels(opts: { json?: boolean }): Promise<void> {
  let client: CloudClient;
  try {
    client = await loadClient();
  } catch {
    return; // loadClient already set exitCode + printed
  }

  try {
    const [response, account] = await Promise.all([
      client.getInferenceModels(),
      client.getInferenceAccount().catch(() => null),
    ]);
    const models = response.data;

    if (opts.json) {
      consolePresentationOutput.stdout(JSON.stringify(models, null, 2), "hosted.models-json");
      process.exitCode = EXIT_OK;
      return;
    }

    if (models.length === 0) {
      consolePresentationOutput.stdout("No qualified hosted models are available. No local model fallback will be selected.", "hosted.models-empty");
      if (account?.allowance) {
        consolePresentationOutput.stdout(formatAllowance(account.allowance), "hosted.models-allowance");
        for (const model of account.allowance.models) {
          consolePresentationOutput.stdout(`  ${model.id}: ${model.state} · ${model.reason ?? model.qualification.status}`, "hosted.model-unavailable");
        }
      }
      process.exitCode = EXIT_OK;
      return;
    }

    // Format as a table
    const rows: string[] = [];
    const labelWidth = Math.min(
      Math.max(...models.map((m) => m.id.length), 10),
      48,
    );

    for (const model of models) {
      const id = model.id.padEnd(labelWidth);
      const ctx = formatTokenCount(model.context_length);
      const detail = account?.allowance?.models.find((row) => row.id === model.id && row.routeIdentity === model.routeIdentity);
      const estimate = detail ? formatSupplierUsd(detail.estimatedSupplierCostUsd) : "unavailable";
      rows.push(`  ${chalk.bold(id)}${model.recommended === true ? " · Recommended" : ""}  ${ctx} context  server scenario estimate: ${estimate}`);
      if (detail) {
        rows.push(`    Scenario: ${detail.scenario.freshInput} fresh input / ${detail.scenario.cacheRead} cached input / ${detail.scenario.output} output tokens (includes billed reasoning)`);
        rows.push(`    Fresh five-hour window estimate: ${detail.requestsPerFreshFiveHours ?? "unavailable"} requests; shared monthly and weekly limits still apply`);
      }
    }

    consolePresentationOutput.stdout(
      `\n${chalk.bold("Qualified 0sec Cloud models:")}\n` +
        rows.join("\n") + "\nEstimates are not invoices or admission guarantees. Actual supplier receipts debit the shared allowance; no model weights or customer-price multipliers.\n",
      "hosted.models-list",
    );
    process.exitCode = EXIT_OK;
  } catch (err) {
    handleApiError(err);
  }
}

async function runBalance(opts: { json?: boolean }): Promise<void> {
  let client: CloudClient;
  try {
    client = await loadClient();
  } catch {
    return; // loadClient already set exitCode + printed
  }

  try {
    const acct = await client.getInferenceAccount();
    if (opts.json) {
      consolePresentationOutput.stdout(JSON.stringify(acct, null, 2), "hosted.balance-json");
    } else if (acct.allowance !== undefined) {
      consolePresentationOutput.stdout(
        acct.allowance ? formatAllowance(acct.allowance) : "  Subscription allowance unavailable; no quota or entitlement inferred.",
        acct.allowance ? "hosted.balance-allowance" : "hosted.balance-allowance-unavailable",
      );
    } else {
      const percent = acct.credits?.remainingPercent;
      const percentLabel = percent === null || percent === undefined
        ? undefined
        : percent > 0 && percent < 0.1
          ? "<0.1"
          : percent > 99.9 && percent < 100
            ? ">99.9"
            : String(Number(percent.toFixed(1)));
      consolePresentationOutput.stdout(
        percentLabel === undefined
          ? "  Legacy credit usage percentage unavailable"
          : `  Legacy credits: ${chalk.bold(`${percentLabel}%`)} remaining (separate from subscription allowance)`,
        "hosted.balance",
      );
      if (acct.credits?.nextResetAt !== null && acct.credits?.nextResetAt !== undefined) {
        consolePresentationOutput.stdout(
          `  Next credit source reset: ${new Date(acct.credits.nextResetAt).toISOString()}`,
          "hosted.balance-reset",
        );
      }
    }
    process.exitCode = EXIT_OK;
  } catch (err) {
    handleApiError(err);
  }
}

function formatSupplierUsd(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value < 0) return "unavailable";
  if (value > 0 && value < 0.000001) return "<$0.000001";
  return `$${Number(value.toFixed(6))}`;
}

function formatAllowance(allowance: HostedAllowanceOverview): string {
  const lines = [
    `  Subscription: ${formatSupplierUsd(allowance.subscription.priceUsd)}/month · ${allowance.subscription.state}`,
    "  Shared supplier-cost allowance: every request counts against all applicable windows, not separate per-model budgets.",
    `  Admission: ${allowance.admission.allowed ? "available at this snapshot" : allowance.admission.reason ?? "unavailable"}`,
    `  Unresolved supplier exposure (including expired windows): ${formatSupplierUsd(allowance.unresolvedReservedUsd)}`,
  ];
  if (allowance.windows.length === 0) lines.push("  Allowance windows not established or unavailable.");
  const labels: Record<string, string> = { monthly: "Monthly", weekly: "Weekly", five_hour: "Five-hour" };
  const resets: Record<string, string> = { billing_period: "paid billing period", utc_monday: "UTC Monday", first_admission: "five hours from first admission" };
  for (const window of allowance.windows) {
    lines.push(`  ${labels[window.kind]}: ${formatSupplierUsd(window.availableUsd)} available / ${formatSupplierUsd(window.limitUsd)} limit · ${window.remainingPercent}%`);
    lines.push(`    Settled ${formatSupplierUsd(window.settledUsd)} · held ${formatSupplierUsd(window.reservedUsd)} (includes ${formatSupplierUsd(window.unknownReservedUsd)} unresolved)`);
    lines.push(`    Window ends ${window.endsAt} · ${resets[window.resetSemantics]}`);
  }
  lines.push("  Window expiry does not guarantee access: entitlement, unresolved holds and route qualification still apply.");
  lines.push(`  Server snapshot: ${allowance.snapshotAt}`);
  return lines.join("\n");
}

function formatTokenCount(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(0)}M`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(0)}K`;
  return String(count);
}