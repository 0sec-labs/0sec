// `0sec login`, `0sec models`, `0sec balance` — 0sec Cloud hosted
// inference CLI commands.
//
// Subcommands:
//   - login        alias for `0sec auth login` (opens browser/polls)
//   - models       list available hosted inference models
//   - balance      show available inference credit balance in USD equivalent
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
    .description("List 0sec Cloud models and catalog rates")
    .option("--json", "Output raw JSON instead of a formatted table")
    .action(async (opts: { json?: boolean }) => {
      await runModels(opts);
    });

  // ── 0sec balance ──
  program
    .command("balance")
    .description("Show inference credit balance in USD equivalent")
    .option("--json", "Output raw JSON instead of a formatted line")
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
    const response = await client.getInferenceModels();
    const models = response.data;

    if (opts.json) {
      consolePresentationOutput.stdout(JSON.stringify(models, null, 2), "hosted.models-json");
      process.exitCode = EXIT_OK;
      return;
    }

    if (models.length === 0) {
      consolePresentationOutput.stdout("No models available.", "hosted.models-empty");
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
      const inputPrice = `$${model.pricing.input_per_million_usd.toFixed(2)}/M`;
      const outputPrice = `$${model.pricing.output_per_million_usd.toFixed(2)}/M`;
      rows.push(
        `  ${chalk.bold(id)}  ${ctx} context  ${inputPrice} input  ${outputPrice} output`,
      );
    }

    consolePresentationOutput.stdout(
      `\n${chalk.bold("0sec Cloud models (catalog base rates):")}\n` +
        rows.join("\n") + "\nCredit charges use catalog rates, peak multipliers and provider usage receipts.\n",
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
    } else {
      consolePresentationOutput.stdout(
        `  Credit balance: ${chalk.bold(`$${acct.remainingUsd.toFixed(2)}`)} ${acct.currency} equivalent`,
        "hosted.balance",
      );
    }
    process.exitCode = EXIT_OK;
  } catch (err) {
    handleApiError(err);
  }
}

function formatTokenCount(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(0)}M`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(0)}K`;
  return String(count);
}