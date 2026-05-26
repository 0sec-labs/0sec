import { gzipSync } from "zlib";
import chalk from "chalk";
import type { ScanReport, AuditReport, ReviewReport, ScanDepth, RuntimeMode } from "@pwnkit/shared";

export interface ApiRuntimeAvailability {
  configured: boolean;
  valid: boolean;
  providerLabel: string;
  error?: string;
}

export interface RuntimeAvailability {
  hasApiKey: boolean;
  availableRuntimes: string[];
  apiRuntime: ApiRuntimeAvailability;
}

export async function getRuntimeAvailability(): Promise<RuntimeAvailability> {
  const { detectAvailableRuntimes, LlmApiRuntime } = await import("@pwnkit/core");
  const apiRuntimeDiagnostics = new LlmApiRuntime({ type: "api", timeout: 5_000 }).getConfigurationDiagnostics();
  const hasApiKey = apiRuntimeDiagnostics.valid;
  const availableRuntimes = [...(await detectAvailableRuntimes())];

  return {
    hasApiKey,
    availableRuntimes,
    apiRuntime: {
      configured: apiRuntimeDiagnostics.reason !== "missing_key",
      valid: apiRuntimeDiagnostics.valid,
      providerLabel: apiRuntimeDiagnostics.providerLabel,
      error: apiRuntimeDiagnostics.fatalError,
    },
  };
}

/**
 * Check if an API key or CLI runtime is available for AI analysis.
 * Prints a warning if not — the scan will still run but without AI.
 */
export async function checkRuntimeAvailability(runtime: RuntimeMode): Promise<void> {
  const availability = await getRuntimeAvailability();
  const { hasApiKey, availableRuntimes, apiRuntime } = availability;

  if (hasApiKey) return;

  console.log("");
  if ((runtime === "api" || runtime === "auto") && apiRuntime.configured && apiRuntime.error) {
    console.log(chalk.red(`  ${apiRuntime.providerLabel} config error: ${apiRuntime.error.split("\n")[0]}`));
  }
  if (runtime === "api") {
    console.log(chalk.yellow(
      apiRuntime.configured
        ? "  Warning: `--runtime api` needs a valid provider configuration. AI analysis will fail until this is fixed."
        : "  Warning: `--runtime api` needs provider credentials. AI analysis may be skipped.",
    ));
  } else if (availableRuntimes.length > 0) {
    console.log(chalk.cyan(`  Using local runtime(s): ${availableRuntimes.join(", ")}`));
  } else {
    console.log(chalk.yellow("  Warning: No API key or local agent runtime detected. AI analysis will be skipped."));
  }
  console.log(chalk.gray("  Provider credentials: PWNKIT_CHATGPT_ACCESS_TOKEN | PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN, OPENROUTER_API_KEY, ANTHROPIC_API_KEY, AZURE_OPENAI_API_KEY, OPENAI_API_KEY"));
  console.log("");
}

/**
 * Encode a report as a base64url-encoded gzipped JSON string for use in a share URL.
 */
export function buildShareUrl(report: ScanReport | AuditReport | ReviewReport): string {
  const json = JSON.stringify(report);
  const compressed = gzipSync(Buffer.from(json, "utf-8"));
  const b64 = compressed.toString("base64url");
  return `https://0sec.ai/r#${b64}`;
}

export function depthLabel(depth: ScanDepth): string {
  switch (depth) {
    case "quick":
      return "~5 probes";
    case "default":
      return "~50 probes";
    case "deep":
      return "full coverage";
  }
}
