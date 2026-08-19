import type { Command } from "commander";
import chalk from "chalk";
import {
  runJsRecon,
  enumerateJsChunkUrls,
  ScopePolicy,
  type JsReconResult,
  type FetchTextResult,
} from "@0sec/core";

interface JsReconCliOptions {
  json?: boolean;
  scope?: string;
  timeout?: string;
  maxFiles?: string;
}

/**
 * Mine a live site's JavaScript bundles for endpoints + redacted secret hits.
 *
 * DENY-BY-DEFAULT: every JS URL is scope-checked before fetch and the library
 * fetches NOTHING without a `ScopePolicy`. The CLI refuses up front when
 * `--scope` is absent so the operator gets a clear message instead of a silent
 * no-op. Secret values are never printed — only the redacted excerpt the
 * library returns.
 */
export function registerJsReconCommand(program: Command): void {
  program
    .command("js-recon")
    .description(
      "Fetch the JS a live site serves and mine each bundle for endpoints/API base URLs + embedded secrets (redacted). Scope-gated, deny-by-default. #927",
    )
    .argument("<url>", "Target page URL whose <script> bundles are mined, e.g. https://app.example.com")
    .requiredOption(
      "--scope <file>",
      "Path to a JSON scope file ({in_scope, out_of_scope}). REQUIRED — every JS URL is checked against it before any fetch. No scope = nothing fetched.",
    )
    .option("--timeout <ms>", "Per-request fetch timeout in milliseconds", "10000")
    .option("--max-files <n>", "Maximum JS files to fetch (clamped to [0,100])")
    .option("--json", "Emit the result as machine-readable JSON")
    .action(async (url: string, opts: JsReconCliOptions) => {
      const timeout = Number(opts.timeout ?? "10000");
      if (!Number.isFinite(timeout) || timeout <= 0) {
        console.error(chalk.red(`Invalid --timeout '${opts.timeout}': must be a positive number (ms).`));
        process.exitCode = 2;
        return;
      }

      let maxFiles: number | undefined;
      if (opts.maxFiles !== undefined) {
        maxFiles = Number(opts.maxFiles);
        if (!Number.isFinite(maxFiles) || maxFiles < 0) {
          console.error(chalk.red(`Invalid --max-files '${opts.maxFiles}': must be a non-negative number.`));
          process.exitCode = 2;
          return;
        }
      }

      // Deny-by-default. `--scope` is requiredOption, so commander already
      // enforces presence; load + validate it before any network touch.
      let scope: ScopePolicy;
      try {
        scope = ScopePolicy.fromJsonFile(opts.scope!);
      } catch (err) {
        console.error(chalk.red(`Failed to load --scope '${opts.scope}': ${err instanceof Error ? err.message : String(err)}`));
        process.exitCode = 2;
        return;
      }

      const fetchText = async (target: string): Promise<FetchTextResult> => {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), timeout);
        try {
          const res = await fetch(target, { signal: ctrl.signal });
          const body = await res.text();
          return { status: res.status, body };
        } catch {
          return { status: 0, body: "" };
        } finally {
          clearTimeout(t);
        }
      };

      // Step 1: fetch the page and extract its <script src> bundle URLs. The
      // page fetch itself is scope-gated — an out-of-scope page yields no
      // script URLs and therefore no JS sweep.
      if (!scope.match(url).allowed) {
        console.error(chalk.red(`Target page '${url}' is out of scope — refusing (deny-by-default).`));
        process.exitCode = 2;
        return;
      }
      const page = await fetchText(url);
      const scriptUrls = page.status === 200 && page.body ? enumerateJsChunkUrls(page.body, url) : [];

      // Step 2: mine the bundles. runJsRecon re-checks every URL against scope
      // before fetching, so scope is enforced at both the page and bundle leg.
      let result: JsReconResult;
      try {
        result = await runJsRecon({ scriptUrls, scope, fetchText, maxFiles });
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 2;
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      renderJsRecon(url, result);
    });
}

function renderJsRecon(url: string, result: JsReconResult): void {
  console.log(chalk.bold(`js-recon: ${url}`));
  console.log(`  scanned: ${result.scanned.length}  skipped: ${result.skipped.length}`);
  console.log("");

  console.log(chalk.bold(`endpoints (${result.endpoints.length})`));
  for (const ep of result.endpoints) {
    console.log(`  ${ep.value}`);
  }
  console.log("");

  if (result.apiBaseUrls.length > 0) {
    console.log(chalk.bold(`api base URLs (${result.apiBaseUrls.length})`));
    for (const base of result.apiBaseUrls) console.log(`  ${base}`);
    console.log("");
  }

  console.log(chalk.bold(`secrets (${result.secrets.length})`));
  for (const s of result.secrets) {
    const conf = s.confidence === "high" ? chalk.red(s.confidence) : chalk.yellow(s.confidence);
    // s.match is already redacted by the library — never the raw value.
    console.log(`  ${s.kind} [${conf}] ${chalk.dim(s.match)} ${chalk.dim(`(${s.chunk})`)}`);
  }
}
