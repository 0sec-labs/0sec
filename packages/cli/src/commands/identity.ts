import type { Command } from "commander";
import chalk from "chalk";
import {
  runIdentityAssessment,
  ScopePolicy,
  type IdentityAssessmentResult,
  type IdentityFinding,
  type IdentitySeverity,
} from "@0sec/core";

/** Env var holding the Graph bearer token. Never a CLI argument — see below. */
const TOKEN_ENV = "0SEC_GRAPH_ACCESS_TOKEN";

const DEFAULT_TIMEOUT_MS = "300000";

const SEVERITY_ORDER: IdentitySeverity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLOR: Record<IdentitySeverity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.dim,
};

interface IdentityOptions {
  tenant: string;
  json?: boolean;
  timeout?: string;
  scope?: string;
}

export function registerIdentityCommand(program: Command): void {
  program
    .command("identity")
    .description(
      "Read-only posture assessment of a Microsoft Entra ID (Azure AD) tenant — privileged role assignments, conditional-access coverage, app registrations, service principals, and federated-domain trust. The Graph access token is read from the " +
        TOKEN_ENV +
        " environment variable; it is never accepted as an argument.",
    )
    .requiredOption("--tenant <tenantId>", "Entra tenant id (GUID) the supplied token is expected to belong to")
    .option("--json", "Emit the assessment result as machine-readable JSON")
    .option("--timeout <ms>", "Wall-clock bound on the whole assessment in milliseconds", DEFAULT_TIMEOUT_MS)
    .option(
      "--scope <file>",
      "Path to a JSON scope file ({in_scope, out_of_scope}). When supplied, graph.microsoft.com must be explicitly in scope or no request goes out.",
    )
    .action(async (opts: IdentityOptions) => {
      const tenant = opts.tenant?.trim();
      if (!tenant) {
        console.error(chalk.red("Invalid --tenant: expected a non-empty Entra tenant id."));
        process.exitCode = 2;
        return;
      }

      let timeout = Number(DEFAULT_TIMEOUT_MS);
      if (opts.timeout !== undefined) {
        const parsed = Number(opts.timeout);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          console.error(chalk.red(`Invalid --timeout '${opts.timeout}': must be a positive number (ms).`));
          process.exitCode = 2;
          return;
        }
        timeout = parsed;
      }

      // The token is deliberately env-only: a CLI argument lands in `ps` output
      // and in shell history, and a Graph directory-read token is a
      // whole-tenant credential.
      const accessToken = process.env[TOKEN_ENV]?.trim();
      if (!accessToken) {
        console.error(
          chalk.red(
            `Missing ${TOKEN_ENV}. Export a Microsoft Graph access token with directory read scopes, e.g.\n` +
              `  export ${TOKEN_ENV}="$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)"\n` +
              `The token is read from the environment only — 0sec never accepts it as a command-line argument.`,
          ),
        );
        process.exitCode = 2;
        return;
      }

      let scope: ScopePolicy | undefined;
      if (opts.scope) {
        try {
          scope = ScopePolicy.fromJsonFile(opts.scope);
        } catch (err) {
          console.error(
            chalk.red(`Failed to load --scope '${opts.scope}': ${err instanceof Error ? err.message : String(err)}`),
          );
          process.exitCode = 2;
          return;
        }
      }

      // One timer drives both halves of the bound: it aborts in-flight Graph
      // requests *and* rejects the deadline promise in the same callback, so a
      // timed-out run always surfaces as a timeout rather than as a silently
      // truncated (and therefore misleading) partial assessment.
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error(`Assessment exceeded --timeout ${timeout}ms.`));
        }, timeout);
      });

      let result: IdentityAssessmentResult;
      try {
        result = await Promise.race([
          runIdentityAssessment({
            accessToken,
            scope,
            fetchImpl: ((input: RequestInfo | URL, init?: RequestInit) =>
              fetch(input, { ...init, signal: controller.signal })) as typeof fetch,
          }),
          deadline,
        ]);
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 2;
        return;
      } finally {
        if (timer) clearTimeout(timer);
      }

      // `collectTenantSnapshot` is fault-tolerant by design: a rejected token
      // produces warnings and an empty snapshot rather than a thrown error. An
      // empty snapshot is a failed run, not a clean tenant, so fail loudly.
      const collected = Object.values(result.snapshot.counts).reduce((a, b) => a + b, 0);
      if (collected === 0) {
        console.error(
          chalk.red(
            `Graph collection returned no data for tenant ${tenant}. The token is likely expired, scoped to the wrong audience, or missing directory read permissions.`,
          ),
        );
        for (const warning of result.snapshot.warnings) console.error(chalk.dim(`  - ${warning}`));
        process.exitCode = 2;
        return;
      }

      // Guard against pointing a token at the wrong tenant: the assessed tenant
      // comes from /organization on the token itself, so a mismatch means the
      // operator is looking at a tenant they did not ask for.
      if (result.tenantId !== "unknown" && result.tenantId.toLowerCase() !== tenant.toLowerCase()) {
        console.error(
          chalk.red(
            `Tenant mismatch: --tenant ${tenant} but the ${TOKEN_ENV} token belongs to tenant ${result.tenantId}. Refusing to report an assessment of a tenant that was not requested.`,
          ),
        );
        process.exitCode = 2;
        return;
      }
      if (result.tenantId === "unknown") {
        console.error(
          chalk.yellow(
            `Warning: could not read /organization, so the tenant id could not be confirmed against --tenant ${tenant}.`,
          ),
        );
      }

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      renderIdentity(result);
    });
}

function renderIdentity(result: IdentityAssessmentResult): void {
  console.log(chalk.bold(`identity: ${result.tenantDisplayName ?? result.tenantId}`));
  console.log(`  tenant: ${result.tenantId}`);
  console.log(`  findings: ${result.summary.total}`);
  for (const severity of SEVERITY_ORDER) {
    const count = result.summary.bySeverity[severity] ?? 0;
    if (count > 0) console.log(`    ${SEVERITY_COLOR[severity](severity)}: ${count}`);
  }
  const counts = Object.entries(result.snapshot.counts)
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
  console.log(`  collected: ${counts}`);
  console.log(`  duration: ${result.durationMs}ms (collection ${result.collectionMs}ms)`);
  console.log("");

  // Required by the module contract: a partial snapshot cannot be read as a
  // clean bill of health, and the renderer has to say so.
  if (result.snapshot.partial) {
    console.log(
      chalk.yellow(
        `PARTIAL SNAPSHOT — ${result.snapshot.warnings.length} collection step(s) failed. A short finding list here is NOT evidence of a healthy tenant.`,
      ),
    );
    for (const warning of result.snapshot.warnings) console.log(chalk.dim(`  - ${warning}`));
    console.log("");
  }

  const bySeverity: Record<string, IdentityFinding[]> = {};
  for (const finding of result.findings) (bySeverity[finding.severity] ??= []).push(finding);

  for (const severity of SEVERITY_ORDER) {
    const findings = bySeverity[severity];
    if (!findings?.length) continue;
    console.log(SEVERITY_COLOR[severity](chalk.bold(severity.toUpperCase())));
    for (const finding of findings) {
      console.log(`  ${chalk.bold(finding.title)} ${chalk.dim(`[${finding.check}]`)}`);
      console.log(`    ${finding.description}`);
      if (finding.affectedPrincipals.length > 0) {
        const names = finding.affectedPrincipals
          .slice(0, 5)
          .map((p) => p.displayName ?? p.userPrincipalName ?? p.id)
          .join(", ");
        const more = finding.affectedPrincipals.length > 5 ? ` (+${finding.affectedPrincipals.length - 5} more)` : "";
        console.log(chalk.dim(`    affected: ${names}${more}`));
      }
      console.log(chalk.dim(`    fix: ${finding.remediation}`));
    }
    console.log("");
  }
}
