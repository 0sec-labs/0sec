import type { Command } from "commander";
import chalk from "chalk";
import { consolePresentationOutput } from "../presentation/process-output.js";
import {
  probeS3Bucket,
  classifyTakeover,
  bucketInScope,
  validateAwsCredentials,
  features,
  ScopePolicy,
  type BucketProbeResult,
  type TakeoverVerdict,
  type CredentialValidationResult,
} from "@0sec/core";

interface S3ProbeOptions {
  scope?: string;
  region?: string;
  maxKeys?: string;
  json?: boolean;
}

interface ValidateCredsOptions {
  scope?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  region?: string;
  json?: boolean;
}

const FEATURE_OFF_MSG =
  "cloud commands are disabled. Set 0SEC_FEATURE_CLOUD_SURFACE=1 to enable (read-only S3/credential probes, deny-by-default).";

/**
 * Live cloud-surface probes (#925). Every subcommand is gated behind BOTH the
 * 0SEC_FEATURE_CLOUD_SURFACE feature flag AND an engagement ScopePolicy
 * (`--scope`). Both rails are deny-by-default and refuse with a clear message.
 * All probes are anonymous or read-only — nothing is mutated or exfiltrated.
 */
export function registerCloudCommand(program: Command): void {
  const cloud = program
    .command("cloud")
    .description(
      "Read-only cloud-surface probes (S3 public-access / takeover, AWS credential validation). Gated behind 0SEC_FEATURE_CLOUD_SURFACE + an engagement scope, deny-by-default. #925",
    );

  cloud
    .command("s3-probe")
    .description(
      "Anonymously probe one or more S3 buckets for public listability + orphaned-bucket takeover. Read-only, no credentials sent.",
    )
    .argument("<bucket...>", "Bucket name(s) to probe, e.g. acme-assets")
    .requiredOption(
      "--scope <file>",
      "Path to a JSON scope file ({in_scope, out_of_scope}). REQUIRED — each bucket's S3 endpoint must be in scope or it is refused.",
    )
    .option("--region <region>", "Bucket home region (default us-east-1 / global endpoint)")
    .option("--max-keys <n>", "Max object keys to sample from a public listing (1-100, default 10)")
    .option("--json", "Emit results as machine-readable JSON")
    .action(async (buckets: string[], opts: S3ProbeOptions) => {
      if (!features.cloudSurface) {
        consolePresentationOutput.stderr(chalk.red(FEATURE_OFF_MSG), "cloud.feature-off");
        process.exitCode = 2;
        return;
      }
      const scope = loadScopeOrExit(opts.scope);
      if (!scope) return;

      let maxKeys: number | undefined;
      if (opts.maxKeys !== undefined) {
        maxKeys = Number(opts.maxKeys);
        if (!Number.isFinite(maxKeys) || maxKeys <= 0) {
          consolePresentationOutput.stderr(chalk.red(`Invalid --max-keys '${opts.maxKeys}': must be a positive number.`), "cloud.s3-probe.invalid-keys");
          process.exitCode = 2;
          return;
        }
      }

      const out: Array<{ bucket: string; probe?: BucketProbeResult; takeover?: TakeoverVerdict; refused?: string }> = [];
      for (const bucket of buckets) {
        // Deny-by-default scope gate per bucket — the same predicate the agent
        // tool uses. Out-of-scope buckets are never probed.
        const inScope = bucketInScope(bucket, scope, opts.region);
        if (!inScope.allowed) {
          out.push({ bucket, refused: inScope.reason });
          continue;
        }
        const probe = await probeS3Bucket(bucket, { region: opts.region, maxKeys });
        const takeover = classifyTakeover(probe);
        out.push({ bucket, probe, takeover });
      }

      if (opts.json) {
        consolePresentationOutput.stdout(JSON.stringify(out, null, 2), "cloud.s3-probe.json");
        return;
      }
      for (const row of out) {
        if (row.refused) {
          consolePresentationOutput.stdout(`${chalk.bold(row.bucket)}  ${chalk.yellow("refused")} ${chalk.dim(row.refused)}`, "cloud.s3-probe.refused");
          continue;
        }
        const p = row.probe!;
        const verdictColour = p.verdict === "public" ? chalk.red : p.verdict === "not-found" ? chalk.yellow : chalk.dim;
        consolePresentationOutput.stdout(`${chalk.bold(row.bucket)}  ${verdictColour(p.verdict)} ${chalk.dim(`(sev ${p.severity}, list ${p.listStatus})`)}`, "cloud.s3-probe.result");
        consolePresentationOutput.stdout(`  ${chalk.dim(p.note)}`, "cloud.s3-probe.note");
        if (row.takeover?.takeoverable) {
          consolePresentationOutput.stdout(`  ${chalk.red("takeover-able")} ${chalk.dim(row.takeover.note)}`, "cloud.s3-probe.takeover");
        }
        if (p.sampleKeys.length > 0) {
          consolePresentationOutput.stdout(`  keys: ${p.sampleKeys.join(", ")}`, "cloud.s3-probe.keys");
        }
      }
    });

  cloud
    .command("validate-creds")
    .description(
      "Validate a harvested AWS credential READ-ONLY via sts:GetCallerIdentity + read-only over-privilege probes. No mutation, ever.",
    )
    .requiredOption(
      "--scope <file>",
      "Path to a JSON scope file ({in_scope, out_of_scope}). REQUIRED — validating a credential is recon against the target org, deny-by-default.",
    )
    .option("--access-key-id <id>", "AWS access key id (defaults to $AWS_ACCESS_KEY_ID)")
    .option("--secret-access-key <key>", "AWS secret access key (defaults to $AWS_SECRET_ACCESS_KEY)")
    .option("--session-token <token>", "AWS session token (defaults to $AWS_SESSION_TOKEN)")
    .option("--region <region>", "AWS region for the STS call (default us-east-1)")
    .option("--json", "Emit the result as machine-readable JSON")
    .action(async (opts: ValidateCredsOptions) => {
      if (!features.cloudSurface) {
        consolePresentationOutput.stderr(chalk.red(FEATURE_OFF_MSG), "cloud.feature-off");
        process.exitCode = 2;
        return;
      }
      const scope = loadScopeOrExit(opts.scope);
      if (!scope) return;

      const accessKeyId = (opts.accessKeyId ?? process.env.AWS_ACCESS_KEY_ID ?? "").trim();
      const secretAccessKey = (opts.secretAccessKey ?? process.env.AWS_SECRET_ACCESS_KEY ?? "").trim();
      const sessionToken = opts.sessionToken ?? process.env.AWS_SESSION_TOKEN ?? undefined;
      if (!accessKeyId || !secretAccessKey) {
        consolePresentationOutput.stderr(chalk.red(
          "access key + secret required: pass --access-key-id/--secret-access-key or set $AWS_ACCESS_KEY_ID/$AWS_SECRET_ACCESS_KEY.",
        ), "cloud.validate-creds.missing-creds");
        process.exitCode = 2;
        return;
      }

      let result: CredentialValidationResult;
      try {
        result = await validateAwsCredentials({ accessKeyId, secretAccessKey, sessionToken, region: opts.region });
      } catch (err) {
        consolePresentationOutput.stderr(chalk.red(err instanceof Error ? err.message : String(err)), "cloud.validate-creds.error");
        process.exitCode = 2;
        return;
      }

      if (opts.json) {
        // Never echo the credential — only the non-secret verdict.
        consolePresentationOutput.stdout(
          JSON.stringify(
            {
              valid: result.valid,
              account: result.account,
              userId: result.userId,
              arn: result.arn,
              effectivePermissions: result.effectivePermissions,
              severity: result.severity,
              note: result.note,
            },
            null,
            2,
          ),
          "cloud.validate-creds.json",
        );
        return;
      }
      const valid = result.valid ? chalk.green("valid") : chalk.dim("invalid");
      consolePresentationOutput.stdout(`credential: ${valid} ${chalk.dim(`(sev ${result.severity})`)}`, "cloud.validate-creds.result");
      if (result.valid) {
        if (result.arn) consolePresentationOutput.stdout(`  arn: ${result.arn}`, "cloud.validate-creds.arn");
        if (result.account) consolePresentationOutput.stdout(`  account: ${result.account}`, "cloud.validate-creds.account");
        consolePresentationOutput.stdout(`  effective read perms: ${result.effectivePermissions.join(", ")}`, "cloud.validate-creds.permissions");
      }
      consolePresentationOutput.stdout(`  ${chalk.dim(result.note)}`, "cloud.validate-creds.note");
    });
}

/**
 * Load + validate a `--scope` file; on failure print a clear message and set a
 * non-zero exit code, returning `undefined` so the caller bails. `--scope` is a
 * requiredOption on every subcommand, so the only failure mode here is an
 * unreadable / malformed file.
 */
function loadScopeOrExit(path: string | undefined): ScopePolicy | undefined {
  try {
    return ScopePolicy.fromJsonFile(path!);
  } catch (err) {
    consolePresentationOutput.stderr(chalk.red(`Failed to load --scope '${path}': ${err instanceof Error ? err.message : String(err)}`), "cloud.scope.load-error");
    process.exitCode = 2;
    return undefined;
  }
}
