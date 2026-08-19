import type { Command } from "commander";
import chalk from "chalk";
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
} from "@pwnkit/core";

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
  "cloud commands are disabled. Set PWNKIT_FEATURE_CLOUD_SURFACE=1 to enable (read-only S3/credential probes, deny-by-default).";

/**
 * Live cloud-surface probes (#925). Every subcommand is gated behind BOTH the
 * PWNKIT_FEATURE_CLOUD_SURFACE feature flag AND an engagement ScopePolicy
 * (`--scope`). Both rails are deny-by-default and refuse with a clear message.
 * All probes are anonymous or read-only — nothing is mutated or exfiltrated.
 */
export function registerCloudCommand(program: Command): void {
  const cloud = program
    .command("cloud")
    .description(
      "Read-only cloud-surface probes (S3 public-access / takeover, AWS credential validation). Gated behind PWNKIT_FEATURE_CLOUD_SURFACE + an engagement scope, deny-by-default. #925",
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
        console.error(chalk.red(FEATURE_OFF_MSG));
        process.exitCode = 2;
        return;
      }
      const scope = loadScopeOrExit(opts.scope);
      if (!scope) return;

      let maxKeys: number | undefined;
      if (opts.maxKeys !== undefined) {
        maxKeys = Number(opts.maxKeys);
        if (!Number.isFinite(maxKeys) || maxKeys <= 0) {
          console.error(chalk.red(`Invalid --max-keys '${opts.maxKeys}': must be a positive number.`));
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
        console.log(JSON.stringify(out, null, 2));
        return;
      }
      for (const row of out) {
        if (row.refused) {
          console.log(`${chalk.bold(row.bucket)}  ${chalk.yellow("refused")} ${chalk.dim(row.refused)}`);
          continue;
        }
        const p = row.probe!;
        const verdictColour = p.verdict === "public" ? chalk.red : p.verdict === "not-found" ? chalk.yellow : chalk.dim;
        console.log(`${chalk.bold(row.bucket)}  ${verdictColour(p.verdict)} ${chalk.dim(`(sev ${p.severity}, list ${p.listStatus})`)}`);
        console.log(`  ${chalk.dim(p.note)}`);
        if (row.takeover?.takeoverable) {
          console.log(`  ${chalk.red("takeover-able")} ${chalk.dim(row.takeover.note)}`);
        }
        if (p.sampleKeys.length > 0) {
          console.log(`  keys: ${p.sampleKeys.join(", ")}`);
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
        console.error(chalk.red(FEATURE_OFF_MSG));
        process.exitCode = 2;
        return;
      }
      const scope = loadScopeOrExit(opts.scope);
      if (!scope) return;

      const accessKeyId = (opts.accessKeyId ?? process.env.AWS_ACCESS_KEY_ID ?? "").trim();
      const secretAccessKey = (opts.secretAccessKey ?? process.env.AWS_SECRET_ACCESS_KEY ?? "").trim();
      const sessionToken = opts.sessionToken ?? process.env.AWS_SESSION_TOKEN ?? undefined;
      if (!accessKeyId || !secretAccessKey) {
        console.error(
          chalk.red(
            "access key + secret required: pass --access-key-id/--secret-access-key or set $AWS_ACCESS_KEY_ID/$AWS_SECRET_ACCESS_KEY.",
          ),
        );
        process.exitCode = 2;
        return;
      }

      let result: CredentialValidationResult;
      try {
        result = await validateAwsCredentials({ accessKeyId, secretAccessKey, sessionToken, region: opts.region });
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exitCode = 2;
        return;
      }

      if (opts.json) {
        // Never echo the credential — only the non-secret verdict.
        console.log(
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
        );
        return;
      }
      const valid = result.valid ? chalk.green("valid") : chalk.dim("invalid");
      console.log(`credential: ${valid} ${chalk.dim(`(sev ${result.severity})`)}`);
      if (result.valid) {
        if (result.arn) console.log(`  arn: ${result.arn}`);
        if (result.account) console.log(`  account: ${result.account}`);
        console.log(`  effective read perms: ${result.effectivePermissions.join(", ")}`);
      }
      console.log(`  ${chalk.dim(result.note)}`);
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
    console.error(chalk.red(`Failed to load --scope '${path}': ${err instanceof Error ? err.message : String(err)}`));
    process.exitCode = 2;
    return undefined;
  }
}
