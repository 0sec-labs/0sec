import type {
  ScanConfig,
  ScanContext,
  TargetInfo,
  Finding,
  AttackResult,
} from "@pwnkit/shared";

export function createScanContext(config: ScanConfig): ScanContext {
  return {
    config,
    target: {
      url: normalizeTargetUrl(config.target),
      type: "unknown",
    },
    findings: [],
    attacks: [],
    warnings: [],
    startedAt: Date.now(),
  };
}

/**
 * Normalize the user-supplied target string into a URL the agent's
 * tools can hand to `new URL(input, base)` without throwing.
 *
 * Without this, bare hostnames like `doruk.ch` (which is how the cloud
 * dashboard often stores web targets, and how a CLI user would type
 * one) blow up every URL-using tool — `crawl`, `http_request`, the
 * playwright `goto` path. Each tool's internal `new URL(startUrl,
 * ctx.target.url)` requires the base to be an absolute URL, so a bare
 * hostname is fatal regardless of the tool.
 *
 * Rules:
 *   - empty / non-string → returned as-is so package targets
 *     (`lodash`, `requests`, etc.) keep flowing through audit unchanged
 *   - already has scheme (`http://` / `https://`) → returned as-is
 *   - everything else (bare hostname, host:port, host/path, IP) →
 *     prefixed with `https://`
 *
 * Stays defensive: a value like `:::not-a-url:::` simply gets
 * `https://` prefixed and lets the downstream URL parser reject it
 * with the real reason; the agent's tool error path handles that.
 */
export function normalizeTargetUrl(input: string): string {
  if (typeof input !== "string" || input.length === 0) return input;
  const trimmed = input.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

export function addFinding(ctx: ScanContext, finding: Finding): void {
  ctx.findings.push(finding);
}

export function addAttackResult(ctx: ScanContext, result: AttackResult): void {
  ctx.attacks.push(result);
}

export function updateTarget(ctx: ScanContext, info: Partial<TargetInfo>): void {
  ctx.target = { ...ctx.target, ...info };
}

export function finalize(ctx: ScanContext): ScanContext {
  ctx.completedAt = Date.now();
  return ctx;
}
