/**
 * Live cloud-surface prober (pwnkit#925, part of #923 CodeWall parity).
 *
 * What this module answers — the BCG-post cloud angle that pwnkit was blind to.
 * Today the engine only spots hardcoded AWS keys *in source*
 * (`malicious-detector.ts`) and harvests `AKIA…` ids into the loot ledger
 * (`loot.ts`). It never *touches* the cloud. This module adds three live,
 * READ/VERIFY-ONLY probes against AWS:
 *
 *   1. `probeS3Bucket`    — does a named bucket exist, and is it public?
 *      Anonymous `GET /` + `GET /?acl`. No credentials, no SDK.
 *   2. `classifyTakeover` — is a *referenced-but-nonexistent* bucket
 *      re-creatable? The exact BCG finding: an orphaned integration points at
 *      a deleted bucket; an attacker re-creates it and intercepts whatever the
 *      integration writes/reads. Derived from the `NoSuchBucket` signal.
 *   3. `validateAwsCredentials` — given a harvested access key + secret,
 *      call `sts:GetCallerIdentity` (the read-only "whoami" of AWS) and
 *      optionally a handful of read-only `List*` calls to gauge how
 *      over-privileged the key is. SigV4 is computed with Node's built-in
 *      `crypto` (HMAC-SHA256) — no `@aws-sdk/*` dependency.
 *
 * DESIGN — mirrors `auth-boundary-prober.ts`:
 *   - Pure functions + an injectable `FetchLike` (default `globalThis.fetch`)
 *     so every verdict is unit-testable with mocked responses — NO live cloud
 *     calls in tests.
 *   - Verdict classifiers (`classifyBucketAccess`, `classifyTakeover`) are
 *     pure over the response shape.
 *
 * SAFETY — strictly read-only by default (the issue's hard requirement):
 *   - S3 probes are anonymous `GET` of `/` and `/?acl` only. Never PUT/DELETE,
 *     never write an object, never create the takeover-able bucket — we only
 *     *classify* it as re-creatable and report it; re-creation is an operator
 *     decision, not something the engine does.
 *   - Credential validation calls ONLY zero-impact read APIs:
 *     `sts:GetCallerIdentity` and read-only `List*` / `Get*CallerIdentity`-class
 *     actions. `assertReadOnlyAction` rejects anything that is not on the
 *     allowlist, so a future caller cannot smuggle a mutating action through.
 *   - Object listings are capped (`max-keys=…`) and bodies truncated — minimal
 *     proof, never bulk exfiltration.
 *
 * SCOPE GATING — deny-by-default, mirroring recon/scope.ts (#924):
 *   Probing a target org's bucket-name space or validating a harvested
 *   credential is RECON AGAINST THAT ORG, not an infra call like web_search —
 *   so it must respect the engagement scope, never the validateTargetUrl
 *   external-service exemption. `bucketInScope` is a pure predicate that:
 *     - returns FALSE when no scope policy is configured (deny-by-default), and
 *     - otherwise checks the bucket's virtual-host endpoint against the policy.
 *   The tool handlers (agent/tools.ts) skip out-of-scope buckets as a no-op and
 *   refuse credential validation entirely when no engagement scope exists.
 *
 * SCOPE: AWS/S3 is the MVP per the issue. Azure (Blob Storage SAS / orphaned
 * CNAME) and GCP (GCS uniform/ACL) are deferred follow-ups — the verdict
 * vocabulary here (`public` / `takeover` / `over-privileged`) is provider
 * neutral so they can be added as sibling probers without reshaping callers.
 */

import { createHmac, createHash } from "node:crypto";

// ── Injectable fetch (mirrors auth-boundary-prober.FetchLike) ──

export type CloudFetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  headers?: { get(name: string): string | null } | Record<string, string>;
  text: () => Promise<string>;
}>;

const DEFAULT_FETCH: CloudFetchLike = (url, init) =>
  // foxguard:ignore — the URL is a fixed AWS service endpoint
  // (s3/sts/iam.amazonaws.com). The TARGET authorization happens upstream in
  // the tool handler (`bucketInScope` / scope-presence gate), NOT here — this
  // is the transport, after the deny-by-default scope check has passed.
  fetch(url, init as RequestInit) as unknown as ReturnType<CloudFetchLike>;

const PROBE_TIMEOUT_MS = 15_000;

// ── S3 bucket public-access probe ──

export type BucketAccessVerdict =
  /** Anonymous read succeeded — bucket is PUBLIC (or its ACL grants AllUsers). */
  | "public"
  /** Bucket exists but anonymous access is denied (403). Boundary holds. */
  | "private"
  /** Bucket does not exist (404 / NoSuchBucket) — candidate for takeover. */
  | "not-found"
  /** Region redirect, throttle, or ambiguous status — could not decide. */
  | "inconclusive";

export interface BucketProbeResult {
  bucket: string;
  /** The regional/virtual-host endpoint probed. */
  endpoint: string;
  verdict: BucketAccessVerdict;
  /** Severity of a PUBLIC verdict; "info" otherwise. */
  severity: "high" | "medium" | "low" | "info";
  /** HTTP status of the anonymous `GET /` probe. */
  listStatus: number;
  /** Whether the anonymous `GET /?acl` returned a readable ACL document. */
  aclReadable: boolean;
  /** Object keys observed in the public listing (capped, non-secret evidence). */
  sampleKeys: string[];
  /** Human-readable rationale. */
  note: string;
}

/**
 * The S3 error code S3 returns in the XML body. We only need to distinguish a
 * handful for the verdict; this keeps us off the XML-parser dependency.
 */
export function extractS3ErrorCode(body: string): string | null {
  const m = /<Code>([^<]+)<\/Code>/i.exec(body);
  return m ? m[1] : null;
}

/** Pull up to `cap` object keys out of a public ListBucketResult body. */
export function extractObjectKeys(body: string, cap = 10): string[] {
  const keys: string[] = [];
  const re = /<Key>([^<]+)<\/Key>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null && keys.length < cap) {
    keys.push(m[1]);
  }
  return keys;
}

/**
 * Pure verdict over the anonymous list-response. Separated so it is unit-tested
 * with synthetic statuses/bodies and never needs the network.
 */
export function classifyBucketAccess(
  listStatus: number,
  listBody: string,
): { verdict: BucketAccessVerdict; note: string } {
  if (listStatus === 200) {
    return { verdict: "public", note: "Anonymous GET / returned 200 — bucket contents are publicly listable." };
  }
  if (listStatus === 403) {
    return { verdict: "private", note: "Anonymous access denied (403 AccessDenied) — bucket exists but is not public." };
  }
  if (listStatus === 404) {
    const code = extractS3ErrorCode(listBody);
    return {
      verdict: "not-found",
      note: `Bucket does not exist (404${code ? ` ${code}` : ""}) — referenced-but-missing; check for takeover.`,
    };
  }
  if (listStatus === 301 || listStatus === 307) {
    return { verdict: "inconclusive", note: `Region redirect (${listStatus}) — retry against the bucket's home region endpoint.` };
  }
  return { verdict: "inconclusive", note: `Unexpected status ${listStatus} — could not classify bucket access.` };
}

/** Build the virtual-hosted–style S3 endpoint for a bucket. */
export function bucketEndpoint(bucket: string, region?: string): string {
  // us-east-1 uses the global endpoint; every other region is regional.
  if (region && region !== "us-east-1") {
    return `https://${bucket}.s3.${region}.amazonaws.com`;
  }
  return `https://${bucket}.s3.amazonaws.com`;
}

/**
 * Minimal scope-matcher shape — the subset of `ScopePolicy` this module needs.
 * Declared structurally so cloud-surface stays decoupled from the scope module
 * and is unit-testable with a stub matcher (no ScopePolicy construction).
 */
export interface CloudScopeMatcher {
  match(url: string): { allowed: boolean; reason: string };
}

/**
 * Deny-by-default scope predicate for a bucket probe (mirrors recon/#924).
 *
 * Probing a target org's bucket is recon against that org, so it must clear the
 * engagement scope — NOT the validateTargetUrl external-service exemption.
 *
 *   - No scope policy configured → DENY (false). This is the deny-by-default
 *     rule: cloud probing is opt-in and an authorized engagement always carries
 *     a scope. An operator authorizes cloud surface by adding the bucket's S3
 *     endpoint (or `*.amazonaws.com`) to the scope's `in_scope` list.
 *   - Policy present → defer to `policy.match()` on the bucket's virtual-host
 *     endpoint. Out-of-scope wins (the policy's own conservative default).
 */
export function bucketInScope(
  bucket: string,
  scope: CloudScopeMatcher | undefined,
  region?: string,
): { allowed: boolean; reason: string } {
  if (!scope) {
    return { allowed: false, reason: "denied: no engagement scope configured (cloud probing is deny-by-default)" };
  }
  return scope.match(bucketEndpoint(bucket, region));
}

/**
 * Anonymous, read-only probe of one S3 bucket: `GET /` for listability and
 * `GET /?acl` for a readable ACL grant. No credentials are sent.
 */
export async function probeS3Bucket(
  bucket: string,
  opts: { region?: string; fetchImpl?: CloudFetchLike; maxKeys?: number } = {},
): Promise<BucketProbeResult> {
  const fetchImpl = opts.fetchImpl ?? DEFAULT_FETCH;
  const endpoint = bucketEndpoint(bucket, opts.region);
  const cap = clampInt(opts.maxKeys, 10, 1, 100);

  let listStatus = 0;
  let listBody = "";
  try {
    const res = await withTimeout(fetchImpl(`${endpoint}/?max-keys=${cap}`, { method: "GET" }));
    listStatus = res.status;
    listBody = await res.text();
  } catch (err) {
    return {
      bucket,
      endpoint,
      verdict: "inconclusive",
      severity: "info",
      listStatus: 0,
      aclReadable: false,
      sampleKeys: [],
      note: `Network error probing bucket: ${errMsg(err)}`,
    };
  }

  const { verdict, note } = classifyBucketAccess(listStatus, listBody);

  // Only probe the ACL when the bucket actually exists — no point on a 404.
  let aclReadable = false;
  if (verdict !== "not-found") {
    try {
      const aclRes = await withTimeout(fetchImpl(`${endpoint}/?acl`, { method: "GET" }));
      const aclBody = await aclRes.text();
      aclReadable = aclRes.status === 200 && /<AccessControlPolicy/i.test(aclBody);
    } catch {
      // ACL probe is best-effort; the list verdict already stands.
    }
  }

  const sampleKeys = verdict === "public" ? extractObjectKeys(listBody, cap) : [];
  const severity: BucketProbeResult["severity"] =
    verdict === "public" ? (aclReadable ? "high" : "high") : verdict === "not-found" ? "medium" : "info";

  return {
    bucket,
    endpoint,
    verdict,
    severity,
    listStatus,
    aclReadable,
    sampleKeys,
    note: aclReadable ? `${note} ACL is also publicly readable.` : note,
  };
}

// ── Orphaned-integration / bucket-takeover ──

export interface TakeoverVerdict {
  bucket: string;
  /** True when the referenced bucket is re-creatable by an attacker. */
  takeoverable: boolean;
  severity: "high" | "medium" | "info";
  note: string;
}

/**
 * Decide whether a *referenced* bucket (found in app config, HTML, a redirect,
 * an integration manifest) is takeover-able. The signal is a clean
 * `NoSuchBucket` 404: the name is free, so an attacker in the same partition can
 * `CreateBucket` it and intercept whatever the dangling integration sends.
 *
 * Pure over an already-probed `BucketProbeResult` so it composes with
 * `probeS3Bucket` and is trivially unit-tested.
 */
export function classifyTakeover(probe: BucketProbeResult): TakeoverVerdict {
  if (probe.verdict === "not-found") {
    return {
      bucket: probe.bucket,
      takeoverable: true,
      severity: "high",
      note:
        `Bucket "${probe.bucket}" is referenced but does not exist (NoSuchBucket). ` +
        `An attacker can re-create it in the same partition and intercept data the orphaned integration writes/reads. ` +
        `Re-creation is an operator decision — pwnkit only flags it.`,
    };
  }
  return {
    bucket: probe.bucket,
    takeoverable: false,
    severity: "info",
    note: `Bucket "${probe.bucket}" exists (verdict: ${probe.verdict}) — not takeover-able.`,
  };
}

// ── Credential validation (read-only IAM/STS) ──

/**
 * Read-only AWS actions the credential validator is allowed to invoke. Anything
 * not on this list is rejected by `assertReadOnlyAction`, so the no-write
 * invariant is enforced in code, not just by convention.
 */
const READ_ONLY_ACTIONS = new Set<string>([
  "sts:GetCallerIdentity",
  "iam:ListAttachedUserPolicies",
  "iam:ListUserPolicies",
  "iam:GetUser",
  "s3:ListAllMyBuckets",
]);

export function assertReadOnlyAction(action: string): void {
  if (!READ_ONLY_ACTIONS.has(action)) {
    throw new Error(
      `cloud_validate_credentials refused non-read-only action "${action}" (read-only allowlist: ${[...READ_ONLY_ACTIONS].join(", ")})`,
    );
  }
}

export interface CredentialValidationResult {
  valid: boolean;
  /** STS-resolved identity, when the key is live. */
  account?: string;
  userId?: string;
  arn?: string;
  /** Read-only permission probes that SUCCEEDED — over-privilege evidence. */
  effectivePermissions: string[];
  /** "high" when a long-lived key has broad read access; lower otherwise. */
  severity: "high" | "medium" | "low" | "info";
  note: string;
}

/** Clamp/normalize an AWS region; default us-east-1 for the global STS endpoint. */
function normalizeRegion(region?: string): string {
  if (!region || !/^[a-z]{2}-[a-z]+-\d$/.test(region)) return "us-east-1";
  return region;
}

// ── SigV4 (no @aws-sdk dependency) ──

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}
function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Sign a minimal SigV4 POST for a query-style AWS action (STS / IAM). Returns
 * the headers + body for the request. Exported for unit testing the canonical
 * request + signature derivation without a live call.
 */
export function signSigV4(params: {
  service: string;
  region: string;
  host: string;
  body: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  amzDate: string; // YYYYMMDDTHHMMSSZ
}): Record<string, string> {
  const { service, region, host, body, accessKeyId, secretAccessKey, sessionToken, amzDate } = params;
  const dateStamp = amzDate.slice(0, 8);
  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const contentType = "application/x-www-form-urlencoded; charset=utf-8";

  const signedHeaders = sessionToken
    ? "content-type;host;x-amz-date;x-amz-security-token"
    : "content-type;host;x-amz-date";
  const canonicalHeaders =
    `content-type:${contentType}\n` +
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n` +
    (sessionToken ? `x-amz-security-token:${sessionToken}\n` : "");

  const canonicalRequest = [
    "POST",
    "/",
    "",
    canonicalHeaders,
    signedHeaders,
    sha256Hex(body),
  ].join("\n");

  const stringToSign = [algorithm, amzDate, credentialScope, sha256Hex(canonicalRequest)].join("\n");

  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");

  const authorization =
    `${algorithm} Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const headers: Record<string, string> = {
    "Content-Type": contentType,
    "X-Amz-Date": amzDate,
    Authorization: authorization,
  };
  if (sessionToken) headers["X-Amz-Security-Token"] = sessionToken;
  return headers;
}

export function currentAmzDate(now = new Date()): string {
  return now.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

/** Parse the GetCallerIdentity XML response into the three identity fields. */
export function parseCallerIdentity(body: string): { account?: string; userId?: string; arn?: string } {
  const grab = (tag: string): string | undefined => {
    const m = new RegExp(`<${tag}>([^<]+)</${tag}>`, "i").exec(body);
    return m ? m[1] : undefined;
  };
  return { account: grab("Account"), userId: grab("UserId"), arn: grab("Arn") };
}

/**
 * Validate a harvested AWS credential, READ-ONLY. Always calls
 * `sts:GetCallerIdentity` (zero-impact whoami). On success, optionally probes a
 * few read-only `List*` actions to gauge over-privilege — every probed action
 * is run through `assertReadOnlyAction` first.
 */
export async function validateAwsCredentials(opts: {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region?: string;
  fetchImpl?: CloudFetchLike;
  now?: Date;
}): Promise<CredentialValidationResult> {
  const fetchImpl = opts.fetchImpl ?? DEFAULT_FETCH;
  const region = normalizeRegion(opts.region);
  const amzDate = currentAmzDate(opts.now);

  // ── 1. sts:GetCallerIdentity — the read-only whoami. ──
  assertReadOnlyAction("sts:GetCallerIdentity");
  const stsHost = "sts.amazonaws.com";
  const stsBody = "Action=GetCallerIdentity&Version=2011-06-15";
  const stsHeaders = signSigV4({
    service: "sts",
    region,
    host: stsHost,
    body: stsBody,
    accessKeyId: opts.accessKeyId,
    secretAccessKey: opts.secretAccessKey,
    sessionToken: opts.sessionToken,
    amzDate,
  });

  let status = 0;
  let body = "";
  try {
    const res = await withTimeout(
      fetchImpl(`https://${stsHost}/`, { method: "POST", headers: { ...stsHeaders, Host: stsHost }, body: stsBody }),
    );
    status = res.status;
    body = await res.text();
  } catch (err) {
    return {
      valid: false,
      effectivePermissions: [],
      severity: "info",
      note: `Credential validation network error: ${errMsg(err)}`,
    };
  }

  if (status !== 200) {
    return {
      valid: false,
      effectivePermissions: [],
      severity: "info",
      note: `Credential rejected by STS (HTTP ${status}${
        extractStsError(body) ? ` ${extractStsError(body)}` : ""
      }) — key is invalid, expired, or disabled.`,
    };
  }

  const identity = parseCallerIdentity(body);
  const effectivePermissions = ["sts:GetCallerIdentity"];

  // ── 2. Read-only over-privilege probes (best-effort). ──
  // We only need to know WHICH broad read actions succeed; a 403 is expected
  // and simply means the key lacks that permission. No mutation, ever.
  for (const probe of OVER_PRIVILEGE_PROBES) {
    assertReadOnlyAction(probe.action);
    try {
      const headers = signSigV4({
        service: probe.service,
        region,
        host: probe.host,
        body: probe.body,
        accessKeyId: opts.accessKeyId,
        secretAccessKey: opts.secretAccessKey,
        sessionToken: opts.sessionToken,
        amzDate,
      });
      const res = await withTimeout(
        fetchImpl(`https://${probe.host}/`, {
          method: "POST",
          headers: { ...headers, Host: probe.host },
          body: probe.body,
        }),
      );
      if (res.status === 200) effectivePermissions.push(probe.action);
    } catch {
      // best-effort; a failed probe is just "no evidence of that permission".
    }
  }

  const overPrivileged = effectivePermissions.length > 1;
  const longLived = identity.arn ? !identity.arn.includes(":assumed-role/") : true;
  const severity: CredentialValidationResult["severity"] =
    overPrivileged && longLived ? "high" : overPrivileged ? "medium" : "low";

  return {
    valid: true,
    account: identity.account,
    userId: identity.userId,
    arn: identity.arn,
    effectivePermissions,
    severity,
    note:
      `Credential is LIVE${identity.arn ? ` (${identity.arn})` : ""}. ` +
      (overPrivileged
        ? `Over-privileged: ${effectivePermissions.length} read-only action(s) succeeded — broader than a least-privilege key should be.`
        : `Only whoami succeeded — no broad read access detected via the probed actions.`) +
      (longLived ? " Long-lived IAM-user key (no expiry)." : " Temporary (assumed-role) credential."),
  };
}

const OVER_PRIVILEGE_PROBES: Array<{ action: string; service: string; host: string; body: string }> = [
  {
    action: "s3:ListAllMyBuckets",
    service: "s3",
    host: "s3.amazonaws.com",
    // ListBuckets is a GET in the REST API, but the query POST form is fine for
    // a permission probe; a 200 proves the action is allowed.
    body: "",
  },
  {
    action: "iam:ListAttachedUserPolicies",
    service: "iam",
    host: "iam.amazonaws.com",
    body: "Action=ListAttachedUserPolicies&Version=2010-05-08",
  },
];

function extractStsError(body: string): string | null {
  const m = /<Code>([^<]+)<\/Code>/i.exec(body);
  return m ? m[1] : null;
}

// ── helpers ──

function clampInt(v: unknown, dflt: number, min: number, max: number): number {
  const n = typeof v === "number" && Number.isFinite(v) ? Math.floor(v) : dflt;
  return Math.max(min, Math.min(max, n));
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function withTimeout<T>(p: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`cloud probe timed out after ${PROBE_TIMEOUT_MS}ms`)), PROBE_TIMEOUT_MS);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
