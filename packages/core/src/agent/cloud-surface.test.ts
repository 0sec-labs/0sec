import { describe, it, expect } from "vitest";
import {
  probeS3Bucket,
  classifyBucketAccess,
  classifyTakeover,
  extractS3ErrorCode,
  extractObjectKeys,
  bucketEndpoint,
  validateAwsCredentials,
  assertReadOnlyAction,
  signSigV4,
  parseCallerIdentity,
  currentAmzDate,
  type CloudFetchLike,
} from "./cloud-surface.js";

// pwnkit#925 — every test mocks the fetch layer. NO live cloud calls.

// A scripted fetch: maps a url-substring → {status, body}. Records calls.
function mockFetch(routes: Array<{ match: string; status: number; body: string }>): {
  fetchImpl: CloudFetchLike;
  calls: Array<{ url: string; method: string; body?: string }>;
} {
  const calls: Array<{ url: string; method: string; body?: string }> = [];
  const fetchImpl: CloudFetchLike = async (url, init) => {
    calls.push({ url, method: init?.method ?? "GET", body: init?.body });
    const route = routes.find((r) => url.includes(r.match));
    const status = route?.status ?? 500;
    const body = route?.body ?? "";
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => null },
      text: async () => body,
    };
  };
  return { fetchImpl, calls };
}

describe("classifyBucketAccess (pure)", () => {
  it("200 → public", () => {
    expect(classifyBucketAccess(200, "").verdict).toBe("public");
  });
  it("403 → private", () => {
    expect(classifyBucketAccess(403, "<Error><Code>AccessDenied</Code></Error>").verdict).toBe("private");
  });
  it("404 → not-found (takeover candidate)", () => {
    const r = classifyBucketAccess(404, "<Error><Code>NoSuchBucket</Code></Error>");
    expect(r.verdict).toBe("not-found");
    expect(r.note).toMatch(/NoSuchBucket|takeover/i);
  });
  it("301/307 region redirect → inconclusive", () => {
    expect(classifyBucketAccess(301, "").verdict).toBe("inconclusive");
    expect(classifyBucketAccess(307, "").verdict).toBe("inconclusive");
  });
  it("unexpected status → inconclusive", () => {
    expect(classifyBucketAccess(500, "").verdict).toBe("inconclusive");
  });
});

describe("XML helpers (pure)", () => {
  it("extracts the S3 error code", () => {
    expect(extractS3ErrorCode("<Error><Code>NoSuchBucket</Code></Error>")).toBe("NoSuchBucket");
    expect(extractS3ErrorCode("no xml here")).toBeNull();
  });
  it("extracts object keys capped", () => {
    const body = "<Contents><Key>a.txt</Key></Contents><Contents><Key>b.txt</Key></Contents>";
    expect(extractObjectKeys(body)).toEqual(["a.txt", "b.txt"]);
    expect(extractObjectKeys(body, 1)).toEqual(["a.txt"]);
  });
});

describe("bucketEndpoint", () => {
  it("uses the global endpoint for us-east-1 / unset", () => {
    expect(bucketEndpoint("acme")).toBe("https://acme.s3.amazonaws.com");
    expect(bucketEndpoint("acme", "us-east-1")).toBe("https://acme.s3.amazonaws.com");
  });
  it("uses a regional endpoint otherwise", () => {
    expect(bucketEndpoint("acme", "eu-central-1")).toBe("https://acme.s3.eu-central-1.amazonaws.com");
  });
});

describe("probeS3Bucket (mocked fetch)", () => {
  it("flags a public bucket and samples keys, ACL readable → high", async () => {
    const { fetchImpl, calls } = mockFetch([
      { match: "?max-keys", status: 200, body: "<ListBucketResult><Contents><Key>secret.csv</Key></Contents></ListBucketResult>" },
      { match: "?acl", status: 200, body: "<AccessControlPolicy></AccessControlPolicy>" },
    ]);
    const r = await probeS3Bucket("acme-exports", { fetchImpl });
    expect(r.verdict).toBe("public");
    expect(r.severity).toBe("high");
    expect(r.aclReadable).toBe(true);
    expect(r.sampleKeys).toEqual(["secret.csv"]);
    // both the list probe and the acl probe ran, anonymously (no auth header).
    expect(calls.length).toBe(2);
    expect(calls.every((c) => c.method === "GET")).toBe(true);
  });

  it("private bucket → private, no key sampling, does not probe acl as not-found", async () => {
    const { fetchImpl } = mockFetch([
      { match: "?max-keys", status: 403, body: "<Error><Code>AccessDenied</Code></Error>" },
      { match: "?acl", status: 403, body: "" },
    ]);
    const r = await probeS3Bucket("acme-private", { fetchImpl });
    expect(r.verdict).toBe("private");
    expect(r.severity).toBe("info");
    expect(r.sampleKeys).toEqual([]);
  });

  it("missing bucket → not-found, and skips the ACL probe", async () => {
    const { fetchImpl, calls } = mockFetch([
      { match: "?max-keys", status: 404, body: "<Error><Code>NoSuchBucket</Code></Error>" },
    ]);
    const r = await probeS3Bucket("acme-deleted", { fetchImpl });
    expect(r.verdict).toBe("not-found");
    expect(r.aclReadable).toBe(false);
    // Only the list probe — no ?acl call on a 404.
    expect(calls.length).toBe(1);
  });

  it("network error → inconclusive, never throws", async () => {
    const fetchImpl: CloudFetchLike = async () => {
      throw new Error("ENOTFOUND");
    };
    const r = await probeS3Bucket("acme", { fetchImpl });
    expect(r.verdict).toBe("inconclusive");
    expect(r.note).toMatch(/network error/i);
  });
});

describe("classifyTakeover (pure)", () => {
  it("not-found bucket is takeover-able (high)", () => {
    const t = classifyTakeover({
      bucket: "acme-deleted",
      endpoint: "https://acme-deleted.s3.amazonaws.com",
      verdict: "not-found",
      severity: "medium",
      listStatus: 404,
      aclReadable: false,
      sampleKeys: [],
      note: "",
    });
    expect(t.takeoverable).toBe(true);
    expect(t.severity).toBe("high");
    expect(t.note).toMatch(/re-create|intercept/i);
  });
  it("existing bucket is not takeover-able", () => {
    const t = classifyTakeover({
      bucket: "acme",
      endpoint: "https://acme.s3.amazonaws.com",
      verdict: "private",
      severity: "info",
      listStatus: 403,
      aclReadable: false,
      sampleKeys: [],
      note: "",
    });
    expect(t.takeoverable).toBe(false);
  });
});

describe("assertReadOnlyAction (safety guarantee)", () => {
  it("permits whitelisted read-only actions", () => {
    expect(() => assertReadOnlyAction("sts:GetCallerIdentity")).not.toThrow();
    expect(() => assertReadOnlyAction("s3:ListAllMyBuckets")).not.toThrow();
  });
  it("rejects any mutating action", () => {
    expect(() => assertReadOnlyAction("s3:PutObject")).toThrow(/refused non-read-only/);
    expect(() => assertReadOnlyAction("s3:DeleteObject")).toThrow();
    expect(() => assertReadOnlyAction("iam:CreateUser")).toThrow();
  });
});

describe("SigV4 + identity parsing (pure)", () => {
  it("derives a stable signature for fixed inputs", () => {
    const headers = signSigV4({
      service: "sts",
      region: "us-east-1",
      host: "sts.amazonaws.com",
      body: "Action=GetCallerIdentity&Version=2011-06-15",
      accessKeyId: "***REMOVED***",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      amzDate: "20260617T000000Z",
    });
    expect(headers.Authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=***REMOVED***\/20260617\/us-east-1\/sts\/aws4_request/);
    expect(headers.Authorization).toMatch(/Signature=[0-9a-f]{64}$/);
    expect(headers["X-Amz-Date"]).toBe("20260617T000000Z");
    expect(headers["X-Amz-Security-Token"]).toBeUndefined();
  });
  it("includes the session token header when supplied", () => {
    const headers = signSigV4({
      service: "sts",
      region: "us-east-1",
      host: "sts.amazonaws.com",
      body: "x",
      accessKeyId: "AKIA",
      secretAccessKey: "s",
      sessionToken: "tok123",
      amzDate: "20260617T000000Z",
    });
    expect(headers["X-Amz-Security-Token"]).toBe("tok123");
    expect(headers.Authorization).toMatch(/x-amz-security-token/);
  });
  it("currentAmzDate produces the AWS basic-format timestamp", () => {
    expect(currentAmzDate(new Date("2026-06-17T12:34:56.789Z"))).toBe("20260617T123456Z");
  });
  it("parses GetCallerIdentity XML", () => {
    const body =
      "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ci</Arn><UserId>AIDA</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>";
    expect(parseCallerIdentity(body)).toEqual({
      account: "123456789012",
      userId: "AIDA",
      arn: "arn:aws:iam::123456789012:user/ci",
    });
  });
});

describe("validateAwsCredentials (mocked fetch)", () => {
  const creds = { accessKeyId: "AKIAEXAMPLE", secretAccessKey: "secret", now: new Date("2026-06-17T00:00:00Z") };

  it("invalid key → STS 403, not valid, no permissions", async () => {
    const { fetchImpl } = mockFetch([{ match: "sts.amazonaws.com", status: 403, body: "<Error><Code>InvalidClientTokenId</Code></Error>" }]);
    const r = await validateAwsCredentials({ ...creds, fetchImpl });
    expect(r.valid).toBe(false);
    expect(r.effectivePermissions).toEqual([]);
    expect(r.note).toMatch(/rejected by STS|invalid/i);
  });

  it("valid least-privilege key → only whoami → low", async () => {
    const { fetchImpl } = mockFetch([
      {
        match: "sts.amazonaws.com",
        status: 200,
        body: "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::1:user/ci</Arn><Account>1</Account></GetCallerIdentityResult></GetCallerIdentityResponse>",
      },
      // both over-privilege probes denied
      { match: "s3.amazonaws.com", status: 403, body: "" },
      { match: "iam.amazonaws.com", status: 403, body: "" },
    ]);
    const r = await validateAwsCredentials({ ...creds, fetchImpl });
    expect(r.valid).toBe(true);
    expect(r.account).toBe("1");
    expect(r.effectivePermissions).toEqual(["sts:GetCallerIdentity"]);
    expect(r.severity).toBe("low");
  });

  it("over-privileged long-lived key → high", async () => {
    const { fetchImpl } = mockFetch([
      {
        match: "sts.amazonaws.com",
        status: 200,
        body: "<GetCallerIdentityResult><Arn>arn:aws:iam::1:user/ci</Arn><Account>1</Account></GetCallerIdentityResult>",
      },
      { match: "s3.amazonaws.com", status: 200, body: "<ListAllMyBucketsResult></ListAllMyBucketsResult>" },
      { match: "iam.amazonaws.com", status: 200, body: "<ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResult>" },
    ]);
    const r = await validateAwsCredentials({ ...creds, fetchImpl });
    expect(r.valid).toBe(true);
    expect(r.severity).toBe("high");
    expect(r.effectivePermissions).toContain("s3:ListAllMyBuckets");
    expect(r.effectivePermissions).toContain("iam:ListAttachedUserPolicies");
  });

  it("assumed-role (temporary) over-privileged key → medium, not high", async () => {
    const { fetchImpl } = mockFetch([
      {
        match: "sts.amazonaws.com",
        status: 200,
        body: "<GetCallerIdentityResult><Arn>arn:aws:sts::1:assumed-role/app/sess</Arn><Account>1</Account></GetCallerIdentityResult>",
      },
      { match: "s3.amazonaws.com", status: 200, body: "ok" },
      { match: "iam.amazonaws.com", status: 403, body: "" },
    ]);
    const r = await validateAwsCredentials({ ...creds, fetchImpl });
    expect(r.severity).toBe("medium");
    expect(r.note).toMatch(/Temporary|assumed-role/i);
  });
});
