import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const probeS3BucketMock = vi.fn();
const classifyTakeoverMock = vi.fn();
const validateAwsCredentialsMock = vi.fn();

vi.mock("@0sec/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@0sec/core")>();
  return {
    ...actual,
    probeS3Bucket: probeS3BucketMock,
    classifyTakeover: classifyTakeoverMock,
    validateAwsCredentials: validateAwsCredentialsMock,
  };
});

const { registerCloudCommand } = await import("../cloud.js");

function captureIO() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const o = vi.spyOn(console, "log").mockImplementation((...a) => stdout.push(a.map(String).join(" ")));
  const e = vi.spyOn(console, "error").mockImplementation((...a) => stderr.push(a.map(String).join(" ")));
  return { stdout, stderr, restore: () => { o.mockRestore(); e.mockRestore(); } };
}

async function runCli(argv: string[]): Promise<void> {
  const program = new Command();
  program.exitOverride();
  registerCloudCommand(program);
  await program.parseAsync(["node", "0sec-cli", ...argv]);
}

const ORIGINAL_FLAG = process.env["0SEC_FEATURE_CLOUD_SURFACE"];

describe("0sec cloud", () => {
  let io: ReturnType<typeof captureIO>;
  let dir: string;
  let scopePath: string;

  beforeEach(() => {
    process.exitCode = undefined;
    io = captureIO();
    dir = mkdtempSync(join(tmpdir(), "cloud-test-"));
    scopePath = join(dir, "scope.json");
    // In-scope: the bucket's virtual-hosted S3 endpoint host.
    writeFileSync(scopePath, JSON.stringify({ in_scope: ["acme-assets.s3.amazonaws.com"], out_of_scope: [] }));
    probeS3BucketMock.mockResolvedValue({
      bucket: "acme-assets", endpoint: "https://acme-assets.s3.amazonaws.com",
      verdict: "public", severity: "high", listStatus: 200, aclReadable: false,
      sampleKeys: ["secret.txt"], note: "public",
    });
    classifyTakeoverMock.mockReturnValue({ bucket: "acme-assets", takeoverable: false, severity: "info", note: "exists" });
    validateAwsCredentialsMock.mockResolvedValue({
      valid: true, account: "1234", userId: "U", arn: "arn:aws:iam::1234:user/x",
      effectivePermissions: ["sts:GetCallerIdentity"], severity: "medium", note: "ok",
    });
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.clearAllMocks();
    io.restore();
    rmSync(dir, { recursive: true, force: true });
    if (ORIGINAL_FLAG === undefined) delete process.env["0SEC_FEATURE_CLOUD_SURFACE"];
    else process.env["0SEC_FEATURE_CLOUD_SURFACE"] = ORIGINAL_FLAG;
  });

  describe("s3-probe", () => {
    it("refuses when the feature flag is off", async () => {
      delete process.env["0SEC_FEATURE_CLOUD_SURFACE"];
      await runCli(["cloud", "s3-probe", "acme-assets", "--scope", scopePath]);
      expect(probeS3BucketMock).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(2);
      expect(io.stderr.join("\n")).toContain("0SEC_FEATURE_CLOUD_SURFACE=1");
    });

    it("deny-by-default: requires --scope (commander rejects without it)", async () => {
      process.env["0SEC_FEATURE_CLOUD_SURFACE"] = "1";
      await expect(runCli(["cloud", "s3-probe", "acme-assets"])).rejects.toBeDefined();
      expect(probeS3BucketMock).not.toHaveBeenCalled();
    });

    it("probes an in-scope bucket when flag on + scope present", async () => {
      process.env["0SEC_FEATURE_CLOUD_SURFACE"] = "1";
      await runCli(["cloud", "s3-probe", "acme-assets", "--scope", scopePath]);
      expect(probeS3BucketMock).toHaveBeenCalledTimes(1);
      expect(io.stdout.join("\n")).toContain("public");
    });

    it("refuses an out-of-scope bucket (does not probe it)", async () => {
      process.env["0SEC_FEATURE_CLOUD_SURFACE"] = "1";
      writeFileSync(scopePath, JSON.stringify({ in_scope: ["other.s3.amazonaws.com"], out_of_scope: [] }));
      await runCli(["cloud", "s3-probe", "acme-assets", "--scope", scopePath]);
      expect(probeS3BucketMock).not.toHaveBeenCalled();
      expect(io.stdout.join("\n")).toContain("refused");
    });
  });

  describe("validate-creds", () => {
    it("refuses when the feature flag is off", async () => {
      delete process.env["0SEC_FEATURE_CLOUD_SURFACE"];
      await runCli(["cloud", "validate-creds", "--scope", scopePath, "--access-key-id", "AKIA", "--secret-access-key", "s"]);
      expect(validateAwsCredentialsMock).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(2);
    });

    it("deny-by-default: requires --scope (commander rejects without it)", async () => {
      process.env["0SEC_FEATURE_CLOUD_SURFACE"] = "1";
      await expect(
        runCli(["cloud", "validate-creds", "--access-key-id", "AKIA", "--secret-access-key", "s"]),
      ).rejects.toBeDefined();
      expect(validateAwsCredentialsMock).not.toHaveBeenCalled();
    });

    it("validates when flag on + scope + creds present, never echoing the secret", async () => {
      process.env["0SEC_FEATURE_CLOUD_SURFACE"] = "1";
      await runCli([
        "cloud", "validate-creds", "--scope", scopePath,
        "--access-key-id", "AKIAEXAMPLE", "--secret-access-key", "topsecretvalue", "--json",
      ]);
      expect(validateAwsCredentialsMock).toHaveBeenCalledTimes(1);
      const out = io.stdout.join("\n");
      expect(out).not.toContain("topsecretvalue");
      expect(JSON.parse(out).valid).toBe(true);
    });

    it("refuses with flag on + scope but no credentials", async () => {
      process.env["0SEC_FEATURE_CLOUD_SURFACE"] = "1";
      delete process.env.AWS_ACCESS_KEY_ID;
      delete process.env.AWS_SECRET_ACCESS_KEY;
      await runCli(["cloud", "validate-creds", "--scope", scopePath]);
      expect(validateAwsCredentialsMock).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(2);
    });
  });
});
