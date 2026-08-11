import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  CloudSinkNormalizeError,
  getCloudSinkConfig,
  normalizeFinding,
  postFinding,
  postFinalReport,
  postAsset,
  postAssets,
  reconAssetToCloudSinkAsset,
  type CloudSinkAsset,
} from "./cloud-sink.js";
import type { ReconAsset } from "./recon/recon.js";

const ENV_KEYS = [
  "PWNKIT_CLOUD_SINK",
  "PWNKIT_CLOUD_SCAN_ID",
  "PWNKIT_CLOUD_TOKEN",
  "PWNKIT_CLOUD_ORG_ID",
  "PWNKIT_FEATURE_CLOUD_SINK",
];

describe("cloud-sink", () => {
  const originalFetch = globalThis.fetch;
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    for (const k of ENV_KEYS) delete process.env[k];
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k]!;
    }
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("getCloudSinkConfig returns null when env vars are unset", () => {
    expect(getCloudSinkConfig()).toBeNull();
  });

  it("getCloudSinkConfig returns null when only the URL is set", () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    expect(getCloudSinkConfig()).toBeNull();
  });

  it("getCloudSinkConfig returns config when URL + scan id are set", () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-123";
    process.env.PWNKIT_CLOUD_TOKEN = "tok-abc";
    expect(getCloudSinkConfig()).toEqual({
      sinkUrl: "https://api.example.com",
      scanId: "scan-123",
      token: "tok-abc",
    });
  });

  it("postFinding does NOT call fetch when env vars are unset", async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await postFinding({ severity: "high", title: "test" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("postFinding POSTs to /scans/<id>/findings with correct headers + body", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com/";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-123";
    process.env.PWNKIT_CLOUD_TOKEN = "tok-abc";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const finding = {
      id: "finding-1",
      templateId: "rce-template",
      title: "RCE",
      description: "...",
      severity: "critical",
      category: "command-injection",
      status: "discovered",
      evidence: { request: "GET /", response: "pwned" },
      timestamp: 1234567890,
    };
    await postFinding(finding);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/scans/scan-123/findings");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(init.headers["X-Pwnkit-Scan-Id"]).toBe("scan-123");
    expect(init.headers["x-cloud-sink-version"]).toBe("1");
    expect(init.headers["Authorization"]).toBe("Bearer tok-abc");
    // The wire payload is the NORMALIZED finding, not the raw input.
    const body = JSON.parse(init.body);
    expect(body).toEqual({
      finding: {
        id: "finding-1",
        templateId: "rce-template",
        title: "RCE",
        description: "...",
        severity: "critical",
        category: "command-injection",
        status: "discovered",
        evidence: { request: "GET /", response: "pwned" },
        timestamp: 1234567890,
      },
    });
  });

  it("normalizes and transports research evidence envelopes", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-research";
    process.env.PWNKIT_CLOUD_TOKEN = "tok";
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, text: async () => "" });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const receipt = {
      schemaVersion: 1, evidenceId: "e-1", grade: "reproduced",
      executionContext: { privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 },
    };

    await postFinding({
      id: "f-research", templateId: "research", title: "Finding", description: "Proof",
      severity: "high", category: "other", status: "confirmed",
      evidence: { request: "", response: "" }, timestamp: 1,
      researchEvidence: [receipt],
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.finding.researchEvidence).toEqual([receipt]);
  });

  it("normalizes save_finding source fields into a review annotation", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-review";
    process.env.PWNKIT_CLOUD_TOKEN = "tok";
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await postFinding({
      title: "Unsafe parser",
      description: "Input reaches eval",
      severity: "high",
      category: "command-injection",
      source_path: "src/parser.ts",
      source_start_line: 41,
      source_end_line: 42,
      suggested_replacement: "return parseSafe(input);",
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.finding.reviewAnnotation).toEqual({
      path: "src/parser.ts",
      startLine: 41,
      endLine: 42,
      suggestion: "return parseSafe(input);",
    });
  });

  it("still POSTs the finding when its review annotation is dropped as non-repo-relative", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-review-drop";
    process.env.PWNKIT_CLOUD_TOKEN = "tok";
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await postFinding({
      title: "Unsafe parser",
      description: "Input reaches eval",
      severity: "high",
      category: "command-injection",
      source_path: "src\\parser.ts",
      source_start_line: 41,
      suggested_replacement: "return parseSafe(input);",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    // The cloud schema would 400 this path — the sink drops ONLY the
    // annotation; the finding itself must still ship.
    expect(body.finding.reviewAnnotation).toBeUndefined();
    expect(body.finding.title).toBe("Unsafe parser");
    expect(body.finding.severity).toBe("high");
  });

  it("postFinalReport POSTs the final report flag", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-456";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const report = { target: "https://x.test", findings: [], summary: {} };
    await postFinalReport(report);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/scans/scan-456/findings");
    const parsed = JSON.parse(init.body);
    expect(parsed.report).toEqual(report);
    expect(parsed.final).toBe(true);
    // No token configured → no Authorization header
    expect(init.headers["Authorization"]).toBeUndefined();
  });

  it("does NOT throw when sink returns 5xx — local scan continues", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-789";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => "service unavailable",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    // Silence the diagnostic write
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    await expect(postFinding({ title: "x" })).resolves.toBeUndefined();
    await expect(postFinalReport({ target: "x" })).resolves.toBeUndefined();
    expect(stderrSpy).toHaveBeenCalled();
  });

  it("does NOT throw when fetch itself rejects (network error)", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-net";

    const fetchMock = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    await expect(postFinding({ title: "x" })).resolves.toBeUndefined();
    expect(stderrSpy).toHaveBeenCalled();
  });

  it("postFinding drops malformed findings without throwing or calling fetch", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-drop";

    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    // Not an object
    await expect(postFinding("nope")).resolves.toBeUndefined();
    // Object with no title and no description
    await expect(postFinding({ severity: "high" })).resolves.toBeUndefined();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(stderrSpy).toHaveBeenCalled();
  });

  it("postFinding normalizes raw LLM tool-call args (snake_case) before posting", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-llm";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await postFinding({
      title: "Prompt injection in /chat",
      description: "System prompt leaked",
      severity: "HIGH",
      category: "prompt-injection",
      template_id: "pi-001",
      evidence_request: "user: ignore previous",
      evidence_response: "assistant: my system prompt is…",
      evidence_analysis: "model complied with override",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.finding.title).toBe("Prompt injection in /chat");
    expect(body.finding.templateId).toBe("pi-001");
    expect(body.finding.severity).toBe("high"); // lowercased
    expect(body.finding.category).toBe("prompt-injection");
    expect(body.finding.status).toBe("discovered"); // defaulted
    expect(body.finding.evidence).toEqual({
      request: "user: ignore previous",
      response: "assistant: my system prompt is…",
      analysis: "model complied with override",
    });
    expect(typeof body.finding.id).toBe("string");
    expect(body.finding.id.length).toBeGreaterThan(0);
    expect(typeof body.finding.timestamp).toBe("number");
  });

  it("respects PWNKIT_FEATURE_CLOUD_SINK=0 even when URL is set", async () => {
    // Note: features.ts is evaluated at module load, so we have to import a
    // fresh copy to observe the flag change.
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-disabled";
    process.env.PWNKIT_FEATURE_CLOUD_SINK = "0";

    vi.resetModules();
    const mod = await import("./cloud-sink.js");
    expect(mod.getCloudSinkConfig()).toBeNull();

    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await mod.postFinding({ title: "x" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("normalizeFinding", () => {
  it("preserves a valid structured 0review annotation", () => {
    const out = normalizeFinding({
      title: "unsafe parser",
      reviewAnnotation: {
        path: "src/parser.ts",
        startLine: 41,
        endLine: 42,
        suggestion: "safeParse(input)",
        knownMarker: true,
      },
    });
    expect(out.reviewAnnotation).toEqual({
      path: "src/parser.ts",
      startLine: 41,
      endLine: 42,
      suggestion: "safeParse(input)",
      knownMarker: true,
    });
  });

  it("drops annotations with non-repo-relative paths but keeps the finding", () => {
    // Each of these fails the orchestrator's zod refine on
    // reviewAnnotation.path — before this gate the cloud 400'd the ENTIRE
    // finding POST and the sink only logged to stderr (finding lost).
    const badPaths = [
      "../secrets.txt", // `..` segment
      "src/../../etc/passwd", // nested traversal
      "/etc/passwd", // absolute POSIX
      "C:\\src\\parser.ts", // drive-letter absolute (also backslashes)
      "src\\parser.ts", // backslash separators
    ];
    for (const path of badPaths) {
      const out = normalizeFinding({
        title: `finding for ${path}`,
        reviewAnnotation: { path, startLine: 1 },
      });
      expect(out.reviewAnnotation).toBeUndefined();
      expect(out.title).toBe(`finding for ${path}`); // finding itself survives
    }
  });

  it("drops an oversized suggestion instead of truncating it (location kept)", () => {
    const out = normalizeFinding({
      title: "oversized suggestion",
      reviewAnnotation: {
        path: "src/parser.ts",
        startLine: 41,
        suggestion: "x".repeat(20_001),
      },
    });
    // A truncated half-function inside a suggestion block applies as broken
    // code — the whole suggestion is dropped, the location is kept.
    expect(out.reviewAnnotation).toEqual({
      path: "src/parser.ts",
      startLine: 41,
    });
  });

  it("keeps a suggestion at exactly the 20k cloud cap", () => {
    const suggestion = "x".repeat(20_000);
    const out = normalizeFinding({
      title: "at-cap suggestion",
      reviewAnnotation: { path: "src/parser.ts", startLine: 1, suggestion },
    });
    expect(out.reviewAnnotation).toEqual({
      path: "src/parser.ts",
      startLine: 1,
      suggestion,
    });
  });

  it("drops fenced or unified-diff suggestions (location kept)", () => {
    const fence = ["```ts", "safe(input)", "```"].join("\n");
    const diff = ["@@ -1,3 +1,3 @@", "-unsafe(input)", "+safe(input)"].join("\n");
    for (const suggestion of [fence, diff]) {
      const out = normalizeFinding({
        title: "unrenderable suggestion",
        reviewAnnotation: { path: "src/parser.ts", startLine: 1, suggestion },
      });
      expect(out.reviewAnnotation).toEqual({
        path: "src/parser.ts",
        startLine: 1,
      });
    }
  });
  it("happy path: full OSS Finding → strict CloudSinkFinding", () => {
    const ossFinding = {
      id: "f-1",
      templateId: "xss-reflected",
      title: "Reflected XSS in /search",
      description: "q param is reflected without encoding",
      severity: "high" as const,
      category: "xss",
      status: "discovered",
      evidence: {
        request: "GET /search?q=<script>",
        response: "<script> echoed",
        analysis: "no encoding in the template",
      },
      timestamp: 1_700_000_000_000,
      confidence: 0.92,
    };
    const out = normalizeFinding(ossFinding);
    expect(out).toEqual({
      id: "f-1",
      templateId: "xss-reflected",
      title: "Reflected XSS in /search",
      description: "q param is reflected without encoding",
      severity: "high",
      category: "xss",
      status: "discovered",
      evidence: {
        request: "GET /search?q=<script>",
        response: "<script> echoed",
        analysis: "no encoding in the template",
      },
      timestamp: 1_700_000_000_000,
      confidence: 0.92,
    });
  });

  it("missing severity defaults to info", () => {
    const out = normalizeFinding({ title: "x", description: "y" });
    expect(out.severity).toBe("info");
  });

  it("unknown severity alias falls back to info (with some known aliases mapped)", () => {
    expect(normalizeFinding({ title: "a", severity: "CRITICAL" }).severity).toBe("critical");
    expect(normalizeFinding({ title: "a", severity: "informational" }).severity).toBe("info");
    expect(normalizeFinding({ title: "a", severity: "warning" }).severity).toBe("medium");
    expect(normalizeFinding({ title: "a", severity: "gibberish" }).severity).toBe("info");
    expect(normalizeFinding({ title: "a" }).severity).toBe("info");
  });

  it("missing id is generated as a non-empty string", () => {
    const a = normalizeFinding({ title: "x" });
    const b = normalizeFinding({ title: "x" });
    expect(typeof a.id).toBe("string");
    expect(a.id.length).toBeGreaterThan(0);
    expect(a.id).not.toBe(b.id);
  });

  it("object evidence is JSON-stringified", () => {
    const out = normalizeFinding({
      title: "x",
      evidence: {
        request: { method: "GET", path: "/" },
        response: { status: 200, body: { ok: true } },
      },
    });
    expect(typeof out.evidence.request).toBe("string");
    expect(typeof out.evidence.response).toBe("string");
    expect(JSON.parse(out.evidence.request)).toEqual({ method: "GET", path: "/" });
    expect(JSON.parse(out.evidence.response)).toEqual({ status: 200, body: { ok: true } });
  });

  it("overlong evidence is truncated below ~64KB with a truncation marker", () => {
    const huge = "A".repeat(200_000);
    const out = normalizeFinding({
      title: "x",
      evidence: { request: huge, response: huge },
    });
    expect(out.evidence.request.length).toBeLessThan(huge.length);
    expect(out.evidence.request).toContain("[truncated");
    expect(out.evidence.request.startsWith("A".repeat(1000))).toBe(true);
  });

  it("flat LLM tool-call args (snake_case) are mapped into nested evidence", () => {
    const out = normalizeFinding({
      title: "Prompt injection",
      description: "leaked system prompt",
      severity: "high",
      category: "prompt-injection",
      template_id: "pi-42",
      evidence_request: "ignore previous",
      evidence_response: "ok, my system prompt is…",
      evidence_analysis: "clear bypass",
    });
    expect(out.templateId).toBe("pi-42");
    expect(out.evidence).toEqual({
      request: "ignore previous",
      response: "ok, my system prompt is…",
      analysis: "clear bypass",
    });
  });

  it("missing required fields (no title, no description) throws CloudSinkNormalizeError", () => {
    expect(() => normalizeFinding({ severity: "high" })).toThrow(CloudSinkNormalizeError);
    expect(() => normalizeFinding(null)).toThrow(CloudSinkNormalizeError);
    expect(() => normalizeFinding("not an object")).toThrow(CloudSinkNormalizeError);
    expect(() => normalizeFinding(42)).toThrow(CloudSinkNormalizeError);
  });

  it("ISO-8601 timestamp strings are parsed to epoch ms", () => {
    const out = normalizeFinding({
      title: "x",
      timestamp: "2024-01-15T10:30:00.000Z",
    });
    expect(out.timestamp).toBe(Date.parse("2024-01-15T10:30:00.000Z"));
  });

  it("confidence is clamped to [0,1]", () => {
    expect(normalizeFinding({ title: "x", confidence: 1.5 }).confidence).toBe(1);
    expect(normalizeFinding({ title: "x", confidence: -0.2 }).confidence).toBe(0);
    expect(normalizeFinding({ title: "x", confidence: 0.5 }).confidence).toBe(0.5);
    expect(normalizeFinding({ title: "x" }).confidence).toBeUndefined();
  });

  it("defaults templateId to 'manual', category to 'unknown', status to 'discovered'", () => {
    const out = normalizeFinding({ title: "x" });
    expect(out.templateId).toBe("manual");
    expect(out.category).toBe("unknown");
    expect(out.status).toBe("discovered");
  });

  it("passes through semanticDedupe when well-formed", () => {
    const out = normalizeFinding({
      title: "x",
      semanticDedupe: {
        canonicalId: "f-1",
        isCanonical: true,
        clusterId: "s1:f-1",
        reason: "most representative",
      },
    });
    expect(out.semanticDedupe).toEqual({
      canonicalId: "f-1",
      isCanonical: true,
      clusterId: "s1:f-1",
      reason: "most representative",
    });
  });

  it("passes through semanticDedupe for duplicate findings", () => {
    const out = normalizeFinding({
      title: "x",
      semanticDedupe: {
        canonicalId: "f-2",
        isCanonical: false,
        clusterId: "s1:f-2",
        reason: "duplicate of f-2",
      },
    });
    expect(out.semanticDedupe?.isCanonical).toBe(false);
    expect(out.semanticDedupe?.canonicalId).toBe("f-2");
  });

  it("drops malformed semanticDedupe (missing fields)", () => {
    const out = normalizeFinding({
      title: "x",
      semanticDedupe: { canonicalId: "f-1" },
    });
    expect(out.semanticDedupe).toBeUndefined();
  });

  it("drops malformed semanticDedupe (wrong types)", () => {
    const out = normalizeFinding({
      title: "x",
      semanticDedupe: {
        canonicalId: "f-1",
        isCanonical: "true",
        clusterId: 123,
        reason: "test",
      },
    });
    expect(out.semanticDedupe).toBeUndefined();
  });

  it("passes through findingRank when finite", () => {
    const out = normalizeFinding({ title: "x", findingRank: 3 });
    expect(out.findingRank).toBe(3);
  });

  it("passes through findingRank = 0 (valid)", () => {
    const out = normalizeFinding({ title: "x", findingRank: 0 });
    expect(out.findingRank).toBe(0);
  });

  it("drops non-finite findingRank", () => {
    expect(normalizeFinding({ title: "x", findingRank: Infinity }).findingRank).toBeUndefined();
    expect(normalizeFinding({ title: "x", findingRank: NaN }).findingRank).toBeUndefined();
  });

  it("drops findingRank when not a number", () => {
    expect(normalizeFinding({ title: "x", findingRank: "3" }).findingRank).toBeUndefined();
  });

  it("semanticDedupe and findingRank are both undefined when absent", () => {
    const out = normalizeFinding({ title: "x" });
    expect(out.semanticDedupe).toBeUndefined();
    expect(out.findingRank).toBeUndefined();
  });
});

// ── discovered-asset push (pwnkit#768 / #761) ──
describe("cloud-sink assets", () => {
  const originalFetch = globalThis.fetch;
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    for (const k of ENV_KEYS) delete process.env[k];
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k]!;
    }
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ── reconAssetToCloudSinkAsset mapper ──

  it("maps an endpoint ReconAsset to a url-bearing /assets payload", () => {
    const asset: ReconAsset = {
      kind: "endpoint",
      value: "GET /api/users",
      source: "https://api.example.com/openapi.json",
      metadata: { method: "GET", path: "/api/users" },
    };
    const out = reconAssetToCloudSinkAsset(asset, "api.example.com");
    expect(out).toEqual({
      discovery_source: "openapi",
      ecosystem: "api.example.com",
      name: "GET /api/users",
      metadata: {
        kind: "endpoint",
        url: "GET /api/users",
        method: "GET",
        path: "/api/users",
        source: "https://api.example.com/openapi.json",
      },
    });
  });

  it("maps an openapi_spec ReconAsset and surfaces endpointCount as an endpoints[] array", () => {
    const asset: ReconAsset = {
      kind: "openapi_spec",
      value: "https://api.example.com/openapi.json",
      source: "https://api.example.com/openapi.json",
      metadata: { title: "Example API", version: "1.0", endpointCount: "3" },
    };
    const out = reconAssetToCloudSinkAsset(asset, "api.example.com");
    expect(out.discovery_source).toBe("openapi");
    expect(out.metadata.url).toBe("https://api.example.com/openapi.json");
    expect(out.metadata.title).toBe("Example API");
    // describeMetadata's "N endpoints" probe reads array length.
    expect(Array.isArray(out.metadata.endpoints)).toBe(true);
    expect((out.metadata.endpoints as unknown[]).length).toBe(3);
  });

  it("maps a subdomain ReconAsset onto a host-keyed payload (dns-bruteforce source)", () => {
    const asset: ReconAsset = {
      kind: "subdomain",
      value: "admin.example.com",
      source: "crt.sh",
      metadata: { addresses: "1.2.3.4", cname: "cdn.example.net" },
    };
    const out = reconAssetToCloudSinkAsset(asset, "example.com");
    expect(out.discovery_source).toBe("dns-bruteforce");
    expect(out.name).toBe("admin.example.com");
    expect(out.metadata.host).toBe("admin.example.com");
    expect(out.metadata.addresses).toBe("1.2.3.4");
    expect(out.metadata.cname).toBe("cdn.example.net");
  });

  it("maps an mcp_server ReconAsset with service=mcp", () => {
    const asset: ReconAsset = {
      kind: "mcp_server",
      value: "https://x.test/mcp",
      source: "https://x.test",
      metadata: { status: "200" },
    };
    const out = reconAssetToCloudSinkAsset(asset, "x.test");
    expect(out.discovery_source).toBe("mcp");
    expect(out.metadata.service).toBe("mcp");
    expect(out.metadata.url).toBe("https://x.test/mcp");
    expect(out.metadata.status).toBe("200");
  });

  it("tags js-recon endpoints with discovery_source=js-recon and a secret_hits count", () => {
    const asset: ReconAsset = {
      kind: "endpoint",
      value: "POST /login",
      source: "https://x.test/app.js",
      metadata: { method: "POST", path: "/login", origin: "js-recon" },
    };
    const out = reconAssetToCloudSinkAsset(asset, "x.test", { fromJs: true, secretHits: 2 });
    expect(out.discovery_source).toBe("js-recon");
    // hasSecretHits() reads a numeric secret_hits key.
    expect(out.metadata.secret_hits).toBe(2);
  });

  it("omits secret_hits when the count is zero", () => {
    const asset: ReconAsset = { kind: "endpoint", value: "GET /", source: "s" };
    const out = reconAssetToCloudSinkAsset(asset, "x.test", { fromJs: true, secretHits: 0 });
    expect(out.metadata.secret_hits).toBeUndefined();
  });

  // ── postAsset / postAssets wire behavior ──

  it("postAsset does NOT call fetch when the sink is unconfigured", async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await postAsset({ discovery_source: "openapi", ecosystem: "x.test", name: "GET /", metadata: {} });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("postAsset POSTs to /assets with the bearer + org header and the asset body", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com/";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-123";
    process.env.PWNKIT_CLOUD_TOKEN = "tok-abc";
    process.env.PWNKIT_CLOUD_ORG_ID = "org_ABCDEFGHIJKLMNOP";

    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 201, text: async () => "" });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const asset: CloudSinkAsset = {
      discovery_source: "openapi",
      ecosystem: "api.example.com",
      name: "GET /api/users",
      metadata: { kind: "endpoint", url: "GET /api/users" },
    };
    await postAsset(asset);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/assets");
    expect(init.method).toBe("POST");
    expect(init.headers["Authorization"]).toBe("Bearer tok-abc");
    // Org scope is forwarded for the non-scan-id-pathed asset write.
    expect(init.headers["X-Pwnkit-Org-Id"]).toBe("org_ABCDEFGHIJKLMNOP");
    expect(JSON.parse(init.body)).toEqual(asset);
  });

  it("postAsset swallows a 5xx — an asset-push failure never aborts the scan", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-1";

    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 500, text: async () => "boom" });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(
      postAsset({ discovery_source: "openapi", ecosystem: "x.test", name: "GET /", metadata: {} }),
    ).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("postAsset swallows a thrown network error (fetch rejects)", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-1";

    const fetchMock = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(
      postAsset({ discovery_source: "openapi", ecosystem: "x.test", name: "GET /", metadata: {} }),
    ).resolves.toBeUndefined();
  });

  it("postAssets posts every asset and never throws when one push fails", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-1";

    let call = 0;
    const fetchMock = vi.fn().mockImplementation(async () => {
      call += 1;
      if (call === 2) throw new Error("transient");
      return { ok: true, status: 201, text: async () => "" };
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const assets: CloudSinkAsset[] = [
      { discovery_source: "openapi", ecosystem: "x.test", name: "GET /a", metadata: {} },
      { discovery_source: "openapi", ecosystem: "x.test", name: "GET /b", metadata: {} },
      { discovery_source: "openapi", ecosystem: "x.test", name: "GET /c", metadata: {} },
    ];
    await expect(postAssets(assets)).resolves.toBeUndefined();
    // All three were attempted despite the middle one failing.
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("postAssets is a no-op for an empty list", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-1";
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await postAssets([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
