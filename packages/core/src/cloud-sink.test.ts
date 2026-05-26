import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  CloudSinkNormalizeError,
  getCloudSinkConfig,
  normalizeFinding,
  postFinding,
  postFinalReport,
} from "./cloud-sink.js";

const ENV_KEYS = [
  "PWNKIT_CLOUD_SINK",
  "PWNKIT_CLOUD_SCAN_ID",
  "PWNKIT_CLOUD_TOKEN",
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
});
