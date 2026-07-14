import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  WindowsEvidenceWorkerClient,
  WindowsEvidenceWorkerTransportError,
  type WindowsEvidenceWorkerBlob,
} from "./windows-evidence-worker.js";

const BASE_URL = "https://worker.example.test/api";
const JOB_ID = "550e8400-e29b-41d4-a716-446655440000";
const GRANT = "A".repeat(43);
const NOW = Date.parse("2026-07-14T10:00:00.000Z");
const EXPIRY = "2026-07-14T10:05:00.000Z";
const PACK_ID = "b".repeat(64);

function blob(text: string, mediaType = "application/octet-stream"): WindowsEvidenceWorkerBlob {
  const bytes = new TextEncoder().encode(text);
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    sizeBytes: bytes.byteLength,
    mediaType,
    bytes,
  };
}

function stored(
  input: WindowsEvidenceWorkerBlob,
  status: "stored" | "already-stored" = "stored",
): Response {
  return Response.json({
    status,
    ref: {
      sha256: input.sha256,
      sizeBytes: input.sizeBytes,
      mediaType: input.mediaType,
    },
  });
}

function client(
  fetchImpl: typeof fetch,
  options: {
    now?: () => number;
    sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
    maxAttemptsPerRequest?: number;
  } = {},
): WindowsEvidenceWorkerClient {
  return new WindowsEvidenceWorkerClient(
    {
      baseUrl: BASE_URL,
      jobId: JOB_ID,
      uploadGrant: GRANT,
      uploadGrantExpiresAt: EXPIRY,
    },
    { fetchImpl, now: options.now ?? (() => NOW), ...options },
  );
}

describe("WindowsEvidenceWorkerClient uploads", () => {
  it("uses the exact grant-bound PUT route and verifies the response binding", async () => {
    const input = blob("retained evidence", "application/json");
    let captured: { url: string; init: RequestInit } | undefined;
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      captured = { url: String(url), init: init ?? {} };
      return stored(input);
    }) as typeof fetch;

    const result = await client(fetchImpl).uploadBlob(input);

    expect(result).toEqual({
      status: "stored",
      ref: { sha256: input.sha256, sizeBytes: input.sizeBytes, mediaType: input.mediaType },
    });
    expect(captured?.url).toBe(
      `${BASE_URL}/internal/windows-evidence-worker/jobs/${JOB_ID}/blobs/${input.sha256}`,
    );
    expect(captured?.init.method).toBe("PUT");
    expect(captured?.init.redirect).toBe("error");
    const headers = captured?.init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${GRANT}`);
    expect(headers["Content-Length"]).toBe(String(input.sizeBytes));
    expect(headers["Content-Type"]).toBe(input.mediaType);
    expect(
      new Uint8Array(await new Response(captured?.init.body).arrayBuffer()),
    ).toEqual(input.bytes);
  });

  it("deduplicates equal digests while preserving first-seen order", async () => {
    const first = blob("first");
    const second = blob("second");
    const seen: string[] = [];
    const fetchImpl = (async (url: string | URL | Request) => {
      const digest = String(url).split("/").at(-1)!;
      seen.push(digest);
      const input = digest === first.sha256 ? first : second;
      return stored(input, "already-stored");
    }) as typeof fetch;

    const result = await client(fetchImpl).uploadBlobs([first, first, second]);

    expect(seen).toEqual([first.sha256, second.sha256]);
    expect(result.map((entry) => entry.status)).toEqual(["already-stored", "already-stored"]);
  });

  it("polls 202 using Retry-After and retries transient 503 responses", async () => {
    const input = blob("poll me");
    const responses = [
      new Response(JSON.stringify({ status: "in-progress" }), {
        status: 202,
        headers: { "retry-after": "2" },
      }),
      new Response("unavailable", { status: 503 }),
      stored(input),
    ];
    const fetchImpl = vi.fn(async () => responses.shift()!) as unknown as typeof fetch;
    const sleep = vi.fn(async () => undefined);

    await expect(
      client(fetchImpl, { sleep }).uploadBlob(input),
    ).resolves.toMatchObject({ status: "stored" });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(sleep.mock.calls.map(([milliseconds]) => milliseconds)).toEqual([2_000, 250]);
  });

  it.each([404, 409, 422, 500])("fails closed on HTTP %s without retrying", async (status) => {
    const input = blob(`status-${status}`);
    const fetchImpl = vi.fn(
      async () => new Response("rejected", { status }),
    ) as unknown as typeof fetch;
    const error = await client(fetchImpl).uploadBlob(input).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(WindowsEvidenceWorkerTransportError);
    expect((error as WindowsEvidenceWorkerTransportError).status).toBe(status);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("bounds retries and refuses a retry that reaches grant expiry", async () => {
    const input = blob("expires");
    let now = NOW;
    const fetchImpl = vi.fn(async () => new Response("busy", {
      status: 503,
      headers: { "retry-after": "2" },
    })) as unknown as typeof fetch;
    const sleep = async (milliseconds: number) => { now += milliseconds; };
    const expiring = new WindowsEvidenceWorkerClient(
      {
        baseUrl: BASE_URL,
        jobId: JOB_ID,
        uploadGrant: GRANT,
        uploadGrantExpiresAt: new Date(NOW + 2_000),
      },
      { fetchImpl, now: () => now, sleep, maxAttemptsPerRequest: 20 },
    );

    await expect(expiring.uploadBlob(input)).rejects.toThrow(/expire before retry/);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("validates bytes before any network request", async () => {
    const input = blob("identity");
    const fetchImpl = vi.fn(async () => stored(input)) as unknown as typeof fetch;
    const invalid = { ...input, sha256: "0".repeat(64) };
    await expect(client(fetchImpl).uploadBlob(invalid)).rejects.toThrow(/declared digest/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects a mismatched 200 response instead of trusting it", async () => {
    const input = blob("binding");
    const fetchImpl = (async () => Response.json({
      status: "stored",
      ref: { sha256: "f".repeat(64), sizeBytes: input.sizeBytes, mediaType: input.mediaType },
    })) as typeof fetch;
    await expect(client(fetchImpl).uploadBlob(input)).rejects.toThrow(/invalid response/);
  });
});

describe("WindowsEvidenceWorkerClient submission", () => {
  it("posts caller-provided JSON to the exact submit route and validates the receipt", async () => {
    let captured: { url: string; init: RequestInit } | undefined;
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      captured = { url: String(url), init: init ?? {} };
      return Response.json({ jobId: JOB_ID, packId: PACK_ID, status: "submitted" });
    }) as typeof fetch;
    const envelope = { schemaVersion: "caller-owned", packId: PACK_ID };

    await expect(client(fetchImpl).submitEnvelope(envelope)).resolves.toEqual({
      jobId: JOB_ID,
      packId: PACK_ID,
      status: "submitted",
    });
    expect(captured?.url).toBe(
      `${BASE_URL}/internal/windows-evidence-worker/jobs/${JOB_ID}/submit`,
    );
    expect(captured?.init.method).toBe("POST");
    expect(captured?.init.redirect).toBe("error");
    const headers = captured?.init.headers as Record<string, string>;
    const body = new Uint8Array(await new Response(captured?.init.body).arrayBuffer());
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["Content-Length"]).toBe(String(body.byteLength));
    expect(JSON.parse(new TextDecoder().decode(body))).toEqual(envelope);
  });

  it("retries 503 but treats 202 and 409 as terminal for submit", async () => {
    const success = Response.json({ jobId: JOB_ID, packId: PACK_ID, status: "submitted" });
    const responses = [new Response("busy", { status: 503 }), success];
    const retryFetch = vi.fn(async () => responses.shift()!) as unknown as typeof fetch;
    await expect(
      client(retryFetch, { sleep: async () => undefined }).submitEnvelope({}),
    ).resolves.toMatchObject({ status: "submitted" });
    expect(retryFetch).toHaveBeenCalledTimes(2);

    for (const status of [202, 409]) {
      const fetchImpl = vi.fn(
        async () => new Response("no", { status }),
      ) as unknown as typeof fetch;
      await expect(client(fetchImpl).submitEnvelope({})).rejects.toMatchObject({ status });
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    }
  });

  it("accepts the 256 KiB boundary and rejects larger envelopes before fetch", async () => {
    const fetchImpl = vi.fn(async () => Response.json({
      jobId: JOB_ID,
      packId: PACK_ID,
      status: "submitted",
    })) as unknown as typeof fetch;
    const atLimit = { x: "a".repeat(256 * 1024 - 8) };
    await expect(client(fetchImpl).submitEnvelope(atLimit)).resolves.toMatchObject({
      status: "submitted",
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const overLimit = { x: "a".repeat(256 * 1024 - 7) };
    await expect(client(fetchImpl).submitEnvelope(overLimit)).rejects.toThrow(/256 KiB/);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe("WindowsEvidenceWorkerClient capability hygiene", () => {
  it("redacts the upload grant from hostile network errors", async () => {
    const input = blob("secret hygiene");
    const fetchImpl = (async () => {
      throw new Error(`socket failed while using Bearer ${GRANT}`);
    }) as typeof fetch;
    const error = await client(fetchImpl).uploadBlob(input).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(WindowsEvidenceWorkerTransportError);
    expect((error as Error).message).toContain("[REDACTED]");
    expect((error as Error).message).not.toContain(GRANT);
  });

  it("refuses redirects instead of forwarding the bearer capability", async () => {
    const input = blob("redirect hygiene");
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      expect(init?.redirect).toBe("error");
      throw new Error(`redirect blocked for bearer ${GRANT}`);
    }) as typeof fetch;
    const error = await client(fetchImpl).uploadBlob(input).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(WindowsEvidenceWorkerTransportError);
    expect((error as Error).message).not.toContain(GRANT);
    expect((error as Error).message).toContain("[REDACTED]");
  });

  it("rejects malformed or expired handoffs before use", () => {
    expect(() => new WindowsEvidenceWorkerClient({
      baseUrl: "http://worker.example.test",
      jobId: JOB_ID,
      uploadGrant: GRANT,
      uploadGrantExpiresAt: EXPIRY,
    }, { now: () => NOW })).toThrow(/base URL/);
    expect(() => new WindowsEvidenceWorkerClient({
      baseUrl: BASE_URL,
      jobId: JOB_ID,
      uploadGrant: GRANT,
      uploadGrantExpiresAt: new Date(NOW),
    }, { now: () => NOW })).toThrow(/expired/);
  });
});
