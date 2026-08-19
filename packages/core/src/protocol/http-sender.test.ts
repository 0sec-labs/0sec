import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import type {
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeToolDef,
} from "../runtime/types.js";
import { runHttpConformanceCheck } from "./http-conformance.js";
import { createLiveHttpSender } from "./http-sender.js";

/**
 * A deliberately NON-CONFORMANT little server, standing in for a `<Limit>`-style
 * method-restriction bypass: the spec excerpt below says the admin endpoint MUST
 * reject DELETE (405), but this server happily accepts DELETE and returns 200.
 * GET to the same path is a legitimate, conformant control (200).
 */
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    // PLANTED BUG: DELETE is accepted on the restricted resource (should be 405).
    if (req.method === "DELETE") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("deleted");
      return;
    }
    // Conformant control: GET is allowed.
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
      return;
    }
    res.writeHead(405, { "content-type": "text/plain", allow: "GET" });
    res.end("method not allowed");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
});

describe("createLiveHttpSender", () => {
  it("sends the exact method and returns the http_request output shape", async () => {
    const send = createLiveHttpSender();
    const result = await send({ url: `${baseUrl}/admin`, method: "DELETE" });
    expect(result.success).toBe(true);
    expect(result.output?.status).toBe(200);
    expect(result.output?.headers?.["content-type"]).toContain("text/plain");
  });

  it("sends a conformant control method and observes its status", async () => {
    const send = createLiveHttpSender();
    const result = await send({ url: `${baseUrl}/admin`, method: "GET" });
    expect(result.success).toBe(true);
    expect(result.output?.status).toBe(200);
  });

  it("never throws on a transport error — returns success:false", async () => {
    const send = createLiveHttpSender({ timeoutMs: 200 });
    // Port 1 is unbindable / refused → connection error, not an exception.
    const result = await send({ url: "http://127.0.0.1:1/x", method: "GET" });
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

/**
 * Drives the REAL driver + REAL deterministic oracle + REAL live HTTP send
 * against the live server above. Only the conformance-gen (LLM) step is stubbed
 * with the known hypotheses for the planted bug — so the send/judge loop is
 * genuinely exercised end-to-end against a real socket.
 */
describe("runHttpConformanceCheck with the live sender (real server)", () => {
  const SPEC =
    "The /admin resource is read-only. A server MUST reject a DELETE request " +
    "to /admin with 405 (Method Not Allowed). GET /admin is permitted.";
  const IMPL =
    "createServer((req,res)=>{ if(req.method==='DELETE'){res.writeHead(200);res.end()} })";

  // Two hypotheses: the planted DELETE bug (should CONFIRM) + a GET control
  // (should REFUTE — proves the loop isn't blanket-confirming).
  const MODEL = {
    rules: [
      {
        id: "admin-delete-must-405",
        specCitation: "Internal spec §1 (MUST reject DELETE /admin)",
        level: "MUST",
        surface: "method",
        mandate: "MUST respond 405 to DELETE /admin",
        exercise: { method: "DELETE", path: "/admin" },
      },
      {
        id: "admin-get-allowed",
        specCitation: "Internal spec §1 (GET /admin permitted)",
        level: "MUST",
        surface: "method",
        mandate: "GET /admin returns 200",
        exercise: { method: "GET", path: "/admin" },
      },
    ],
    hypotheses: [
      {
        ruleId: "admin-delete-must-405",
        specCitation: "Internal spec §1",
        level: "MUST",
        implLocation: "createServer handler, DELETE branch",
        rationale: "handler returns 200 for DELETE instead of 405",
        predictedObservable: {
          surface: "method",
          expectedStatusIn: [405],
          forbiddenStatusIn: [200],
        },
        exercise: { method: "DELETE", path: "/admin" },
        confidence: 0.6,
      },
      {
        ruleId: "admin-get-allowed",
        specCitation: "Internal spec §1",
        level: "MUST",
        implLocation: "createServer handler, GET branch",
        rationale: "control: GET should be permitted (conformant)",
        predictedObservable: {
          surface: "method",
          expectedStatusIn: [200],
          forbiddenStatusIn: [403, 405],
        },
        exercise: { method: "GET", path: "/admin" },
        confidence: 0.3,
      },
    ],
  };

  function stubLlm(obj: unknown): NativeRuntime {
    return {
      type: "api",
      async executeNative(
        _s: string,
        _m: NativeMessage[],
        _t: NativeToolDef[],
      ): Promise<NativeRuntimeResult> {
        return {
          content: [
            { type: "text", text: "```json\n" + JSON.stringify(obj) + "\n```" },
          ],
          stopReason: "end_turn",
          durationMs: 1,
        };
      },
      async isAvailable() {
        return true;
      },
    };
  }

  it("CONFIRMS the planted DELETE divergence and REFUTES the GET control", async () => {
    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      baseUrl,
      stubLlm(MODEL),
      createLiveHttpSender(),
      { name: "HTTP/1.1", version: "RFC 9110", specRef: "Internal spec" },
    );

    expect(result.ok).toBe(true);
    // Exactly one confirmed finding: the DELETE bypass.
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.fingerprint).toContain("admin-delete-must-405");
    expect(result.findings[0]!.status).toBe("confirmed");
    expect(result.findings[0]!.confidence).toBe(1.0);

    const byRule = Object.fromEntries(
      result.attempts.map((a) => [a.hypothesis.ruleId, a]),
    );
    // The planted bug: observed 200, oracle confirmed against forbidden set.
    expect(byRule["admin-delete-must-405"]!.observed.status).toBe(200);
    expect(byRule["admin-delete-must-405"]!.verdict.status).toBe("confirmed");
    // The control: observed 200, in the expected set → refuted (NOT flagged).
    expect(byRule["admin-get-allowed"]!.observed.status).toBe(200);
    expect(byRule["admin-get-allowed"]!.verdict.status).toBe("refuted");
  });
});
