/**
 * 0sec#170 — formalise Finding.evidence into a PoC step graph.
 *
 * Coverage:
 *   1. Type narrowing on PocStepAction / PocStepExpect discriminated unions.
 *   2. JSON serialisation round-trip on a populated PocStep[].
 *   3. Backward-compat: a Finding with no pocSteps is still a valid Finding.
 *   4. The agent-loop `parsePocStepsArg` helper accepts JSON strings and
 *      already-parsed arrays, and rejects malformed payloads cleanly.
 *   5. The cloud-sink `normalizeFinding` passes pocSteps through and drops
 *      malformed step graphs without dropping the finding itself.
 *
 * The PoC step graph is OPTIONAL and ADDITIVE — the existing prose evidence
 * fields (`request`/`response`/`analysis`) stay intact alongside it.
 */
import { randomUUID } from "node:crypto";
import { describe, it, expect } from "vitest";
import type { Finding, PocStep, PocStepAction, PocStepExpect } from "@0sec/shared";
import { parsePocStepsArg } from "./agent/tools.js";
import { normalizeFinding } from "./cloud-sink.js";

function makePocSteps(): PocStep[] {
  return [
    {
      id: "setup-docker",
      kind: "setup",
      summary: "Boot the vulnerable target in Docker",
      action: { type: "shell", cmd: "docker run -d -p 8080:80 vuln/app:latest" },
      expect: { type: "exit-zero" },
    },
    {
      id: "auth-signup",
      kind: "auth",
      summary: "Create a low-privilege attacker account",
      action: {
        type: "http",
        method: "POST",
        url: "http://localhost:8080/signup",
        headers: { "Content-Type": "application/json" },
        body: '{"username":"attacker","password":"hunter2"}',
      },
      expect: { type: "http-status", status: [200, 201] },
    },
    {
      id: "exploit-rce",
      kind: "exploit",
      summary: "Trigger command injection via the avatar URL",
      action: {
        type: "http",
        method: "POST",
        url: "http://localhost:8080/profile/avatar",
        body: 'url=$(id)',
      },
      expect: { type: "body-contains", text: "uid=0(root)" },
    },
    {
      id: "verify-shell",
      kind: "verify",
      summary: "Confirm we landed a shell on the target container",
      action: { type: "docker", image: "kalilinux/kali-rolling", args: ["nc", "127.0.0.1", "4444"] },
      expect: { type: "body-matches", pattern: "root@.*#" },
    },
    {
      id: "note-cleanup",
      kind: "verify",
      summary: "Operator note: tear down the target before re-running",
      action: { type: "note", text: "docker rm -f $(docker ps -q --filter ancestor=vuln/app)" },
    },
  ];
}

describe("PocStep types (0sec#170)", () => {
  it("narrows action.type to the right variant fields", () => {
    const shell: PocStepAction = { type: "shell", cmd: "ls", cwd: "/tmp" };
    const http: PocStepAction = { type: "http", method: "GET", url: "http://x" };
    const docker: PocStepAction = { type: "docker", image: "alpine", args: ["sh"] };
    const note: PocStepAction = { type: "note", text: "do this manually" };

    // The narrowing here is the test — if the union ever broke, tsc would
    // flag .cmd / .url / .image / .text being missing on the wrong variant.
    if (shell.type === "shell") expect(shell.cmd).toBe("ls");
    if (http.type === "http") expect(http.url).toBe("http://x");
    if (docker.type === "docker") expect(docker.image).toBe("alpine");
    if (note.type === "note") expect(note.text).toBe("do this manually");
  });

  it("narrows expect.type to the right predicate fields", () => {
    const exitZero: PocStepExpect = { type: "exit-zero" };
    const httpStatus: PocStepExpect = { type: "http-status", status: 200 };
    const httpStatusList: PocStepExpect = { type: "http-status", status: [200, 201, 204] };
    const bodyContains: PocStepExpect = { type: "body-contains", text: "ok" };
    const bodyMatches: PocStepExpect = { type: "body-matches", pattern: "^ok$" };
    const fileExists: PocStepExpect = { type: "file-exists", path: "/tmp/flag" };

    if (exitZero.type === "exit-zero") expect(exitZero).toBeTruthy();
    if (httpStatus.type === "http-status") expect(httpStatus.status).toBe(200);
    if (httpStatusList.type === "http-status" && Array.isArray(httpStatusList.status)) {
      expect(httpStatusList.status).toEqual([200, 201, 204]);
    }
    if (bodyContains.type === "body-contains") expect(bodyContains.text).toBe("ok");
    if (bodyMatches.type === "body-matches") expect(bodyMatches.pattern).toBe("^ok$");
    if (fileExists.type === "file-exists") expect(fileExists.path).toBe("/tmp/flag");
  });
});

describe("Finding.pocSteps backward compatibility (0sec#170)", () => {
  it("a Finding without pocSteps is still a valid Finding", () => {
    // This is intentionally the legacy shape: prose evidence only, no step
    // graph. Every renderer / sink / DB writer must keep working in this
    // case — the field is OPTIONAL.
    const legacy: Finding = {
      id: randomUUID(),
      templateId: "manual",
      title: "Legacy reflected XSS",
      description: "q param reflected without encoding",
      severity: "high",
      category: "xss",
      status: "discovered",
      evidence: {
        request: "GET /search?q=<script>",
        response: "<script> echoed",
        analysis: "no encoding in the template",
      },
      timestamp: 1_700_000_000_000,
    };
    expect(legacy.pocSteps).toBeUndefined();
    expect(legacy.evidence.request).toContain("<script>");
  });

  it("a Finding with pocSteps coexists with prose evidence (additive)", () => {
    const enriched: Finding = {
      id: randomUUID(),
      templateId: "manual",
      title: "RCE via avatar URL",
      description: "shell metacharacters reach a curl invocation",
      severity: "critical",
      category: "command-injection",
      status: "discovered",
      evidence: {
        request: "POST /profile/avatar url=$(id)",
        response: "uid=0(root)",
        analysis: "$() reaches the shell",
      },
      pocSteps: makePocSteps(),
      timestamp: 1_700_000_000_000,
    };
    // Both halves of the contract present.
    expect(enriched.evidence.request).toContain("$(id)");
    expect(enriched.pocSteps).toBeDefined();
    expect(enriched.pocSteps).toHaveLength(5);
    expect(enriched.pocSteps![0].kind).toBe("setup");
    expect(enriched.pocSteps![enriched.pocSteps!.length - 1].kind).toBe("verify");
  });

  it("JSON serialisation round-trips a populated step graph byte-identically", () => {
    const steps = makePocSteps();
    const wire = JSON.stringify(steps);
    const restored = JSON.parse(wire) as PocStep[];
    // Deep-equal restores; identity does not, by design.
    expect(restored).toEqual(steps);
    expect(restored).not.toBe(steps);
    // Re-stringifying yields the same bytes — i.e. no reordering / loss.
    expect(JSON.stringify(restored)).toBe(wire);
  });

  it("a Finding with pocSteps round-trips through JSON unchanged", () => {
    const f: Finding = {
      id: "f-1",
      templateId: "manual",
      title: "x",
      description: "y",
      severity: "low",
      category: "ssrf",
      status: "discovered",
      evidence: { request: "GET /", response: "ok" },
      pocSteps: makePocSteps(),
      timestamp: 1,
    };
    const restored = JSON.parse(JSON.stringify(f)) as Finding;
    expect(restored).toEqual(f);
  });
});

describe("parsePocStepsArg (agent tool wire shape, 0sec#170)", () => {
  it("returns null for nullish / empty / non-string non-array input", () => {
    expect(parsePocStepsArg(null)).toBeNull();
    expect(parsePocStepsArg(undefined)).toBeNull();
    expect(parsePocStepsArg("")).toBeNull();
    expect(parsePocStepsArg(42)).toBeNull();
    expect(parsePocStepsArg(true)).toBeNull();
    expect(parsePocStepsArg({ kind: "setup" })).toBeNull();
  });

  it("returns null for malformed JSON", () => {
    expect(parsePocStepsArg("[{")).toBeNull();
    expect(parsePocStepsArg("not json")).toBeNull();
  });

  it("returns null for valid JSON that isn't an array", () => {
    expect(parsePocStepsArg('{"kind":"setup"}')).toBeNull();
    expect(parsePocStepsArg('"setup"')).toBeNull();
    expect(parsePocStepsArg("123")).toBeNull();
  });

  it("parses a JSON-encoded string of valid steps", () => {
    const steps = makePocSteps();
    const out = parsePocStepsArg(JSON.stringify(steps));
    expect(out).not.toBeNull();
    expect(out).toHaveLength(steps.length);
    expect(out![0].id).toBe("setup-docker");
  });

  it("accepts an already-parsed array of valid steps", () => {
    const steps = makePocSteps();
    const out = parsePocStepsArg(steps);
    expect(out).toEqual(steps);
  });

  it("drops individual malformed steps but keeps the well-formed ones", () => {
    const mixed = [
      // good
      {
        id: "ok",
        kind: "exploit",
        summary: "send the payload",
        action: { type: "shell", cmd: "id" },
      },
      // missing id
      { kind: "exploit", summary: "no id", action: { type: "shell", cmd: "id" } },
      // unknown kind
      {
        id: "x",
        kind: "armageddon",
        summary: "bad kind",
        action: { type: "shell", cmd: "id" },
      },
      // unknown action type
      {
        id: "y",
        kind: "exploit",
        summary: "bad action",
        action: { type: "smtp", host: "x" },
      },
      // not an object
      "nope",
      null,
    ];
    const out = parsePocStepsArg(mixed);
    expect(out).toHaveLength(1);
    expect(out![0].id).toBe("ok");
  });

  it("drops a malformed expect predicate but keeps the step itself", () => {
    const out = parsePocStepsArg([
      {
        id: "exp",
        kind: "exploit",
        summary: "send and check",
        action: { type: "shell", cmd: "id" },
        expect: { type: "definitely-not-a-predicate" },
      },
    ]);
    expect(out).toHaveLength(1);
    expect(out![0].expect).toBeUndefined();
  });

  it("returns null when every candidate step is malformed", () => {
    const out = parsePocStepsArg([{ kind: "broken" }, "string", 7]);
    expect(out).toBeNull();
  });
});

describe("cloud-sink normalizeFinding pass-through of pocSteps (0sec#170)", () => {
  it("passes a structured pocSteps array through unchanged", () => {
    const steps = makePocSteps();
    const out = normalizeFinding({
      id: "f-1",
      title: "RCE",
      severity: "critical",
      evidence: { request: "x", response: "y" },
      pocSteps: steps,
    });
    expect(out.pocSteps).toEqual(steps);
  });

  it("parses a JSON-encoded poc_steps string (LLM tool-call shape)", () => {
    const steps = makePocSteps();
    const out = normalizeFinding({
      title: "RCE",
      severity: "high",
      evidence_request: "x",
      evidence_response: "y",
      poc_steps: JSON.stringify(steps),
    });
    expect(Array.isArray(out.pocSteps)).toBe(true);
    expect(out.pocSteps).toHaveLength(steps.length);
    expect(out.pocSteps).toEqual(steps);
  });

  it("drops malformed pocSteps without dropping the finding", () => {
    const out = normalizeFinding({
      title: "still useful",
      severity: "high",
      evidence: { request: "x", response: "y" },
      pocSteps: "not json [",
    });
    expect(out.pocSteps).toBeUndefined();
    expect(out.title).toBe("still useful");
  });

  it("omits pocSteps when the input has none (legacy findings)", () => {
    const out = normalizeFinding({
      title: "legacy",
      severity: "low",
      evidence: { request: "x", response: "y" },
    });
    expect(out.pocSteps).toBeUndefined();
  });
});
