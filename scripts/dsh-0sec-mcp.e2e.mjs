import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import { access, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(scriptPath), "..");
const runnerPath = join(repoRoot, "scripts", "dsh-0sec-mcp.mjs");
const entrypoint = join(repoRoot, "dist", "0sec.js");
const marker = "DSH-0SEC-E2E: health tool completed.";

function listen(server) {
  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", rejectPromise);
      const address = server.address();
      if (!address || typeof address === "string") {
        rejectPromise(new Error("fixture did not bind a TCP port"));
        return;
      }
      resolvePromise(`http://127.0.0.1:${address.port}`);
    });
  });
}

async function close(server) {
  server.close();
  await once(server, "close");
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1024 * 1024) throw new Error("fixture request exceeds 1 MiB");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function writeSse(response, chunks) {
  response.writeHead(200, {
    "cache-control": "no-cache",
    connection: "keep-alive",
    "content-type": "text/event-stream",
  });
  for (const chunk of chunks) response.write(`data: ${JSON.stringify(chunk)}\n\n`);
  response.end("data: [DONE]\n\n");
}

function streamToolCall(target) {
  const now = Math.floor(Date.now() / 1000);
  return [
    {
      id: "chatcmpl-dsh-0sec-e2e-tool",
      object: "chat.completion.chunk",
      created: now,
      model: "fixture-agent",
      choices: [{
        index: 0,
        delta: {
          role: "assistant",
          tool_calls: [{
            index: 0,
            id: "call-0sec-health",
            type: "function",
            function: {
              name: "mcp__0sec__http_request",
              arguments: JSON.stringify({ method: "GET", url: `${target}/health` }),
            },
          }],
        },
        finish_reason: null,
      }],
    },
    {
      id: "chatcmpl-dsh-0sec-e2e-tool",
      object: "chat.completion.chunk",
      created: now,
      model: "fixture-agent",
      choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
    },
  ];
}

function streamFinalAnswer() {
  const now = Math.floor(Date.now() / 1000);
  return [
    {
      id: "chatcmpl-dsh-0sec-e2e-final",
      object: "chat.completion.chunk",
      created: now,
      model: "fixture-agent",
      choices: [{ index: 0, delta: { role: "assistant", content: marker }, finish_reason: null }],
    },
    {
      id: "chatcmpl-dsh-0sec-e2e-final",
      object: "chat.completion.chunk",
      created: now,
      model: "fixture-agent",
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    },
  ];
}

function toolNames(request) {
  return (request.tools ?? []).map((tool) => tool.function?.name ?? tool.name).filter(Boolean);
}

function run(command, args, env, timeoutMs = 90_000) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, { cwd: repoRoot, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", (error) => {
      clearTimeout(timeout);
      rejectPromise(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      resolvePromise({ code: code ?? 1, signal, stdout, stderr });
    });
  });
}

function dshHomePatch(modelOrigin) {
  return `- id: llm-pi-ai
  config:
    providers:
      fixture:
        apiKeyEnv: DSH_E2E_FAKE_KEY
        api: openai-completions
        baseURL: ${JSON.stringify(`${modelOrigin}/v1`)}
        compat:
          supportsDeveloperRole: false
          maxTokensField: max_tokens
        models:
          - id: fixture-agent
            contextWindow: 16384
            maxTokens: 1024


- id: session-title-llm
  disabled: true
- id: agent-default-model
  config:
    provider: fixture
    model: fixture-agent
`;
}

async function main() {
  const dshBin = process.env.DSH_E2E_BIN;
  if (!dshBin) {
    throw new Error("set DSH_E2E_BIN to the pinned @deepseek-ai/dsh executable");
  }
  await access(dshBin);
  await access(entrypoint);

  const targetRequests = [];
  const timings = {
    firstModelRequest: undefined,
    runnerEnd: 0,
    runnerStart: 0,
    secondModelRequest: undefined,
    targetRequest: undefined,
  };
  const targetServer = createServer((request, response) => {
    targetRequests.push({ method: request.method, url: request.url });
    timings.targetRequest ??= performance.now();
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ status: "ok", fixture: "0sec-dsh-e2e" }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  const targetOrigin = await listen(targetServer);

  const modelRequests = [];
  let fixtureError;
  const modelServer = createServer(async (request, response) => {
    try {
      if (request.method !== "POST" || !["/v1/chat/completions", "/chat/completions"].includes(request.url ?? "")) {
        response.writeHead(404);
        response.end();
        return;
      }
      const body = await readJson(request);
      modelRequests.push(body);
      if (modelRequests.length === 1) timings.firstModelRequest = performance.now();
      if (modelRequests.length === 2) timings.secondModelRequest = performance.now();
      if (modelRequests.length === 1) {
        const names = toolNames(body);
        if (!names.includes("mcp__0sec__http_request")) {
          fixtureError = new Error(`0sec MCP http_request was absent from DSH tools: ${JSON.stringify(names)}`);
        }
        if (names.some((name) => !name.startsWith("mcp__0sec__"))) {
          fixtureError = new Error(`generic DSH tool leaked into the model request: ${JSON.stringify(names)}`);
        }
        writeSse(response, streamToolCall(targetOrigin));
        return;
      }
      writeSse(response, streamFinalAnswer());
    } catch (error) {
      fixtureError = error instanceof Error ? error : new Error(String(error));
      response.writeHead(500);
      response.end(fixtureError.message);
    }
  });
  const modelOrigin = await listen(modelServer);

  const fixture = await mkdtemp(join(tmpdir(), "0sec-dsh-mcp-e2e-"));
  try {
    const dshHome = join(fixture, "dsh-home");
    const zeroSecHome = join(fixture, "0sec-home");
    const scopePath = join(fixture, "scope.json");
    await mkdir(dshHome, { recursive: true });
    await mkdir(zeroSecHome, { recursive: true });
    await writeFile(join(dshHome, "cordis.patch.yml"), dshHomePatch(modelOrigin), { mode: 0o600 });
    await writeFile(scopePath, JSON.stringify({ in_scope: ["127.0.0.1"] }), { mode: 0o600 });

    const runnerArgs = [
      runnerPath,
      "--target", targetOrigin,
      "--scan-id", "dsh-mcp-e2e",
      "--scope", scopePath,
      ...(process.env.DSH_E2E_MCP_TOOLS
        ? ["--mcp-tools", process.env.DSH_E2E_MCP_TOOLS]
        : []),
      "--mcp-env", "HOME",
      "--dsh-bin", dshBin,
      "Call the 0sec MCP http_request tool on the target health endpoint, then report completion.",
    ];
    timings.runnerStart = performance.now();
    const result = await run(
      process.execPath,
      runnerArgs,
      {
        ...process.env,
        DSH_E2E_FAKE_KEY: "fixture-key",
        DSH_HOME: dshHome,
        HOME: zeroSecHome,
      },
    );
    timings.runnerEnd = performance.now();

    assert.equal(result.signal, null, `runner was terminated by ${result.signal}`);
    assert.equal(result.code, 0, `runner failed:\n${result.stderr}`);
    assert.match(result.stdout, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.equal(fixtureError, undefined, fixtureError?.message);
    assert.equal(modelRequests.length, 2, `expected two model turns, received ${modelRequests.length}`);
    assert.deepEqual(targetRequests, [{ method: "GET", url: "/health" }]);

    const schemaBytes = Buffer.byteLength(JSON.stringify(modelRequests[0].tools ?? []));
    const toolSchemaBytes = (modelRequests[0].tools ?? []).map((tool) => ({
      bytes: Buffer.byteLength(JSON.stringify(tool)),
      name: tool.function?.name ?? tool.name,
    }));
    const firstRequestBytes = Buffer.byteLength(JSON.stringify(modelRequests[0]));
    const secondRequestBytes = Buffer.byteLength(JSON.stringify(modelRequests[1]));
    const elapsed = (from, to) => from === undefined || to === undefined ? "n/a" : `${Math.round(to - from)}ms`;

    process.stdout.write(
      `DSH MCP E2E passed: ${toolNames(modelRequests[0]).length} scoped MCP tools, ` +
      `${schemaBytes} tool-schema bytes, ${firstRequestBytes}/${secondRequestBytes} request bytes, ` +
      `${elapsed(timings.runnerStart, timings.runnerEnd)} total, ` +
      `${elapsed(timings.firstModelRequest, timings.targetRequest)} model-to-tool, ` +
      `${elapsed(timings.targetRequest, timings.secondModelRequest)} tool-to-model.\n` +
      `Tool schema bytes: ${toolSchemaBytes.map(({ name, bytes }) => `${name}=${bytes}`).join(", ")}.\n`,
    );
  } finally {
    await close(modelServer);
    await close(targetServer);
    await rm(fixture, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`dsh-0sec-mcp.e2e: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
