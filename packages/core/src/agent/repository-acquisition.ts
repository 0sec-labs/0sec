import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { BlockList, connect, isIP, type Socket } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ScopePolicy } from "../scope/scope.js";
import { superviseChild } from "./scanner-tools.js";
import { sanitizedEnv } from "./sanitized-env.js";
import { shellTokens } from "./shell-tokens.js";
import { formatTruncated } from "./output-truncation.js";
import type { ToolResult } from "./types.js";

export interface RepositoryAcquisition {
  url: string;
  cwd: string;
  cloneArgs: string[];
}

/** Recognize a whole checkout command, never a download followed by arbitrary shell work. */
export function parseRepositoryAcquisition(command: string): RepositoryAcquisition | null {
  if (/[\x00-\x1f$`\\<>()[\]{}!*?#]/.test(command) || !/^(?:[^'"]|'[^']*'|"[^"]*")*$/.test(command)) return null;
  const tokens = shellTokens(command);
  let cwd = process.cwd();
  const directory = (path: string) => resolve(cwd, path.startsWith("~/") ? join(homedir(), path.slice(2)) : path);
  if (tokens[0] === "cd") {
    const pathIndex = tokens[1] === "--" ? 2 : 1;
    if (!tokens[pathIndex] || tokens[pathIndex + 1] !== "&&") return null;
    cwd = directory(tokens[pathIndex]);
    tokens.splice(0, pathIndex + 2);
  }
  if (tokens.shift() !== "git") return null;
  if (tokens[0] === "-C") {
    if (!tokens[1]) return null;
    cwd = directory(tokens[1]);
    tokens.splice(0, 2);
  }
  if (tokens.shift() !== "clone" || tokens.some(token => /^(?:[|&;]+|\n)$/.test(token))) return null;
  const cloneArgs: string[] = [];
  while (tokens[0]?.startsWith("-")) {
    const flag = tokens.shift()!;
    if (flag === "--") break;
    if (["--quiet", "-q", "--verbose", "-v", "--progress", "--single-branch", "--no-single-branch", "--no-checkout", "-n", "--bare"].includes(flag)) {
      cloneArgs.push(flag);
      continue;
    }
    const equals = flag.indexOf("=");
    const name = equals < 0 ? flag : flag.slice(0, equals);
    if (!["--depth", "--branch", "-b", "--filter"].includes(name)) return null;
    const value = equals < 0 ? tokens.shift() : flag.slice(equals + 1);
    if (!value || (name === "--depth" && !/^[1-9]\d*$/.test(value))) return null;
    if (name === "--filter" && !/^(?:blob:none|blob:limit=\d+[kmg]?|tree:\d+)$/.test(value)) return null;
    cloneArgs.push(name, value);
  }
  if (tokens.length < 1 || tokens.length > 2) return null;
  try {
    const url = new URL(tokens[0]);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || (url.port && url.port !== "443") || url.pathname === "/") return null;
    url.hostname = url.hostname.replace(/\.+$/, "");
    cloneArgs.push("--", url.href, ...tokens.slice(1));
    return { url: url.href, cwd, cloneArgs };
  } catch {
    return null;
  }
}

/** Preserve explicit exclusions without turning a source host into an attack target. */
export function repositoryAcquisitionAllowed(plan: RepositoryAcquisition, scope?: ScopePolicy): boolean {
  if (!scope) return true;
  return ScopePolicy.fromJson({
    ...scope.raw,
    in_scope: [...(scope.raw.in_scope ?? []), new URL(plan.url).hostname],
  }).match(plan.url).allowed;
}

const blockedIpv4 = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["192.88.99.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blockedIpv4.addSubnet(address, prefix, "ipv4");
const globalIpv6 = new BlockList();
globalIpv6.addSubnet("2000::", 3, "ipv6");
const blockedIpv6 = new BlockList();
blockedIpv6.addSubnet("2001:db8::", 32, "ipv6");
blockedIpv6.addSubnet("2001::", 23, "ipv6");
blockedIpv6.addSubnet("2002::", 16, "ipv6");

export function isPublicRepositoryAddress(address: string): boolean {
  const family = isIP(address);
  return family === 4 ? !blockedIpv4.check(address, "ipv4")
    : family === 6 && globalIpv6.check(address, "ipv6") && !blockedIpv6.check(address, "ipv6");
}

/** Git can only tunnel to the validated source address; redirects/alternates cannot widen egress. */
export async function runRepositoryAcquisition(
  plan: RepositoryAcquisition,
  command: string,
  timeoutMs: number,
  ceilingMs: number,
  scope?: ScopePolicy,
): Promise<ToolResult> {
  const url = new URL(plan.url);
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = await lookup(hostname, { all: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicRepositoryAddress(address))) {
    throw new Error("Repository acquisition requires a public HTTPS source; private/internal destinations are not authorized by checkout setup");
  }
  for (const { address, family } of addresses) {
    const resolvedUrl = new URL(url);
    resolvedUrl.hostname = family === 6 ? `[${address}]` : address;
    if (!repositoryAcquisitionAllowed({ ...plan, url: resolvedUrl.href }, scope)) {
      throw new Error("Repository source address is explicitly excluded by the engagement scope");
    }
  }
  const source = addresses[0];
  const sockets = new Set<Socket>();
  const track = (socket: Socket) => {
    sockets.add(socket);
    socket.on("error", () => socket.destroy());
    socket.once("close", () => sockets.delete(socket));
  };
  const proxy = createServer((_request, response) => { response.writeHead(403).end(); });
  proxy.on("connection", track);
  proxy.on("connect", (request, client, head) => {
    if (request.url?.toLowerCase() !== `${url.hostname.toLowerCase()}:443`) {
      client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    const upstream = connect({ host: source.address, family: source.family, port: 443 });
    track(upstream);
    client.once("close", () => upstream.destroy());
    upstream.once("error", () => client.destroy());
    upstream.once("connect", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      client.pipe(upstream).pipe(client);
    });
  });
  const home = await mkdtemp(join(tmpdir(), "0sec-source-acquisition-"));
  try {
    await new Promise<void>((resolveReady, reject) => {
      proxy.once("error", reject);
      proxy.listen(0, "127.0.0.1", resolveReady);
    });
    const address = proxy.address();
    if (!address || typeof address === "string") throw new Error("Cannot open source acquisition tunnel");
    const argv = [
      "-C", plan.cwd,
      "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
      "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "-c", "init.templateDir=",
      "-c", "http.sslVerify=true", "-c", "http.followRedirects=false",
      "-c", `http.proxy=http://127.0.0.1:${address.port}`,
      "clone", ...plan.cloneArgs,
    ];
    const startedAt = Date.now();
    const child = spawn("git", argv, {
      shell: false, detached: true, stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...sanitizedEnv({ PATH: process.env.PATH, LANG: process.env.LANG, LC_ALL: process.env.LC_ALL, LC_CTYPE: process.env.LC_CTYPE, TMPDIR: process.env.TMPDIR }),
        HOME: home, XDG_CONFIG_HOME: home,
        GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0",
        GIT_ASKPASS: "/bin/false", NO_PROXY: "", no_proxy: "",
      },
    });
    const outcome = await superviseChild(child, Math.min(timeoutMs, ceilingMs), startedAt);
    const output = formatTruncated(outcome.kind === "exit" ? outcome.combined : outcome.kind === "timeout" ? outcome.partial : outcome.message);
    const success = outcome.kind === "exit" && outcome.exitCode === 0;
    return {
      success,
      output: success ? output || "Repository checkout completed" : null,
      ...(!success ? { error: outcome.kind === "timeout" ? `Repository checkout timed out after ${Math.round(timeoutMs / 1000)}s` : output || "Repository checkout failed" } : {}),
      meta: {
        kind: "command", command, exitCode: outcome.kind === "exit" ? outcome.exitCode : null,
        durationMs: outcome.durationMs, timeoutMs, timedOut: outcome.kind === "timeout", stdout: output,
      },
    };
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolveClosed => proxy.close(() => resolveClosed()));
    await rm(home, { recursive: true, force: true });
  }
}
