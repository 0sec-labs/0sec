import { lookup } from "node:dns/promises";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import { Readable, Transform, pipeline } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";
import { ScopePolicy, normalizeScopeHostname } from "./scope/scope.js";

export interface ScopedHttpPolicy {
  baseUrl: string;
  scope?: ScopePolicy;
  validateUrl?: (url: string) => void;
  beforeRequest?: (url: string) => void | Promise<void>;
  maxResponseBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
}

const privateNetworks = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.168.0.0", 16],
] as const) privateNetworks.addSubnet(address, prefix, "ipv4");
privateNetworks.addAddress("::", "ipv6");
privateNetworks.addAddress("::1", "ipv6");
privateNetworks.addSubnet("fc00::", 7, "ipv6");
privateNetworks.addSubnet("fe80::", 10, "ipv6");
const supportedContentEncodings = new Set(["identity", "gzip", "x-gzip", "deflate", "br"]);

export function isPrivateAddress(hostname: string): boolean {
  const address = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const family = isIP(address);
  return family !== 0 && privateNetworks.check(address, family === 4 ? "ipv4" : "ipv6");
}

function isLocalHost(hostname: string): boolean {
  const name = normalizeScopeHostname(hostname);
  return name === "localhost" || name.endsWith(".localhost") || isPrivateAddress(name);
}

function authorizeHttpUrl(input: string, policy: ScopedHttpPolicy): URL {
  const base = new URL(policy.baseUrl);
  const url = new URL(input, base);
  if ((base.protocol !== "http:" && base.protocol !== "https:") ||
      (url.protocol !== "http:" && url.protocol !== "https:")) {
    throw new Error("Only HTTP(S) requests are supported");
  }
  if (url.username || url.password) throw new Error("URL-embedded credentials are not supported");
  if (isLocalHost(url.hostname) && !isLocalHost(base.hostname)) {
    throw new Error(`Local/internal HTTP request blocked: ${url.hostname}`);
  }
  if (policy.scope) {
    const verdict = policy.scope.match(url.href);
    if (!verdict.allowed) throw new Error(`Scope violation blocked: ${verdict.reason}`);
  } else if (url.origin !== base.origin) {
    throw new Error(`Cross-origin HTTP request blocked: ${url.origin}`);
  }
  policy.validateUrl?.(url.href);
  return url;
}

function authorizeAddress(url: URL, address: string, policy: ScopedHttpPolicy): void {
  if (!isIP(address)) throw new Error("DNS returned an invalid IP address");
  if (isPrivateAddress(address) && !isLocalHost(new URL(policy.baseUrl).hostname)) {
    throw new Error(`Local/internal DNS address blocked for ${url.hostname}`);
  }
  if (!policy.scope?.raw.out_of_scope?.length) return;
  const candidates = [address];
  if (isIP(address) === 6) {
    const canonical = new URL(`http://[${address}]/`).hostname;
    const mapped = /^\[::ffff:([0-9a-f]+):([0-9a-f]+)\]$/i.exec(canonical);
    if (mapped) {
      const upper = Number.parseInt(mapped[1], 16);
      const lower = Number.parseInt(mapped[2], 16);
      candidates.push(`${upper >>> 8}.${upper & 255}.${lower >>> 8}.${lower & 255}`);
    }
  }
  for (const candidate of candidates) {
    const resolved = new URL(url);
    resolved.hostname = isIP(candidate) === 6 ? `[${candidate}]` : candidate;
    // Hostname authorization already passed; augment allows only to evaluate
    // existing explicit IP exclusions, never to persist new authorization.
    const addressScope = ScopePolicy.fromJson({
      ...policy.scope.raw,
      in_scope: [...(policy.scope.raw.in_scope ?? []), resolved.hostname],
    });
    const verdict = addressScope.match(resolved.href);
    if (!verdict.allowed) throw new Error(`Resolved address is excluded by scope: ${verdict.reason}`);
  }
}

async function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  });
}

/**
 * Scope-check every hop and DNS answer, then connect using that exact address.
 * No shared dispatcher, proxy, DNS cache, or TLS override is installed.
 * Redirects are manual unless explicitly requested; response bodies are streamed
 * with a decoded-byte ceiling and one deadline through DNS, headers and body.
 */
export async function fetchScoped(
  input: string,
  init: RequestInit,
  policy: ScopedHttpPolicy,
): Promise<Response> {
  const timeoutMs = policy.timeoutMs ?? 30_000;
  const maxBytes = policy.maxResponseBytes ?? 16 * 1024 * 1024;
  const maxRedirects = policy.maxRedirects ?? 5;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 0 ||
      !Number.isSafeInteger(maxRedirects) || maxRedirects < 0) {
    throw new Error("Invalid scoped HTTP timeout, body limit, or redirect limit");
  }
  let url = authorizeHttpUrl(input, policy);
  let method = (init.method ?? "GET").toUpperCase();
  let body = init.body;
  let headers = new Headers(init.headers);
  // URL authority controls both the destination and HTTP Host, including when
  // the caller supplies a differently-cased Host header.
  headers.delete("host");
  const redirect = init.redirect ?? "manual";
  let redirects = 0;
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(new Error("Scoped HTTP request timed out")), timeoutMs);
  const signal = init.signal ? AbortSignal.any([init.signal, deadline.signal]) : deadline.signal;
  const finish = () => clearTimeout(timer);
  let activeResponse: IncomingMessage | undefined;
  try {
    for (;;) {
      signal.throwIfAborted();
      url = authorizeHttpUrl(url.href, policy);
      const hostname = url.hostname.replace(/^\[|\]$/g, "");
      const literalFamily = isIP(hostname);
      const addresses = literalFamily
        ? [{ address: hostname, family: literalFamily }]
        : await abortable(lookup(hostname, { all: true }), signal);
      if (!addresses.length) throw new Error("DNS returned no addresses");
      for (const address of addresses) authorizeAddress(url, address.address, policy);
      await abortable(Promise.resolve(policy.beforeRequest?.(url.href)), signal);
      // Approval/authority may have changed while DNS or the rate limiter waited.
      authorizeHttpUrl(url.href, policy);
      for (const address of addresses) authorizeAddress(url, address.address, policy);
      signal.throwIfAborted();
      const pinned = addresses[0];
      const request = new Request(url, {
        ...init, method, body, headers, signal,
        ...(body instanceof ReadableStream ? { duplex: "half" } : {}),
      } as RequestInit);
      const response = await new Promise<IncomingMessage>((resolve, reject) => {
        const send = url.protocol === "https:" ? httpsRequest : httpRequest;
        const outgoing = send({
          protocol: url.protocol,
          port: url.port || undefined,
          path: url.pathname + url.search,
          method: request.method,
          hostname: pinned.address,
          servername: literalFamily ? "" : hostname,
          headers: { ...Object.fromEntries(request.headers), host: url.host },
          signal,
          agent: false,
          family: pinned.family,
          // Connect to the literal approved address. Host and TLS identity stay
          // bound to the original URL, without a runtime-dependent DNS callback.
        }, resolve);
        outgoing.once("error", reject);
        outgoing.once("upgrade", (_response, socket) => {
          socket.destroy();
          reject(new Error("HTTP protocol upgrades are not supported"));
        });
        if (request.body) {
          const source = Readable.fromWeb(request.body as import("node:stream/web").ReadableStream);
          pipeline(source, outgoing, error => { if (error) reject(error); });
        } else outgoing.end();
      });
      activeResponse = response;
      const status = response.statusCode!;
      const isRedirect = [301, 302, 303, 307, 308].includes(status);
      const location = response.headers.location;
      if (isRedirect && redirect === "error") {
        response.destroy();
        throw new Error("HTTP redirect refused");
      }
      if (isRedirect && location && redirect === "follow") {
        response.destroy();
        if (++redirects > maxRedirects) throw new Error("Too many HTTP redirects");
        const next = authorizeHttpUrl(new URL(location, url).href, policy);
        if (next.origin !== url.origin) {
          // Arbitrary custom headers can also contain credentials. Do not
          // forward any caller header across origins, even if both are scoped.
          headers = new Headers();
        }
        if (((status === 301 || status === 302) && method === "POST") ||
            (status === 303 && method !== "GET" && method !== "HEAD")) {
          method = "GET";
          body = undefined;
          headers.delete("content-length");
          headers.delete("content-type");
        } else if (body instanceof ReadableStream) {
          throw new Error("Cannot replay a streaming request body through a redirect");
        }
        url = next;
        continue;
      }
      const responseHeaders = new Headers();
      for (let i = 0; i < response.rawHeaders.length; i += 2) {
        responseHeaders.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
      }
      let responseBody: ReadableStream<Uint8Array> | null = null;
      if (method === "HEAD" || [204, 205, 304].includes(status)) {
        response.resume();
        response.once("end", finish);
        response.once("error", finish);
        response.once("close", finish);
      } else {
        let bytes = 0;
        const limit = new Transform({
          transform(chunk, _encoding, callback) {
            bytes += chunk.length;
            if (bytes > maxBytes) callback(new Error(`HTTP response exceeds ${maxBytes} decoded bytes`));
            else callback(null, chunk);
          },
        });
        const encodings = (response.headers["content-encoding"] ?? "identity")
          .toLowerCase().split(",").map(encoding => encoding.trim());
        if (encodings.length > 4) throw new Error("Too many HTTP content encodings");
        if (encodings.some(encoding => !supportedContentEncodings.has(encoding))) {
          throw new Error("Unsupported HTTP content encoding");
        }
        const decoders: Transform[] = [];
        for (const encoding of encodings.reverse()) {
          if (encoding === "gzip" || encoding === "x-gzip") decoders.push(createGunzip());
          else if (encoding === "deflate") decoders.push(createInflate());
          else if (encoding === "br") decoders.push(createBrotliDecompress());
        }
        pipeline([response, ...decoders, limit], finish);
        responseBody = Readable.toWeb(limit) as ReadableStream<Uint8Array>;
      }
      const result = new Response(responseBody, {
        status, statusText: response.statusMessage, headers: responseHeaders,
      });
      Object.defineProperties(result, {
        url: { value: url.href },
        redirected: { value: redirects > 0 },
      });
      return result;
    }
  } catch (error) {
    deadline.abort(error);
    activeResponse?.destroy();
    finish();
    throw error;
  }
}

export interface HttpResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
  latencyMs: number;
}

export function isMcpTarget(target: string): boolean {
  return target.startsWith("mcp://");
}

export async function sendPrompt(
  target: string,
  prompt: string,
  options?: { timeout?: number; headers?: Record<string, string>; baseUrl?: string; scope?: ScopePolicy; signal?: AbortSignal }
): Promise<HttpResponse> {
  const start = Date.now();
  const timeout = options?.timeout ?? 30_000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetchScoped(target, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
      body: JSON.stringify({
        messages: [{ role: "user", content: prompt }],
      }),
      signal: options?.signal ? AbortSignal.any([controller.signal, options.signal]) : controller.signal,
      redirect: "follow",
    }, { baseUrl: options?.baseUrl ?? target, scope: options?.scope, timeoutMs: timeout });

    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k] = v;
    });

    return {
      status: res.status,
      body,
      headers,
      latencyMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

export function extractResponseText(body: string): string {
  try {
    const json = JSON.parse(body);
    // OpenAI-compatible format
    if (json.choices?.[0]?.message?.content) {
      return json.choices[0].message.content;
    }
    // Anthropic format
    if (json.content?.[0]?.text) {
      return json.content[0].text;
    }
    // Simple message format
    if (json.message) return json.message;
    if (json.response) return json.response;
    if (json.text) return json.text;
    if (json.output) return json.output;
    // Fallback to raw body
    return body;
  } catch {
    return body;
  }
}
