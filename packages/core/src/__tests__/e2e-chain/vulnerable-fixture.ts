// Deliberately-vulnerable LOCAL fixture for the CodeWall-chain e2e self-test.
//
// SAFETY CONTRACT — this is a self-test target, never a real/external host:
//   * The server binds to 127.0.0.1 ONLY (see `listen` call below). It is never
//     reachable off-box and is torn down at the end of the test run.
//   * Every "vulnerability" here is PLANTED on purpose so we can prove the
//     newly-added tools (js-recon, auth-boundary probe, structural-sqli probe)
//     actually fire end-to-end against a controlled target. No external scan.
//
// Planted vulns (each maps to one stage of the chain):
//   1. PUBLIC JS  (`/static/app.js`) — ships the app's route table inline plus
//      a hardcoded fake AWS key (AKIA-prefixed dummy) and a referenced S3
//      bucket name. Feeds js_recon (endpoint + secret discovery).
//   2. UNAUTH endpoint (`/api/public/users`) — returns the same protected user
//      list with or without credentials → auth_boundary_probe flags it.
//   3. AUTH-required endpoint (`/api/admin/config`) — 401 without creds, 200
//      with → the boundary that correctly HOLDS (negative control).
//   4. STRUCTURAL SQLi (`/api/reports`) — concatenates a JSON *key* into a SQL
//      ORDER BY. A broken key (trailing quote) yields a sqlite parser error; a
//      balanced key (quote + comment) parses cleanly → structural_sqli confirms.

import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";

/** A fake, non-functional AWS key id (AKIA + 16 chars). NOT a real credential. */
export const FAKE_AWS_KEY_ID = "***REMOVED***";
/** A fake referenced S3 bucket name the JS points at (for the cloud probe). */
export const REFERENCED_S3_BUCKET = "acme-reports-export-fixture";

/**
 * The route table + secrets we plant inside the public JS bundle. js_recon is
 * expected to pull the `/api/...` paths out as endpoints and the AKIA id out as
 * a redacted secret.
 */
function buildAppJs(): string {
  // Written like a real minified-ish SPA bundle: a base URL, an axios route
  // map, a couple of fetch() call sites, and — the planted leak — a hardcoded
  // AWS key and the export bucket name.
  return [
    `const API_BASE="/api";`,
    `const ROUTES={`,
    `  users:"/api/public/users",`,
    `  adminConfig:"/api/admin/config",`,
    `  reports:"/api/reports"`,
    `};`,
    `axios.get("/api/public/users");`,
    `axios.post("/api/reports");`,
    `fetch("/api/admin/config");`,
    // Planted hardcoded cloud credential + bucket reference (the CodeWall move).
    `const AWS_ACCESS_KEY_ID="${FAKE_AWS_KEY_ID}";`,
    `const EXPORT_BUCKET="${REFERENCED_S3_BUCKET}";`,
    `const S3_BASE="https://${REFERENCED_S3_BUCKET}.s3.amazonaws.com";`,
  ].join("\n");
}

/** The protected resource body served by BOTH the unauth leak and admin paths. */
const USER_LIST_JSON = JSON.stringify([
  { id: 1, email: "alice@acme.test", role: "admin" },
  { id: 2, email: "bob@acme.test", role: "user" },
]);

/**
 * Structural-SQLi oracle: the fixture concatenates the request's JSON *key*
 * into `SELECT * FROM reports ORDER BY <key>`. We simulate the SQLite parser:
 *   - a key ending in a single unbalanced quote → parser error (broken).
 *   - a key that re-balances the quote and comments the tail (`...'--`) →
 *     parses cleanly (no error).
 * This is exactly the differential the probe needs to declare `confirmed`.
 */
function evaluateOrderByKey(key: string): { status: number; body: string } {
  // Count unescaped single quotes. An odd count = syntactically broken unless
  // the remainder is commented out.
  const commented = /--/.test(key);
  const quoteCount = (key.match(/'/g) ?? []).length;

  // Balanced: even number of quotes, OR an odd quote that is neutralised by a
  // trailing SQL line-comment (the `key'--` close the probe builds).
  const balanced = quoteCount % 2 === 0 || (quoteCount % 2 === 1 && commented);

  if (balanced) {
    return { status: 200, body: JSON.stringify({ ok: true, rows: 2 }) };
  }
  // Unbalanced quote reaches the SQLite parser → emit a recognisable error
  // string (matches structural-sqli.ts sqlite fingerprints).
  return {
    status: 500,
    body: JSON.stringify({
      error: `SQLite3::SQLException: near "${key}": syntax error`,
    }),
  };
}

export interface FixtureHandle {
  server: Server;
  /** Base origin, e.g. http://127.0.0.1:53122 — always 127.0.0.1. */
  origin: string;
  port: number;
  close: () => Promise<void>;
}

/**
 * Start the local vulnerable fixture, bound to 127.0.0.1 on an ephemeral port.
 * Resolves once the server is listening with its concrete origin.
 */
export function startVulnerableFixture(): Promise<FixtureHandle> {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const path = url.pathname;
    const authHeader = req.headers["authorization"] ?? "";
    const hasAuth = typeof authHeader === "string" && authHeader.length > 0;

    const json = (status: number, body: string) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(body);
    };

    // 1. Public JS bundle — the recon entrypoint.
    if (path === "/static/app.js") {
      res.writeHead(200, { "content-type": "application/javascript" });
      res.end(buildAppJs());
      return;
    }

    // The HTML page that references the bundle (so a crawl would find it).
    if (path === "/" || path === "/index.html") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<!doctype html><script src="/static/app.js"></script>`);
      return;
    }

    // 2. UNAUTH leak — returns the protected list regardless of credentials.
    if (path === "/api/public/users") {
      json(200, USER_LIST_JSON);
      return;
    }

    // 3. AUTH-required admin endpoint — boundary that holds (negative control).
    if (path === "/api/admin/config") {
      if (!hasAuth) {
        json(401, JSON.stringify({ error: "unauthorized" }));
        return;
      }
      json(200, JSON.stringify({ flags: { maintenance: false }, secretSeed: 42 }));
      return;
    }

    // 4. STRUCTURAL SQLi — injectable JSON key concatenated into ORDER BY.
    if (path === "/api/reports") {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        let key = "id";
        try {
          const parsed = JSON.parse(raw || "{}") as Record<string, unknown>;
          // The injectable surface is the FIRST key name, not its value.
          const firstKey = Object.keys(parsed)[0];
          if (firstKey) key = firstKey;
        } catch {
          /* malformed JSON → fall back to default key */
        }
        const { status, body } = evaluateOrderByKey(key);
        json(status, body);
      });
      return;
    }

    json(404, JSON.stringify({ error: "not found" }));
  });

  return new Promise<FixtureHandle>((resolve) => {
    // 127.0.0.1 ONLY — never 0.0.0.0, never a hostname. Hard safety rail.
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${port}`;
      resolve({
        server,
        origin,
        port,
        close: () =>
          new Promise<void>((res, rej) =>
            server.close((err) => (err ? rej(err) : res())),
          ),
      });
    });
  });
}
