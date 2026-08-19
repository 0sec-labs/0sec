#!/usr/bin/env node
/**
 * 0sec-cli npm launcher.
 *
 * The npm package is a launcher that downloads the right standalone binary
 * for the host platform on first run, caches it, and re-execs every
 * subsequent run with the user's args. The standalone binary has the Bun
 * runtime baked in, so the full OpenTUI experience is available even
 * though npm itself runs under Node.
 *
 * The build script (`scripts/build-npm-shim.mjs`) substitutes
 * `__0SEC_VERSION__` with the published version at build time, so this
 * launcher always pulls the binary that matches its own npm version.
 *
 * Cache layout:
 *   ~/.0sec/cache/v<version>/0sec         (executable)
 *   ~/.0sec/cache/v<version>/0sec.exe     (Windows)
 *
 * Env knobs:
 *   0SEC_BINARY                 — explicit path to a binary; bypasses
 *                                   the cache + download entirely.
 *                                   Used by tests and operators who
 *                                   build from source.
 *   0SEC_NO_DOWNLOAD=1          — never download; if the binary isn't
 *                                   cached, print the install.sh fallback
 *                                   URL and exit 1.
 *   0SEC_DOWNLOAD_TIMEOUT_MS    — per-attempt timeout for the GH
 *                                   release download (default: 120000).
 *
 * Supply-chain integrity (added 2026-05-16):
 *   Every downloaded binary is verified against the SHA-256 manifest
 *   published as `checksums.txt` alongside the release binaries before
 *   it is made executable. A mismatch, a missing manifest, or a manifest
 *   that doesn't list the expected asset filename aborts the install
 *   instead of caching the binary. See `verifyChecksum` below and the
 *   "Binary integrity" section of SECURITY.md.
 */

"use strict";

const {
  existsSync,
  mkdirSync,
  chmodSync,
  renameSync,
  statSync,
  createWriteStream,
  unlinkSync,
  createReadStream,
} = require("node:fs");
const { homedir, tmpdir } = require("node:os");
const { join, dirname } = require("node:path");
const { spawn } = require("node:child_process");
const { request } = require("node:https");
const { createHash } = require("node:crypto");

const VERSION = "__0SEC_VERSION__";
const REPO = "0sec-labs/0sec";
const CHECKSUMS_FILENAME = "checksums.txt";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const ORANGE = "\x1b[38;2;250;178;131m";
const RED = "\x1b[31m";

function err(msg) {
  process.stderr.write(`${RED}[0sec]${RESET} ${msg}\n`);
}

function detectAsset() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "darwin" && arch === "arm64") return "0sec-darwin-arm64";
  if (platform === "linux" && arch === "x64") return "0sec-linux-x64";
  if (platform === "linux" && arch === "arm64") return "0sec-linux-arm64";
  if (platform === "win32" && arch === "x64") return "0sec-windows-x64.exe";
  return null;
}

function cachePath(asset) {
  return join(homedir(), ".0sec", "cache", `v${VERSION}`, asset);
}

function downloadUrl(asset) {
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
}

function checksumsUrl() {
  return `https://github.com/${REPO}/releases/download/v${VERSION}/${CHECKSUMS_FILENAME}`;
}

// Follow redirects (GH releases bounce through codeload). Returns a
// readable stream of body bytes once we land on a 2xx, or rejects.
function fetchFollowRedirects(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    let redirects = 0;
    const MAX_REDIRECTS = 5;

    const go = (currentUrl) => {
      const req = request(currentUrl, { method: "GET" }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          redirects++;
          if (redirects > MAX_REDIRECTS) {
            reject(new Error(`too many redirects (${MAX_REDIRECTS}+) for ${url}`));
            return;
          }
          // Drain the redirect response body so the socket can be reused.
          res.resume();
          // GH gives absolute URLs in Location, but be defensive.
          const next = new URL(res.headers.location, currentUrl).toString();
          go(next);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} fetching ${currentUrl}`));
          res.resume();
          return;
        }
        resolve(res);
      });
      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`download timeout after ${timeoutMs}ms`));
      });
      req.on("error", reject);
      req.end();
    };

    go(url);
  });
}

// Buffer a full HTTP body (used for the small `checksums.txt` manifest).
async function fetchTextBody(url, timeoutMs) {
  const res = await fetchFollowRedirects(url, timeoutMs);
  return new Promise((resolve, reject) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c));
    res.on("error", reject);
    res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

// ─── Checksum verification ─────────────────────────────────────────────
//
// Pure helpers, exported via `module.exports` so they can be unit-tested
// without standing up the full launcher. Anything that touches the
// network or filesystem state lives above; the parsing + comparison
// logic stays here and stays deterministic.

/**
 * Parse a `sha256sum`-format manifest:
 *
 *   <64-hex-digit>  <filename>
 *   <64-hex-digit> *<filename>      (binary-mode marker)
 *
 * Lines that don't match are ignored (so a trailing blank line or
 * informational comment doesn't kill the parse). Filenames are taken
 * verbatim — no path normalisation, no quoting tricks.
 *
 * Returns a Map<filename, lowercase-hex-digest>.
 */
function parseChecksumsManifest(text) {
  const out = new Map();
  if (typeof text !== "string") {
    throw new TypeError("checksums manifest must be a string");
  }
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    // GNU `sha256sum`: "<hex>  <name>" (two spaces, text mode) or
    // "<hex> *<name>" (single space + asterisk, binary mode). BSD
    // `shasum -a 256` produces the same line shape.
    const m = line.match(/^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/);
    if (!m) continue;
    out.set(m[2], m[1].toLowerCase());
  }
  return out;
}

/** Compute a hex-encoded SHA-256 of a file by streaming it. */
function sha256File(path) {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(path);
    s.on("error", reject);
    s.on("data", (chunk) => h.update(chunk));
    s.on("end", () => resolve(h.digest("hex")));
  });
}

/**
 * Verify a downloaded asset against a checksums-manifest text.
 *
 * Throws (with an actionable message) if:
 *   - the manifest parses to zero entries
 *   - the manifest has no entry for `expectedAsset`
 *   - the computed digest doesn't match the manifest entry
 *
 * Resolves to the matched hex digest on success.
 */
async function verifyChecksum({ filePath, expectedAsset, manifestText }) {
  const entries = parseChecksumsManifest(manifestText);
  if (entries.size === 0) {
    throw new Error(
      `checksums manifest is empty or unparseable — refusing to trust ${expectedAsset}`,
    );
  }
  const expected = entries.get(expectedAsset);
  if (!expected) {
    throw new Error(
      `checksums manifest has no entry for "${expectedAsset}" — refusing to install (manifest lists: ${[...entries.keys()].join(", ")})`,
    );
  }
  const actual = await sha256File(filePath);
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(
      `SHA-256 mismatch for ${expectedAsset}\n  expected: ${expected}\n  actual:   ${actual}\nrefusing to install a binary that doesn't match the release manifest.`,
    );
  }
  return actual;
}

function printInstallFallback(asset) {
  const url = downloadUrl(asset);
  err("could not provision the standalone binary automatically.");
  err("");
  err("install via:");
  err(`  ${ORANGE}curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash${RESET}`);
  err("");
  err("or download the binary directly:");
  err(`  ${url}`);
  err("");
}

async function ensureBinary() {
  // Operator override — used by tests + source builds.
  const explicit = process.env["0SEC_BINARY"];
  if (explicit && existsSync(explicit)) return explicit;

  const asset = detectAsset();
  if (!asset) {
    err(`unsupported platform: ${process.platform}/${process.arch}`);
    err("supported: darwin-arm64, linux-x64, linux-arm64, windows-x64");
    err("");
    err(`Intel Mac users: install Bun and build from source — see ${ORANGE}https://github.com/${REPO}#standalone-binary${RESET}`);
    process.exit(2);
  }

  const cached = cachePath(asset);
  if (existsSync(cached)) return cached;

  if (process.env["0SEC_NO_DOWNLOAD"] === "1") {
    printInstallFallback(asset);
    process.exit(1);
  }

  // Lazy first-run UX: tell the user we're fetching ~75-130 MB so they
  // don't think the CLI is hung.
  const url = downloadUrl(asset);
  process.stderr.write(`${DIM}[0sec] first-run setup — downloading ${asset} (${url})${RESET}\n`);

  const cacheDir = dirname(cached);
  mkdirSync(cacheDir, { recursive: true });
  const tmpFile = join(tmpdir(), `0sec-${process.pid}-${Date.now()}-${asset}`);

  try {
    const timeoutMs = Number(process.env["0SEC_DOWNLOAD_TIMEOUT_MS"] ?? 120000);

    // 1) Fetch the SHA-256 manifest BEFORE the binary. If the release
    //    is missing its manifest (e.g. an old pre-0.11.x tag) we abort
    //    here rather than ever writing an unverified binary to disk.
    const checksumsTxt = await fetchTextBody(checksumsUrl(), timeoutMs).catch((e) => {
      throw new Error(
        `could not fetch ${CHECKSUMS_FILENAME} from the release: ${e.message}. ` +
          `Refusing to install an unverified binary.`,
      );
    });

    // 2) Stream the binary into a tmp file.
    const body = await fetchFollowRedirects(url, timeoutMs);
    await new Promise((resolve, reject) => {
      // Note: we set mode 0o600 here. The binary stays non-executable
      // on disk until verifyChecksum succeeds — defence in depth in
      // case some other process scans tmpdir.
      const out = createWriteStream(tmpFile, { mode: 0o600 });
      body.pipe(out);
      body.on("error", reject);
      out.on("error", reject);
      out.on("finish", resolve);
    });

    // Sanity-check size; an empty file means we got something pathological.
    const size = statSync(tmpFile).size;
    if (size < 1024 * 1024) {
      try { unlinkSync(tmpFile); } catch { /* ignore */ }
      throw new Error(`downloaded file is only ${size} bytes — refusing to cache`);
    }

    // 3) Verify SHA-256 against the manifest BEFORE chmod +x. A
    //    mismatch never gets the exec bit and never reaches the cache.
    await verifyChecksum({
      filePath: tmpFile,
      expectedAsset: asset,
      manifestText: checksumsTxt,
    });

    // 4) Only now mark executable + publish into the cache atomically.
    chmodSync(tmpFile, 0o755);
    renameSync(tmpFile, cached);
    process.stderr.write(`${DIM}[0sec] cached at ${cached} (sha-256 verified)${RESET}\n`);
    return cached;
  } catch (e) {
    try { unlinkSync(tmpFile); } catch { /* ignore */ }
    err(`download failed: ${e.message}`);
    err("");
    printInstallFallback(asset);
    process.exit(1);
  }
}

// Only run the launcher when invoked directly. When required from a
// test file we expose the pure helpers via module.exports so the
// verification logic can be unit-tested without spawning a binary.
if (require.main === module) {
  (async () => {
    const binary = await ensureBinary();
    // Re-exec the user's args against the standalone binary. stdio:'inherit'
    // wires the parent's terminal through so OpenTUI works as if invoked
    // directly. The launcher exits with the binary's own exit code.
    const child = spawn(binary, process.argv.slice(2), {
      stdio: "inherit",
      env: process.env,
    });
    child.on("error", (e) => {
      err(`failed to spawn ${binary}: ${e.message}`);
      process.exit(1);
    });
    child.on("exit", (code, signal) => {
      if (signal) {
        // Mirror the signal so shells see the right exit reason.
        process.kill(process.pid, signal);
        return;
      }
      process.exit(code ?? 0);
    });
  })().catch((e) => {
    err(`launcher error: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}

module.exports = {
  parseChecksumsManifest,
  sha256File,
  verifyChecksum,
  detectAsset,
  downloadUrl,
  checksumsUrl,
};
