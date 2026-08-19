/**
 * Crypto-misuse source-audit detector — deterministic static-pattern oracles
 * for cryptographic API misuse in JS/TS (and Python) source.
 *
 * Motivation (issue #662): for a source-audit engine, crypto-misuse coverage
 * was thin. The category set covered SQLi/XSS/SSRF/proto-pollution/deser/
 * memory-corruption/supply-chain and there was a `jwt-attacks.yaml` skill, but
 * no dedicated crypto-misuse detector. Crypto bugs are reliably
 * disclosure-worthy and provable deterministically (the weakness is in the
 * code, not behaviour-dependent), which means a low inconclusive rate and high
 * precision. This mirrors the deterministic `malicious-detector.ts` model: a
 * pure static pass that runs BEFORE the LLM agent and emits `Finding` objects.
 *
 * Detectors (each precision-gated to real security-relevant usage to avoid the
 * FP floods we've been fighting — we do NOT flag every MD5):
 *
 *   1. Weak hash for security — MD5 / SHA-1 used for a password, token,
 *      signature, HMAC, or key-derivation purpose. A bare `md5(file)` checksum
 *      is NOT flagged; we gate on a security-relevant identifier nearby.
 *   2. Hardcoded key / IV / secret — string literals passed to
 *      crypto.createCipheriv / createHmac / sign etc. and `jsonwebtoken` /
 *      `jose` secrets. Gated on entropy / length so config placeholders like
 *      "changeme" alone don't dominate; literal IVs to createCipheriv are
 *      always flagged.
 *   3. ECB block-cipher mode — `aes-*-ecb` cipher selection (and `mode:
 *      ECB`). ECB leaks plaintext block structure; always security-relevant.
 *   4. JWT alg-confusion — `algorithms: ["none"]` / `alg: "none"` acceptance,
 *      and verify() paths that accept both an HMAC and an asymmetric alg
 *      (HS-vs-RS confusion), or jwt.verify with NO `algorithms` allow-list.
 *   5. Predictable RNG for secrets — `Math.random()` (and Python `random`)
 *      used to derive a token / key / secret / password / nonce / OTP. A
 *      `Math.random()` driving an animation is NOT flagged.
 *
 * Every finding is deterministic and self-evidencing, so it is emitted with
 * `status: "verified"` and `category: "crypto-misuse"` (a high-impact class
 * protected from score-only auto-suppression — see can-auto-suppress.ts).
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { relative } from "node:path";
import { randomUUID } from "node:crypto";
import type { Finding, Severity } from "@0sec/shared";
import { collectScopeFiles } from "./source-files.js";

// ────────────────────────────────────────────────────────────────────
// Shared helpers
// ────────────────────────────────────────────────────────────────────

/**
 * Identifiers whose presence on a line makes a crypto operation
 * security-relevant. Used to gate weak-hash / predictable-RNG detection so a
 * plain content checksum or a UI random doesn't trip the detector.
 */
// Note: no trailing `\b`, so camelCase identifiers like `resetToken` /
// `sessionKey` (where the context word is a substring) still match. The leading
// boundary keeps it from firing on unrelated words that merely contain a stem.
const SECURITY_CONTEXT_RX =
  /(?:password|passwd|secret|token|api[_-]?key|apikey|auth|credential|signature|hmac|salt|nonce|session|csrf|otp|mfa|2fa|private[_-]?key|derive|pbkdf)/i;

/** Source file extensions this detector understands. */
const CRYPTO_SOURCE_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx",
  ".py",
]);

/** Per-detector finding shape, before it is turned into a {@link Finding}. */
export interface CryptoHit {
  detector:
    | "weak-hash"
    | "hardcoded-key"
    | "ecb-mode"
    | "jwt-alg-confusion"
    | "predictable-rng";
  templateId: string;
  title: string;
  description: string;
  severity: Severity;
  /** 1-based line number in the source file. */
  line: number;
  /** The matched source line, trimmed and length-capped for evidence. */
  snippet: string;
  confidence: number;
}

/** Split a source blob into lines once; callers reuse the array. */
function toLines(source: string): string[] {
  return source.split(/\r?\n/);
}

/** Trim + cap a source line for safe inclusion in finding evidence. */
function snippetOf(line: string): string {
  const t = line.trim();
  return t.length > 200 ? `${t.slice(0, 197)}...` : t;
}

/** True for lines that are pure comments — skipped to cut comment-only FPs. */
function isCommentLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("#") || t.startsWith("/*");
}

/**
 * Shannon-entropy estimate (bits/char) for a string literal. Used to separate
 * a real embedded key/secret from a benign short placeholder.
 */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// ────────────────────────────────────────────────────────────────────
// Detector 1 — weak hash for a security purpose
// ────────────────────────────────────────────────────────────────────

/** Crypto APIs that select a hash algorithm by name. */
const WEAK_HASH_RX =
  /\b(?:createHash|createHmac)\s*\(\s*['"`](md5|sha1|sha-1|rsa-md5|rsa-sha1)['"`]|\bhashlib\.(md5|sha1)\s*\(|\balgorithm\s*[:=]\s*['"`](md5|sha1|sha-1)['"`]/i;

/**
 * Detect MD5 / SHA-1 used for a security purpose. Precision gate: the line (or
 * the createHmac call itself, which is always keyed/security-relevant) must
 * carry a security-context identifier. A bare `createHash('md5')` over file
 * bytes for a cache key is intentionally NOT flagged.
 */
export function detectWeakHash(source: string): CryptoHit[] {
  const hits: CryptoHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;
    const m = WEAK_HASH_RX.exec(line);
    if (!m) continue;
    const algo = (m[1] ?? m[2] ?? m[3] ?? "").toLowerCase().replace("-", "");
    const isHmac = /createHmac/.test(line);
    // HMAC with a weak hash is always security-relevant (it is a keyed MAC).
    // For plain hashing, require a security-context identifier on the line.
    if (!isHmac && !SECURITY_CONTEXT_RX.test(line)) continue;
    hits.push({
      detector: "weak-hash",
      templateId: "crypto-weak-hash",
      title: `Weak hash (${algo.toUpperCase()}) used for a security purpose`,
      description:
        `\`${algo.toUpperCase()}\` is cryptographically broken (collision/preimage weaknesses) and ` +
        `must not be used for ${isHmac ? "message authentication" : "passwords, tokens, signatures, or key derivation"}. ` +
        (isHmac
          ? "HMAC-MD5/HMAC-SHA1 should be replaced with HMAC-SHA-256 or better."
          : "Use a memory-hard password hash (argon2id / scrypt / bcrypt) for passwords, or SHA-256+ for integrity/signing.") +
        ` This line carries a security-relevant identifier, so the weak digest is on a sensitive path.`,
      severity: "high",
      line: i + 1,
      snippet: snippetOf(line),
      confidence: isHmac ? 0.85 : 0.8,
    });
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Detector 2 — hardcoded key / IV / secret
// ────────────────────────────────────────────────────────────────────

/** createCipheriv/createDecipheriv with literal key and/or IV arguments. */
const CIPHER_IV_RX =
  /\bcreate(?:De)?cipheriv\s*\(\s*[^,]+,\s*(['"`])([^'"`]+)\1\s*,\s*(['"`])([^'"`]+)\3/i;
/** createHmac / sign / jwt.sign with a literal secret as the key argument. */
const HMAC_SECRET_RX =
  /\b(?:createHmac\s*\(\s*['"`][^'"`]+['"`]\s*,\s*|jwt\.sign\s*\([^,]+,\s*)(['"`])([^'"`]{6,})\1/;
/** Assignment of a literal to a key/secret-named identifier. */
const SECRET_ASSIGN_RX =
  /\b(?:secret|secretKey|privateKey|signingKey|api[_-]?key|encryptionKey|jwtSecret|hmacKey|passphrase)\b\s*[:=]\s*(['"`])([^'"`]{8,})\1/i;

/** A literal value that is clearly a placeholder, not a real secret. */
function isObviousPlaceholder(value: string): boolean {
  const v = value.toLowerCase();
  return (
    /^(?:changeme|your[-_ ]?(?:secret|key)|xxx+|todo|placeholder|example|<[^>]+>|\$\{[^}]+\}|process\.env)/.test(v) ||
    /^[-_*x.]+$/.test(v)
  );
}

/**
 * Detect hardcoded keys / IVs / secrets. Precision strategy:
 *  - A literal IV passed to createCipheriv is ALWAYS flagged (a static IV
 *    defeats semantic security for CBC/CTR/GCM regardless of value).
 *  - A literal HMAC/JWT secret or a key/secret-named literal is flagged only
 *    when it is long enough and high-entropy enough to be a real embedded key,
 *    and is not an obvious placeholder or an env-var reference.
 */
export function detectHardcodedKey(source: string): CryptoHit[] {
  const hits: CryptoHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    const ivMatch = CIPHER_IV_RX.exec(line);
    if (ivMatch) {
      const key = ivMatch[2];
      const iv = ivMatch[4];
      hits.push({
        detector: "hardcoded-key",
        templateId: "crypto-hardcoded-key-iv",
        title: "Hardcoded encryption key and IV passed to createCipheriv",
        description:
          "`createCipheriv` is called with string-literal key and IV arguments. A hardcoded key means " +
          "anyone with the source can decrypt all ciphertext; a hardcoded/static IV defeats semantic " +
          "security (identical plaintexts produce identical ciphertext, and for CTR/GCM a reused IV is " +
          `catastrophic — key recovery for GCM). Derive the key from a secret manager / KMS and generate ` +
          `a fresh random IV per message (\`crypto.randomBytes\`). Observed key length ${key.length}, IV length ${iv.length}.`,
        severity: "critical",
        line: i + 1,
        snippet: snippetOf(line),
        confidence: 0.9,
      });
      continue;
    }

    const hmacMatch = HMAC_SECRET_RX.exec(line);
    if (hmacMatch) {
      const value = hmacMatch[2];
      if (!isObviousPlaceholder(value) && shannonEntropy(value) >= 2.5) {
        hits.push({
          detector: "hardcoded-key",
          templateId: "crypto-hardcoded-secret",
          title: "Hardcoded signing/HMAC secret in source",
          description:
            "A string-literal secret is passed to an HMAC / JWT-signing call. Embedding the signing key " +
            "in source means anyone with read access (repo, published npm tarball, decompiled bundle) can " +
            "forge valid signatures / tokens. Load the secret from an environment variable or secret manager " +
            "at runtime; never commit it.",
          severity: "high",
          line: i + 1,
          snippet: snippetOf(line),
          confidence: 0.8,
        });
        continue;
      }
    }

    const assignMatch = SECRET_ASSIGN_RX.exec(line);
    if (assignMatch) {
      const value = assignMatch[2];
      if (!isObviousPlaceholder(value) && shannonEntropy(value) >= 3.0 && value.length >= 12) {
        hits.push({
          detector: "hardcoded-key",
          templateId: "crypto-hardcoded-secret",
          title: "Hardcoded secret/key literal assigned in source",
          description:
            "A high-entropy literal is assigned to a key/secret-named identifier. Hardcoded credentials " +
            "are recoverable by anyone with source access and cannot be rotated without a code change. Move " +
            "the value to an environment variable or secret manager.",
          severity: "high",
          line: i + 1,
          snippet: snippetOf(line),
          confidence: 0.75,
        });
      }
    }
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Detector 3 — ECB block-cipher mode
// ────────────────────────────────────────────────────────────────────

const ECB_RX =
  /['"`]\s*(?:aes|des|bf|camellia|rc2|seed)-?(?:128|192|256)?-?ecb\s*['"`]|\bmode\s*[:=]\s*(?:CipherMode\.)?ECB\b|\bMODE_ECB\b|AES\.MODE_ECB/i;

/**
 * Detect ECB block-cipher mode. ECB encrypts each block independently, so it
 * leaks plaintext structure (the classic "ECB penguin"). Always
 * security-relevant — no extra context gate needed.
 */
export function detectEcbMode(source: string): CryptoHit[] {
  const hits: CryptoHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;
    if (!ECB_RX.test(line)) continue;
    hits.push({
      detector: "ecb-mode",
      templateId: "crypto-ecb-mode",
      title: "Block cipher used in ECB mode",
      description:
        "ECB (Electronic Code Book) encrypts each block independently with no IV/chaining, so identical " +
        "plaintext blocks map to identical ciphertext blocks. This leaks data structure and patterns (the " +
        "canonical 'ECB penguin') and provides no semantic security. Use an authenticated mode such as " +
        "AES-256-GCM (or AES-CBC with a random IV + separate MAC) instead.",
      severity: "high",
      line: i + 1,
      snippet: snippetOf(line),
      confidence: 0.85,
    });
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Detector 4 — JWT algorithm confusion
// ────────────────────────────────────────────────────────────────────

/** `algorithms: ["none"]` / `alg: "none"` — accepting unsigned tokens. */
const JWT_NONE_RX =
  /\balgorithms?\s*[:=]\s*\[?\s*['"`]none['"`]|\balg\s*[:=]\s*['"`]none['"`]/i;
/** A jwt.verify(...) call, for the "no allow-list" / mixed-family checks. */
const JWT_VERIFY_RX = /\bjwt\.verify\s*\(/;
/** An `algorithms:` allow-list that mixes a symmetric (HS*) and asymmetric (RS/ES/PS*) alg. */
const JWT_MIXED_FAMILY_RX =
  /algorithms?\s*[:=]\s*\[[^\]]*\bHS\d{3}\b[^\]]*\b(?:RS|ES|PS)\d{3}\b[^\]]*\]|algorithms?\s*[:=]\s*\[[^\]]*\b(?:RS|ES|PS)\d{3}\b[^\]]*\bHS\d{3}\b[^\]]*\]/i;

/**
 * Detect JWT algorithm-confusion misuse:
 *   a) `alg: "none"` / `algorithms: ["none"]` — accepts unsigned forged tokens.
 *   b) `jwt.verify` whose `algorithms` allow-list contains BOTH a symmetric
 *      (HS*) and an asymmetric (RS/ES/PS*) family — the classic HS-vs-RS
 *      confusion where an attacker signs with the public key as an HMAC secret.
 *   c) `jwt.verify` with NO `algorithms` option at all — the library will
 *      accept whatever `alg` the token header claims, which enables (a)/(b).
 */
export function detectJwtAlgConfusion(source: string): CryptoHit[] {
  const hits: CryptoHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    if (JWT_NONE_RX.test(line)) {
      hits.push({
        detector: "jwt-alg-confusion",
        templateId: "crypto-jwt-alg-none",
        title: "JWT `alg: none` accepted — unsigned-token forgery",
        description:
          "The code accepts the JWT `none` algorithm. An attacker can craft a token with header " +
          "`{\"alg\":\"none\"}` and an empty signature, set arbitrary claims (e.g. `\"role\":\"admin\"`), and " +
          "it will pass verification — a full authentication bypass. Never accept `none`; pin an explicit " +
          "`algorithms` allow-list of the single signing algorithm you actually use.",
        severity: "critical",
        line: i + 1,
        snippet: snippetOf(line),
        confidence: 0.9,
      });
      continue;
    }

    if (JWT_MIXED_FAMILY_RX.test(line)) {
      hits.push({
        detector: "jwt-alg-confusion",
        templateId: "crypto-jwt-alg-mixed",
        title: "JWT verify allows both HMAC and asymmetric algorithms (alg confusion)",
        description:
          "The `algorithms` allow-list mixes a symmetric HMAC algorithm (HS*) with an asymmetric one " +
          "(RS/ES/PS*). If the server verifies with the RSA/EC public key, an attacker can re-sign a forged " +
          "token using that public key as an HMAC secret (HS256) and the verifier will accept it — the " +
          "HS-vs-RS algorithm-confusion bypass. Restrict the allow-list to exactly the one algorithm in use.",
        severity: "critical",
        line: i + 1,
        snippet: snippetOf(line),
        confidence: 0.85,
      });
      continue;
    }

    if (JWT_VERIFY_RX.test(line)) {
      // Inspect the verify call (and a couple of following lines, since options
      // are often on their own line) for an `algorithms` allow-list.
      const window = [line, lines[i + 1] ?? "", lines[i + 2] ?? ""].join("\n");
      if (!/\balgorithms?\s*[:=]/i.test(window)) {
        hits.push({
          detector: "jwt-alg-confusion",
          templateId: "crypto-jwt-no-allowlist",
          title: "jwt.verify called without an `algorithms` allow-list",
          description:
            "`jwt.verify` is called without pinning an `algorithms` allow-list, so the library trusts the " +
            "`alg` value in the (attacker-controlled) token header. This is what enables `alg:none` and " +
            "HS-vs-RS algorithm-confusion forgery. Pass `{ algorithms: ['RS256'] }` (or whichever single " +
            "algorithm you sign with).",
          severity: "high",
          line: i + 1,
          snippet: snippetOf(line),
          confidence: 0.7,
        });
      }
    }
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Detector 5 — predictable RNG for secrets
// ────────────────────────────────────────────────────────────────────

const MATH_RANDOM_RX = /\bMath\.random\s*\(\s*\)/;
/** Python `random.random()/randint/choice` (the insecure module, not secrets). */
const PY_WEAK_RANDOM_RX = /\brandom\.(?:random|randint|randrange|choice|choices|sample|getrandbits)\s*\(/;

/**
 * Detect predictable RNG used to derive a secret. Precision gate: the line
 * must carry a security-context identifier (token/key/secret/nonce/otp/...).
 * `Math.random()` for jitter / sampling / animation is intentionally ignored.
 */
export function detectPredictableRng(source: string): CryptoHit[] {
  const hits: CryptoHit[] = [];
  const lines = toLines(source);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;
    const isJs = MATH_RANDOM_RX.test(line);
    const isPy = PY_WEAK_RANDOM_RX.test(line);
    if (!isJs && !isPy) continue;
    if (!SECURITY_CONTEXT_RX.test(line)) continue;
    hits.push({
      detector: "predictable-rng",
      templateId: "crypto-predictable-rng",
      title: `Predictable RNG (${isJs ? "Math.random()" : "random module"}) used to derive a secret`,
      description:
        (isJs
          ? "`Math.random()` is a non-cryptographic PRNG (typically xorshift128+) whose internal state is " +
            "recoverable from a few outputs, letting an attacker predict all past and future values. "
          : "Python's `random` module is a Mersenne-Twister PRNG that is fully predictable once enough output " +
            "is observed. ") +
        "This line uses it on a security-sensitive value (token / key / secret / nonce / OTP / password-reset), " +
        "so the generated value is guessable. Use a CSPRNG instead: " +
        (isJs ? "`crypto.randomBytes` / `crypto.randomUUID` / `crypto.getRandomValues`." : "the `secrets` module."),
      severity: "high",
      line: i + 1,
      snippet: snippetOf(line),
      confidence: 0.8,
    });
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────
// Aggregate single-source scan
// ────────────────────────────────────────────────────────────────────

/** Run every detector over one source blob and return the merged hits. */
export function scanSourceForCryptoMisuse(source: string): CryptoHit[] {
  return [
    ...detectWeakHash(source),
    ...detectHardcodedKey(source),
    ...detectEcbMode(source),
    ...detectJwtAlgConfusion(source),
    ...detectPredictableRng(source),
  ];
}

// ────────────────────────────────────────────────────────────────────
// Public entry point — produce Finding[] for the audit pipeline
// ────────────────────────────────────────────────────────────────────

export interface CryptoScanOptions {
  /** Root directory of the package/repo to audit. */
  packagePath: string;
  /** Package/target name, used only to label findings. */
  packageName?: string;
  /** Max source files to scan (deterministic order). Defaults to 400. */
  maxFiles?: number;
}

const DEFAULT_CRYPTO_MAX_FILES = 400;

/**
 * Walk the package source tree and run all crypto-misuse detectors, returning
 * `Finding` objects ready to drop into `AuditReport.findings`. Findings are
 * deterministic and self-evidencing, so they are emitted `status: "verified"`.
 *
 * Fail-soft: an unreadable directory / file is skipped, never thrown.
 */
export function scanForCryptoMisuse(opts: CryptoScanOptions): Finding[] {
  const { packagePath } = opts;
  if (!existsSync(packagePath)) return [];

  let files: string[];
  try {
    files = statSync(packagePath).isDirectory()
      ? collectScopeFiles(packagePath, {
          maxFiles: opts.maxFiles ?? DEFAULT_CRYPTO_MAX_FILES,
          extensions: CRYPTO_SOURCE_EXTS,
        })
      : [packagePath];
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  const now = Date.now();

  for (const file of files) {
    let source: string;
    try {
      source = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = (() => {
      try {
        return relative(packagePath, file) || file;
      } catch {
        return file;
      }
    })();

    for (const hit of scanSourceForCryptoMisuse(source)) {
      findings.push({
        id: randomUUID(),
        templateId: hit.templateId,
        title: hit.title,
        description: `${hit.description}\n\n**Location:** \`${rel}:${hit.line}\``,
        severity: hit.severity,
        category: "crypto-misuse",
        status: "verified",
        evidence: {
          request: `${rel}:${hit.line}`,
          response: hit.snippet,
          analysis:
            `Deterministic crypto-misuse oracle (detector: ${hit.detector}; no LLM, no network). ` +
            `The weakness is in the source, so the finding is provable by inspection.`,
        },
        confidence: hit.confidence,
        timestamp: now,
      });
    }
  }

  return findings;
}
