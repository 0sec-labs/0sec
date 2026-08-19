/**
 * Tests for crypto-misuse-detector.ts
 *
 * Each detector has positive fixtures (real misuse → flagged) and negative
 * fixtures (benign / placeholder usage → NOT flagged) so the precision gates
 * that keep FP volume down are pinned by tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  shannonEntropy,
  detectWeakHash,
  detectHardcodedKey,
  detectEcbMode,
  detectJwtAlgConfusion,
  detectPredictableRng,
  scanSourceForCryptoMisuse,
  scanForCryptoMisuse,
} from "./crypto-misuse-detector.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "crypto-misuse-test-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writeSource(rel: string, content: string): string {
  const abs = join(tmp, rel);
  const parent = abs.slice(0, abs.lastIndexOf("/"));
  mkdirSync(parent, { recursive: true });
  writeFileSync(abs, content);
  return abs;
}

// ────────────────────────────────────────────────────────────────────
// shannonEntropy
// ────────────────────────────────────────────────────────────────────

describe("shannonEntropy", () => {
  it("is 0 for empty / single-char strings", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy("aaaa")).toBe(0);
  });
  it("rises with character diversity", () => {
    expect(shannonEntropy("aXk9Qm2Zr7Lp")).toBeGreaterThan(3);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 1 — weak hash
// ────────────────────────────────────────────────────────────────────

describe("detectWeakHash", () => {
  it("flags MD5 used for a password", () => {
    const hits = detectWeakHash(
      `const hashed = crypto.createHash('md5').update(password).digest('hex');`,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("crypto-weak-hash");
    expect(hits[0].severity).toBe("high");
  });

  it("flags SHA-1 used for a token signature", () => {
    const hits = detectWeakHash(
      `const sig = crypto.createHash('sha1').update(token).digest('hex');`,
    );
    expect(hits).toHaveLength(1);
  });

  it("flags HMAC-MD5 even without an extra context word (HMAC is always keyed)", () => {
    const hits = detectWeakHash(`const mac = createHmac('md5', someKey).update(data).digest();`);
    expect(hits).toHaveLength(1);
  });

  it("flags Python hashlib.md5 on a password line", () => {
    const hits = detectWeakHash(`digest = hashlib.md5(password.encode()).hexdigest()`);
    expect(hits).toHaveLength(1);
  });

  it("does NOT flag MD5 used as a plain content checksum (no security context)", () => {
    const hits = detectWeakHash(
      `const etag = crypto.createHash('md5').update(fileBytes).digest('hex');`,
    );
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag SHA-256", () => {
    const hits = detectWeakHash(
      `const h = crypto.createHash('sha256').update(password).digest('hex');`,
    );
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag a comment mentioning md5 password", () => {
    const hits = detectWeakHash(`// legacy: we used to createHash('md5') for the password`);
    expect(hits).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 2 — hardcoded key / IV / secret
// ────────────────────────────────────────────────────────────────────

describe("detectHardcodedKey", () => {
  it("flags literal key + IV into createCipheriv as critical", () => {
    const hits = detectHardcodedKey(
      `const c = crypto.createCipheriv('aes-256-cbc', '0123456789abcdef0123456789abcdef', '1234567890abcdef');`,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].severity).toBe("critical");
    expect(hits[0].templateId).toBe("crypto-hardcoded-key-iv");
  });

  it("flags a high-entropy hardcoded JWT signing secret", () => {
    const hits = detectHardcodedKey(
      `const token = jwt.sign(payload, 'kJ8xQ2mZr7Lp9Wn4Tb6Vc3Yd1Hf5Gg');`,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("crypto-hardcoded-secret");
  });

  it("flags a high-entropy secret-named literal assignment", () => {
    const hits = detectHardcodedKey(
      `const jwtSecret = 'aZ9kQ2mXr7Lp4Wn8Tb6Vc';`,
    );
    expect(hits).toHaveLength(1);
  });

  it("does NOT flag createCipheriv with env-var key/IV", () => {
    const hits = detectHardcodedKey(
      `const c = crypto.createCipheriv('aes-256-gcm', key, iv);`,
    );
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag a placeholder secret like changeme", () => {
    const hits = detectHardcodedKey(`const secret = 'changeme-please';`);
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag a process.env reference assigned to secret", () => {
    const hits = detectHardcodedKey(`const secret = process.env.JWT_SECRET;`);
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag a short low-entropy secret literal", () => {
    const hits = detectHardcodedKey(`const apiKey = 'aaaaaaaaaaaa';`);
    expect(hits).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 3 — ECB mode
// ────────────────────────────────────────────────────────────────────

describe("detectEcbMode", () => {
  it("flags aes-256-ecb cipher selection", () => {
    const hits = detectEcbMode(`const c = crypto.createCipheriv('aes-256-ecb', key, null);`);
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("crypto-ecb-mode");
  });

  it("flags Python AES.MODE_ECB", () => {
    const hits = detectEcbMode(`cipher = AES.new(key, AES.MODE_ECB)`);
    expect(hits).toHaveLength(1);
  });

  it("does NOT flag aes-256-gcm", () => {
    const hits = detectEcbMode(`const c = crypto.createCipheriv('aes-256-gcm', key, iv);`);
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag an unrelated identifier containing 'ecb'", () => {
    const hits = detectEcbMode(`const recbox = computeBox();`);
    expect(hits).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 4 — JWT algorithm confusion
// ────────────────────────────────────────────────────────────────────

describe("detectJwtAlgConfusion", () => {
  it("flags algorithms: ['none'] as critical", () => {
    const hits = detectJwtAlgConfusion(
      `jwt.verify(token, key, { algorithms: ['none'] });`,
    );
    expect(hits.some((h) => h.templateId === "crypto-jwt-alg-none")).toBe(true);
    expect(hits.find((h) => h.templateId === "crypto-jwt-alg-none")?.severity).toBe("critical");
  });

  it("flags a mixed HS/RS algorithms allow-list (alg confusion)", () => {
    const hits = detectJwtAlgConfusion(
      `jwt.verify(token, pub, { algorithms: ['HS256', 'RS256'] });`,
    );
    expect(hits.some((h) => h.templateId === "crypto-jwt-alg-mixed")).toBe(true);
  });

  it("flags jwt.verify with no algorithms allow-list", () => {
    const hits = detectJwtAlgConfusion(`const decoded = jwt.verify(token, secret);`);
    expect(hits.some((h) => h.templateId === "crypto-jwt-no-allowlist")).toBe(true);
  });

  it("finds the algorithms option across following lines (no false no-allowlist hit)", () => {
    const src = [
      "const decoded = jwt.verify(token, key, {",
      "  algorithms: ['RS256'],",
      "});",
    ].join("\n");
    const hits = detectJwtAlgConfusion(src);
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag a properly pinned single-algorithm verify", () => {
    const hits = detectJwtAlgConfusion(
      `jwt.verify(token, pub, { algorithms: ['RS256'] });`,
    );
    expect(hits).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 5 — predictable RNG
// ────────────────────────────────────────────────────────────────────

describe("detectPredictableRng", () => {
  it("flags Math.random() used to build a token", () => {
    const hits = detectPredictableRng(
      `const resetToken = Math.random().toString(36).slice(2);`,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("crypto-predictable-rng");
  });

  it("flags Python random for an OTP", () => {
    const hits = detectPredictableRng(`otp = random.randint(100000, 999999)`);
    expect(hits).toHaveLength(1);
  });

  it("does NOT flag Math.random() for animation jitter", () => {
    const hits = detectPredictableRng(`const offset = Math.random() * 10;`);
    expect(hits).toHaveLength(0);
  });

  it("does NOT flag crypto.randomBytes for a token", () => {
    const hits = detectPredictableRng(
      `const token = crypto.randomBytes(32).toString('hex');`,
    );
    expect(hits).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Aggregate + filesystem scan
// ────────────────────────────────────────────────────────────────────

describe("scanSourceForCryptoMisuse", () => {
  it("merges hits from multiple detectors in one blob", () => {
    const src = [
      `const h = crypto.createHash('md5').update(password).digest('hex');`,
      `jwt.verify(token, key, { algorithms: ['none'] });`,
      `const sessionToken = Math.random().toString(36);`,
    ].join("\n");
    const hits = scanSourceForCryptoMisuse(src);
    const detectors = new Set(hits.map((h) => h.detector));
    expect(detectors.has("weak-hash")).toBe(true);
    expect(detectors.has("jwt-alg-confusion")).toBe(true);
    expect(detectors.has("predictable-rng")).toBe(true);
  });
});

describe("scanForCryptoMisuse (filesystem)", () => {
  it("returns [] for a non-existent path", () => {
    expect(scanForCryptoMisuse({ packagePath: join(tmp, "nope") })).toEqual([]);
  });

  it("walks a package and emits verified crypto-misuse findings", () => {
    writeSource(
      "src/auth.js",
      `const sig = crypto.createHash('sha1').update(password).digest('hex');\n` +
        `jwt.verify(token, pub, { algorithms: ['HS256', 'RS256'] });`,
    );
    writeSource("src/safe.js", `const h = crypto.createHash('sha256').update(x).digest();`);

    const findings = scanForCryptoMisuse({ packagePath: tmp, packageName: "demo" });
    expect(findings.length).toBeGreaterThanOrEqual(2);
    for (const f of findings) {
      expect(f.category).toBe("crypto-misuse");
      expect(f.status).toBe("verified");
      expect(f.evidence.request).toMatch(/auth\.js:\d+/);
      expect(f.description).toContain("**Location:**");
    }
  });

  it("produces no findings for a clean package", () => {
    writeSource(
      "index.js",
      `const token = crypto.randomBytes(32).toString('hex');\n` +
        `const c = crypto.createCipheriv('aes-256-gcm', key, iv);\n` +
        `jwt.verify(token, pub, { algorithms: ['RS256'] });`,
    );
    expect(scanForCryptoMisuse({ packagePath: tmp })).toEqual([]);
  });

  it("can scan a single source file path directly", () => {
    const file = writeSource(
      "lib/jwt.ts",
      `export const opts = { algorithms: ['none'] };`,
    );
    const findings = scanForCryptoMisuse({ packagePath: file });
    expect(findings).toHaveLength(1);
    expect(findings[0].templateId).toBe("crypto-jwt-alg-none");
  });
});
