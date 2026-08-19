import { describe, it, expect } from "vitest";
import {
  detectScannerBinary,
  SCANNER_BINARY_BLACKLIST,
} from "./scanner-binaries.js";

// pwnkit#217. The detector is the leaf — `shellExec` consumes its
// output. These tests pin the contract: which invocations match,
// which don't, and that the well-known evasion shapes (path prefix,
// quoting, env-var prefix, pipeline tail) all fail to bypass.

describe("detectScannerBinary — blacklist hits", () => {
  for (const binary of SCANNER_BINARY_BLACKLIST) {
    it(`detects bare invocation of ${binary}`, () => {
      const hit = detectScannerBinary(`${binary} -u https://example.com`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });

    it(`detects ${binary} via absolute path`, () => {
      const hit = detectScannerBinary(`/usr/bin/${binary} --target https://example.com`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });

    it(`detects ${binary} via relative path`, () => {
      const hit = detectScannerBinary(`./${binary} -u https://example.com`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });

    it(`detects ${binary} after env-var prefix`, () => {
      const hit = detectScannerBinary(`HTTP_PROXY=http://p:8080 ${binary} -u https://example.com`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });

    it(`detects ${binary} on the right side of a pipeline`, () => {
      const hit = detectScannerBinary(`echo https://example.com | ${binary} --batch`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });

    it(`detects ${binary} after \`&&\``, () => {
      const hit = detectScannerBinary(`curl https://example.com && ${binary} -u https://example.com`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });

    it(`detects ${binary} after \`;\``, () => {
      const hit = detectScannerBinary(`echo go ; ${binary} -u https://example.com`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });

    it(`detects ${binary} when name is double-quoted`, () => {
      const hit = detectScannerBinary(`"${binary}" -u https://example.com`);
      expect(hit).not.toBeNull();
      expect(hit!.binary).toBe(binary);
    });
  }
});

describe("detectScannerBinary — nmap special-casing", () => {
  it("blocks `nmap -sV` (service-version scan, scanner-pattern)", () => {
    const hit = detectScannerBinary("nmap -sV target.example.com");
    expect(hit).not.toBeNull();
    expect(hit!.binary).toBe("nmap -sV");
  });

  it("blocks `nmap -A` (aggressive: OS+version+scripts)", () => {
    const hit = detectScannerBinary("nmap -A target.example.com");
    expect(hit).not.toBeNull();
    expect(hit!.binary).toBe("nmap -A");
  });

  it("blocks `nmap -p 80 -sV target` (forbidden flag in the middle)", () => {
    const hit = detectScannerBinary("nmap -p 80 -sV target.example.com");
    expect(hit).not.toBeNull();
    expect(hit!.binary).toBe("nmap -sV");
  });

  it("ALLOWS plain `nmap target` (port scan, policy-orthogonal)", () => {
    const hit = detectScannerBinary("nmap target.example.com");
    expect(hit).toBeNull();
  });

  it("ALLOWS `nmap -p 1-1000 target` (port range only)", () => {
    const hit = detectScannerBinary("nmap -p 1-1000 target.example.com");
    expect(hit).toBeNull();
  });

  it("blocks /usr/bin/nmap -A (absolute path nmap with forbidden flag)", () => {
    const hit = detectScannerBinary("/usr/bin/nmap -A target.example.com");
    expect(hit).not.toBeNull();
    expect(hit!.binary).toBe("nmap -A");
  });
});

describe("detectScannerBinary — python -m form", () => {
  it("blocks `python3 -m sqlmap`", () => {
    const hit = detectScannerBinary("python3 -m sqlmap -u https://example.com");
    expect(hit).not.toBeNull();
    expect(hit!.binary).toBe("python -m sqlmap");
  });

  it("blocks `python -m wfuzz`", () => {
    const hit = detectScannerBinary("python -m wfuzz -c -z file,wordlist.txt https://example.com/FUZZ");
    expect(hit).not.toBeNull();
    expect(hit!.binary).toBe("python -m wfuzz");
  });

  it("ALLOWS `python3 -m http.server` (not a scanner module)", () => {
    const hit = detectScannerBinary("python3 -m http.server 8080");
    expect(hit).toBeNull();
  });

  it("ALLOWS `python3 -m json.tool` (unrelated module)", () => {
    const hit = detectScannerBinary("python3 -m json.tool /tmp/x.json");
    expect(hit).toBeNull();
  });
});

describe("detectScannerBinary — clean traffic passes through", () => {
  it("ALLOWS curl", () => {
    expect(detectScannerBinary("curl -X POST https://api.example.com/login")).toBeNull();
  });

  it("ALLOWS wget", () => {
    expect(detectScannerBinary("wget -O - https://example.com/")).toBeNull();
  });

  it("ALLOWS bash pipelines that don't contain a scanner", () => {
    expect(
      detectScannerBinary(
        "curl -s https://example.com/ | grep -i 'X-Powered-By' | head -n 1",
      ),
    ).toBeNull();
  });

  it("ALLOWS empty / whitespace input", () => {
    expect(detectScannerBinary("")).toBeNull();
    expect(detectScannerBinary("   \n\t")).toBeNull();
  });

  it("does not false-positive on substrings (`sqlmaps_friend`)", () => {
    // The blacklist is exact basename, not substring. A binary called
    // `sqlmaps_friend` is allowed (this is a niche case but the
    // detector must not trigger on it).
    expect(detectScannerBinary("sqlmaps_friend --help")).toBeNull();
  });

  it("does not false-positive on file arguments (`cat sqlmap.log`)", () => {
    expect(detectScannerBinary("cat sqlmap.log")).toBeNull();
  });
});

describe("detectScannerBinary — error message quality", () => {
  it("names the binary in the reason string", () => {
    const hit = detectScannerBinary("sqlmap -u https://example.com");
    expect(hit!.reason).toContain("sqlmap");
    expect(hit!.reason).toContain("--allow-scanners");
  });

  it("cites pwnkit#217 in the reason string", () => {
    const hit = detectScannerBinary("nikto -h https://example.com");
    expect(hit!.reason).toContain("pwnkit#217");
  });

  it("nmap reason names the specific flag combination", () => {
    const hit = detectScannerBinary("nmap -A target");
    expect(hit!.reason).toContain("-A");
  });
});
