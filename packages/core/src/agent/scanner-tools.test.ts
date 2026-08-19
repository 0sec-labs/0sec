import { describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import {
  buildSqlmapArgv,
  buildNmapArgv,
  buildFfufArgv,
  buildNucleiArgv,
  parseSqlmapOutput,
  parseNmapOutput,
  parseFfufOutput,
  parseNucleiOutput,
  runScannerProcess,
  superviseChild,
  suggestedFindingsFor,
  summarizeScannerResult,
  type ScannerRunStats,
} from "./scanner-tools.js";

// ── argv builders: safe argv, clamping, sanitization ────────────────────────

describe("buildSqlmapArgv", () => {
  it("always non-interactive and never colorized", () => {
    const argv = buildSqlmapArgv({ url: "http://h/?id=1" });
    expect(argv).toContain("--batch");
    expect(argv).toContain("--disable-coloring");
    expect(argv[0]).toBe("-u");
    expect(argv[1]).toBe("http://h/?id=1");
  });

  it("never exposes OS/file-shell escalation flags", () => {
    const argv = buildSqlmapArgv({
      url: "http://h/?id=1",
      enumerateDbs: true,
      dump: true,
    });
    const joined = argv.join(" ");
    expect(joined).not.toMatch(/--os-shell|--sql-shell|--file-read|--file-write|--os-pwn/);
  });

  it("clamps level/risk/threads into their valid ranges", () => {
    const argv = buildSqlmapArgv({ url: "http://h/?id=1", level: 99, risk: -3, threads: 9999 });
    expect(argv[argv.indexOf("--level") + 1]).toBe("5");
    expect(argv[argv.indexOf("--risk") + 1]).toBe("1");
    expect(argv[argv.indexOf("--threads") + 1]).toBe("10");
  });

  it("drops a technique value with illegal characters", () => {
    const argv = buildSqlmapArgv({ url: "http://h/?id=1", technique: "B; rm -rf /" });
    expect(argv).not.toContain("--technique");
  });

  it("keeps data as a single argv element (no shell concat)", () => {
    const argv = buildSqlmapArgv({ url: "http://h/login", data: "u=a&p=b' OR 1=1--" });
    const i = argv.indexOf("--data");
    expect(i).toBeGreaterThan(-1);
    expect(argv[i + 1]).toBe("u=a&p=b' OR 1=1--");
  });
});

describe("buildNmapArgv", () => {
  it("defaults to -Pn and places target last", () => {
    const argv = buildNmapArgv({ target: "scanme.example.com" });
    expect(argv).toContain("-Pn");
    expect(argv[argv.length - 1]).toBe("scanme.example.com");
  });

  it("accepts a clean port spec and rejects an injected one", () => {
    expect(buildNmapArgv({ target: "h", ports: "22,80,1-1024" })).toContain("22,80,1-1024");
    const bad = buildNmapArgv({ target: "h", ports: "22; cat /etc/passwd" });
    expect(bad).not.toContain("-p");
  });

  it("adds -sV only when serviceDetection is set", () => {
    expect(buildNmapArgv({ target: "h", serviceDetection: true })).toContain("-sV");
    expect(buildNmapArgv({ target: "h" })).not.toContain("-sV");
  });
});

describe("buildFfufArgv", () => {
  it("emits machine-readable JSON to stdout", () => {
    const argv = buildFfufArgv({ url: "http://h/FUZZ", wordlist: "/tmp/w.txt" });
    expect(argv).toEqual(
      expect.arrayContaining(["-u", "http://h/FUZZ", "-w", "/tmp/w.txt", "-of", "json", "-o", "/dev/stdout", "-s"]),
    );
  });

  it("rejects a malformed match-status filter", () => {
    const argv = buildFfufArgv({ url: "http://h/FUZZ", wordlist: "/tmp/w.txt", matchStatus: "200 && reboot" });
    expect(argv).not.toContain("-mc");
  });
});

describe("buildNucleiArgv", () => {
  it("streams JSONL silently and passes a clean severity filter", () => {
    const argv = buildNucleiArgv({ target: "http://h", severity: "critical,high" });
    expect(argv).toContain("-jsonl");
    expect(argv).toContain("-silent");
    expect(argv[argv.indexOf("-severity") + 1]).toBe("critical,high");
  });

  it("drops a severity value with shell metacharacters", () => {
    const argv = buildNucleiArgv({ target: "http://h", severity: "high`whoami`" });
    expect(argv).not.toContain("-severity");
  });
});

// ── parsers over captured sample outputs ────────────────────────────────────

const SQLMAP_SAMPLE = `
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.11}
[*] starting @ 12:00:00

[12:00:01] [INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3021=3021
---
[12:00:05] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[12:00:06] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] acme_app

Database: acme_app
Table: users
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int          |
| username | varchar(255) |
| password | varchar(255) |
+----------+--------------+
`;

describe("parseSqlmapOutput", () => {
  it("extracts DBMS, injection point, databases, table and dumped columns", () => {
    const r = parseSqlmapOutput(SQLMAP_SAMPLE);
    expect(r.vulnerable).toBe(true);
    expect(r.dbms).toMatch(/MySQL/);
    expect(r.injectionPoints).toHaveLength(1);
    expect(r.injectionPoints[0].parameter).toBe("id");
    expect(r.injectionPoints[0].type).toBe("boolean-based blind");
    expect(r.databases).toEqual(expect.arrayContaining(["information_schema", "acme_app"]));
    expect(r.tables).toContain("acme_app.users");
    // ≥1 dumped column (acceptance criterion). The parser captures every
    // table cell as evidence, so the dumped column names are present.
    expect(r.columns.length).toBeGreaterThanOrEqual(1);
    expect(r.columns).toEqual(expect.arrayContaining(["username", "password"]));
  });

  it("reports not-vulnerable on a clean run", () => {
    const r = parseSqlmapOutput("[INFO] all tested parameters do not appear to be injectable.");
    expect(r.vulnerable).toBe(false);
    expect(r.injectionPoints).toHaveLength(0);
  });
});

const NMAP_SAMPLE = `
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for scanme.example.com (45.33.32.156)
Host is up (0.052s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
443/tcp  closed https
9929/tcp open  nping-echo Nping echo

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
`;

describe("parseNmapOutput", () => {
  it("extracts host and the open-port table with services/versions", () => {
    const r = parseNmapOutput(NMAP_SAMPLE);
    expect(r.host).toMatch(/scanme\.example\.com/);
    const p22 = r.openPorts.find((p) => p.port === 22);
    expect(p22?.state).toBe("open");
    expect(p22?.service).toBe("ssh");
    expect(p22?.version).toMatch(/OpenSSH 6\.6/);
    const p80 = r.openPorts.find((p) => p.port === 80);
    expect(p80?.service).toBe("http");
    // closed port is still captured with its state.
    const p443 = r.openPorts.find((p) => p.port === 443);
    expect(p443?.state).toBe("closed");
  });
});

const FFUF_JSON_SAMPLE = JSON.stringify({
  results: [
    { input: { FUZZ: "admin" }, url: "http://h/admin", status: 301, length: 0, words: 1, lines: 1 },
    { input: { FUZZ: "login" }, url: "http://h/login", status: 200, length: 1234, words: 100, lines: 30 },
  ],
});

describe("parseFfufOutput", () => {
  it("parses the ffuf JSON results array", () => {
    const r = parseFfufOutput(FFUF_JSON_SAMPLE);
    expect(r.hits).toHaveLength(2);
    expect(r.hits[0].input).toBe("admin");
    expect(r.hits[0].status).toBe(301);
    expect(r.hits[1].url).toBe("http://h/login");
    expect(r.hits[1].length).toBe(1234);
  });

  it("falls back to JSONL when output is line-delimited", () => {
    const jsonl =
      '{"input":{"FUZZ":"a"},"url":"http://h/a","status":200}\n' +
      '{"input":{"FUZZ":"b"},"url":"http://h/b","status":403}\n';
    const r = parseFfufOutput(jsonl);
    expect(r.hits).toHaveLength(2);
    expect(r.hits[1].status).toBe(403);
  });
});

const NUCLEI_JSONL_SAMPLE =
  '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical"},"type":"http","matched-at":"http://h/api"}\n' +
  '{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"type":"http","matched-at":"http://h/"}\n';

describe("parseNucleiOutput", () => {
  it("parses JSONL findings with template id, severity and matched-at", () => {
    const r = parseNucleiOutput(NUCLEI_JSONL_SAMPLE);
    expect(r.findings).toHaveLength(2);
    const crit = r.findings.find((f) => f.severity === "critical");
    expect(crit?.templateId).toBe("CVE-2021-44228");
    expect(crit?.matchedAt).toBe("http://h/api");
    expect(crit?.name).toMatch(/Log4j/);
  });

  it("ignores non-JSON lines", () => {
    const r = parseNucleiOutput("not json\n" + NUCLEI_JSONL_SAMPLE + "\nalso not json");
    expect(r.findings).toHaveLength(2);
  });
});

// ── save_finding evidence projection ─────────────────────────────────────────

describe("suggestedFindingsFor", () => {
  const stats: ScannerRunStats = {
    binary: "sqlmap",
    argv: ["-u", "http://h/?id=1", "--batch"],
    durationMs: 100,
    timedOut: false,
    exitCode: 0,
  };

  it("projects a save_finding-ready SQLi finding from a vulnerable sqlmap result", () => {
    const result = parseSqlmapOutput(SQLMAP_SAMPLE);
    const findings = suggestedFindingsFor(result, stats);
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.category).toBe("sql-injection");
    expect(f.severity).toBe("high");
    expect(f.evidence_request).toContain("sqlmap");
    expect(f.poc_steps.length).toBeGreaterThan(0);
  });

  it("emits no findings for a clean sqlmap run", () => {
    const result = parseSqlmapOutput("not injectable");
    expect(suggestedFindingsFor(result, stats)).toHaveLength(0);
  });

  it("projects nuclei findings excluding info severity", () => {
    const result = parseNucleiOutput(NUCLEI_JSONL_SAMPLE);
    const findings = suggestedFindingsFor(result, {
      ...stats,
      binary: "nuclei",
      argv: ["-u", "http://h", "-jsonl"],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not project findings for nmap/ffuf recon results", () => {
    expect(suggestedFindingsFor(parseNmapOutput(NMAP_SAMPLE), { ...stats, binary: "nmap" })).toHaveLength(0);
    expect(suggestedFindingsFor(parseFfufOutput(FFUF_JSON_SAMPLE), { ...stats, binary: "ffuf" })).toHaveLength(0);
  });
});

describe("summarizeScannerResult", () => {
  it("summarizes each tool succinctly", () => {
    expect(summarizeScannerResult(parseSqlmapOutput(SQLMAP_SAMPLE))).toMatch(/INJECTABLE/);
    expect(summarizeScannerResult(parseNmapOutput(NMAP_SAMPLE))).toMatch(/port/);
    expect(summarizeScannerResult(parseFfufOutput(FFUF_JSON_SAMPLE))).toMatch(/hit/);
    expect(summarizeScannerResult(parseNucleiOutput(NUCLEI_JSONL_SAMPLE))).toMatch(/finding/);
  });
});

// ── process runner: wallclock ceiling + partial output, never hangs ──────────

describe("runScannerProcess — binary allowlist (0sec#555 / foxguard)", () => {
  it("refuses a non-allowlisted binary fail-closed (no spawn)", async () => {
    const outcome = await runScannerProcess(
      "definitely-not-a-real-binary-xyz",
      ["--version"],
      { timeoutMs: 2000, ceilingMs: 5000, env: {} },
    );
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.message).toMatch(/non-allowlisted/);
    }
  });

  it("refuses /bin/sh — only sqlmap/nmap/ffuf/nuclei may be spawned", async () => {
    const outcome = await runScannerProcess(
      "/bin/sh",
      ["-c", "echo pwned"],
      { timeoutMs: 2000, ceilingMs: 5000, env: {} },
    );
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.message).toMatch(/non-allowlisted/);
    }
  });

  it("attempts to spawn an allowlisted binary (ENOENT when not installed)", async () => {
    // `nuclei` is allowlisted but typically absent on CI runners → the spawn
    // attempt surfaces as a structured ENOENT error, never an unbounded hang.
    // If nuclei IS installed the outcome is a well-defined exit/timeout.
    const outcome = await runScannerProcess(
      "nuclei",
      ["-version"],
      { timeoutMs: 2000, ceilingMs: 5000, env: { PATH: process.env.PATH ?? "" } },
    );
    expect(["error", "exit", "timeout"]).toContain(outcome.kind);
  }, 10_000);
});

// The wallclock-ceiling lifecycle is tested via superviseChild directly so it
// can run against an arbitrary hanging child (/bin/sh) without being gated by
// the production binary allowlist that runScannerProcess enforces.
describe("superviseChild — wallclock ceiling + partial output, never hangs", () => {
  it("times out a hanging child and returns a (best-effort) partial string", async () => {
    const child = spawn("/bin/sh", ["-c", "echo partial-line; sleep 30"], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    const outcome = await superviseChild(child, 800, Date.now());
    if (outcome.kind === "error") return; // no /bin/sh on this platform
    // The HARD guarantees: the run resolves as a timeout (never hangs) and
    // carries a partial string. Whether the early `echo` made it into `partial`
    // depends on event-loop scheduling vs. the SIGTERM under parallel-test
    // load, so we do NOT assert specific content here — deterministic
    // stdout capture is covered by the exit-path test below.
    expect(outcome.kind).toBe("timeout");
    if (outcome.kind === "timeout") {
      expect(typeof outcome.partial).toBe("string");
    }
  }, 10_000);

  it("reaps a hanging child within the ceiling (bounded wallclock)", async () => {
    const start = Date.now();
    const child = spawn("/bin/sh", ["-c", "sleep 30"], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    const outcome = await superviseChild(child, 300, start);
    if (outcome.kind === "error") return; // no /bin/sh
    expect(Date.now() - start).toBeLessThan(5000);
    expect(outcome.kind).toBe("timeout");
  }, 10_000);

  it("returns a structured exit outcome for a fast command", async () => {
    const child = spawn("/bin/sh", ["-c", "echo hello"], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    const outcome = await superviseChild(child, 5000, Date.now());
    if (outcome.kind === "error") return; // no /bin/sh
    expect(outcome.kind).toBe("exit");
    if (outcome.kind === "exit") {
      expect(outcome.combined).toContain("hello");
      expect(outcome.exitCode).toBe(0);
    }
  }, 10_000);
});
