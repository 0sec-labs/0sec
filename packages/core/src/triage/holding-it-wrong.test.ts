import { describe, it, expect } from "vitest";
import { isHoldingItWrong } from "./holding-it-wrong.js";
import type { AttackCategory, Finding } from "@pwnkit/shared";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "hiw-test",
    templateId: "audit-sink",
    title: "Arbitrary file write in helper",
    description: "The helper accepts a path argument.",
    severity: "high",
    category: "path-traversal" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "",
      response: "",
    },
    confidence: 0.7,
    timestamp: Date.now(),
    ...overrides,
  };
}

describe("isHoldingItWrong", () => {
  // ── The 10 findings from the CVE-hunt verification report ──
  // Each describes a library-internal sink whose whole documented purpose
  // IS to do the "dangerous" operation. They should all be flagged.

  it("1. fs.writeFile in a file-storage helper", () => {
    const f = makeFinding({
      title: "Arbitrary file write via persistData",
      description:
        "The persistData(path, data) function calls fs.writeFile(path, data). If the caller passes an attacker-controlled path, arbitrary files can be written.",
    });
    const result = isHoldingItWrong(f);
    expect(result.isHoldingItWrong).toBe(true);
    expect(result.reason).toBeTruthy();
  });

  it("2. toFunction(cb) helper that wraps a callback", () => {
    const f = makeFinding({
      title: "Code execution via toFunction",
      description:
        "toFunction(cb) returns a wrapped callable. By design, the caller passes a function that will be invoked.",
      evidence: {
        request: "const fn = toFunction(function () { return 'pwned'; });",
        response: "",
      },
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("3. template compile() sink", () => {
    const f = makeFinding({
      title: "Template injection in compile()",
      description:
        "The compile(templateString) function is a template engine compiler. If the developer passes untrusted input as the template source, arbitrary code execution is possible.",
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("4. renderFile with attacker-controlled path", () => {
    const f = makeFinding({
      title: "SSTI via renderFile",
      description:
        "renderFile(path, data) reads a template from disk. When the host application pipes attacker input into the path argument, templates may be rendered from arbitrary locations.",
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("5. eval-like Function constructor sink", () => {
    const f = makeFinding({
      title: "Code injection via new Function",
      description:
        "The helper uses new Function(code) to build a dynamic function. This is the function's intended use.",
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("6. persistData(path, data) helper", () => {
    const f = makeFinding({
      title: "Arbitrary write via persistData",
      description:
        "The persistData(path, data) helper writes to disk at the location specified by the caller. Expected behavior.",
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("7. shell exec wrapper", () => {
    const f = makeFinding({
      title: "Command injection in run(cmd)",
      description:
        "The run(cmd) helper is a thin wrapper around exec(cmd). If the developer passes untrusted input, commands run.",
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("8. provider SDK / trusted backend 'attacker'", () => {
    const f = makeFinding({
      title: "Prompt injection via provider SDK",
      description:
        "A malicious provider SDK could return crafted JSON that the client would parse. The attacker is the backend service itself.",
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("9. callback-requiring PoC (class constructor)", () => {
    const f = makeFinding({
      title: "RCE via register()",
      description: "register() stores a handler for later invocation.",
      evidence: {
        request: "register(new MaliciousHandler());",
        response: "",
      },
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("10. 'documented purpose' language for a writeFileSync sink", () => {
    const f = makeFinding({
      title: "Arbitrary file write",
      description:
        "The module calls fs.writeFileSync(dest, buf). This is the documented purpose of the helper and is by design.",
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  // ── Negative cases: real vulns should NOT be flagged ──

  it("does NOT flag a realistic SQL injection via HTTP query param", () => {
    const f = makeFinding({
      title: "SQL injection in /users?id=",
      description:
        "The /users endpoint concatenates the `id` query parameter into a SQL query. Sending `?id=1' OR '1'='1` returns all users.",
      category: "sql-injection" as AttackCategory,
      evidence: {
        request: "GET /users?id=1'%20OR%20'1'='1 HTTP/1.1",
        response:
          "HTTP/1.1 200 OK\n\n[{\"id\":1,\"email\":\"admin@example.com\"},{\"id\":2}]",
      },
    });
    const result = isHoldingItWrong(f);
    expect(result.isHoldingItWrong).toBe(false);
    expect(result.reason).toBeNull();
  });

  it("does NOT flag a reflected XSS through a search param", () => {
    const f = makeFinding({
      title: "Reflected XSS in /search",
      description:
        "The search page reflects the `q` parameter without encoding. Payload fires alert(1).",
      category: "xss" as AttackCategory,
      evidence: {
        request: "GET /search?q=<script>alert(1)</script> HTTP/1.1",
        response: "HTTP/1.1 200 OK\n\n<html>results for <script>alert(1)</script></html>",
      },
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(false);
  });
});

// ── Regression: the 2026-03 npm "criticals" that disclosure verification
//    (2026-06-03) found to be by-design / moot. The gate must now catch all
//    five, AND must NOT suppress the two genuinely-real injections that share
//    a documented sink name (execSync / JS-string build) — see #802.
describe("isHoldingItWrong — verified-by-design npm duds (#802 regression)", () => {
  it("eta SSTI: attacker-controlled template compiled via new Function (by design)", () => {
    const f = makeFinding({
      title: "SSTI to RCE in Eta template compilation",
      description:
        "Eta compiles templates with new Function() via compileToString(). An attacker-controlled template string passed to render() yields RCE — the documented behavior of a template engine.",
      category: "code-injection" as AttackCategory,
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("nunjucks SSTI: renderString on an attacker-controlled template (by design)", () => {
    const f = makeFinding({
      title: "SSTI to RCE in nunjucks",
      description:
        "nunjucks renderString() evaluates an attacker-controlled template; memberLookup (obj[val]) exposes the constructor, enabling RCE when an application uses the template source as user input.",
      category: "code-injection" as AttackCategory,
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("expr-eval: toJSFunction compiles an attacker expression via new Function (opt-in)", () => {
    const f = makeFinding({
      title: "Sandbox escape in expr-eval toJSFunction",
      description:
        "Parser.parse(expr).toJSFunction() builds a function via new Function(); an attacker-controlled expression escapes to global scope. toJSFunction is an opt-in compile-to-JS escape hatch.",
      category: "code-injection" as AttackCategory,
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("jsonpath-plus: only reachable under the non-default eval:'native' option", () => {
    const f = makeFinding({
      title: "RCE in jsonpath-plus with native eval",
      description:
        "With the non-default eval: 'native' option an attacker-controlled JSONPath expression runs via new vm.Script().runInNewContext(). The default 'safe' evaluator blocks this; native is opt-in unsafe.",
      category: "code-injection" as AttackCategory,
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  it("vm2: sandboxed code escapes only when the vm builtin is configured in (moot)", () => {
    const f = makeFinding({
      title: "Sandbox escape in vm2 via vm builtin",
      description:
        "When NodeVM is configured with require: { builtin: ['vm'] }, sandboxed code escapes the sandbox via runInNewContext(). vm2 is deprecated and discontinued; the maintainer recommends isolated-vm.",
      category: "code-injection" as AttackCategory,
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(true);
  });

  // ── The two that are GENUINELY real — must survive the gate ──

  it("dd-trace-js: unescaped git URL interpolated into a JS banner is REAL (not suppressed)", () => {
    const f = makeFinding({
      title: "Code injection in dd-trace-js esbuild banner",
      description:
        "datadog-esbuild interpolates an unescaped git remote.origin.url into a single-quoted JS banner string; a malicious repository URL injects arbitrary JS into every shipped bundle.",
      category: "code-injection" as AttackCategory,
      evidence: {
        request:
          "banner: { js: `process.env.DD_GIT_REPOSITORY_URL = '${gitMetadata.repositoryURL}';` }",
        response: "",
      },
    });
    const r = isHoldingItWrong(f);
    expect(r.isHoldingItWrong).toBe(false);
    expect(r.reason).toBeNull();
  });

  it("justeattakeaway: attacker filename interpolated into execSync is REAL (not suppressed)", () => {
    const f = makeFinding({
      title: "Command injection in @justeattakeaway/eslint-plugin via filename",
      description:
        "git-utils.js runs git show with an attacker-controlled filename from the linted repository; a crafted filename injects shell commands when CI lints the repo.",
      category: "command-injection" as AttackCategory,
      evidence: {
        request: 'execSync(`git cat-file -e HEAD:"${relativeFilePath}"`)',
        response: "",
      },
    });
    expect(isHoldingItWrong(f).isHoldingItWrong).toBe(false);
  });
});
