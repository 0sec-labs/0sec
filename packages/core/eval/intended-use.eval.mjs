// Live eval (#802): does our LLM correctly apply the intended-use gate?
// Runs the 7 ground-truth cases (5 verified-by-design npm duds + 2 genuinely-
// real injections) through OUR LLM service (@0cloud/llm callLlm), credential
// resolved from the `codex login` token — the same path the verify runners use.
// No raw vendor key (see AGENTS.md "Use the unified LLM service, never raw keys").
//
// Run from the repo root: node 0sec/packages/core/eval/intended-use.eval.mjs
// Requires `codex login` (~/.codex/auth.json). Last result: 7/7 (gpt-5.5, 2026-06-03).
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolveLlmCredential, callLlm } from "../../../../packages/llm/dist/index.js";

function codexTokenResolver() {
  const auth = JSON.parse(readFileSync(`${homedir()}/.codex/auth.json`, "utf8"));
  const t = auth.tokens ?? {};
  if (!t.access_token) return Promise.resolve(null);
  return Promise.resolve({ accessToken: t.access_token, accountId: t.account_id });
}

const SYSTEM = `You are a security-triage judge. Decide if a candidate finding is a REAL vulnerability or BY-DESIGN (the API doing exactly what it is documented to do).

A sink doing exactly what it is documented to do is NOT a vulnerability, even if it executes attacker-supplied code. Mark BY-DESIGN when ANY of:
1. The untrusted input IS itself the template/expression/script the API exists to evaluate (template engines compiling templates, eval/new Function/vm.* by contract, expr-eval.toJSFunction).
2. It is only reachable under a NON-DEFAULT, opt-in unsafe option the app must explicitly enable (e.g. eval:'native'). Default path is safe.
3. The PoC requires the caller/developer to pass the dangerous argument directly, or to pass a callable/constructor/function (attacker already runs code).
4. The "escape" presupposes already executing inside the sandbox, or a malicious/compromised backend / provider SDK.

It IS REAL when untrusted DATA (a filename, URL, query param, header, path) is interpolated/concatenated into a code/command/query context that was never meant to be code (e.g. attacker-controlled filename into execSync, unescaped git URL into a JS string).

Respond with ONLY compact JSON: {"verdict":"real"|"by-design","rationale":"<=20 words"}`;

const CASES = [
  { id: "eta", expect: "by-design", text: "Eta SSTI to RCE: Eta compiles templates with new Function via compileToString; an attacker-controlled template string passed to render() yields RCE." },
  { id: "nunjucks", expect: "by-design", text: "nunjucks SSTI to RCE: renderString() evaluates an attacker-controlled template; memberLookup exposes the constructor, enabling RCE when the app uses the template source as user input." },
  { id: "expr-eval", expect: "by-design", text: "expr-eval sandbox escape: Parser.parse(expr).toJSFunction() builds a function via new Function; an attacker-controlled expression escapes to global scope. toJSFunction is an opt-in compile-to-JS escape hatch." },
  { id: "jsonpath-plus", expect: "by-design", text: "jsonpath-plus RCE: with the non-default eval:'native' option, an attacker-controlled JSONPath expression runs via new vm.Script().runInNewContext. The default 'safe' evaluator blocks this." },
  { id: "vm2", expect: "by-design", text: "vm2 sandbox escape: when NodeVM is configured with require:{builtin:['vm']}, sandboxed code escapes via runInNewContext. vm2 is deprecated; maintainer recommends isolated-vm." },
  { id: "dd-trace-js", expect: "real", text: "dd-trace-js code injection: datadog-esbuild interpolates an unescaped git remote.origin.url into a single-quoted JS banner (`...= '${repositoryURL}';`); a malicious repo URL injects arbitrary JS into every shipped bundle." },
  { id: "justeattakeaway", expect: "real", text: "@justeattakeaway/eslint-plugin command injection: git-utils.js runs execSync(`git show ${sha}:\"${relativeFilePath}\"`) where relativeFilePath is an attacker-controlled filename from the linted repo; a crafted filename injects shell commands in CI." },
];

const cred = await resolveLlmCredential({ provider: "chatgpt-codex", chatgptTokenResolver: codexTokenResolver });
if (!cred) throw new Error("no LLM credential — is `codex login` done?");

let correct = 0;
console.log(`provider: chatgpt-codex (model ${cred.model ?? "gpt-5.5"})\n`);
for (const c of CASES) {
  try {
    const { text } = await callLlm(cred, { system: SYSTEM, messages: [{ role: "user", content: c.text }] });
    const m = text.match(/\{[\s\S]*\}/);
    const v = JSON.parse(m ? m[0] : text);
    const ok = v.verdict === c.expect;
    if (ok) correct++;
    console.log(`${ok ? "PASS" : "FAIL"}  ${c.id.padEnd(16)} expected=${c.expect.padEnd(10)} got=${String(v.verdict).padEnd(10)} — ${String(v.rationale || "").slice(0, 80)}`);
  } catch (e) {
    console.log(`ERR   ${c.id.padEnd(16)} ${String(e).slice(0, 150)}`);
  }
}
console.log(`\nSCORE: ${correct}/${CASES.length}`);
process.exit(correct === CASES.length ? 0 : 1);
