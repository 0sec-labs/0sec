import { describe, expect, it } from "vitest";

import {
  SECURITY_RULES,
  buildRuleInjection,
  ruleMatches,
  selectRules,
  type Rule,
} from "./rules.js";

const r = (over: Partial<Rule> & { id: string; trigger: Rule["trigger"] }): Rule => ({
  name: over.id,
  severity: "hint",
  rule: `rule ${over.id}`,
  ...over,
});

describe("ruleMatches", () => {
  it("matches on a regex over the tool input", () => {
    const rule = r({ id: "x", trigger: { regex: ["requests\\.get\\("] } });
    expect(ruleMatches(rule, { toolInput: "requests.get(url)" })).toBe(true);
    expect(ruleMatches(rule, { toolInput: "session.get(url)" })).toBe(false);
  });

  it("requires ALL present facets (phase AND tool AND regex)", () => {
    const rule = r({ id: "x", trigger: { phase: ["exploit"], tool: ["bash"], regex: ["curl"] } });
    expect(ruleMatches(rule, { phase: "exploit", toolName: "bash", toolInput: "curl x" })).toBe(true);
    expect(ruleMatches(rule, { phase: "recon", toolName: "bash", toolInput: "curl x" })).toBe(false);
    expect(ruleMatches(rule, { phase: "exploit", toolName: "http_request", toolInput: "curl x" })).toBe(false);
  });

  it("matches lang off the edited file extension", () => {
    const rule = r({ id: "x", trigger: { lang: ["python"] } });
    expect(ruleMatches(rule, { editedPath: "poc/exploit.py" })).toBe(true);
    expect(ruleMatches(rule, { editedPath: "poc/exploit.js" })).toBe(false);
    expect(ruleMatches(rule, {})).toBe(false);
  });

  it("matches globs on the edited path", () => {
    const rule = r({ id: "x", trigger: { glob: ["**/*.py"] } });
    expect(ruleMatches(rule, { editedPath: "a/b/c.py" })).toBe(true);
    expect(ruleMatches(rule, { editedPath: "a/b/c.txt" })).toBe(false);
  });

  it("an empty trigger matches everything", () => {
    expect(ruleMatches(r({ id: "x", trigger: {} }), {})).toBe(true);
  });

  it("ignores a malformed regex facet rather than throwing", () => {
    const rule = r({ id: "x", trigger: { regex: ["(unclosed"] } });
    expect(ruleMatches(rule, { toolInput: "anything" })).toBe(false);
  });
});

describe("selectRules", () => {
  const rules = [
    r({ id: "a", trigger: { regex: ["foo"] } }),
    r({ id: "b", trigger: { regex: ["bar"] } }),
    r({ id: "always", repeat: "always", trigger: { regex: ["foo"] } }),
  ];

  it("returns matching rules", () => {
    expect(selectRules(rules, { toolInput: "foo" }).map((x) => x.id)).toEqual(["a", "always"]);
  });

  it("skips already-injected rules unless repeat is always", () => {
    const injected = new Set(["a", "always"]);
    expect(selectRules(rules, { toolInput: "foo" }, injected).map((x) => x.id)).toEqual(["always"]);
  });

  it("caps the number returned", () => {
    const many = Array.from({ length: 5 }, (_, i) => r({ id: `m${i}`, trigger: { regex: ["hit"] } }));
    expect(selectRules(many, { toolInput: "hit" }, new Set(), 2)).toHaveLength(2);
  });
});

describe("buildRuleInjection", () => {
  it("renders nothing for no rules", () => {
    expect(buildRuleInjection([])).toBe("");
  });
  it("renders a fenced, attributed block", () => {
    const out = buildRuleInjection([r({ id: "x", trigger: {}, rule: "do the thing" })]);
    expect(out).toContain('<rule id="x">do the thing</rule>');
    expect(out).toContain("0sec rules");
  });
});

describe("SECURITY_RULES seed set", () => {
  it("all have unique ids and non-empty rule text", () => {
    const ids = SECURITY_RULES.map((x) => x.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const rule of SECURITY_RULES) expect(rule.rule.length).toBeGreaterThan(10);
  });

  it("fires the python session rule on a bare requests call in a .py edit", () => {
    const sel = selectRules(SECURITY_RULES, { editedPath: "poc.py", toolInput: 'requests.get("http://t/")' });
    expect(sel.map((x) => x.id)).toContain("py-exploit-session");
  });

  it("fires the WAF rule on a 403 in bash output context", () => {
    const sel = selectRules(SECURITY_RULES, { toolName: "bash", toolInput: "curl → HTTP/1.1 403 Forbidden" });
    expect(sel.map((x) => x.id)).toContain("waf-rotate-headers");
  });
});
