/**
 * Just-in-time rule injection.
 *
 * 0sec already has two JIT layers, but both deliver LARGE methodology documents:
 * dynamic playbooks (vuln-class methodology, ~3.6k tokens) and JIT skills
 * (model-pulled full guides). Neither delivers a small, atomic DO/DON'T rule at
 * the moment of the offending ACTION — scoped by phase / language / the specific
 * tool / the command or diff about to run. That is this layer, modelled on Oh My
 * Pi's TTSR (see the `rule-injection` research paper).
 *
 * The engine is pure: `selectRules(rules, ctx, alreadyInjected)` takes the action
 * context and returns the rules to inject, `buildRuleInjection` renders them. The
 * agent loop supplies the context and does the injection + telemetry. Everything
 * here is deterministic and unit-testable without a model.
 */

export type EngagementPhase = "recon" | "exploit" | "report";

export interface RuleTrigger {
  /** Fire only in these phases (omit = any phase). */
  readonly phase?: readonly EngagementPhase[];
  /** Fire only when the edited file is one of these languages (omit = any). */
  readonly lang?: readonly string[];
  /** Fire only when one of these tools armed the action (omit = any). */
  readonly tool?: readonly string[];
  /** Fire only when the edited path matches one of these globs (omit = any). */
  readonly glob?: readonly string[];
  /** Fire only when one of these regexes matches the tool INPUT (omit = any). */
  readonly regex?: readonly string[];
}

export interface Rule {
  readonly id: string;
  readonly name: string;
  /** `warn` surfaces an amber banner; `hint` is quiet. */
  readonly severity: "hint" | "warn";
  readonly trigger: RuleTrigger;
  /** The one-line DO/DON'T injected into context. */
  readonly rule: string;
  /** How often it may re-fire. Default `once-per-scan`. */
  readonly repeat?: "once-per-scan" | "always";
}

export interface RuleContext {
  readonly phase?: EngagementPhase;
  readonly toolName?: string;
  /** Serialized tool arguments / command / diff — matched by `trigger.regex`. */
  readonly toolInput?: string;
  /** Path the action edited (for lang/glob triggers). */
  readonly editedPath?: string;
}

/** Map a file extension to a coarse language tag for `trigger.lang`. */
function langOf(path: string | undefined): string | undefined {
  if (!path) return undefined;
  const ext = path.slice(path.lastIndexOf(".") + 1).toLowerCase();
  const map: Record<string, string> = {
    py: "python", js: "js", mjs: "js", cjs: "js", ts: "ts", tsx: "ts",
    go: "go", rb: "ruby", php: "php", java: "java", rs: "rust", sh: "bash", c: "c", h: "c",
  };
  return map[ext];
}

/** Minimal glob → RegExp: `**` → any, `*` → any-non-slash, `?` → one char. */
function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i += 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

function safeRegex(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

/**
 * Whether a rule's trigger matches the current action. ALL present facets must
 * hold (an omitted facet is a wildcard); a rule with an empty trigger matches
 * everything (so a truly always-on rule is possible but discouraged).
 */
export function ruleMatches(rule: Rule, ctx: RuleContext): boolean {
  const t = rule.trigger;
  if (t.phase && (!ctx.phase || !t.phase.includes(ctx.phase))) return false;
  if (t.tool && (!ctx.toolName || !t.tool.includes(ctx.toolName))) return false;
  if (t.lang) {
    const lang = langOf(ctx.editedPath);
    if (!lang || !t.lang.includes(lang)) return false;
  }
  if (t.glob) {
    if (!ctx.editedPath || !t.glob.some((g) => globToRegExp(g).test(ctx.editedPath!))) return false;
  }
  if (t.regex) {
    if (!ctx.toolInput) return false;
    const hit = t.regex.some((p) => {
      const re = safeRegex(p);
      return re !== null && re.test(ctx.toolInput!);
    });
    if (!hit) return false;
  }
  return true;
}

/**
 * Select the rules to inject for this action: matching, not already injected
 * (unless `repeat: "always"`), capped so an injection stays small.
 */
export function selectRules(
  rules: readonly Rule[],
  ctx: RuleContext,
  alreadyInjected: ReadonlySet<string> = new Set(),
  max = 3,
): Rule[] {
  const out: Rule[] = [];
  for (const rule of rules) {
    if (rule.repeat !== "always" && alreadyInjected.has(rule.id)) continue;
    if (!ruleMatches(rule, ctx)) continue;
    out.push(rule);
    if (out.length >= max) break;
  }
  return out;
}

/** Render selected rules as a fenced, attributed injection block. */
export function buildRuleInjection(rules: readonly Rule[]): string {
  if (rules.length === 0) return "";
  const lines = rules.map((r) => `<rule id="${r.id}">${r.rule}</rule>`);
  return `[0sec rules — apply to what you're doing now]\n${lines.join("\n")}`;
}

/**
 * The built-in security rules — atomic DO/DON'T guidance triggered on the ACTION
 * (tool input / edited file / phase), not the whole target. Kept short; each is
 * one correction the agent should heed at the moment it applies.
 */
export const SECURITY_RULES: readonly Rule[] = [
  {
    id: "py-exploit-session",
    name: "requests-session-for-cookies",
    severity: "hint",
    trigger: { lang: ["python"], regex: ["requests\\.(get|post|put|delete)\\("] },
    rule: "Use a requests.Session() so auth cookies / CSRF tokens persist across the exploit chain; bare requests.get/post drops session state between steps.",
    repeat: "once-per-scan",
  },
  {
    id: "waf-rotate-headers",
    name: "rotate-headers-on-403",
    severity: "warn",
    trigger: { tool: ["bash", "run_command", "http_request"], regex: ["HTTP/\\S*\\s+403", "cloudflare", "Access denied", "Just a moment"] },
    rule: "WAF/403 on the last request — rotate the User-Agent and add realistic Accept/Referer/Origin headers (or switch to the browser tool) before retrying; don't hammer the blocked request unchanged.",
    repeat: "once-per-scan",
  },
  {
    id: "shell-injection-safe-poc",
    name: "argv-not-shell-true",
    severity: "hint",
    trigger: { lang: ["python"], regex: ["subprocess\\.(call|run|Popen)\\([^)]*shell\\s*=\\s*True", "os\\.system\\("] },
    rule: "Build the PoC command as an argv list without shell=True; a shell-string PoC that concatenates target-controlled data can misfire or self-inject and muddies the evidence.",
    repeat: "once-per-scan",
  },
  {
    id: "minimal-proof-no-exfil",
    name: "minimal-non-pii-proof",
    severity: "warn",
    trigger: { phase: ["exploit"], regex: ["information_schema", "SELECT\\s+\\*\\s+FROM\\s+users", "password", "credit_card", "ssn"] },
    rule: "Extract the MINIMUM non-sensitive proof of unauthorized access (a row count, one non-PII field, a schema name) — do not dump credential tables or PII. Save the ordered evidence trail, not bulk data.",
    repeat: "once-per-scan",
  },
  {
    id: "idor-body-and-path",
    name: "idor-both-path-and-body",
    severity: "hint",
    trigger: { phase: ["exploit"], regex: ["/(users|orders|accounts?|invoices?)/\\d+", "[?&](id|user_id|account_id)=\\d+"] },
    rule: "For IDOR, change the id in BOTH the URL path and the request body (user_id/owner_id/account_id). A 200 alone isn't proof — confirm the SAME other-tenant resource crossed the boundary (use access_control_probe).",
    repeat: "once-per-scan",
  },
];
