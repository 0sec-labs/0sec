import { mergeIntel, uniqueStrings } from "./normalize.js";
import { buildPriorVulnerabilityAuditGraph } from "./audit-graph.js";
import type {
  AdvisorySearchInput,
  FetchOptions,
  IntelDossier,
  IntelDossierInput,
  IntelDossierSummary,
  IntelGraphSnapshot,
  IntelInvestigationStep,
  IntelPriorVulnerabilityPlaybook,
  IntelSeverity,
  IntelSource,
  IntelVariantLead,
  SimilarSearchInput,
  VulnerabilityIntel,
} from "./types.js";

type AdvisorySearchResult = { advisories: VulnerabilityIntel[]; graph: IntelGraphSnapshot };
type SearchAdvisoriesFn = (input: AdvisorySearchInput, opts?: FetchOptions) => Promise<AdvisorySearchResult>;
type SearchSimilarFn = (input: SimilarSearchInput, opts?: FetchOptions) => Promise<AdvisorySearchResult>;

export async function buildIntelDossierFromSearch(
  input: IntelDossierInput,
  searchAdvisoriesFn: SearchAdvisoriesFn,
  searchSimilarFn: SearchSimilarFn,
  opts: FetchOptions = {},
): Promise<IntelDossier> {
  const advisoryResult = await searchAdvisoriesFn(input, opts);
  const advisories = advisoryResult.advisories;
  const cwes = uniqueStrings(advisories.flatMap((advisory) => advisory.cwes));
  const similarTerms = dossierSearchTerms(input, advisories, cwes);
  const similarResult = input.includeSimilar === false || (cwes.length === 0 && similarTerms.length === 0)
    ? { advisories: [], graph: { nodes: [], edges: [] } }
    : await searchSimilarFn({
      cwe: cwes[0],
      ecosystem: input.ecosystem,
      keywords: similarTerms,
      limit: input.similarLimit ?? 10,
      cacheDir: input.cacheDir,
      offline: input.offline,
      ttlMs: input.ttlMs,
    }, opts);

  const variantLeads = toVariantLeads(advisories, similarResult.advisories);
  const playbooks = buildPriorVulnerabilityPlaybooks(advisories, variantLeads);
  const auditGraph = buildPriorVulnerabilityAuditGraph(playbooks);
  const graph = mergeGraphs(advisoryResult.graph, similarResult.graph);
  const sources = uniqueStrings([
    ...advisories.flatMap((advisory) => advisory.sources),
    ...similarResult.advisories.flatMap((advisory) => advisory.sources),
  ]) as IntelSource[];

  return {
    package: {
      ecosystem: input.ecosystem,
      name: input.packageName,
    },
    version: input.version,
    generatedAt: new Date().toISOString(),
    summary: summarizeDossier(advisories, variantLeads, playbooks),
    advisories,
    variantLeads,
    playbooks,
    auditGraph,
    graph,
    provenance: {
      sources,
      offline: input.offline || undefined,
    },
  };
}

export function buildPriorVulnerabilityPlaybooks(
  advisories: VulnerabilityIntel[],
  variantLeads: IntelVariantLead[],
): IntelPriorVulnerabilityPlaybook[] {
  const byClass = new Map<string, { cwes: Set<string>; ids: Set<string>; summaries: string[] }>();
  for (const item of [...advisories, ...variantLeads]) {
    const bugClass = classifyBugClass(item.cwes, item.summary);
    const entry = byClass.get(bugClass.id) ?? { cwes: new Set<string>(), ids: new Set<string>(), summaries: [] };
    for (const cwe of item.cwes) entry.cwes.add(cwe);
    entry.ids.add(item.id);
    for (const alias of item.aliases) entry.ids.add(alias);
    if (item.summary) entry.summaries.push(item.summary);
    byClass.set(bugClass.id, entry);
  }

  return [...byClass.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([id, entry]) => {
      const bugClass = bugClassLabel(id);
      const cwes = [...entry.cwes].sort((a, b) => a.localeCompare(b));
      const priorVulnerabilityIds = [...entry.ids]
        .filter((value) => /^(CVE-|GHSA-)/i.test(value))
        .sort((a, b) => a.localeCompare(b))
        .slice(0, 12);
      return {
        id: `playbook:${id}`,
        bugClass,
        cwes,
        priorVulnerabilityIds,
        relevance: playbookRelevance(bugClass, cwes, priorVulnerabilityIds),
        steps: playbookSteps(id, bugClass, cwes),
      };
    })
    .filter((playbook) => playbook.priorVulnerabilityIds.length > 0)
    .slice(0, 6);
}

function classifyBugClass(cwes: string[], summary: string | undefined): { id: string } {
  const text = `${cwes.join(" ")} ${summary ?? ""}`.toLowerCase();
  if (text.includes("cwe-22") || text.includes("path traversal") || text.includes("zip slip")) return { id: "path-traversal" };
  if (text.includes("cwe-434") || text.includes("file upload") || text.includes("unrestricted upload")) return { id: "file-upload" };
  if (text.includes("cwe-338") || text.includes("random") || text.includes("cryptographic")) return { id: "weak-randomness" };
  if (text.includes("cwe-78") || text.includes("command injection")) return { id: "command-injection" };
  if (text.includes("cwe-89") || text.includes("sql injection")) return { id: "sql-injection" };
  if (text.includes("cwe-79") || text.includes("xss") || text.includes("cross-site scripting")) return { id: "xss" };
  if (
    text.includes("cwe-918")
    || text.includes("ssrf")
    || text.includes("server-side request forgery")
    || text.includes("server side request forgery")
  ) return { id: "ssrf" };
  if (text.includes("prototype pollution")) return { id: "prototype-pollution" };
  if (text.includes("deserialization")) return { id: "deserialization" };
  if (
    text.includes("auth bypass")
    || text.includes("authentication bypass")
    || text.includes("authorization bypass")
    || text.includes("access control bypass")
    || text.includes("broken access control")
    || (text.includes("privilege escalation") && text.includes("bypass"))
  ) return { id: "auth-bypass" };
  return { id: cwes[0]?.toLowerCase() ?? "generic-vulnerability" };
}

function bugClassLabel(id: string): string {
  const labels: Record<string, string> = {
    "path-traversal": "Path traversal / archive extraction escape",
    "file-upload": "Unrestricted or unsafe file upload",
    "weak-randomness": "Predictable randomness or identifier generation",
    "command-injection": "Command injection",
    "sql-injection": "SQL injection",
    xss: "Cross-site scripting",
    ssrf: "Server-side request forgery",
    "prototype-pollution": "Prototype pollution",
    deserialization: "Unsafe deserialization",
    "auth-bypass": "Authentication or authorization bypass",
  };
  return labels[id] ?? id.toUpperCase();
}

function playbookRelevance(bugClass: string, cwes: string[], ids: string[]): string {
  const cweText = cwes.length > 0 ? ` (${cwes.slice(0, 3).join(", ")})` : "";
  return `${bugClass}${cweText} appears in prior advisories ${ids.slice(0, 4).join(", ")}; use the old bug shape to drive source/sink/guard verification before reporting.`;
}

function playbookSteps(id: string, bugClass: string, cwes: string[]): IntelInvestigationStep[] {
  const cweHint = cwes.length > 0 ? `Relevant CWE context: ${cwes.join(", ")}.` : `Relevant bug class: ${bugClass}.`;
  const common: IntelInvestigationStep[] = [
    {
      id: "map-entrypoints",
      title: "Map reachable entry points",
      rationale: `Prior vulnerabilities only matter if the same bug shape is reachable. ${cweHint}`,
      actions: [
        "Find exported APIs, HTTP handlers, CLI commands, parser hooks, and framework integrations that accept attacker-controlled input.",
        "Record the concrete input object, parameter, file, URL, archive entry, or request field that enters the code.",
      ],
      expectedEvidence: [
        "File/function references for attacker-controlled sources.",
        "A short source-to-parser call chain.",
      ],
    },
    {
      id: "trace-sinks",
      title: "Trace into dangerous sinks",
      rationale: "A prior CVE shape becomes actionable when user-controlled data reaches a sink with insufficient transformation.",
      actions: [
        "Follow the input through normalization, decoding, validation, and wrapper helpers.",
        "Identify filesystem, process, template, database, network, deserialization, or object-merge sinks.",
      ],
      expectedEvidence: [
        "Source-to-sink path with function names.",
        "Sink arguments showing which values remain attacker-influenced.",
      ],
    },
  ];
  return [...common, ...classSpecificSteps(id), {
    id: "prove-or-retire",
    title: "Prove impact or retire the lead",
    rationale: "Intel leads are not findings until local behavior proves reachability and impact.",
    actions: [
      "Write the smallest local harness or command that exercises the source-to-sink path.",
      "Test the old payload shape and at least one bypass mutation against current guards.",
      "If guards hold, record why the prior vulnerability does not apply.",
    ],
    expectedEvidence: [
      "Passing exploit/negative test output, or a concise non-applicability note.",
      "Version/commit context tying the conclusion to the scanned target.",
    ],
  }];
}

function classSpecificSteps(id: string): IntelInvestigationStep[] {
  const steps: Record<string, IntelInvestigationStep[]> = {
    "path-traversal": [{
      id: "exercise-path-bypasses",
      title: "Exercise traversal and archive-entry bypasses",
      rationale: "Historical traversal bugs often hide in decode order, separator handling, and archive entry normalization.",
      actions: [
        "Check whether paths are decoded before or after validation.",
        "Try absolute paths, dot-dot segments, mixed separators, symlinks, unicode separators, and nested archive entries.",
        "Verify final resolved paths remain inside the intended base directory.",
      ],
      expectedEvidence: [
        "Resolved-path comparison at the final write/read sink.",
        "Positive or negative payload matrix for traversal mutations.",
      ],
    }],
    "file-upload": [{
      id: "audit-upload-controls",
      title: "Audit upload naming, type, and execution controls",
      rationale: "Prior upload CVEs usually depend on extension handling, filename trust, storage location, or executable delivery.",
      actions: [
        "Trace uploaded filename, generated name, extension, MIME sniffing, and destination directory.",
        "Check whether attacker input can influence executable extensions, overwrite paths, or public serving paths.",
        "Test double extensions, null bytes where relevant, path separators, content-type mismatch, and archive/polyglot files.",
      ],
      expectedEvidence: [
        "Filename/type validation logic with sink arguments.",
        "Upload harness output showing accepted/rejected payloads.",
      ],
    }],
    "weak-randomness": [{
      id: "measure-identifier-predictability",
      title: "Measure identifier entropy and guessability",
      rationale: "Prior randomness bugs become exploitable when generated IDs protect access to attacker-reachable objects.",
      actions: [
        "Locate ID/token generation and the security decision that relies on secrecy.",
        "Estimate entropy from alphabet, length, seed source, truncation, and collision behavior.",
        "Check whether partial disclosure or predictable prefixes reduce the search space.",
      ],
      expectedEvidence: [
        "Generator code and entropy estimate.",
        "Object access path showing whether guessing has security impact.",
      ],
    }],
    "command-injection": [{
      id: "separate-argv-from-shell",
      title: "Separate argv-safe execution from shell execution",
      rationale: "Command-injection variants hinge on whether attacker data enters a shell-parsed string.",
      actions: [
        "Find process execution calls and determine whether they use shell strings or argv arrays.",
        "Trace quoting, escaping, allowlists, and environment-variable influence.",
        "Test metacharacters, argument injection, option smuggling, and newline payloads.",
      ],
      expectedEvidence: [
        "Exact command construction site.",
        "Harness showing payload behavior at the process boundary.",
      ],
    }],
  };
  return steps[id] ?? [{
    id: "derive-bug-shape",
    title: "Derive the historical bug shape locally",
    rationale: "No specialized deterministic playbook exists yet, so preserve the prior advisory shape and verify it against local code.",
    actions: [
      "Extract source, transformation, sink, guard, and impact from the prior advisory summaries and references.",
      "Map each element to equivalent local code paths.",
      "Create a small proof or negative test for the most similar path.",
    ],
    expectedEvidence: [
      "Prior-to-local mapping table.",
      "Proof or non-applicability result.",
    ],
  }];
}

function summarizeDossier(
  advisories: VulnerabilityIntel[],
  variantLeads: IntelVariantLead[],
  playbooks: IntelPriorVulnerabilityPlaybook[],
): IntelDossierSummary {
  const criticalCount = advisories.filter((advisory) => advisory.severity === "critical").length;
  const highCount = advisories.filter((advisory) => advisory.severity === "high").length;
  const kevCount = advisories.filter((advisory) => advisory.kev?.knownExploited).length;
  const cwes = uniqueStrings(advisories.flatMap((advisory) => advisory.cwes));
  const topSeverity = highestSeverity(advisories.map((advisory) => advisory.severity));
  const riskScore = computeRiskScore(advisories, variantLeads.length);
  return {
    advisoryCount: advisories.length,
    variantLeadCount: variantLeads.length,
    playbookCount: playbooks.length,
    criticalCount,
    highCount,
    kevCount,
    cweCount: cwes.length,
    topSeverity,
    riskScore,
    riskLevel: riskLevel(riskScore),
    recommendedFocus: recommendedFocus(advisories, variantLeads),
  };
}

function computeRiskScore(advisories: VulnerabilityIntel[], variantLeadCount: number): number {
  const severityScore = advisories.reduce((score, advisory) => score + severityPoints(advisory.severity), 0);
  const kevScore = advisories.filter((advisory) => advisory.kev?.knownExploited).length * 45;
  const cvssScore = Math.max(0, ...advisories.map((advisory) => advisory.cvss?.score ?? 0));
  return Math.min(100, Math.round(severityScore + kevScore + cvssScore + Math.min(variantLeadCount, 5) * 2));
}

function severityPoints(severity: IntelSeverity): number {
  if (severity === "critical") return 35;
  if (severity === "high") return 25;
  if (severity === "medium") return 12;
  if (severity === "low") return 4;
  return 0;
}

function highestSeverity(severities: IntelSeverity[]): IntelSeverity {
  const order: IntelSeverity[] = ["critical", "high", "medium", "low", "info"];
  return order.find((severity) => severities.includes(severity)) ?? "info";
}

function riskLevel(score: number): IntelDossierSummary["riskLevel"] {
  if (score <= 0) return "none";
  if (score >= 80) return "critical";
  if (score >= 55) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function recommendedFocus(advisories: VulnerabilityIntel[], variantLeads: IntelVariantLead[]): string[] {
  const focus = new Set<string>();
  if (advisories.some((advisory) => advisory.kev?.knownExploited)) focus.add("known exploited CVEs");
  for (const cwe of uniqueStrings(advisories.flatMap((advisory) => advisory.cwes)).slice(0, 4)) focus.add(cwe);
  for (const advisory of advisories.filter((item) => item.severity === "critical" || item.severity === "high").slice(0, 3)) {
    focus.add(advisory.id);
  }
  if (variantLeads.length > 0) focus.add("variant-hunt similar advisories");
  return [...focus];
}

function dossierSearchTerms(
  input: IntelDossierInput,
  advisories: VulnerabilityIntel[],
  cwes: string[],
): string[] {
  const summaryTerms = advisories.flatMap((advisory) => extractSecurityTerms(advisory.summary ?? advisory.details ?? ""));
  return uniqueStrings([
    ...(input.keywords ?? []),
    ...cwes,
    ...summaryTerms,
  ]).slice(0, 8);
}

function extractSecurityTerms(text: string): string[] {
  const lower = text.toLowerCase();
  const terms: string[] = [];
  for (const term of [
    "path traversal",
    "zip slip",
    "prototype pollution",
    "command injection",
    "sql injection",
    "cross-site scripting",
    "xss",
    "ssrf",
    "deserialization",
    "auth bypass",
  ]) {
    if (lower.includes(term)) terms.push(term);
  }
  return terms;
}

function toVariantLeads(advisories: VulnerabilityIntel[], similar: VulnerabilityIntel[]): IntelVariantLead[] {
  const knownIds = new Set(advisories.flatMap((advisory) => [advisory.id, ...advisory.aliases]).map((id) => id.toUpperCase()));
  return mergeIntel(similar)
    .filter((lead) => ![lead.id, ...lead.aliases].some((id) => knownIds.has(id.toUpperCase())))
    .slice(0, 10)
    .map((lead) => ({
      id: lead.id,
      aliases: lead.aliases,
      severity: lead.severity,
      cwes: lead.cwes,
      summary: lead.summary,
      reason: lead.cwes.length > 0
        ? `Shares ${lead.cwes.slice(0, 3).join(", ")} with package advisory context.`
        : "Matched dossier variant-hunt keywords.",
      references: lead.references.slice(0, 3),
    }));
}

function mergeGraphs(left: IntelGraphSnapshot, right: IntelGraphSnapshot): IntelGraphSnapshot {
  const nodes = new Map(left.nodes.map((node) => [node.id, node]));
  const edges = new Map(left.edges.map((edge) => [`${edge.from}\0${edge.kind}\0${edge.to}`, edge]));
  for (const node of right.nodes) nodes.set(node.id, node);
  for (const edge of right.edges) edges.set(`${edge.from}\0${edge.kind}\0${edge.to}`, edge);
  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
  };
}
