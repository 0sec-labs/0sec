import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { buildPriorVulnerabilityAuditGraph } from "./audit-graph.js";
import { buildPriorVulnerabilityPlaybooks } from "./dossier.js";
import { mergeIntel, toGraphSnapshot, uniqueStrings } from "./normalize.js";
import type {
  IntelSeverity,
  IntelSource,
  IntelTargetHistory,
  TargetHistorySearchInput,
  VulnerabilityIntel,
} from "./types.js";

export interface TargetHistoryInference {
  input: TargetHistorySearchInput;
  sources: string[];
}

export function buildTargetHistoryResult(
  input: TargetHistorySearchInput,
  advisories: VulnerabilityIntel[],
): IntelTargetHistory {
  const hints = targetHistoryHints(input);
  const filtered = mergeIntel(advisories).filter((advisory) => matchesTargetHint(advisory, hints));
  const playbooks = buildPriorVulnerabilityPlaybooks(filtered, []);
  const auditGraph = buildPriorVulnerabilityAuditGraph(playbooks);
  const graph = toGraphSnapshot(filtered);
  return {
    target: {
      target: input.target,
      repoPath: input.repoPath,
      repository: normalizeRepositoryHint(input.repository ?? input.target),
      ecosystem: input.ecosystem,
      packageName: input.packageName,
      product: input.product,
      vendor: input.vendor,
      keywords: input.keywords ?? [],
    },
    generatedAt: new Date().toISOString(),
    summary: summarizeTargetHistory(filtered, playbooks.length, hints),
    advisories: filtered,
    playbooks,
    auditGraph,
    graph,
    provenance: {
      sources: uniqueStrings(filtered.flatMap((advisory) => advisory.sources)) as IntelSource[],
      offline: input.offline || undefined,
    },
  };
}

export function resolveTargetHistoryInput(input: TargetHistorySearchInput): TargetHistorySearchInput {
  if (!input.repoPath) return input;
  const inferred = inferTargetHistoryInputFromRepo(input.repoPath).input;
  return {
    ...inferred,
    ...input,
    repository: input.repository ?? inferred.repository,
    ecosystem: input.ecosystem ?? inferred.ecosystem,
    packageName: input.packageName ?? inferred.packageName,
    product: input.product ?? inferred.product,
    vendor: input.vendor ?? inferred.vendor,
    keywords: uniqueStrings([...(inferred.keywords ?? []), ...(input.keywords ?? [])]),
  };
}

export function inferTargetHistoryInputFromRepo(repoPath: string): TargetHistoryInference {
  const input: TargetHistorySearchInput = { repoPath };
  const sources: string[] = [];

  const packageJson = readJsonFile(join(repoPath, "package.json"));
  if (packageJson) {
    sources.push("package.json");
    const name = typeof packageJson.name === "string" ? packageJson.name : undefined;
    const repo = repositoryFromPackageJson(packageJson.repository);
    input.ecosystem = "npm";
    input.packageName = name;
    input.product = unscopedPackageName(name);
    input.repository = repo;
  }

  const pyproject = readTextFile(join(repoPath, "pyproject.toml"));
  if (pyproject) {
    sources.push("pyproject.toml");
    input.ecosystem ??= "pypi";
    input.packageName ??= matchTomlString(pyproject, "name");
    input.product ??= input.packageName;
    input.repository ??= normalizeRepositoryHint(matchTomlUrl(pyproject, "repository") ?? matchTomlUrl(pyproject, "source") ?? matchTomlUrl(pyproject, "homepage"));
  }

  const cargo = readTextFile(join(repoPath, "Cargo.toml"));
  if (cargo) {
    sources.push("Cargo.toml");
    input.ecosystem ??= "cargo";
    input.packageName ??= matchTomlString(cargo, "name");
    input.product ??= input.packageName;
    input.repository ??= normalizeRepositoryHint(matchTomlString(cargo, "repository"));
  }

  const goMod = readTextFile(join(repoPath, "go.mod"));
  if (goMod) {
    sources.push("go.mod");
    input.ecosystem ??= "Go";
    const module = goMod.match(/^module\s+(\S+)/m)?.[1];
    input.packageName ??= module;
    input.product ??= module?.split("/").filter(Boolean).at(-1);
    input.repository ??= normalizeRepositoryHint(module);
  }

  const gitConfig = readTextFile(join(repoPath, ".git", "config"));
  if (gitConfig) {
    sources.push(".git/config");
    input.repository ??= normalizeRepositoryHint(matchGitRemoteUrl(gitConfig));
  }

  const repo = normalizeRepositoryHint(input.repository);
  const repoName = repo?.split("/")[1];
  input.repository = repo ?? input.repository;
  input.vendor ??= repo?.split("/")[0];
  input.keywords = uniqueStrings([
    input.product,
    input.packageName,
    repoName,
  ].filter((value) => value && value !== input.product));

  return { input, sources };
}

export function targetHistoryHints(input: TargetHistorySearchInput): string[] {
  const repo = normalizeRepositoryHint(input.repository ?? input.target);
  const repoName = repo?.split("/")[1];
  return uniqueStrings([
    input.target,
    repo,
    repoName,
    input.packageName,
    input.product,
    input.vendor && input.product ? `${input.vendor} ${input.product}` : undefined,
    ...(input.keywords ?? []),
  ])
    .map((hint) => hint.toLowerCase())
    .filter((hint) => hint.length >= 3);
}

function readJsonFile(path: string): Record<string, unknown> | undefined {
  const text = readTextFile(path);
  if (!text) return undefined;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function readTextFile(path: string): string | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return readFileSync(path, "utf-8");
  } catch {
    return undefined;
  }
}

function repositoryFromPackageJson(value: unknown): string | undefined {
  if (typeof value === "string") return normalizeRepositoryHint(value);
  if (value && typeof value === "object" && "url" in value && typeof value.url === "string") {
    return normalizeRepositoryHint(value.url);
  }
  return undefined;
}

function unscopedPackageName(name: string | undefined): string | undefined {
  if (!name) return undefined;
  return name.replace(/^@[^/]+\//, "");
}

function matchTomlString(text: string, key: string): string | undefined {
  return text.match(new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*["']([^"']+)["']`, "m"))?.[1];
}

function matchTomlUrl(text: string, key: string): string | undefined {
  const direct = matchTomlString(text, key);
  if (direct) return direct;
  return text.match(new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*\\{[^}]*url\\s*=\\s*["']([^"']+)["']`, "m"))?.[1];
}

function matchGitRemoteUrl(text: string): string | undefined {
  const originBlock = text.match(/\[remote "origin"\]([\s\S]*?)(?:\n\[|$)/)?.[1];
  return (originBlock ?? text).match(/^\s*url\s*=\s*(\S+)/m)?.[1];
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function normalizeRepositoryHint(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim().replace(/^git\+/, "");
  if (!trimmed) return undefined;
  const plainMatch = trimmed.match(/^([^/\s:]+)\/([^/\s]+?)(?:\.git)?$/i);
  if (plainMatch?.[1] && plainMatch[2] && !plainMatch[1].includes(".")) return `${plainMatch[1]}/${plainMatch[2]}`;
  const sshMatch = trimmed.match(/^git@github\.com:([^/\s:]+)\/([^/\s]+?)(?:\.git)?$/i);
  if (sshMatch?.[1] && sshMatch[2]) return `${sshMatch[1]}/${sshMatch[2]}`;
  try {
    const url = new URL(trimmed.startsWith("http") ? trimmed : `https://${trimmed}`);
    if (!/github\.com$/i.test(url.hostname)) return undefined;
    const [owner, repo] = url.pathname.split("/").filter(Boolean);
    if (!owner || !repo) return undefined;
    return `${owner}/${repo.replace(/\.git$/i, "")}`;
  } catch {
    const match = trimmed.match(/(?:github\.com[:/])?([^/\s:]+)\/([^/\s]+?)(?:\.git)?$/i);
    return match?.[1] && match[2] ? `${match[1]}/${match[2]}` : undefined;
  }
}

function matchesTargetHint(advisory: VulnerabilityIntel, hints: string[]): boolean {
  if (hints.length === 0) return true;
  const haystack = [
    advisory.id,
    ...advisory.aliases,
    advisory.summary,
    advisory.details,
    advisory.package?.name,
    advisory.package?.ecosystem,
    ...advisory.references.map((ref) => ref.url),
  ].filter((value): value is string => Boolean(value)).join("\n").toLowerCase();
  return hints.some((hint) => haystack.includes(hint));
}

function summarizeTargetHistory(
  advisories: VulnerabilityIntel[],
  playbookCount: number,
  hints: string[],
): IntelTargetHistory["summary"] {
  const criticalCount = advisories.filter((advisory) => advisory.severity === "critical").length;
  const highCount = advisories.filter((advisory) => advisory.severity === "high").length;
  const kevCount = advisories.filter((advisory) => advisory.kev?.knownExploited).length;
  const cwes = uniqueStrings(advisories.flatMap((advisory) => advisory.cwes));
  return {
    advisoryCount: advisories.length,
    playbookCount,
    criticalCount,
    highCount,
    kevCount,
    cweCount: cwes.length,
    topSeverity: highestSeverity(advisories.map((advisory) => advisory.severity)),
    matchedHints: hints.slice(0, 10),
  };
}

function highestSeverity(severities: IntelSeverity[]): IntelSeverity {
  const order: IntelSeverity[] = ["critical", "high", "medium", "low", "info"];
  return order.find((severity) => severities.includes(severity)) ?? "info";
}
