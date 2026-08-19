import type { Finding } from "@0sec/shared";

interface GitHubIssue {
  title: string;
  number: number;
  state: string;
}

interface ExportResult {
  created: number;
  skipped: number;
}

function buildIssueTitle(finding: Finding): string {
  const sev = finding.severity.toUpperCase();
  return `[${sev}] ${finding.title}`;
}

function buildIssueBody(finding: Finding): string {
  const lines: string[] = [];

  lines.push(`## Description`);
  lines.push(finding.description);
  lines.push("");

  lines.push(`## Details`);
  lines.push(`- **Severity:** ${finding.severity}`);
  lines.push(`- **Category:** ${finding.category}`);
  lines.push(`- **Status:** ${finding.status}`);
  if (finding.cvssScore !== undefined) {
    lines.push(`- **CVSS Score:** ${finding.cvssScore}`);
  }
  if (finding.cvssVector) {
    lines.push(`- **CVSS Vector:** ${finding.cvssVector}`);
  }
  if (finding.confidence !== undefined) {
    lines.push(`- **Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
  }
  lines.push("");

  if (finding.evidence) {
    lines.push(`## Evidence`);
    if (finding.evidence.request) {
      lines.push(`### Request`);
      lines.push("```");
      lines.push(finding.evidence.request);
      lines.push("```");
      lines.push("");
    }
    if (finding.evidence.response) {
      lines.push(`### Response`);
      lines.push("```");
      lines.push(finding.evidence.response);
      lines.push("```");
      lines.push("");
    }
    if (finding.evidence.analysis) {
      lines.push(`### Analysis`);
      lines.push(finding.evidence.analysis);
      lines.push("");
    }
  }

  lines.push("---");
  lines.push(`*Exported by [0sec](https://github.com/0sec-labs/0sec) | Finding ID: \`${finding.id}\`*`);

  return lines.join("\n");
}

function getLabels(finding: Finding): string[] {
  const labels: string[] = ["0sec", `severity:${finding.severity}`, `category:${finding.category}`];
  return labels;
}

async function githubApi<T>(
  method: string,
  url: string,
  token: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const resp = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`GitHub API ${method} ${url} returned ${resp.status}: ${text}`);
  }

  return resp.json() as Promise<T>;
}

/**
 * Fetch all open issues with the "0sec" label to check for duplicates.
 * Paginates through all pages.
 */
async function fetchExistingIssueTitles(repo: string, token: string): Promise<Set<string>> {
  const titles = new Set<string>();
  let page = 1;
  const perPage = 100;

  while (true) {
    const url = `https://api.github.com/repos/${repo}/issues?state=open&labels=0sec&per_page=${perPage}&page=${page}`;
    const issues = await githubApi<GitHubIssue[]>("GET", url, token);
    for (const issue of issues) {
      titles.add(issue.title);
    }
    if (issues.length < perPage) break;
    page++;
  }

  return titles;
}

/**
 * Ensure all required labels exist in the repo, creating any that are missing.
 */
async function ensureLabels(repo: string, token: string, labels: string[]): Promise<void> {
  const url = `https://api.github.com/repos/${repo}/labels?per_page=100`;
  const existing = await githubApi<Array<{ name: string }>>("GET", url, token);
  const existingNames = new Set(existing.map((l) => l.name));

  const severityColors: Record<string, string> = {
    "severity:critical": "b60205",
    "severity:high": "d93f0b",
    "severity:medium": "e4e669",
    "severity:low": "0e8a16",
    "severity:info": "c5def5",
  };

  for (const label of labels) {
    if (existingNames.has(label)) continue;
    const color = severityColors[label] ?? "ededed";
    try {
      await githubApi("POST", `https://api.github.com/repos/${repo}/labels`, token, {
        name: label,
        color,
      });
    } catch {
      // Label may have been created concurrently; ignore 422 errors
    }
  }
}

/**
 * Export findings as GitHub Issues.
 *
 * Each finding becomes one issue. Issues are deduplicated by title against
 * existing open issues that carry the "0sec" label.
 */
export async function exportToGitHubIssues(
  findings: Finding[],
  repo: string,
): Promise<ExportResult> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error(
      "GITHUB_TOKEN environment variable is required for GitHub Issues export. " +
      "Create a token at https://github.com/settings/tokens with the 'repo' scope.",
    );
  }

  if (findings.length === 0) {
    return { created: 0, skipped: 0 };
  }

  // Collect all unique labels we need and ensure they exist
  const allLabels = new Set<string>();
  allLabels.add("0sec");
  for (const f of findings) {
    for (const l of getLabels(f)) {
      allLabels.add(l);
    }
  }
  await ensureLabels(repo, token, [...allLabels]);

  // Fetch existing issue titles for deduplication
  const existingTitles = await fetchExistingIssueTitles(repo, token);

  let created = 0;
  let skipped = 0;

  for (const finding of findings) {
    const title = buildIssueTitle(finding);

    if (existingTitles.has(title)) {
      skipped++;
      continue;
    }

    await githubApi("POST", `https://api.github.com/repos/${repo}/issues`, token, {
      title,
      body: buildIssueBody(finding),
      labels: getLabels(finding),
    });

    // Track the title so subsequent findings with the same title are skipped
    existingTitles.add(title);
    created++;
  }

  return { created, skipped };
}
