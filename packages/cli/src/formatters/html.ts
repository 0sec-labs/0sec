import type { ScanReport, Finding, Severity } from "@pwnkit/shared";

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; accent: string }> = {
  critical: { bg: "#991b1b", text: "#ffffff", accent: "#f87171" },
  high: { bg: "#c2410c", text: "#ffffff", accent: "#fb923c" },
  medium: { bg: "#a16207", text: "#000000", accent: "#facc15" },
  low: { bg: "#1d4ed8", text: "#ffffff", accent: "#60a5fa" },
  info: { bg: "#4b5563", text: "#ffffff", accent: "#9ca3af" },
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function formatCategory(cat: string): string {
  return cat
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function riskLevel(summary: { critical: number; high: number; medium: number; low: number; info: number }): { label: string; color: string } {
  if (summary.critical > 0) return { label: "CRITICAL", color: "#ef4444" };
  if (summary.high > 0) return { label: "HIGH", color: "#f97316" };
  if (summary.medium > 0) return { label: "MEDIUM", color: "#eab308" };
  if (summary.low > 0) return { label: "LOW", color: "#3b82f6" };
  return { label: "CLEAN", color: "#22c55e" };
}

function renderFinding(finding: Finding, index: number): string {
  const sev = SEVERITY_COLORS[finding.severity];
  const confidence = finding.confidence != null ? `${Math.round(finding.confidence * 100)}%` : null;
  const cvss = finding.cvssScore != null ? finding.cvssScore.toFixed(1) : null;

  return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="severity-badge" style="background:${sev.bg};color:${sev.text}">${finding.severity.toUpperCase()}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
      </div>
      <div class="finding-meta">
        <span class="meta-tag">Category: ${formatCategory(finding.category)}</span>
        ${finding.status === "confirmed" ? '<span class="meta-tag confirmed">Confirmed</span>' : `<span class="meta-tag">${escapeHtml(finding.status)}</span>`}
        ${confidence ? `<span class="meta-tag">Confidence: ${confidence}</span>` : ""}
        ${cvss ? `<span class="meta-tag">CVSS: ${cvss}</span>` : ""}
      </div>
      <p class="finding-desc">${escapeHtml(finding.description)}</p>
      ${finding.evidence.analysis ? `<div class="evidence-analysis"><strong>Analysis:</strong> ${escapeHtml(finding.evidence.analysis)}</div>` : ""}
      <details class="evidence-details">
        <summary>Request / Response</summary>
        <div class="evidence-block">
          <div class="evidence-label">Request</div>
          <pre><code>${escapeHtml(finding.evidence.request.slice(0, 2000))}</code></pre>
        </div>
        <div class="evidence-block">
          <div class="evidence-label">Response</div>
          <pre><code>${escapeHtml(finding.evidence.response.slice(0, 2000))}</code></pre>
        </div>
      </details>
    </div>`;
}

function renderSeverityBar(summary: { critical: number; high: number; medium: number; low: number; info: number }): string {
  const total = summary.critical + summary.high + summary.medium + summary.low + summary.info;
  if (total === 0) return "";

  const segments = SEVERITY_ORDER
    .filter((s) => summary[s] > 0)
    .map((s) => {
      const pct = (summary[s] / total) * 100;
      return `<div class="bar-segment" style="width:${pct}%;background:${SEVERITY_COLORS[s].accent}" title="${summary[s]} ${s}"></div>`;
    })
    .join("");

  return `<div class="severity-bar">${segments}</div>`;
}

export function formatHtml(report: ScanReport): string {
  const risk = riskLevel(report.summary);
  const sorted = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  const findingsHtml = sorted.length > 0
    ? sorted.map((f, i) => renderFinding(f, i)).join("\n")
    : `<div class="no-findings">${report.warnings.length > 0 ? "No vulnerabilities confirmed. Scan finished with warnings." : "No vulnerabilities found. Target passed all tests."}</div>`;

  const warningsHtml = report.warnings.length > 0
    ? `<div class="section">
        <h2 class="section-title warning-title">Warnings</h2>
        ${report.warnings.map((w) => `<div class="warning-item"><span class="warning-stage">${escapeHtml(w.stage)}</span> ${escapeHtml(w.message)}</div>`).join("\n")}
      </div>`
    : "";

  const sevCountsHtml = SEVERITY_ORDER
    .map((s) => {
      const count = report.summary[s];
      return `<div class="sev-count"><span class="sev-dot" style="background:${SEVERITY_COLORS[s].accent}"></span><span class="sev-label">${s}</span><span class="sev-num">${count}</span></div>`;
    })
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pwnkit Report — ${escapeHtml(report.target)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #09090b;
    color: #d4d4d8;
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Consolas', monospace;
    font-size: 14px;
    line-height: 1.6;
    padding: 2rem;
    max-width: 960px;
    margin: 0 auto;
  }
  a { color: #f87171; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Header */
  .header {
    border-bottom: 1px solid #27272a;
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }
  .header-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1rem;
  }
  .brand {
    color: #f87171;
    font-size: 1.6rem;
    font-weight: bold;
    letter-spacing: 0.15em;
  }
  .brand-sub { color: #52525b; font-size: 0.8rem; }
  .risk-badge {
    font-size: 0.85rem;
    font-weight: bold;
    padding: 0.3rem 1rem;
    border-radius: 4px;
    letter-spacing: 0.1em;
  }
  .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.5rem;
    margin-top: 1rem;
    font-size: 0.85rem;
    color: #71717a;
  }
  .meta-grid span { display: block; }
  .meta-grid strong { color: #a1a1aa; }

  /* Summary */
  .summary-section {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid #27272a;
  }
  @media (max-width: 600px) {
    .summary-section { grid-template-columns: 1fr; }
  }
  .stat-box {
    background: #18181b;
    border: 1px solid #27272a;
    border-radius: 6px;
    padding: 1rem;
  }
  .stat-box h3 {
    color: #71717a;
    font-size: 0.75rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }
  .stat-box .big-num {
    font-size: 2rem;
    font-weight: bold;
    color: #fafafa;
  }
  .sev-counts {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-top: 0.5rem;
  }
  .sev-count {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.8rem;
  }
  .sev-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }
  .sev-label { color: #71717a; }
  .sev-num { color: #d4d4d8; font-weight: bold; }

  .severity-bar {
    display: flex;
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
    margin-top: 0.75rem;
  }
  .bar-segment { min-width: 4px; }

  /* Findings */
  .section { margin-bottom: 2rem; }
  .section-title {
    color: #f87171;
    font-size: 0.9rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 1rem;
  }
  .warning-title { color: #facc15; }

  .finding-card {
    background: #18181b;
    border: 1px solid #27272a;
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 0.75rem;
  }
  .finding-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }
  .severity-badge {
    font-size: 0.7rem;
    font-weight: bold;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    letter-spacing: 0.05em;
    flex-shrink: 0;
  }
  .finding-title {
    color: #fafafa;
    font-weight: bold;
    font-size: 0.95rem;
  }
  .finding-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }
  .meta-tag {
    font-size: 0.75rem;
    color: #71717a;
    background: #27272a;
    padding: 0.1rem 0.5rem;
    border-radius: 3px;
  }
  .meta-tag.confirmed { color: #4ade80; background: #052e16; }
  .finding-desc {
    color: #a1a1aa;
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
  }
  .evidence-analysis {
    color: #a1a1aa;
    font-size: 0.85rem;
    font-style: italic;
    padding: 0.5rem;
    background: #1c1c1e;
    border-left: 3px solid #3f3f46;
    border-radius: 2px;
    margin-bottom: 0.5rem;
  }
  .evidence-details {
    margin-top: 0.5rem;
  }
  .evidence-details summary {
    cursor: pointer;
    color: #71717a;
    font-size: 0.8rem;
    padding: 0.3rem 0;
  }
  .evidence-details summary:hover { color: #a1a1aa; }
  .evidence-block {
    margin-top: 0.5rem;
  }
  .evidence-label {
    font-size: 0.75rem;
    color: #71717a;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.25rem;
  }
  .evidence-details pre {
    background: #0a0a0a;
    border: 1px solid #27272a;
    border-radius: 4px;
    padding: 0.75rem;
    overflow-x: auto;
    font-size: 0.8rem;
    line-height: 1.5;
    color: #a1a1aa;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .no-findings {
    background: #052e16;
    color: #4ade80;
    padding: 1rem;
    border-radius: 6px;
    border: 1px solid #166534;
    font-size: 0.9rem;
  }

  .warning-item {
    padding: 0.4rem 0.5rem;
    margin-bottom: 0.25rem;
    background: #1c1307;
    border-left: 3px solid #facc15;
    border-radius: 2px;
    font-size: 0.85rem;
  }
  .warning-stage {
    color: #facc15;
    font-weight: bold;
    margin-right: 0.5rem;
  }

  /* Timeline */
  .timeline {
    font-size: 0.8rem;
    color: #71717a;
  }
  .timeline-row {
    display: flex;
    gap: 0.5rem;
    padding: 0.2rem 0;
  }
  .timeline-label { color: #52525b; min-width: 80px; }
  .timeline-value { color: #a1a1aa; }

  /* Footer */
  .footer {
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid #27272a;
    color: #3f3f46;
    font-size: 0.75rem;
    text-align: center;
  }
</style>
</head>
<body>
  <div class="header">
    <div class="header-top">
      <div>
        <div class="brand">PWNKIT</div>
        <div class="brand-sub">Security Scan Report</div>
      </div>
      <div class="risk-badge" style="background:${risk.color};color:#fff">${risk.label} RISK</div>
    </div>
    <div class="meta-grid">
      <span><strong>Target:</strong> ${escapeHtml(report.target)}</span>
      <span><strong>Depth:</strong> ${report.scanDepth}</span>
      <span><strong>Duration:</strong> ${formatDuration(report.durationMs)}</span>
      <span><strong>Started:</strong> ${escapeHtml(report.startedAt)}</span>
    </div>
  </div>

  <div class="summary-section">
    <div class="stat-box">
      <h3>Findings</h3>
      <div class="big-num">${report.summary.totalFindings}</div>
      <div class="sev-counts">
        ${sevCountsHtml}
      </div>
      ${renderSeverityBar(report.summary)}
    </div>
    <div class="stat-box">
      <h3>Attacks Tested</h3>
      <div class="big-num">${report.summary.totalAttacks}</div>
      <div class="timeline">
        <div class="timeline-row"><span class="timeline-label">Started</span><span class="timeline-value">${escapeHtml(report.startedAt)}</span></div>
        <div class="timeline-row"><span class="timeline-label">Completed</span><span class="timeline-value">${escapeHtml(report.completedAt)}</span></div>
        <div class="timeline-row"><span class="timeline-label">Duration</span><span class="timeline-value">${formatDuration(report.durationMs)}</span></div>
      </div>
    </div>
  </div>

  ${warningsHtml}

  <div class="section">
    <h2 class="section-title">Findings</h2>
    ${findingsHtml}
  </div>

  <div class="footer">
    Generated by pwnkit &middot; ${escapeHtml(new Date().toISOString())}
  </div>
</body>
</html>`;
}
