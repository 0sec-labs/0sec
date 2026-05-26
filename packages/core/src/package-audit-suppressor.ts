import type { Finding, Severity } from "@pwnkit/shared";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

interface PostProcessDecision {
  action: "suppress" | "downgrade";
  note: string;
  severity?: Severity;
}

/**
 * Package-audit-specific post-processing for agent findings.
 *
 * The package audit path does not flow through the main repository triage
 * moat, so we apply a narrow deterministic cleanup pass here to suppress
 * or downgrade the recurring "package hunt" noise called out in issue #86.
 */
export function postProcessPackageAuditFindings(findings: Finding[]): Finding[] {
  return findings.flatMap((finding) => {
    const decision = classifyPackageAuditFinding(finding);
    if (!decision) return [finding];
    if (decision.action === "suppress") return [];

    return [{
      ...finding,
      severity: decision.severity ?? finding.severity,
      triageStatus: finding.triageStatus ?? "accepted",
      triageNote: appendTriageNote(finding.triageNote, decision.note),
    }];
  });
}

function classifyPackageAuditFinding(finding: Finding): PostProcessDecision | null {
  const text = findingText(finding);

  if (isDocumentedExtensionHookNoise(text)) {
    return {
      action: "suppress",
      note: "package-audit: suppressed documented extension/codegen hook noise",
    };
  }

  if (isPureCliSelfDosNoise(text)) {
    return {
      action: "suppress",
      note: "package-audit: suppressed pure local CLI self-DoS noise",
    };
  }

  if (isKnownBinaryBootstrapNoise(text)) {
    return {
      action: "suppress",
      note: "package-audit: suppressed known binary-bootstrap install hook for esbuild",
    };
  }

  if (isBenignInstallHookNoise(text)) {
    return {
      action: "suppress",
      note: "package-audit: suppressed generic install-hook finding with no suspicious pattern matches",
    };
  }

  if (isCallerControlledRegexNoise(text)) {
    return {
      action: "downgrade",
      severity: "info",
      note: "package-audit: downgraded caller-controlled regex surface; likely application misuse rather than a package vulnerability",
    };
  }

  if (isObjectScopedPrototypeMutation(text)) {
    return {
      action: "downgrade",
      severity: downgradeSeverityOnce(finding.severity),
      note: "package-audit: downgraded object-scoped prototype mutation confined to a returned/result object",
    };
  }

  return null;
}

function findingText(finding: Finding): string {
  return [
    finding.title,
    finding.description,
    finding.evidence.request,
    finding.evidence.response,
    finding.evidence.analysis,
  ]
    .filter((value): value is string => Boolean(value))
    .join("\n")
    .toLowerCase();
}

function isDocumentedExtensionHookNoise(text: string): boolean {
  if (/\bcode\.process\b/.test(text)) return true;
  if (/\brequire-from-string\b/.test(text)) return true;
  if (/\bstandalone\b/.test(text) && /\b(codegen|code generation|generated validator)\b/.test(text)) return true;
  if (/\bcustom keyword\b/.test(text) && /\b(codegen|compile|generated)\b/.test(text)) return true;
  return false;
}

function isCallerControlledRegexNoise(text: string): boolean {
  if (!/\b(redos|regex dos|regex|regular expression)\b/.test(text)) return false;
  if (/\b(user|caller|application|schema(?: author| descriptor)?|manifest)[-\s]*(supplied|provided|controlled)\s+(regex|pattern|regular expression)\b/.test(text)) {
    return true;
  }
  if (/\b(regex|pattern|regular expression)\b.{0,80}\b(user|caller|application|schema(?: author| descriptor)?|manifest)[-\s]*(supplied|provided|controlled)\b/.test(text)) {
    return true;
  }
  if (/\bjoi\.build\b/.test(text) && /\b(manifest|schema descriptor)\b/.test(text)) return true;
  if (/\bobject\.pattern\b/.test(text) && /\b(regex|pattern)\b/.test(text)) return true;
  return false;
}

function isPureCliSelfDosNoise(text: string): boolean {
  if (!/\b(cli|command[- ]line|argv|process\.argv)\b/.test(text)) return false;
  if (!/--(?:size|count|length)\b/.test(text)) return false;
  return /\b(self-dos|self dos|dos|denial of service|resource exhaustion|memory exhaustion|cpu exhaustion|hang)\b/.test(text);
}

function isKnownBinaryBootstrapNoise(text: string): boolean {
  if (!/\besbuild\b/.test(text)) return false;
  if (!/\bpackage executes \d+ install-time hook/.test(text)) return false;
  if (!/\bpostinstall\b/.test(text)) return false;
  if (!/\bnode install\.js\b/.test(text)) return false;
  if (!/\bchild_process spawned in install hook\b/.test(text)) return false;
  if (!/\bexec\/spawn family in install hook\b/.test(text)) return false;
  return /\b(outbound http request|fetch\(\) in install hook)\b/.test(text);
}

function isBenignInstallHookNoise(text: string): boolean {
  if (!/\bpackage executes \d+ install-time hook/.test(text)) return false;
  return /\bno suspicious patterns matched\b/.test(text) || /\b0 pattern matches\b/.test(text);
}

function isObjectScopedPrototypeMutation(text: string): boolean {
  if (!(/__proto__/.test(text) || /prototype pollution/.test(text))) return false;
  if (/\b(reach(?:es|ing)?|pollut(?:e|es|ed|ion)|mutat(?:e|es|ed|ion)|writ(?:e|es|ten)|touch(?:es|ed))\s+(?:the\s+)?object\.prototype\b/.test(text)) {
    return false;
  }
  if (/\bglobal prototype\b/.test(text)) return false;
  if (/\b(returned|validated|result|output|destination)\s+object\b/.test(text)) return true;
  if (/\breturned value\b/.test(text)) return true;
  return /\bobject\.rename\b/.test(text) && /\b(returned|destination)\b/.test(text);
}

function downgradeSeverityOnce(severity: Severity): Severity {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index <= 0 ? "info" : SEVERITY_ORDER[index - 1];
}

function appendTriageNote(existing: string | undefined, note: string): string {
  return existing ? `${existing}; ${note}` : note;
}
