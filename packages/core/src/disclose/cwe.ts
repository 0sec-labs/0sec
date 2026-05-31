import type { AttackCategory } from "@pwnkit/shared";

export interface CweEntry {
  id: string;
  name: string;
  role: "primary" | "secondary";
}

// Ranked per category. First entry is the primary; the rest are secondaries
// an operator may want to tick in the GHSA form's multi-select.
const CWE_MAP: Record<AttackCategory, CweEntry[]> = {
  // LLM / agent
  "prompt-injection": [
    { id: "CWE-1039", name: "Inadequate Detection or Handling of Adversarial Input Perturbations in AI/ML Classifier", role: "primary" },
    { id: "CWE-20", name: "Improper Input Validation", role: "secondary" },
    { id: "CWE-94", name: "Improper Control of Generation of Code ('Code Injection')", role: "secondary" },
  ],
  "jailbreak": [
    { id: "CWE-1039", name: "Inadequate Detection or Handling of Adversarial Input Perturbations in AI/ML Classifier", role: "primary" },
    { id: "CWE-284", name: "Improper Access Control", role: "secondary" },
  ],
  "system-prompt-extraction": [
    { id: "CWE-200", name: "Exposure of Sensitive Information to an Unauthorized Actor", role: "primary" },
    { id: "CWE-1039", name: "Inadequate Detection or Handling of Adversarial Input Perturbations in AI/ML Classifier", role: "secondary" },
  ],
  "data-exfiltration": [
    { id: "CWE-200", name: "Exposure of Sensitive Information to an Unauthorized Actor", role: "primary" },
    { id: "CWE-522", name: "Insufficiently Protected Credentials", role: "secondary" },
  ],
  "tool-misuse": [
    { id: "CWE-284", name: "Improper Access Control", role: "primary" },
    { id: "CWE-441", name: "Unintended Proxy or Intermediary ('Confused Deputy')", role: "secondary" },
    { id: "CWE-285", name: "Improper Authorization", role: "secondary" },
  ],
  "output-manipulation": [
    { id: "CWE-116", name: "Improper Encoding or Escaping of Output", role: "primary" },
    { id: "CWE-74", name: "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", role: "secondary" },
  ],
  "encoding-bypass": [
    { id: "CWE-176", name: "Improper Handling of Unicode Encoding", role: "primary" },
    { id: "CWE-20", name: "Improper Input Validation", role: "secondary" },
  ],
  "multi-turn": [
    { id: "CWE-1039", name: "Inadequate Detection or Handling of Adversarial Input Perturbations in AI/ML Classifier", role: "primary" },
    { id: "CWE-841", name: "Improper Enforcement of Behavioral Workflow", role: "secondary" },
  ],

  // Source-code audit
  "prototype-pollution": [
    { id: "CWE-1321", name: "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')", role: "primary" },
    { id: "CWE-915", name: "Improperly Controlled Modification of Dynamically-Determined Object Attributes", role: "secondary" },
  ],
  "path-traversal": [
    { id: "CWE-22", name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", role: "primary" },
    { id: "CWE-73", name: "External Control of File Name or Path", role: "secondary" },
    { id: "CWE-284", name: "Improper Access Control", role: "secondary" },
  ],
  "command-injection": [
    { id: "CWE-78", name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", role: "primary" },
    { id: "CWE-77", name: "Improper Neutralization of Special Elements used in a Command ('Command Injection')", role: "secondary" },
  ],
  "code-injection": [
    { id: "CWE-94", name: "Improper Control of Generation of Code ('Code Injection')", role: "primary" },
    { id: "CWE-95", name: "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", role: "secondary" },
  ],
  "regex-dos": [
    { id: "CWE-1333", name: "Inefficient Regular Expression Complexity", role: "primary" },
    { id: "CWE-400", name: "Uncontrolled Resource Consumption", role: "secondary" },
  ],
  "unsafe-deserialization": [
    { id: "CWE-502", name: "Deserialization of Untrusted Data", role: "primary" },
    { id: "CWE-915", name: "Improperly Controlled Modification of Dynamically-Determined Object Attributes", role: "secondary" },
  ],
  "information-disclosure": [
    { id: "CWE-200", name: "Exposure of Sensitive Information to an Unauthorized Actor", role: "primary" },
    { id: "CWE-285", name: "Improper Authorization", role: "secondary" },
    { id: "CWE-522", name: "Insufficiently Protected Credentials", role: "secondary" },
  ],
  "ssrf": [
    { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)", role: "primary" },
    { id: "CWE-20", name: "Improper Input Validation", role: "secondary" },
    { id: "CWE-441", name: "Unintended Proxy or Intermediary ('Confused Deputy')", role: "secondary" },
  ],
  "sql-injection": [
    { id: "CWE-89", name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", role: "primary" },
  ],
  "xss": [
    { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", role: "primary" },
    { id: "CWE-80", name: "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", role: "secondary" },
  ],
  "cors": [
    { id: "CWE-942", name: "Permissive Cross-domain Policy with Untrusted Domains", role: "primary" },
    { id: "CWE-346", name: "Origin Validation Error", role: "secondary" },
  ],
  "security-misconfiguration": [
    { id: "CWE-1188", name: "Initialization of a Resource with an Insecure Default", role: "primary" },
    { id: "CWE-16", name: "Configuration", role: "secondary" },
  ],
  "missing-validation": [
    { id: "CWE-20", name: "Improper Input Validation", role: "primary" },
  ],
  "crypto-misuse": [
    { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm", role: "primary" },
    { id: "CWE-328", name: "Use of Weak Hash", role: "secondary" },
    { id: "CWE-321", name: "Use of Hard-coded Cryptographic Key", role: "secondary" },
    { id: "CWE-329", name: "Generation of Predictable IV with CBC Mode", role: "secondary" },
    { id: "CWE-330", name: "Use of Insufficiently Random Values", role: "secondary" },
    { id: "CWE-347", name: "Improper Verification of Cryptographic Signature", role: "secondary" },
  ],

  // Memory corruption / binary
  "heap-overflow": [
    { id: "CWE-122", name: "Heap-based Buffer Overflow", role: "primary" },
    { id: "CWE-787", name: "Out-of-bounds Write", role: "secondary" },
  ],
  "out-of-bounds-read": [
    { id: "CWE-125", name: "Out-of-bounds Read", role: "primary" },
  ],
  "out-of-bounds-write": [
    { id: "CWE-787", name: "Out-of-bounds Write", role: "primary" },
    { id: "CWE-122", name: "Heap-based Buffer Overflow", role: "secondary" },
  ],
  "use-after-free": [
    { id: "CWE-416", name: "Use After Free", role: "primary" },
    { id: "CWE-672", name: "Operation on a Resource after Expiration or Release", role: "secondary" },
  ],
  "stack-buffer-overflow": [
    { id: "CWE-121", name: "Stack-based Buffer Overflow", role: "primary" },
    { id: "CWE-787", name: "Out-of-bounds Write", role: "secondary" },
  ],
  "null-pointer-deref": [
    { id: "CWE-476", name: "NULL Pointer Dereference", role: "primary" },
  ],
  "null-deref": [
    { id: "CWE-476", name: "NULL Pointer Dereference", role: "primary" },
  ],
  "integer-overflow": [
    { id: "CWE-190", name: "Integer Overflow or Wraparound", role: "primary" },
    { id: "CWE-191", name: "Integer Underflow (Wrap or Wraparound)", role: "secondary" },
  ],
  "integer-truncation": [
    { id: "CWE-197", name: "Numeric Truncation Error", role: "primary" },
    { id: "CWE-681", name: "Incorrect Conversion between Numeric Types", role: "secondary" },
  ],
  "race-condition": [
    { id: "CWE-362", name: "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')", role: "primary" },
    { id: "CWE-367", name: "Time-of-check Time-of-use (TOCTOU) Race Condition", role: "secondary" },
  ],
  "toctou": [
    { id: "CWE-367", name: "Time-of-check Time-of-use (TOCTOU) Race Condition", role: "primary" },
    { id: "CWE-362", name: "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')", role: "secondary" },
  ],
  "type-confusion": [
    { id: "CWE-843", name: "Access of Resource Using Incompatible Type ('Type Confusion')", role: "primary" },
  ],
  "double-free": [
    { id: "CWE-415", name: "Double Free", role: "primary" },
  ],
  "format-string": [
    { id: "CWE-134", name: "Use of Externally-Controlled Format String", role: "primary" },
  ],
  "uninitialized-memory": [
    { id: "CWE-457", name: "Use of Uninitialized Variable", role: "primary" },
    { id: "CWE-908", name: "Use of Uninitialized Resource", role: "secondary" },
  ],

  // Supply-chain / package
  "known-vulnerable-package": [
    { id: "CWE-1395", name: "Dependency on Vulnerable Third-Party Component", role: "primary" },
    { id: "CWE-1104", name: "Use of Unmaintained Third Party Components", role: "secondary" },
    { id: "CWE-937", name: "OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities", role: "secondary" },
  ],
  "supply-chain": [
    { id: "CWE-1357", name: "Reliance on Insufficiently Trustworthy Component", role: "primary" },
    { id: "CWE-506", name: "Embedded Malicious Code", role: "secondary" },
    { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", role: "secondary" },
  ],
  "other": [
    { id: "CWE-693", name: "Protection Mechanism Failure", role: "primary" },
  ],
};

export function suggestCwesForCategory(category: AttackCategory): CweEntry[] {
  return CWE_MAP[category] ?? [
    { id: "CWE-693", name: "Protection Mechanism Failure", role: "primary" },
  ];
}

export function formatCweSection(entries: CweEntry[]): string {
  if (entries.length === 0) return "";
  const lines = ["# CWE", ""];
  lines.push("Pick these in the GHSA form's CWE selector (multi-select):");
  lines.push("");
  for (const entry of entries) {
    const emphasis = entry.role === "primary" ? " *(primary)*" : "";
    lines.push(`- **${entry.id}**: ${entry.name}${emphasis}`);
  }
  return lines.join("\n");
}
