/**
 * Deterministic evidence check for a vulnerable-side craft self-test.
 *
 * A crash alone is not enough for a CyberGym final submission: it may be a
 * raw segfault or an unrelated pre-existing bug. This module only rejects
 * evidence that contradicts an explicit description anchor. Missing evidence
 * stays inconclusive so vague disclosures cannot manufacture false negatives.
 */

export type CraftCrashClass =
  | "overflow"
  | "use-after-free"
  | "double-free"
  | "uninitialized"
  | "invalid-free"
  | "size"
  | "unknown";

export type CraftCandidateIdentityStatus = "match" | "mismatch" | "inconclusive";

export interface CraftCandidateIdentity {
  status: CraftCandidateIdentityStatus;
  expectedCrashClass?: CraftCrashClass;
  observedCrashClass?: CraftCrashClass;
  expectedFunction?: string;
  stackFunctions: string[];
  reasons: string[];
}

const RAW_SEGFAULT = /\b(?:segmentation fault|sigsegv)\b/i;
const SANITIZER_SIGNAL = /\b(?:addresssanitizer|memorysanitizer|undefinedbehaviorsanitizer|ubsan|runtime error:)\b/i;
const FRAME = /#\d+\s+0x[0-9a-f]+\s+in\s+([~A-Za-z_][\w:<>~]*)/gi;
const SUMMARY_FUNCTION = /\bSUMMARY:\s+[^\n]*?\bin\s+([~A-Za-z_][\w:<>~]*)/gi;
const EXPLICIT_FUNCTION = /`([A-Za-z_][\w:<>~]*)\s*(?:\(\))?`/;

function crashClassFromText(text: string): CraftCrashClass | undefined {
  if (/\bdouble[- ]free\b/i.test(text)) return "double-free";
  if (/\b(?:heap|stack|global)[- ]use[- ]after[- ]free\b|\buse[- ]after[- ]free\b|\bUAF\b/i.test(text)) {
    return "use-after-free";
  }
  if (/\b(?:invalid|attempting)\s+free\b/i.test(text)) return "invalid-free";
  if (/\b(?:use[- ]of[- ]uninitialized|uninitialized(?: value| memory)?)\b/i.test(text)) {
    return "uninitialized";
  }
  if (/\b(?:allocation[- ]size[- ]too[- ]big|negative[- ]size[- ]param)\b/i.test(text)) return "size";
  if (/\b(?:buffer[- ]overflow|out[- ]of[- ]bounds|\bOOB\b|runtime error:\s*(?:index|load|store).*(?:bounds|overflow))\b/i.test(text)) {
    return "overflow";
  }
  return undefined;
}


function stackFunctions(output: string): string[] {
  const names = new Set<string>();
  for (const pattern of [FRAME, SUMMARY_FUNCTION]) {
    pattern.lastIndex = 0;
    for (const match of output.matchAll(pattern)) names.add(match[1]!);
  }
  return [...names];
}

/**
 * Compare independently observable crash evidence with anchors stated in the
 * target description. A mismatch is safe to reject before a graded final
 * submission; an inconclusive result remains eligible after the usual self-test.
 */
export function assessCraftCandidateIdentity(
  description: string,
  sanitizerOutput: string,
): CraftCandidateIdentity {
  const expectedCrashClass = crashClassFromText(description);
  const observedCrashClass = crashClassFromText(sanitizerOutput);
  const expectedFunction = EXPLICIT_FUNCTION.exec(description)?.[1];
  const frames = stackFunctions(sanitizerOutput);
  const reasons: string[] = [];

  if (RAW_SEGFAULT.test(sanitizerOutput) && !SANITIZER_SIGNAL.test(sanitizerOutput)) {
    reasons.push("raw segmentation fault has no sanitizer evidence");
    return {
      status: "mismatch",
      ...(expectedCrashClass ? { expectedCrashClass } : {}),
      ...(expectedFunction ? { expectedFunction } : {}),
      stackFunctions: frames,
      reasons,
    };
  }

  if (expectedCrashClass && observedCrashClass && expectedCrashClass !== observedCrashClass) {
    reasons.push(`description expects ${expectedCrashClass}; self-test reported ${observedCrashClass}`);
  }
  if (expectedFunction && frames.length > 0 && !frames.includes(expectedFunction)) {
    reasons.push(`description names ${expectedFunction}; it is absent from sanitizer frames`);
  }
  if (reasons.length > 0) {
    return {
      status: "mismatch",
      ...(expectedCrashClass ? { expectedCrashClass } : {}),
      ...(observedCrashClass ? { observedCrashClass } : {}),
      ...(expectedFunction ? { expectedFunction } : {}),
      stackFunctions: frames,
      reasons,
    };
  }

  const hasCorroboration =
    (expectedCrashClass !== undefined && expectedCrashClass === observedCrashClass) ||
    (expectedFunction !== undefined && frames.includes(expectedFunction));
  if (hasCorroboration) {
    reasons.push("self-test evidence agrees with an explicit target-description anchor");
  } else {
    reasons.push("description or sanitizer output has no deterministic identity anchor");
  }

  return {
    status: hasCorroboration ? "match" : "inconclusive",
    ...(expectedCrashClass ? { expectedCrashClass } : {}),
    ...(observedCrashClass ? { observedCrashClass } : {}),
    ...(expectedFunction ? { expectedFunction } : {}),
    stackFunctions: frames,
    reasons,
  };
}

export function formatCraftCandidateIdentity(identity: CraftCandidateIdentity): string {
  const expected = [
    identity.expectedCrashClass ? `crash=${identity.expectedCrashClass}` : undefined,
    identity.expectedFunction ? `function=${identity.expectedFunction}` : undefined,
  ].filter((value): value is string => value !== undefined);
  const observed = [
    identity.observedCrashClass ? `crash=${identity.observedCrashClass}` : undefined,
    identity.stackFunctions.length > 0 ? `frames=${identity.stackFunctions.slice(0, 4).join(",")}` : undefined,
  ].filter((value): value is string => value !== undefined);
  return `${identity.status.toUpperCase()} — expected ${expected.join("; ") || "no explicit anchor"}; observed ${observed.join("; ") || "no parsed sanitizer anchor"}. ${identity.reasons.join("; ")}`;
}
