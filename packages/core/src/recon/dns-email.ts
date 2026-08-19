// Recon mode — DNS / email security posture for a domain (gap F).
//
// Given a registrable domain, look up and grade the three pillars of email
// anti-spoofing hygiene:
//
//   - SPF   (TXT `v=spf1 …`)  — who is allowed to send mail as this domain,
//                               and how strictly unlisted senders are treated
//                               (the `all` mechanism qualifier).
//   - DMARC (TXT `_dmarc.…`)  — what receivers should do with mail that fails
//                               SPF/DKIM alignment (`p=` policy).
//   - DKIM  (TXT `<sel>._domainkey.…`) — presence of a signing key under a
//                               handful of common selectors.
//
// Grading is intentionally conservative and maps onto 0sec finding
// severities. Missing SPF or DMARC is the bigger spoofing exposure (MEDIUM);
// a present-but-weak policy (SPF `~all` softfail, DMARC `p=none`/`p=quarantine`)
// is a LOW hardening note; SPF `-all` + DMARC `p=reject` earns no finding.
//
// Real pilot evidence (doky.ch): SPF ended in `~all` (softfail, weaker than
// `-all`) and DMARC was `p=quarantine` (not `p=reject`) — both surfaced here
// as hardening opportunities rather than hard failures.
//
// No LLM. Network is injected (`resolveTxt`) so the grader is unit-testable
// without touching DNS.

/** Finding severity, matching the rest of the 0sec finding pipeline. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** The `all` mechanism qualifier at the tail of an SPF record. */
export type SpfPolicy = "-all" | "~all" | "?all" | "+all";

/** The receiver policy declared by a DMARC record's `p=` tag. */
export type DmarcPolicy = "none" | "quarantine" | "reject";

export interface SpfPosture {
  present: boolean;
  record?: string;
  policy?: SpfPolicy;
  /** Human-readable note when the record is missing or weak. */
  issue?: string;
}

export interface DmarcPosture {
  present: boolean;
  record?: string;
  policy?: DmarcPolicy;
  issue?: string;
}

export interface DkimPosture {
  /** Selectors we probed (`<sel>._domainkey.<domain>`). */
  checkedSelectors: string[];
  /** Selectors that returned a usable DKIM key record. */
  found: string[];
}

export interface EmailPostureFinding {
  severity: Severity;
  title: string;
  detail: string;
}

export interface EmailPosture {
  domain: string;
  spf: SpfPosture;
  dmarc: DmarcPosture;
  dkim: DkimPosture;
  findings: EmailPostureFinding[];
}

/**
 * A TXT resolver: name → list of records, each record a list of character
 * strings (DNS TXT records can be chunked into multiple strings that the
 * consumer concatenates). This matches `node:dns/promises` `resolveTxt`.
 */
export type ResolveTxt = (name: string) => Promise<string[][]>;

export interface CheckEmailPostureOptions {
  /** Registrable domain to evaluate, e.g. `doky.ch`. */
  domain: string;
  /**
   * Injectable TXT resolver. Defaults to `node:dns/promises` `resolveTxt`.
   * A rejection (NXDOMAIN / ENODATA / timeout) is treated as "no record".
   */
  resolveTxt?: ResolveTxt;
  /** Override the DKIM selectors to probe. Defaults to {@link DEFAULT_DKIM_SELECTORS}. */
  dkimSelectors?: readonly string[];
}

/**
 * Common DKIM selectors worth probing. Covers Google Workspace (`google`),
 * the generic `default`, Microsoft 365 / generic rotated pairs (`selector1`,
 * `selector2`), and Mailchimp/Mandrill (`k1`).
 */
export const DEFAULT_DKIM_SELECTORS: readonly string[] = [
  "google",
  "default",
  "selector1",
  "selector2",
  "k1",
];

/** Join a chunked TXT record (array of strings) into one logical string. */
function joinTxt(record: string[]): string {
  return record.join("");
}

/**
 * Resolve TXT records for `name`, returning each record as a single joined
 * string. A rejected lookup (NXDOMAIN, ENODATA, SERVFAIL, timeout) is folded
 * into an empty list — "no record" is the answer we care about, not the
 * specific DNS error.
 */
async function resolveTxtStrings(resolveTxt: ResolveTxt, name: string): Promise<string[]> {
  try {
    const records = await resolveTxt(name);
    return records.map(joinTxt);
  } catch {
    return [];
  }
}

/** Extract the `all`-mechanism qualifier from an SPF record, if present. */
export function parseSpfPolicy(record: string): SpfPolicy | undefined {
  // The `all` mechanism is matched anywhere in the record; the qualifier is the
  // single char immediately preceding it (default `+` when bare `all`).
  const match = /(^|\s)([-~?+]?)all(\s|$)/i.exec(record);
  if (!match) return undefined;
  const qualifier = match[2] || "+";
  return `${qualifier}all` as SpfPolicy;
}

/** Extract the `p=` policy tag from a DMARC record, if present and valid. */
export function parseDmarcPolicy(record: string): DmarcPolicy | undefined {
  const match = /(^|;)\s*p\s*=\s*(none|quarantine|reject)\b/i.exec(record);
  if (!match) return undefined;
  return match[2].toLowerCase() as DmarcPolicy;
}

/** Pick the first TXT record that looks like an SPF record (`v=spf1`). */
function findSpfRecord(records: string[]): string | undefined {
  return records.find((r) => /^v=spf1\b/i.test(r.trim()));
}

/** Pick the first TXT record that looks like a DMARC record (`v=DMARC1`). */
function findDmarcRecord(records: string[]): string | undefined {
  return records.find((r) => /^v=DMARC1\b/i.test(r.trim()));
}

/** Heuristic: does a `_domainkey` TXT record look like a real DKIM key? */
function looksLikeDkimKey(record: string): boolean {
  const r = record.trim();
  // A live key has a `p=` with key material; `v=DKIM1` is the canonical
  // header but not all providers emit it. Treat `p=<something>` as the signal,
  // and an explicit empty `p=` (revoked key) as "found but revoked" → present.
  return /(^|;)\s*v\s*=\s*DKIM1\b/i.test(r) || /(^|;)\s*p\s*=/i.test(r);
}

function gradeSpf(spf: SpfPosture, findings: EmailPostureFinding[]): void {
  if (!spf.present) {
    spf.issue = "no SPF record published";
    findings.push({
      severity: "medium",
      title: "Missing SPF record",
      detail:
        "No `v=spf1` TXT record was found for this domain. Without SPF, " +
        "receivers cannot verify which hosts are authorized to send mail as " +
        "the domain, making it trivial to spoof.",
    });
    return;
  }
  switch (spf.policy) {
    case "-all":
      // Hardfail — the strong, desired posture. No finding.
      break;
    case "~all":
      spf.issue = "softfail (`~all`) is weaker than hardfail (`-all`)";
      findings.push({
        severity: "low",
        title: "SPF uses softfail (~all)",
        detail:
          "The SPF record ends in `~all` (softfail). Receivers are asked to " +
          "accept-but-mark unlisted senders rather than reject them. Once the " +
          "sending inventory is confirmed complete, tighten this to `-all` " +
          "(hardfail) for stronger anti-spoofing.",
      });
      break;
    case "?all":
      spf.issue = "neutral (`?all`) provides no enforcement";
      findings.push({
        severity: "low",
        title: "SPF policy is neutral (?all)",
        detail:
          "The SPF record ends in `?all` (neutral), which expresses no opinion " +
          "on unlisted senders and provides no anti-spoofing value. Move to " +
          "`-all` once the authorized-sender list is complete.",
      });
      break;
    case "+all":
      spf.issue = "`+all` permits any host to send as the domain";
      findings.push({
        severity: "medium",
        title: "SPF permits all senders (+all)",
        detail:
          "The SPF record ends in `+all`, explicitly authorizing every host on " +
          "the internet to send mail as this domain. This is equivalent to " +
          "having no SPF protection and should be changed to `-all`.",
      });
      break;
    default:
      // Present but no parseable `all` mechanism (e.g. ends in a redirect).
      spf.issue = "no explicit `all` mechanism — enforcement is ambiguous";
      findings.push({
        severity: "low",
        title: "SPF has no explicit all mechanism",
        detail:
          "An SPF record is published but lacks an explicit `all` mechanism " +
          "(`-all`/`~all`). Add a terminal `-all` so receivers know how to " +
          "treat senders not covered by the record.",
      });
  }
}

function gradeDmarc(dmarc: DmarcPosture, findings: EmailPostureFinding[]): void {
  if (!dmarc.present) {
    dmarc.issue = "no DMARC record published";
    findings.push({
      severity: "medium",
      title: "Missing DMARC record",
      detail:
        "No `v=DMARC1` TXT record was found at `_dmarc.<domain>`. Without " +
        "DMARC, SPF/DKIM failures carry no receiver-side enforcement policy " +
        "and spoofed mail is far more likely to be delivered.",
    });
    return;
  }
  switch (dmarc.policy) {
    case "reject":
      // The strong, desired posture. No finding.
      break;
    case "quarantine":
      dmarc.issue = "`p=quarantine` is weaker than `p=reject`";
      findings.push({
        severity: "low",
        title: "DMARC policy is p=quarantine",
        detail:
          "The DMARC policy is `p=quarantine`, which sends failing mail to " +
          "spam rather than rejecting it. After confirming legitimate senders " +
          "pass alignment, move to `p=reject` for full anti-spoofing.",
      });
      break;
    case "none":
      dmarc.issue = "`p=none` is monitor-only and does not block spoofing";
      findings.push({
        severity: "low",
        title: "DMARC policy is p=none (monitor only)",
        detail:
          "The DMARC policy is `p=none`, which only collects reports and " +
          "applies no enforcement. Progress to `p=quarantine` and then " +
          "`p=reject` once alignment is verified.",
      });
      break;
    default:
      dmarc.issue = "DMARC record present but `p=` tag is missing or invalid";
      findings.push({
        severity: "low",
        title: "DMARC record missing a valid policy",
        detail:
          "A DMARC record is published but its `p=` tag is missing or " +
          "unrecognized. Set an explicit `p=reject` (or staged `p=none` → " +
          "`p=quarantine` → `p=reject`) policy.",
      });
  }
}

/**
 * Look up and grade the DNS / email security posture (SPF, DMARC, DKIM) for a
 * domain. Pure with respect to its injected `resolveTxt`, so the grading rules
 * are exercised deterministically in tests.
 */
export async function checkEmailPosture(opts: CheckEmailPostureOptions): Promise<EmailPosture> {
  const domain = opts.domain.trim().replace(/\.$/, "").toLowerCase();
  if (!domain) throw new Error("dns-email: empty domain");

  const resolveTxt = opts.resolveTxt ?? (await defaultResolveTxt());
  const dkimSelectors = opts.dkimSelectors ?? DEFAULT_DKIM_SELECTORS;
  const findings: EmailPostureFinding[] = [];

  // --- SPF (apex TXT) ---
  const apexTxt = await resolveTxtStrings(resolveTxt, domain);
  const spfRecord = findSpfRecord(apexTxt);
  const spf: SpfPosture = spfRecord
    ? { present: true, record: spfRecord, policy: parseSpfPolicy(spfRecord) }
    : { present: false };
  gradeSpf(spf, findings);

  // --- DMARC (_dmarc TXT) ---
  const dmarcTxt = await resolveTxtStrings(resolveTxt, `_dmarc.${domain}`);
  const dmarcRecord = findDmarcRecord(dmarcTxt);
  const dmarc: DmarcPosture = dmarcRecord
    ? { present: true, record: dmarcRecord, policy: parseDmarcPolicy(dmarcRecord) }
    : { present: false };
  gradeDmarc(dmarc, findings);

  // --- DKIM (probe common selectors) ---
  const checkedSelectors = [...dkimSelectors];
  const found: string[] = [];
  for (const selector of checkedSelectors) {
    const records = await resolveTxtStrings(resolveTxt, `${selector}._domainkey.${domain}`);
    if (records.some(looksLikeDkimKey)) found.push(selector);
  }
  if (found.length === 0) {
    findings.push({
      severity: "low",
      title: "No DKIM key found for common selectors",
      detail:
        `None of the probed DKIM selectors (${checkedSelectors.join(", ")}) ` +
        "returned a signing key. DKIM may use a non-standard selector, or mail " +
        "may be unsigned. Confirm DKIM is configured so DMARC alignment can " +
        "rely on a cryptographic signature, not SPF alone.",
    });
  }
  const dkim: DkimPosture = { checkedSelectors, found };

  return { domain, spf, dmarc, dkim, findings };
}

/** Lazily load the real `node:dns/promises` resolver as the default. */
async function defaultResolveTxt(): Promise<ResolveTxt> {
  const dns = await import("node:dns/promises");
  return (name: string) => dns.resolveTxt(name);
}
