import { describe, it, expect } from "vitest";
import {
  parsePluginsFromHtml,
  parseThemesFromHtml,
  parseReadmeVersion,
  parseStyleCssVersion,
  queryWpVulnerabilityForWordPress,
  queryWpScanForWordPress,
  runWpFingerprint,
  summarizeWpFingerprint,
  type FetchLike,
} from "./wp-fingerprint.js";
import { WP_VULNERABLE_PLUGIN_SLUGS } from "./wp-vuln-db.js";

// ── Pure parser tests ──

describe("parseReadmeVersion", () => {
  it("extracts Stable tag from a realistic readme.txt", () => {
    const readme = [
      "=== Contact Form 7 ===",
      "Contributors: takayukister",
      "Tags: contact, form",
      "Requires at least: 5.7",
      "Tested up to: 6.1",
      "Stable tag: 5.3.1",
      "License: GPLv2",
      "",
      "Just another contact form plugin.",
    ].join("\n");
    expect(parseReadmeVersion(readme)).toBe("5.3.1");
  });

  it("falls back to Version: header when Stable tag is missing", () => {
    const readme = "=== Some Plugin ===\nVersion: 1.2.3\n";
    expect(parseReadmeVersion(readme)).toBe("1.2.3");
  });

  it("returns undefined when no version header is present", () => {
    expect(parseReadmeVersion("=== Some Plugin ===\nTags: foo\n")).toBeUndefined();
  });

  it("handles Stable tag with pre-release suffix", () => {
    expect(parseReadmeVersion("Stable tag: 2.0.0-rc1\n")).toBe("2.0.0-rc1");
  });
});

describe("parseStyleCssVersion", () => {
  it("extracts Version from a theme style.css header block", () => {
    const css = [
      "/*",
      "Theme Name: Twenty Twenty-One",
      "Theme URI: https://wordpress.org/themes/twentytwentyone/",
      "Author: the WordPress team",
      "Version: 1.7.1",
      "License: GPL v2 or later",
      "*/",
    ].join("\n");
    expect(parseStyleCssVersion(css)).toBe("1.7.1");
  });
});

describe("parsePluginsFromHtml", () => {
  it("extracts plugin slugs from asset URLs in rendered HTML", () => {
    const html = `
      <html><head>
        <link rel='stylesheet' href='https://t.example/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1' />
        <script src='https://t.example/wp-content/plugins/woocommerce/assets/js/frontend/cart.min.js?ver=4.0'></script>
        <link href='/wp-content/plugins/contact-form-7/other.css'/>
      </head></html>
    `;
    const out = new Set<string>();
    parsePluginsFromHtml(html, out);
    expect([...out].sort()).toEqual(["contact-form-7", "woocommerce"]);
  });
});

describe("parseThemesFromHtml", () => {
  it("extracts theme slugs from asset URLs", () => {
    const html = `<link href='/wp-content/themes/twentytwentyone/style.css'/>`;
    const out = new Set<string>();
    parseThemesFromHtml(html, out);
    expect([...out]).toEqual(["twentytwentyone"]);
  });
});

// ── End-to-end fingerprint with mocked fetch ──

interface MockResponse {
  status?: number;
  ok?: boolean;
  body?: string;
  json?: unknown;
}

function buildMockFetch(routes: Record<string, MockResponse>): FetchLike {
  return async (url, _init) => {
    // Normalize — strip query string for route matching but remember original
    const u = new URL(url);
    const key = `${u.origin}${u.pathname}`;
    const route = routes[key] ?? routes[url] ?? { status: 404, ok: false, body: "" };
    const status = route.status ?? (route.ok === false ? 404 : 200);
    const ok = route.ok ?? (status >= 200 && status < 300);
    const body = route.body ?? "";
    return {
      ok,
      status,
      text: async () => body,
      json: async () => (route.json !== undefined ? route.json : JSON.parse(body || "{}")),
    };
  };
}

describe("runWpFingerprint (integration, mocked fetch)", () => {
  const BASE = "http://wp.example";

  it("detects WordPress, enumerates a plugin, and reports it in structured output", async () => {
    const homepageHtml = `
      <html><head>
        <link rel='stylesheet' href='${BASE}/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1' />
        <link rel='stylesheet' href='${BASE}/wp-content/themes/twentytwentyone/style.css?ver=1.7.1' />
      </head><body>hello</body></html>
    `;

    const readmeTxt = [
      "=== Contact Form 7 ===",
      "Contributors: takayukister",
      "Stable tag: 5.3.1",
      "License: GPLv2",
    ].join("\n");

    const styleCss = [
      "/*",
      "Theme Name: Twenty Twenty-One",
      "Version: 1.7.1",
      "*/",
    ].join("\n");

    const routes: Record<string, MockResponse> = {
      [`${BASE}/wp-login.php`]: {
        ok: true,
        status: 200,
        body: `<form id="loginform"><input name="log" id="user_login"/><input type="submit" name="wp-submit"/></form>`,
      },
      [`${BASE}/readme.html`]: {
        ok: true,
        status: 200,
        body: "<html><body>Version 6.1 WordPress</body></html>",
      },
      [`${BASE}/`]: { ok: true, status: 200, body: homepageHtml },
      [`${BASE}/wp-content/plugins/contact-form-7/readme.txt`]: {
        ok: true,
        status: 200,
        body: readmeTxt,
      },
      [`${BASE}/wp-content/themes/twentytwentyone/style.css`]: {
        ok: true,
        status: 200,
        body: styleCss,
      },
    };

    const fetchImpl = buildMockFetch(routes);
    const result = await runWpFingerprint({
      target: BASE,
      fetchImpl,
      timeoutMs: 1000,
      skipOsv: true, // never hit the network in tests
    });

    expect(result.isWordPress).toBe(true);
    expect(result.coreVersion).toBe("6.1");
    expect(result.evidence).toContain("wp-login.php");
    expect(result.evidence).toContain("readme.html");

    // Plugin extracted + version parsed from readme.txt
    expect(result.plugins.some((p) => p.slug === "contact-form-7" && p.version === "5.3.1")).toBe(true);

    // Theme extracted + version parsed from style.css
    expect(result.themes.some((t) => t.slug === "twentytwentyone" && t.version === "1.7.1")).toBe(true);

    // findings table populated; skipOsv disables network lookups but the local
    // WordPress catalog still reports known vulnerable plugin versions.
    const cf7 = result.findings.find((f) => f.slug === "contact-form-7");
    expect(cf7).toBeDefined();
    expect(cf7?.version).toBe("5.3.1");
    expect(cf7?.cves.some((cve) => cve.id === "CVE-2020-35489")).toBe(true);
  });

  it("returns isWordPress=false when no WP endpoints respond", async () => {
    const fetchImpl = buildMockFetch({}); // all 404
    const result = await runWpFingerprint({
      target: BASE,
      fetchImpl,
      timeoutMs: 500,
      skipOsv: true,
    });
    expect(result.isWordPress).toBe(false);
    expect(result.plugins).toHaveLength(0);
  });

  it("enriches findings with a curated CVE recipe when OSV reports CVE-2023-3452 (canto RFI)", async () => {
    const homepageHtml = `
      <html><head>
        <link rel='stylesheet' href='${BASE}/wp-content/plugins/canto/assets/style.css?ver=3.0.4' />
      </head><body>hello</body></html>
    `;

    const cantoReadme = [
      "=== Canto ===",
      "Contributors: canto",
      "Stable tag: 3.0.4",
      "License: GPLv2",
    ].join("\n");

    // OSV response — the mock fetch routes by origin+pathname, so a POST to
    // https://api.osv.dev/v1/query will land here. The codex lookup happens
    // off `id`, so we make sure CVE-2023-3452 is reported.
    const osvJson = {
      vulns: [
        {
          id: "CVE-2023-3452",
          aliases: [],
          summary:
            "The Canto plugin for WordPress is vulnerable to Remote File Inclusion via wp_abspath.",
          severity: [{ type: "CVSS_V3", score: "9.8" }],
        },
      ],
    };

    const routes: Record<string, MockResponse> = {
      [`${BASE}/wp-login.php`]: {
        ok: true,
        status: 200,
        body: `<form id="loginform"><input name="log" id="user_login"/><input type="submit" name="wp-submit"/></form>`,
      },
      [`${BASE}/`]: { ok: true, status: 200, body: homepageHtml },
      [`${BASE}/wp-content/plugins/canto/readme.txt`]: {
        ok: true,
        status: 200,
        body: cantoReadme,
      },
      "https://api.osv.dev/v1/query": {
        ok: true,
        status: 200,
        json: osvJson,
        body: JSON.stringify(osvJson),
      },
    };

    const fetchImpl = buildMockFetch(routes);
    const result = await runWpFingerprint({
      target: BASE,
      fetchImpl,
      timeoutMs: 1000,
      skipOsv: false, // exercise the OSV → codex enrichment path
    });

    expect(result.isWordPress).toBe(true);
    const canto = result.findings.find((f) => f.slug === "canto");
    expect(canto).toBeDefined();
    expect(canto?.cves.some((c) => c.id === "CVE-2023-3452")).toBe(true);

    // The curated codex hint should now be embedded in the exploitHints
    // as a fully-formatted recipe — not the generic "check the advisory" line.
    const hintBlob = (canto?.exploitHints ?? []).join("\n");
    expect(hintBlob).toContain("wp_abspath");
    expect(hintBlob).toMatch(/RFI|Remote File Inclusion/);
    expect(hintBlob).toContain("CVE-2023-3452");
  });

  it("proactively probes high-value vulnerable plugin slugs and emits local catalog CVEs offline", async () => {
    const backupReadme = [
      "=== Backup Migration ===",
      "Contributors: backupbliss",
      "Stable tag: 1.3.5",
      "License: GPLv2",
    ].join("\n");

    const routes: Record<string, MockResponse> = {
      [`${BASE}/wp-login.php`]: {
        ok: true,
        status: 200,
        body: `<form id="loginform"><input name="log" id="user_login"/><input type="submit" name="wp-submit"/></form>`,
      },
      [`${BASE}/`]: { ok: true, status: 200, body: "<html><body>plain wp site</body></html>" },
      [`${BASE}/wp-content/plugins/backup-backup/readme.txt`]: {
        ok: true,
        status: 200,
        body: backupReadme,
      },
    };

    const backupBackupProbeBudget = WP_VULNERABLE_PLUGIN_SLUGS.indexOf("backup-backup") + 1;
    expect(backupBackupProbeBudget).toBeGreaterThan(0);

    const result = await runWpFingerprint({
      target: BASE,
      fetchImpl: buildMockFetch(routes),
      timeoutMs: 1000,
      skipOsv: true,
      maxVulnerablePluginProbes: backupBackupProbeBudget,
    });

    const plugin = result.plugins.find((p) => p.slug === "backup-backup");
    expect(plugin).toMatchObject({
      slug: "backup-backup",
      version: "1.3.5",
      source: "vulnerable_catalog",
    });

    const finding = result.findings.find((f) => f.slug === "backup-backup");
    expect(finding?.cves.some((cve) => cve.id === "CVE-2023-6553" && cve.source === "local_catalog")).toBe(true);
    expect((finding?.exploitHints ?? []).join("\n")).toContain("backup-heart.php");
  });

  it("merges live WPScan API findings when a token is provided", async () => {
    const homepageHtml = `
      <html><head>
        <link rel='stylesheet' href='${BASE}/wp-content/plugins/some-new-plugin/assets/style.css?ver=1.2.0' />
      </head><body>hello</body></html>
    `;

    const pluginReadme = [
      "=== Some New Plugin ===",
      "Stable tag: 1.2.0",
    ].join("\n");

    const wpScanJson = {
      some_new_plugin: {
        vulnerabilities: [
          {
            id: "abc123",
            title: "Some New Plugin <= 1.2.3 - Unauthenticated SQL Injection",
            fixed_in: "1.2.4",
            cvss: 9.8,
            references: {
              cve: ["2026-12345"],
              url: ["https://wpscan.com/vulnerability/abc123/"],
            },
          },
        ],
      },
    };

    const routes: Record<string, MockResponse> = {
      [`${BASE}/wp-login.php`]: {
        ok: true,
        status: 200,
        body: `<form id="loginform"><input name="log" id="user_login"/><input type="submit" name="wp-submit"/></form>`,
      },
      [`${BASE}/`]: { ok: true, status: 200, body: homepageHtml },
      [`${BASE}/wp-content/plugins/some-new-plugin/readme.txt`]: {
        ok: true,
        status: 200,
        body: pluginReadme,
      },
      "https://wpscan.com/api/v3/plugins/some-new-plugin": {
        ok: true,
        status: 200,
        json: wpScanJson,
        body: JSON.stringify(wpScanJson),
      },
    };

    const result = await runWpFingerprint({
      target: BASE,
      fetchImpl: buildMockFetch(routes),
      timeoutMs: 1000,
      skipOsv: true,
      wpScanApiToken: "test-token",
    });

    const finding = result.findings.find((f) => f.slug === "some-new-plugin");
    expect(finding?.cves).toContainEqual(expect.objectContaining({
      id: "CVE-2026-12345",
      source: "wpscan",
      url: "https://wpscan.com/vulnerability/abc123/",
    }));
  });

  it("merges no-key WPVulnerability API findings by default", async () => {
    const homepageHtml = `
      <html><head>
        <link rel='stylesheet' href='${BASE}/wp-content/plugins/some-new-plugin/assets/style.css?ver=1.2.0' />
      </head><body>hello</body></html>
    `;

    const routes: Record<string, MockResponse> = {
      [`${BASE}/wp-login.php`]: {
        ok: true,
        status: 200,
        body: `<form id="loginform"><input name="log" id="user_login"/><input type="submit" name="wp-submit"/></form>`,
      },
      [`${BASE}/`]: { ok: true, status: 200, body: homepageHtml },
      [`${BASE}/wp-content/plugins/some-new-plugin/readme.txt`]: {
        ok: true,
        status: 200,
        body: "=== Some New Plugin ===\nStable tag: 1.2.0\n",
      },
      "https://www.wpvulnerability.net/plugin/some-new-plugin/": {
        ok: true,
        status: 200,
        json: {
          error: 0,
          data: {
            plugin: "some-new-plugin",
            vulnerability: [
              {
                uuid: "wpvuln-1",
                name: "Some New Plugin [some-new-plugin] < 1.2.4",
                operator: { max_version: "1.2.4", max_operator: "lt" },
                impact: { cvss: 9.8 },
                source: [
                  {
                    id: "CVE-2026-12345",
                    name: "CVE-2026-12345",
                    link: "https://www.cve.org/CVERecord?id=CVE-2026-12345",
                  },
                ],
              },
            ],
          },
        },
      },
    };

    const result = await runWpFingerprint({
      target: BASE,
      fetchImpl: buildMockFetch(routes),
      timeoutMs: 1000,
      skipOsv: true,
    });

    const finding = result.findings.find((f) => f.slug === "some-new-plugin");
    expect(finding?.cves).toContainEqual(expect.objectContaining({
      id: "CVE-2026-12345",
      source: "wpvulnerability",
      severity: "9.8",
    }));
  });

  it("filters WPVulnerability fixed findings when the installed plugin version is patched", async () => {
    const fetchImpl = buildMockFetch({
      "https://www.wpvulnerability.net/plugin/some-new-plugin/": {
        ok: true,
        status: 200,
        json: {
          error: 0,
          data: {
            plugin: "some-new-plugin",
            vulnerability: [
              {
                uuid: "wpvuln-1",
                name: "Some New Plugin [some-new-plugin] < 1.2.4",
                operator: { max_version: "1.2.4", max_operator: "lt" },
                source: [{ id: "CVE-2026-12345", name: "CVE-2026-12345" }],
              },
            ],
          },
        },
      },
    });

    const vulnerable = await queryWpVulnerabilityForWordPress(
      "plugin",
      "some-new-plugin",
      "1.2.3",
      fetchImpl,
      1000,
    );
    expect(vulnerable.some((hit) => hit.id === "CVE-2026-12345")).toBe(true);

    const fixed = await queryWpVulnerabilityForWordPress(
      "plugin",
      "some-new-plugin",
      "1.2.4",
      fetchImpl,
      1000,
    );
    expect(fixed.some((hit) => hit.id === "CVE-2026-12345")).toBe(false);
  });

  it("filters WPScan fixed findings when the installed plugin version is patched", async () => {
    const fetchImpl = buildMockFetch({
      "https://wpscan.com/api/v3/plugins/some-new-plugin": {
        ok: true,
        status: 200,
        json: {
          some_new_plugin: {
            vulnerabilities: [
              {
                title: "Some New Plugin <= 1.2.3 - Unauthenticated SQL Injection",
                fixed_in: "1.2.4",
                references: { cve: ["2026-12345"] },
              },
            ],
          },
        },
      },
    });

    const vulnerable = await queryWpScanForWordPress(
      "plugin",
      "some-new-plugin",
      "1.2.3",
      "test-token",
      fetchImpl,
      1000,
    );
    expect(vulnerable.some((hit) => hit.id === "CVE-2026-12345")).toBe(true);

    const fixed = await queryWpScanForWordPress(
      "plugin",
      "some-new-plugin",
      "1.2.4",
      "test-token",
      fetchImpl,
      1000,
    );
    expect(fixed.some((hit) => hit.id === "CVE-2026-12345")).toBe(false);
  });

  it("summarizeWpFingerprint produces a non-empty human-readable report", async () => {
    const result = {
      isWordPress: true,
      evidence: ["wp-login.php"],
      coreVersion: "6.1",
      plugins: [{ slug: "contact-form-7", version: "5.3.1", source: "readme" as const }],
      themes: [],
      findings: [
        {
          kind: "plugin" as const,
          slug: "contact-form-7",
          version: "5.3.1",
          source: "readme",
          cves: [
            {
              id: "CVE-2020-35489",
              aliases: ["GHSA-xxxx"],
              severity: "critical",
              summary: "Unrestricted file upload",
              url: "https://osv.dev/vulnerability/CVE-2020-35489",
            },
          ],
          exploitHints: ["Try unauthenticated file upload..."],
        },
      ],
    };
    const summary = summarizeWpFingerprint(result);
    expect(summary).toContain("WordPress detected");
    expect(summary).toContain("contact-form-7");
    expect(summary).toContain("CVE-2020-35489");
  });
});
