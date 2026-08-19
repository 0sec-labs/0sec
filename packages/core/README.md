# @pwnkit/core

Engine package for pwnkit: tool definitions, agent loop, playbooks, runtimes,
audit pipeline, and triage filters. Consumed by `@pwnkit/cli`.

## Feature flags

Feature flags are declared in `src/agent/features.ts`. Each flag maps to a
`PWNKIT_FEATURE_<NAME>` environment variable. The `@pwnkit/cli` `scan` command
also accepts a `--features` flag that sets those env vars automatically:

```bash
pnpm pwnkit scan --target https://example.com --features wp_fingerprint
pnpm pwnkit scan --target https://example.com --features wp_fingerprint,web_search
```

Any token passed to `--features` is upcased, non-alphanumeric chars are
replaced with `_`, and the result is set as `PWNKIT_FEATURE_<TOKEN>=1`. For
most flags the value is captured at module-import time — setting env vars in
your shell is the most reliable approach. Flags that are declared as getters
(e.g. `wpFingerprint`) re-read the env at access time and therefore honour
`--features` even though the flag is applied inside the command action.

## Playbooks

Playbooks live in `src/agent/playbooks.ts`. Each playbook is a string keyed by
vulnerability type (`sqli`, `ssti`, `idor`, `xss`, `cve_exploitation`, …) plus
a set of regex `INDICATORS` that pattern-match against recent tool-result text.
When `PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS=1`, the native agent loop matches
indicators at ~30% of the turn budget and injects the top 3 matching playbooks
as a user message.

## WordPress fingerprinter (`wp_fingerprint`)

Opt-in tool exposed behind the `wp_fingerprint` feature flag. Implemented in
`src/agent/wp-fingerprint.ts`.

### What it does

1. **Detects WordPress** by fetching `wp-login.php`, `wp-admin/`, `readme.html`,
   `wp-includes/version.php`, `feed/`, and `wp-json/`. Extracts the core
   version from `wp-includes/version.php` (authoritative), `readme.html`, or
   the RSS feed's `<generator>` tag.
2. **Enumerates plugins** from four independent sources in parallel:
   - Rendered HTML on `/`, `/?p=1`, `/?page_id=1` (any `/wp-content/plugins/<slug>/…` URL in asset tags)
   - `/wp-json/` namespace index and `/wp-json/wp/v2/posts` rendered content
   - `/wp-content/plugins/` Apache/nginx autoindex listings
3. **Proactively probes high-value vulnerable plugin slugs** from the local
   catalog, WPScan-style, by checking `/wp-content/plugins/<slug>/readme.txt`
   even when the plugin is not linked in rendered HTML.
4. **Enumerates themes** the same way.
5. **Probes versions** by fetching each plugin's `readme.txt` (parsing the
   `Stable tag:` header) and each theme's `style.css` (parsing the `Version:`
   header). Both are WordPress conventions and ship with nearly every
   plugin/theme on wordpress.org.
6. **Matches CVEs** using a built-in high-impact WordPress plugin vulnerability
   catalog, queries the no-key WPVulnerability API for current plugin/theme
   advisories, optionally queries WPScan's API when `WPSCAN_API_TOKEN` (or
   `PWNKIT_WPSCAN_API_TOKEN`) is set, then optionally POSTs each `(slug, version)`
   pair to `https://api.osv.dev/v1/query` for broader OSV coverage.
7. **Returns structured findings** — a list of `(kind, slug, version, cves, exploit_hints)`
   tuples plus a human-readable summary the agent can act on.

### CLI usage

```bash
pnpm pwnkit scan \
  --target https://wordpress-target.example.com \
  --features wp_fingerprint
```

### Tool invocation (from the agent)

```json
{
  "name": "wp_fingerprint",
  "arguments": {
    "max_plugin_probes": 40,
    "max_vulnerable_plugin_probes": 40,
    "wpscan_api_token": "<optional>",
    "skip_osv": false
  }
}
```

### Sample output (structured)

```json
{
  "summary": "WordPress detected — core v6.1. Evidence: wp-login.php, readme.html\nPlugins: 2, Themes: 1\n\nCVE hits (1):\n  - [plugin] contact-form-7@5.3.1: CVE-2020-35489\n      hint: Try unauthenticated file upload against /wp-content/plugins/contact-form-7/ endpoints — check the CVE advisory for the exact path.",
  "result": {
    "isWordPress": true,
    "evidence": ["wp-login.php", "readme.html"],
    "coreVersion": "6.1",
    "plugins": [
      { "slug": "contact-form-7", "version": "5.3.1", "source": "readme" },
      { "slug": "woocommerce", "version": "4.0.0", "source": "readme" }
    ],
    "themes": [
      { "slug": "twentytwentyone", "version": "1.7.1", "source": "style_css" }
    ],
    "findings": [
      {
        "kind": "plugin",
        "slug": "contact-form-7",
        "version": "5.3.1",
        "source": "readme",
        "cves": [
          {
            "id": "CVE-2020-35489",
            "aliases": ["GHSA-..."],
            "severity": "critical",
            "summary": "Unrestricted file upload in Contact Form 7 < 5.3.2",
            "url": "https://osv.dev/vulnerability/CVE-2020-35489"
          }
        ],
        "exploitHints": [
          "Try unauthenticated file upload against /wp-content/plugins/contact-form-7/ endpoints — check the CVE advisory for the exact path."
        ]
      }
    ]
  }
}
```

### Tests

```bash
pnpm --filter @pwnkit/core test -- wp-fingerprint
```

The test suite (`src/agent/wp-fingerprint.test.ts`) mocks `fetch` with an
in-memory route table and exercises: plugin slug extraction, `readme.txt`
version parsing, `style.css` version parsing, the full end-to-end
`runWpFingerprint` with `skipOsv: true`, and the negative case where no WP
endpoints respond. Tests never hit the network.

## Anti-honeypot flag-shape validator (`decoyDetection`)

Some CTF/benchmark targets plant a **decoy flag** as a honeypot — a fake
`FLAG{...}` string sitting in an obvious location (the first file a naive
LFI exploit will land on, the `.git/config` a lazy credential hunt will
open, etc.). A naive agent reads the decoy, sees a flag-shaped literal,
calls `done`, and silently fails. XBEN-079 (Poison Inclusion - Protected)
is the canonical example: the decoy is `FLAG{I'm_a_Script_Kiddie}`, the
real flag is `FLAG{7dda4e738d29a996f343a610}`.

The `decoyDetection` feature (default **ON**) scores every proposed flag's
*shape* before the `done` tool accepts it. Implementation:
`packages/core/src/agent/flag-validator.ts`.

Scoring rules (highest match wins, length penalties apply after):

| Inner content                          | Confidence |
| -------------------------------------- | ---------- |
| UUID4                                  | 0.95       |
| UUID / sha256 / hex ≥ 16 chars         | 0.9        |
| Hex 8–15 chars                         | 0.75       |
| Base64-ish alnum ≥ 16 chars            | 0.7        |
| Mixed alnum/`_`/`-` ≥ 12 chars         | 0.6        |
| Single token, no strong shape signal   | 0.45       |
| Multi-word sentence (spaces or prose)  | 0.2        |
| Alphabetic word chain joined by `_`    | 0.25       |
| Contains `DECOY`/`FAKE`/`HONEYPOT`/etc | 0.05       |
| Length < 8 or > 100                    | clamp 0.3  |
| No `FLAG{...}` wrapper                 | 0.1        |

When confidence is below 0.5, the `done` tool rejects the call **once**
with a hint that the flag looks like a decoy and the agent should keep
exploring. A **second** call with the same flag passes through — the
heuristic is a speed bump, not a hard wall, so an agent that legitimately
only found one candidate can still submit it.

The attack-role system prompt also gets a one-line warning: *"If you find
a flag-shaped string, do not immediately call `done`. Verify the shape
matches the suite's expected format (typically hex/uuid). Defenders
sometimes plant decoy flags in obvious locations to catch script kiddies."*

### Configuration

- Env var: `PWNKIT_FEATURE_DECOY_DETECTION=0` to disable.
- CLI flag: `pwnkit scan --no-decoy-detection <target>`.

### Tests

```bash
pnpm --filter @pwnkit/core test -- flag-validator
```

The test suite (`src/agent/flag-validator.test.ts`) covers the XBEN-079
decoy, UUID / sha256 / hex / short-hex good flags, sentence-style and
word-chain decoys, `DECOY`/`FAKE`/`HONEYPOT` markers, edge cases (empty,
no wrapper, too short, too long, expected-shape mismatch), and the full
`done`-tool integration path including the retry-to-override flow.

See GitHub issue #82 for the original report.
