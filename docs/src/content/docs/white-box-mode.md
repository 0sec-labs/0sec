---
title: White-box Mode
description: Give the agent read access to source code alongside the running target for deeper vulnerability discovery.
---

White-box mode gives the attack agent the application source alongside the
running target. Instead of probing purely over HTTP, the agent reads source,
traces data flows, and finds vulnerabilities invisible from the outside:
hardcoded credentials, server-side logic flaws, unsafe deserialization, and
auth bypasses hidden behind middleware.

## How to use it

Pass `--repo` alongside your target, pointing at the root of the source running
behind the URL (local checkout, clone, or mounted CI volume):

```bash
0sec scan --target http://localhost:8080 --repo ./my-app
```

In the benchmark runner, `--white-box` sets the repo path to the challenge
directory:

```bash
tsx src/xbow-runner.ts --agentic --white-box
```

## What changes

**Extra tools.** The agent gains `read_file` (numbered source lines, scoped to
the repo) and `run_command` (analysis commands — `grep`, `rg`, `find`, `cat`,
`jq`, `foxguard`, `semgrep`, restricted to the scoped directory).

**A source-analysis phase.** Before touching HTTP, the agent runs a "Phase 0"
(2–3 turns) to read the entry point, map routes to handlers, and hunt for
unsanitized inputs, string-concatenated SQL, `eval`/`exec`, unsafe file ops,
weak auth, and hardcoded secrets. It then attacks knowing which parameters reach
which sinks and which validation is missing.

## What it enables

- **Hardcoded credentials** — passwords, API keys, SSH keys in source, env
  defaults, or config templates.
- **Server-side logic flaws** — auth bypasses that look correct over HTTP but
  are visible in code (missing role checks, TOCTOU races, type confusion).
- **Data flow analysis** — trace user input through every transformation to the
  sink, revealing injection points that survive partial sanitization.
- **Unexposed attack surface** — admin routes, debug endpoints, and internal
  APIs registered in code but not linked anywhere public.

## Benchmark results

White-box helps most on challenges whose exploit path is clearer in source than
over HTTP (e.g. XBEN-042 "Too much trust" — hardcoded SSH creds with no web vuln
— flags in white-box, fails black-box). Some challenges still fail even with
source (XBEN-092). The [Benchmark](/benchmark/) page has the current
per-challenge scores.

## When to use it

- **Pre-release audits** — you have source and a staging deploy.
- **Internal pentests** — legitimate repo access, maximum coverage.
- **When black-box stalls** — re-run with `--repo` to see what HTTP-only missed.
- **CTFs / benchmarks** — source-available challenges.

Skip it when testing a third party without source, on most bug bounty targets,
or when you deliberately want the external-attacker threat model.

## Tool set

The standard shell-first set (`bash`, `save_finding`, `done`) is extended with
`read_file` and `run_command`. When Playwright is installed, `browser` is also
available. Full white-box set: `bash`, `browser` (optional), `read_file`,
`run_command`, `spawn_agent`, `save_finding`, `done`.

## Internals

`--repo` sets `config.repoPath`, which controls two things:

1. **Prompt.** `shellPentestPrompt` injects the white-box section when
   `repoPath` is present.
2. **Tools.** The attack stage adds `read_file` and `run_command`, both
   path-scoped. The verify stage also gets file tools
   (`getToolsForRole("verify", { hasScope: true })`) so it can read source when
   confirming findings.
