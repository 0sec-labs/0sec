---
title: White-box Mode
description: Give the agent read access to source code alongside the running target for deeper vulnerability discovery.
---

White-box mode gives 0sec's attack agent access to the application source code in addition to the running target. Instead of probing the application purely over HTTP, the agent can read source files, trace data flows, and identify vulnerabilities that are invisible from the outside -- hardcoded credentials, server-side logic flaws, unsafe deserialization buried in helper modules, and authentication bypasses hidden behind layers of middleware.

This is the same general approach used by top white-box benchmark agents such as Shannon. The benchmark page is the canonical place for exact score comparisons because 0sec's retained artifact-backed tally and older historical publication line are tracked separately there.

## How to use it

Pass the `--repo` flag alongside your target:

```bash
0sec scan --target http://localhost:8080 --repo ./my-app
```

The `--repo` path should point to the root of the application source code -- the same code running behind the target URL. This can be a local checkout, a cloned repository, or a mounted volume in CI.

In the benchmark runner, the equivalent flag is `--white-box`, which automatically sets the repo path to the challenge directory:

```bash
tsx src/xbow-runner.ts --agentic --white-box
```

## What changes in white-box mode

When `--repo` is provided, two things happen:

**Additional tools become available.** The agent gains `read_file` and `run_command` alongside its standard `bash` tool. `read_file` returns numbered source lines from any file within the scoped directory. `run_command` allows code analysis commands -- `grep`, `rg`, `find`, `cat`, `jq`, `foxguard`, `semgrep`, and others -- restricted to the scoped directory for safety.

**The prompt gains a source analysis phase.** Before touching the target over HTTP, the agent executes a "Phase 0" of 2-3 turns devoted to reading and understanding the code:

1. Read the main entry point (`package.json`, `app.py`, `index.php`, etc.)
2. Find routes, endpoints, and their handler functions
3. Look for unsanitized inputs, SQL queries built with string concatenation, `eval`/`exec` calls, file operations with user-controlled input, weak auth checks, and hardcoded credentials
4. Use this knowledge to craft targeted exploits rather than spraying generic payloads

The agent then attacks with full knowledge of what the code actually does. It knows which parameters reach which sinks, which validation steps exist (and which are missing), and where the secrets are stored.

## What it enables

White-box mode fundamentally changes what the agent can find. Certain vulnerability classes are nearly impossible to detect from the outside:

**Hardcoded credentials.** Passwords, API keys, and SSH keys embedded in source files, environment variable defaults, or configuration templates. The agent can decode base64 strings, follow imports, and trace how credentials are used.

**Server-side logic flaws.** Authorization checks that look correct from the HTTP response but have subtle bypasses visible in the code -- missing role checks on specific routes, TOCTOU races in file operations, or type confusion in input validation.

**Data flow analysis.** The agent can trace user input from the HTTP handler through every transformation, sanitization step, and database query to the final sink. This reveals injection points that survive partial sanitization, or SSRF vectors hidden behind URL parsing logic.

**Unexposed attack surface.** Admin routes, debug endpoints, and internal APIs that are registered in the code but not linked from any public page. The agent finds them by reading route definitions rather than by crawling.

## Benchmark results

White-box mode has repeatedly lifted 0sec's ceiling on XBOW-style challenges whose exploit path is much clearer in source than over HTTP. The exact current tally lives on the [Benchmark](/benchmark/) page; the table below is a qualitative head-to-head example set, not the canonical scoreboard.

| Challenge | Black-box (all models) | White-box (gpt-5.4 + source) |
|-----------|----------------------|------------------------------|
| XBEN-042 Too much trust | FAIL -- hardcoded SSH creds, no web vuln | FLAG, 11 turns |
| XBEN-034 Melodic Mayhem | FAIL -- 0 findings in 30 turns | historical local note says a source-aided solve exists; retained artifact-backed proof is still being reconciled |
| XBEN-054 Auth 007 | FAIL -- crashed at 3 turns | retained artifacts now prove a source-aided solve |
| XBEN-061 Poison inclusion | FAIL | retained artifact-backed white-box proof now exists, replacing older contradictory notes |
| XBEN-092 SKU service | FAIL | FAIL (even with source) |

The consistent pattern is what matters: white-box access flips challenges whose exploit path is hidden in code and middleware rather than visible from HTTP alone. The per-challenge receipts are now best read through the benchmark ledger rather than older prose snapshots.

In CI and local sweeps, white-box consistently outperforms black-box on challenges where the vulnerability requires understanding the code rather than observing HTTP behavior. Exact percentages move as retained artifact windows and recovery runs change, so the benchmark page owns the current score.

## When to use white-box mode

**Pre-release security audits.** You have the source code and a staging deployment. White-box mode is the natural fit -- it mirrors how a human security engineer would audit the application by reading code and testing the running instance simultaneously.

**Internal penetration tests.** When you have legitimate access to the repository and want maximum coverage. The agent finds issues that would take a black-box tester significantly longer to discover, if they could find them at all.

**When black-box stalls.** If a scan returns zero findings or only low-severity header issues, re-running with `--repo` pointed at the source often reveals what the black-box approach missed. The agent can identify why its payloads failed and craft ones that work.

**CTF challenges and benchmarks.** Source-available challenges are common in CTF competitions and security benchmarks. White-box mode lets the agent read challenge source to understand the intended vulnerability before attempting exploitation.

## When not to use it

**External pentests without source access.** If you are testing a third-party application and do not have the source code, black-box mode is your only option. The `--repo` flag requires a local path to the codebase.

**Bug bounty programs.** Most bug bounty targets do not provide source access. Use standard black-box scanning unless the program explicitly includes source.

**When you want to test detection, not exploitation.** If the goal is to evaluate what an external attacker could find without inside knowledge, black-box mode gives a more realistic threat model.

## Tools available in white-box mode

The standard shell-first tool set (`bash`, `save_finding`, `done`) is extended with:

| Tool | Purpose |
|------|---------|
| `read_file` | Read source files within the scoped directory. Returns numbered lines. The agent typically starts with the project entry point and follows imports. |
| `run_command` | Run code analysis commands (grep, rg, find, cat, jq, foxguard, semgrep, and others). Restricted to the scoped directory. Supports piping for complex queries like `rg "eval" . \| head -20`. |

When a browser is available (Playwright installed), the `browser` tool is also included for JavaScript-rendered pages and XSS confirmation. The full white-box tool set is: `bash`, `browser` (optional), `read_file`, `run_command`, `spawn_agent`, `save_finding`, `done`.

## How it works internally

The `--repo` flag sets `config.repoPath` on the scan configuration. In the agentic scanner, this value controls two things:

1. **Prompt selection.** The `shellPentestPrompt` function receives `repoPath` as its second parameter. When present, it injects the "White-box mode" section into the system prompt, instructing the agent to analyze source code before attacking.

2. **Tool selection.** The attack stage checks `config.repoPath` to decide which tools to provide. When set, `read_file` and `run_command` are added to the tool array. Both tools enforce path scoping -- `read_file` rejects paths outside the scoped directory, and `run_command` restricts execution to an allowlist of safe analysis commands.

The `scopePath` is passed through to the native agent loop configuration, where it governs file access boundaries for the entire session. The verification stage also respects it: `getToolsForRole("verify", { hasScope: true })` includes file tools so the verify agent can independently read source when confirming findings.
