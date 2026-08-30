---
title: "The Monitor Tool: Supervising Long-Running Processes"
description: "Design and rationale for a new structured monitor tool that lets the 0sec agent start, tail, wait on, and control long-running processes such as dev servers, scanners, fuzzers, and builds."
---

## Problem

0sec's agent can run commands, but it cannot *supervise* a process that
outlives a single tool call. Every execution primitive we ship today is
built around "run to completion within a timeout, then hand back the whole
output." That model breaks the moment the agent needs to:

- Stand up a **dev server / target under test** and then attack it (the
  server must stay up across many subsequent tool calls).
- Drive a **long scanner** — `nuclei`, `nmap`, `ffuf`, `gobuster`,
  `sqlmap` — that legitimately runs for minutes and emits findings
  incrementally.
- Run a **fuzzer** and watch for the first crash/finding marker, then stop
  it.
- Kick off a **build** or install step and continue working while it
  compiles, coming back only when it finishes (or fails).

Right now the agent fakes all of this with `bash` timeouts and shell
plumbing. This doc specifies a dedicated `monitor` tool that makes
long-running supervision a first-class, structured capability.

## The gap in the current tool surface

We audited every execution-capable tool in the engine. None of them
background a process and let the agent poll, tail, or wait on it.

- **`bash`** (`packages/core/src/agent/tools/system.ts:104`) runs a shell
  command with a **timeout only** — default 30s, max 120s
  (`system.ts:110`). It spawns the command in a **detached process group
  purely so the timeout can kill the whole tree**, not so it can be left
  running. There is no handle, no polling, no tail. When the call returns,
  the process is dead.
- **`run_command`** (registered at
  `packages/core/src/agent/tools/index.ts:79`, defined in `system.ts:78`)
  is the read-only analysis variant: a restricted command surface ("No
  shell operators like `;`, `&&`, `<`, `>`, `$`", `system.ts:80`) with the
  same run-to-completion-within-a-timeout contract. Also not a supervisor.
- **`pty_session`** (`index.ts:96`) is the closest existing primitive: a
  *persistent interactive terminal* with create / send / read / close /
  list operations. But it is **interactive-shell oriented** — it models a
  human at a TTY, not a managed daemon with readiness and lifecycle — and
  it is gated behind the `ptySession` feature flag, **default OFF**.
- **`python_exec`** (`index.ts:117`) is a persistent kernel, but it is
  **compute-only** (a Python REPL state), not a process supervisor, and is
  also **default OFF**.
- **`spawn_persistent_agent`** (`index.ts:88`) is an **agent** lifecycle —
  a long-lived *reasoning* worker — not an OS-process monitor.

So a background-run + poll/tail + wait-until primitive is **net-new**.
Nothing in the registry composes into it without gluing shell hacks
together inside `bash`.

## Prior art

### The model to follow — Oh My Pi's `hub` process family

Oh My Pi ships exactly the primitive we want, and its shape is worth
copying closely. See
[the `hub` tool docs](https://github.com/can1357/oh-my-pi/blob/main/docs/tools/hub.md).
The `hub` process family exposes:
`start`, `ps`, `logs`, `stop`, `restart`, `describe`, `send`, `wait`.

The standout primitive is the **ready-gate on `start`**. Instead of
returning as soon as the process is spawned, `start` accepts a
`ready` condition and returns *only once that condition is met*:

- `ready.log` — a **regex** matched against the process's output.
- `ready.port` — a TCP port (1–65535) that must accept a connection.
- `ready.host` — host for the port probe.
- `ready.timeout` — default 30s, capped at 1h.

If both `log` and `port` are supplied, the gate is an **AND**: the process
is "ready" only when the log line has appeared *and* the port is
accepting. This is the difference between "I launched a server" and "the
server is actually serving."

Its `logs` operation is equally well-shaped:

- `grep` — regex filter over the buffered output.
- `lines` — tail N lines.
- `follow` — stream until the log advances or the process exits.
- `cursor` — a **byte offset to resume from**, so repeated polls never
  re-emit output the agent has already seen. Each call returns a **new
  cursor**.
- `timeout` — default 30s, max 3600s.

`send` writes to a running process: `text` (to stdin), `keys` (named keys
like `ENTER` / `CTRL_C`), or a `signal`.

`wait` **races** three outcomes — process exit, an output-pattern regex
match, and a timeout — and also supports a **wait-for-all** mode across
several processes. Critically, `wait` must **track process identity across
auto-restart**: if a supervised process crashes and is restarted, a
pending `wait` on the *old* process must not be spuriously satisfied by
the *replacement*. Identity is per incarnation, not per name.

### The contrast — Claude Code's Monitor tool

Claude Code has a Monitor tool
([writeup](https://zenn.dev/tkou15/articles/claude-code-monitor)) that runs
a shell command in the background and **streams stdout as event
notifications**, with lines batched within a ~200ms window. Its parameters
are `command`, `description`, `timeout_ms` (default 300000, cap 3600000),
and `persistent`.

The instructive weakness: Monitor has **no structured readiness or wait
condition**. To express "wait until the server prints `Listening`" you
encode a `while` loop *inside the command string* — polling `curl` or
grepping a log in shell. That works, but it pushes the control logic into
a fragile, injection-prone shell one-liner that the agent has to author
correctly every time. Claude Code's background `Bash` (`run_in_background`)
is even thinner: detach and notify **once** on completion.

The lesson from both: streaming and backgrounding are necessary but not
sufficient. The **structured ready-gate and structured wait** are what turn
"a process is running" into "a condition the agent can reason about."

## Proposed spec

A single namespaced `monitor` tool with an `op` discriminator, mirroring
`hub` but tightened for a security tool. Operations: `start`, `logs`,
`wait`, `stop`, `restart`, `ps`, `send`.

### `start`

Launch and supervise a process, blocking until ready (or the ready-gate
times out).

| field | type | notes |
| --- | --- | --- |
| `name` | string, 1–48 chars | stable handle used by every other op |
| `application` | string | the executable — **not** a shell string |
| `args` | string[] | argv vector, passed directly to exec |
| `env` | object | extra environment variables |
| `cwd` | string | working directory |
| `ready.log` | regex | output line that marks readiness |
| `ready.port` | 1–65535 | TCP port that must accept |
| `ready.host` | string | host for the port probe |
| `ready.timeout_s` | number | default 30, cap 3600 |
| `restart` | enum | `no` \| `on-failure` \| `always` |

`start` blocks until the ready condition is satisfied. When both
`ready.log` and `ready.port` are given, semantics are **AND** — both must
hold. No `command` shell string is ever accepted (see rationale below).

### `logs`

Pull filtered, cursor-bounded output from a supervised process.

| field | type | notes |
| --- | --- | --- |
| `name` | string | which process |
| `grep` | regex | filter output lines |
| `tail` / `lines` | number | last N lines |
| `follow` | bool | stream until advancement or exit |
| `cursor` | number | byte offset to resume from (no re-emit) |
| `timeout_s` | number | default 30, cap 3600 |

Returns: filtered lines **plus a new cursor**.

### `wait`

Race process outcomes until one resolves.

| field | type | notes |
| --- | --- | --- |
| `name` / `names` | string / string[] | one or many processes |
| `for` | enum | `exit` \| `ready` |
| `pattern` | regex | output pattern to wait for |
| `timeout_s` | number | cap 3600 |
| `mode` | enum | `any` \| `all` |

`wait` resolves on the first of: matching process **exit**, `pattern`
match in output, or `timeout`. `mode: all` requires every named process to
resolve. Process identity is tracked per incarnation, so an auto-restart
never spuriously satisfies a `wait` bound to the crashed process.

### `send`

| field | type | notes |
| --- | --- | --- |
| `name` | string | which process |
| `text` | string | write to stdin |
| `keys` | string[] | named keys: `ENTER`, `CTRL_C`, … |
| `signal` | string | POSIX signal |

### `stop` / `restart` / `ps`

`stop` terminates (graceful signal, then kill). `restart` cycles a
process, preserving its name and config. `ps` lists supervised processes
with state, pid/incarnation, uptime, and last exit code.

## How it reports back to the model

Reporting is where a security-tool monitor should differ from a generic
one. The output has to be **compact, cursor-bounded, and signal-first**.

- **`start`** returns a compact **readiness verdict**:
  `{ status: ready | timeout | exited, elapsed, matched }` where `matched`
  is the log line and/or the port that satisfied the gate. On `exited` it
  includes the exit code — a server that dies during boot is a common and
  important case.
- **`logs` / `wait`** return **only** the filtered, cursor-bounded output
  plus a structured status:
  `{ status, matched_pattern, cursor, exit_code }`. Output is truncated to
  a **token budget (~25K)** with an explicit `"more at cursor: N"` marker
  so the agent can page rather than blow its context on a chatty scanner.
- If streaming (`follow`), lines are **event-batched (~200ms)** — the same
  batching window Claude Code's Monitor uses — so the agent isn't
  interrupted per line.
- **Security-specific reporting rules:**
  - Surface the **matched ready-regex line / found marker verbatim**. For a
    scanner, the line that matched is very often *the finding itself*
    (`[high] SQL injection at …`), so it must not be summarized away.
  - **Always return the exit code.** A non-zero exit from `nuclei`,
    `nmap`, or a fuzzer is signal, not noise — it distinguishes "scan
    completed clean" from "scan crashed / target killed the connection."

## Rationale

### Why a structured ready-gate beats a bash `while` loop

Encoding readiness as a shell loop (`until curl -s localhost:8080; do
sleep 1; done`) has four failure modes that a structured gate eliminates:

1. **Correctness is the model's problem, every time.** The agent has to
   re-author the polling logic — the right endpoint, the right sleep, the
   right exit condition — on each launch. A structured `ready` object is
   declarative and validated once.
2. **No composite conditions.** "Log says ready AND port is open" is
   awkward in shell but a one-line AND in the gate. Servers routinely
   print "listening" *before* the socket is actually accepting; the AND is
   what closes that race.
3. **No clean verdict.** A `while` loop that times out just... stops. The
   agent gets ambiguous output and has to infer what happened. The gate
   returns a discrete `ready | timeout | exited` with the matched
   evidence.
4. **The "server died during boot" case is invisible** to a naive poll
   loop — it keeps polling a dead pid until timeout. The gate watches
   process exit *and* the readiness condition together and reports
   `exited` with the code immediately.

This is the same design instinct behind the engine's kernel-verify loop:
prefer a **validated, structured contract** over trusting free-form model
output to get the plumbing right (see `packages/core/src/agent/CLAUDE.md`,
"Structured output — validate every submission").

### Why `args[]` (no shell) matters for a security tool

`start` deliberately takes `application` + `args[]` and **refuses a shell
command string**. This is not ergonomics — it's a security boundary:

- **No shell injection surface.** The agent is often building command
  lines from *attacker-influenced data* it just scraped off a target — a
  discovered hostname, a reflected parameter, a filename from a directory
  listing. If any of that flows into a shell string, a `; rm -rf` or
  `$(…)` in the target's response becomes command execution on *our*
  host. An argv vector is passed straight to `exec` with no shell
  interpretation, so a malicious value is just an inert argument.
- **Auditability.** `{ application: "nuclei", args: ["-u", url, "-t",
  tpl] }` is trivially inspectable, allowlistable, and loggable per token.
  A shell string is opaque until parsed.
- **Consistency with the existing posture.** `run_command` already bans
  shell operators for exactly this reason (`system.ts:80`). The monitor
  should be *stricter* than `bash`, not looser, because it runs things that
  live longer and touch the network.

### How it composes with the rest of the engine

- **`spawn_persistent_agent`** is the reasoning half; `monitor` is the
  process half. The intended pattern: a persistent agent owns a workflow
  ("attack this app"), uses `monitor.start` to bring the target up with a
  ready-gate, then uses `monitor.logs`/`wait` to observe it while it
  attacks — the process outlives any single agent turn, which is precisely
  what `bash` cannot do.
- **The existing scanner wrappers** (`tools/scanner.ts`, `recon.ts`,
  `detections.ts`) are run-to-completion abstractions. `monitor` is the
  substrate for the *long-tail* cases they can't cover: a `ffuf`/`nuclei`
  run the agent wants to watch incrementally and cut short on first
  finding, or a fuzzer left running while other work proceeds. Over time
  the noisier wrappers could be re-expressed on top of `monitor` rather
  than each re-implementing timeout/tail logic.
- **`pty_session`** stays the tool for genuinely *interactive* TTY work
  (a `msfconsole`, an SSH session, anything that needs a real terminal).
  `monitor` is for **managed daemons and batch jobs** where readiness and
  exit codes matter more than terminal semantics. They are complementary,
  not overlapping.

## Integration notes

- **Zod-validate then reject.** 0sec tools validate their payload against
  an explicit Zod schema and **reject on mismatch before any side
  effect** — `kernel_run` is the reference implementation
  (`packages/core/src/agent/tools/kernel-run.ts`; see
  `kernelRunArgsSchema` / `validateKernelRunArgs`). The `monitor` schema
  must be the single source of truth for its payload: bound `name`
  (1–48), enum `op`/`restart`/`for`/`mode`, port range 1–65535, and the
  `timeout_s` caps (30 default / 3600 max). `.strip()` unknown top-level
  keys — in particular, reject any `command`/`shell` key so a model can't
  smuggle a shell string past the `args[]` contract. A rejection should be
  fed back as an `is_error` tool_result so the model self-corrects,
  matching the kernel-run pattern.
- **Registration.** Add `"monitor"` to `TOOL_REGISTRY_ORDER`
  (`packages/core/src/agent/tools/index.ts:66`) and a corresponding
  `DOMAIN_DEFINITIONS` entry, then a dispatch route in
  `packages/core/src/agent/tools/dispatch.ts` (per-tool handler, not a
  shared chokepoint — see the dispatch-table note at `dispatch.ts:2`).
  Implementation belongs in a new `tools/monitor.ts` alongside the other
  execution tools.
- **Gate it like `bash`.** `monitor` is network- and exec-capable — it
  spawns arbitrary processes that bind ports and reach the network — so it
  must sit behind the **same role/permission gating and feature flagging
  as `bash`/`run_command`**, not be enabled for read-only audit roles.
  Given the persistence and network reach, defaulting the flag **OFF**
  (as `pty_session` and `python_exec` are) is the conservative starting
  point.
- **Lifecycle hygiene.** Supervised processes must be tracked in a
  registry that is torn down on scan completion / agent shutdown, so a
  crashed or forgotten dev server never leaks past the run. Enforce a cap
  on concurrent supervised processes.

## Decision

Build a single namespaced `monitor` tool with ops
`start / logs / wait / stop / restart / ps / send`, modeled on Oh My Pi's
`hub` family, with three deliberate tightenings for a security agent:

1. **`args[]`, never a shell string**, to remove the injection surface
   when launching processes from attacker-influenced data.
2. **A structured, validated ready-gate** (log-regex AND TCP port, capped
   timeout) instead of agent-authored shell poll loops.
3. **Signal-first, cursor-bounded reporting** — verbatim matched lines,
   always-present exit codes, ~25K-token truncation with "more at cursor."

Register it in `TOOL_REGISTRY_ORDER` + `dispatch.ts`, Zod-validate the
payload with reject-on-mismatch (kernel-run pattern), and gate it like
`bash` with the feature flag defaulting OFF.

## Open questions

- **Log retention & spill-to-disk.** How much per-process output do we
  buffer in memory before spilling to a file, and where does that file
  live relative to the scan workspace? Chatty fuzzers can produce GBs.
- **Concurrent-process cap.** What is the right ceiling, and is it
  per-scan or global? A fan-out of `spawn_agents` could each want their
  own supervised target.
- **Restart policy vs. `wait` identity semantics.** With
  `restart: always`, a `wait for: exit` may never resolve. Do we surface
  incarnation count, and does `wait` observe restarts as events?
- **Port-probe scope.** Do we allow `ready.host` to be non-loopback (probe
  a remote target's port), or restrict readiness probing to
  localhost-bound processes we launched?
- **Interaction with `bash` timeouts.** Should `bash` gain a "hand this
  off to monitor" escape hatch when a command exceeds its 120s cap
  (`system.ts:110`), or do we keep the two surfaces strictly separate?
- **Output redaction.** Since matched lines are surfaced verbatim and may
  contain secrets the scanner extracted, do we apply the engine's
  existing secret-scrubbing before returning `logs`/`wait` output?
