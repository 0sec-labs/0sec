---
title: Console
description: The 0sec interactive chat console — talk to the engine, run tools, manage sessions, and navigate every surface from one terminal UI.
---

`0sec console` is a single conversational cockpit where an operator talks to the
engine and invokes every 0sec tool (recon, web pentest, source/package scan,
variant hunt, verify, patch-gen) from one prompt.

Two front-ends share the same engine session (`createConsoleSession` from
`@0sec/core`):

| Front-end | Requirement | Features |
|-----------|-------------|----------|
| **TUI** (full) | [Bun](https://bun.sh) runtime + TTY (`stdout.isTTY && stdin.isTTY`) | All slash commands, visual transcript, sidebars, approval prompts, scope extensions, subagent inspection, command palette, theme picker |
| **readline** (Node) | Node.js 24+, `--scope <file>` required | Text-only REPL; limited command subset; scope extensions and Co-pilot tool approvals always denied |

The runtime auto-detects Bun and uses the TUI when both Bun and a TTY are
available, falling back to the readline console otherwise.

## Launch

```bash
# Interactive chat — requires a configured LLM provider
0sec console

# Start with an engagement target
0sec console --target https://example.com --scope ./scope.json

# Start with a role (tool set)
0sec console --role discovery --target https://example.com --scope ./scope.json

# Start in YOLO mode (no per-action prompts, requires configured scope)
0sec console --yolo --scope ./scope.json --target https://example.com

# Resume the most recent saved session
0sec console --continue

# Open a session picker to resume a specific one
0sec console --resume

# One-shot: run a prompt and exit (non-interactive)
0sec console --print "Summarise findings" --continue

# Resume a specific session by id (or unique prefix)
0sec console --resume a1b2c3d4
```

### Key flags

| Flag | Description | Default |
|------|-------------|---------|
| `--target <url>` | Engagement target the tools operate against | (optional; set in chat) |
| `--scope <file>` | Initial authorization [scope file](/scope/); required under Node | (none) |
| `--role <role>` | Tool set: `audit`, `review`, `discovery`, `attack`, `verify` | `audit` |
| `--mode <mode>` | Autonomy mode: `standard`, `recon`, `copilot`, `yolo` | `standard` |
| `--yolo` | Shortcut for `--mode yolo` | — |
| `--model <id>` | Override the LLM model ID | provider default |
| `--max-tool-calls <n>` | Safety cap on tool-call rounds per operator message | `20` |
| `--allow-scanners` | Expose scanner wrappers (sqlmap, nikto, …) | off |
| `--finding <id>` | Focus the chat on one persisted finding | (none) |
| `--finding-intent <intent>` | Finding workflow: `investigate`, `verify`, `draft_fix` | (none) |
| `--db-path <path>` | Database path containing the finding | `~/.0sec/0sec.db` |
| `--resume [id]` | Reopen a saved session; omitting id opens a picker | (none) |
| `--continue` | Reopen the most recent session, no picker | (none) |
| `--print [prompt]` | One-shot non-interactive; reads from argument or piped stdin | (none) |

A [`--scope` file](/scope/) is required for the Node readline fallback. Under
the Bun TUI it is optional — the TUI can request session-only scope extensions
interactively. YOLO mode requires a configured scope with at least one
`in_scope` entry regardless of runtime.

### Roles

`--role` selects the tool group exposed to the session:

| Role | Tools |
|------|-------|
| `audit` | Full tool registry (default) |
| `review` | Source-code review tools |
| `discovery` | Reconnaissance and enumeration |
| `attack` | Offensive/exploit tools |
| `verify` | Verification and patch validation |

### Autonomy modes

Cycle the mode with **Shift+Tab** in the TUI, or the `/mode` command.

| Mode | Behavior |
|------|----------|
| **Standard** | Runs automatically inside scope; can request a narrow session-only scope extension. |
| **Recon** | Passive, read-only reconnaissance only. Effectful tools are refused. |
| **Co-pilot** | Adds approval for every non-read-only tool. |
| **YOLO** | Runs only inside an explicitly configured scope. Never requests scope extensions. |

The readline fallback allows mode selection including Co-pilot and YOLO, but
Co-pilot tool approvals always return denied — there is no approval surface in
the text REPL. The TUI is required for interactive approval.

### Supported runtimes

The console auto-detects available runtimes. The runtime is determined by
[`0SEC_RUNTIME`](/configuration/) or the model ID matching a provider.

- **auto** — runtime probe, picks the first available
- **api** — direct API access
- **claude** — Claude Code CLI
- **codex** — ChatGPT Codex
- **gemini** — Gemini CLI

## First interaction

When the TUI launches you see:

- The **home screen** with the 0sec brand mark, an engagement panel, and a composer
  (text input area) centred on the screen.
- A **status bar** at the bottom showing the active model, mode, working directory,
  and cost/token counters (when enabled).
- A **header** row showing `0sec`, the engagement target, and an optional objective.

Type a message and press **Enter** to send it to the engine. The engine streams
its response token-by-token into the transcript. Tool calls appear as bordered
cards showing the command or edit, its output, and the exit code (controlled by
the `richToolCards` setting).

The transcript is auto-scrolled to the newest content. **PageUp** / **PageDown**
(or **Ctrl+Up** / **Ctrl+Down**) scroll through history.

## Screens

| Screen | Command | Description |
|--------|---------|-------------|
| Chat | `/chat` | Main conversation transcript and composer |
| Launcher | `/launcher`, `/run`, `/home` | Engagement control pane (start new scans, browse sessions) |
| Operations | `/ops`, `/runs` | Active and recent operation status |
| Doctor | `/doctor` | Runtime and configuration diagnostics |
| History | `/history` | Scan history from the database (completed scans, not chat sessions) |
| Findings | `/findings`, `/finds` | Session finding list with filtering |
| Finding detail | `/finding`, `/finding-detail` | Full detail on one finding |
| Replay | `/replay` | Event-level turn replay for a completed scan |
| Settings | `/settings`, `/config`, `/prefs` | Console display settings (persist across sessions) |
| Theme | `/theme`, `/themes` | Colour theme live preview |
| Model | `/model`, `/models` | Switch the active LLM model mid-session |
| Resume | `/resume`, `/sessions` | Saved chat-session list browser |
| Herd | `/herd`, `/workers` | Active subagent worker overview |
| Market | `/market`, `/marketplace` | Extension marketplace |
| Connect | `/connect`, `/login`, `/auth` | Provider credential entry |
| Usage | `/usage`, `/cost`, `/tokens` | Token, cost, and context-window usage for this chat session |
| Provider | `/providers` | Provider connection and OAuth pane |
| Scope | `/scope` | Current engagement scope view |
| Back | `/back` | Navigate to the previous screen |

### Slash commands

Every command is available as `/command` in the composer. Type `/` to open
the command menu. The readline console supports a subset (noted below).

| Command | Aliases | Category | Readline? |
|---------|---------|----------|-----------|
| `/help` | `/?`, `/commands` | info | ✓ |
| `/capabilities` | `/caps` | info | — |
| `/status` | — | info | ✓ |
| `/tools` | — | info | ✓ |
| `/agents` | — | info | — |
| `/clear` | `/new` | session | ✓ |
| `/history` | — | session | — |
| `/transcript` | `/review` | session | — |
| `/findings` | `/finds` | session | — |
| `/finding` | `/finding-detail` | session | — |
| `/replay` | — | session | — |
| `/resume` | `/sessions` | session | — |
| `/explain` | `/eli5` | session | — |
| `/mode` | — | mode | ✓ |
| `/model` | `/models` | mode | — |
| `/chat` | — | navigation | — |
| `/launcher` | `/run`, `/home` | navigation | — |
| `/ops` | `/runs` | navigation | — |
| `/herd` | `/workers` | navigation | — |
| `/market` | `/marketplace` | navigation | — |
| `/connect` | `/login`, `/auth` | navigation | — |
| `/usage` | `/cost`, `/tokens` | navigation | — |
| `/back` | — | navigation | — |
| `/scope` | — | navigation | — |
| `/exit` | `/quit` | system | ✓ |
| `/feedback` | — | system | — |
| `/settings` | `/config`, `/prefs` | system | — |
| `/theme` | `/themes` | system | — |
| `/doctor` | — | system | — |
| `/providers` | — | system | — |

### Command palette

Open with **Ctrl+P** (or **Ctrl+K**) from any screen. Type to filter commands;
each entry shows its title, keybinding or category, and description. Press
**Enter** to run.

The palette is available on every screen. On the home screen it lists workspace
commands and navigation destinations; on the chat screen it lists session
actions, settings toggles, and screen switches.

## Keyboard shortcuts

All shortcuts apply in the main Chat screen unless otherwise noted.

### Global exit

| Shortcut | Context | Action |
|----------|---------|--------|
| **Ctrl+C** (once) | Chat screen | Shows exit confirmation with running subagent count |
| **Ctrl+C** (twice) | Chat screen | Quits |
| **Ctrl+C** | Any modal/overlay | Exits (declines pending action, releases caller) |
| **q** | Screens without composer | Quit (Run.tsx screens: Findings, History, Operations, …) |

### Navigation and overlays

| Shortcut | Action |
|----------|--------|
| **Ctrl+P** / **Ctrl+K** | Open command palette (all screens) |
| **Ctrl+O** | Open transcript review overlay (scrollable full session) |
| **Ctrl+R** | Toggle collapsed/expanded tool call detail across the entire transcript |
| **Esc** | Clear composer / close overlay / go back / interrupt running turn |
| **Esc** (with no overlay or draft) | Stop a running turn, or navigate back |

### Composer

| Shortcut | Action |
|----------|--------|
| **Enter** | Send message / execute command |
| **Shift+Enter** | Insert newline |
| **Esc** | Cancel draft / close command menu |
| **Up** | Recall previous submission (readline history) |
| **Down** | Walk history forward / enter subagent list |
| **Ctrl+U** | Delete to start of line |
| **Ctrl+W** | Delete previous word |
| **Alt+Backspace** / **Ctrl+Backspace** | Delete previous word |
| **Tab** | Auto-complete slash command |
| **Ctrl+Y** | Pull last queued message back into composer for editing |

### Transcript

| Shortcut | Action |
|----------|--------|
| **PageUp** / **Ctrl+Up** | Scroll transcript up (half page) |
| **PageDown** / **Ctrl+Down** | Scroll transcript down (half page) |
| **Ctrl+Home** | Scroll to transcript start (transcript review only) |
| **Ctrl+End** | Scroll to transcript end (transcript review only) |

### Sidebars and mode

| Shortcut | Action |
|----------|--------|
| **Ctrl+B** | Toggle left sidebar (recent chat sessions + findings) |
| **Ctrl+L** | Toggle right sidebar (active agents + context strip) |
| **Shift+Tab** | Cycle autonomy mode |

### Approval and picker modals

| Shortcut | Action |
|----------|--------|
| **↑ / ↓** | Move selection |
| **Enter** | Confirm selection / approve |
| **Esc** | Cancel / decline |
| **Space** | Toggle option (multi-select) |
| **Backspace** | Remove last character (filter/input field) |
| **Type** | Filter items (in picker) / Enter text (in free-text field) |

### Subagent focus

| Shortcut | Action |
|----------|--------|
| **Down** (idle composer) | Enter subagent list |
| **↑ / ↓** (in list) | Navigate subagent list |
| **Enter** (on agent) | Drill into focused subagent |
| **Esc / Left** (focused) | Return from subagent focus |
| **PageUp / PageDown** | Scroll subagent activity log |

### Transcript review overlay (Ctrl+O)

| Shortcut | Action |
|----------|--------|
| **PageUp** / **Ctrl+Up** | Scroll up |
| **PageDown** / **Ctrl+Down** | Scroll down |
| **Ctrl+Home** | Scroll to start |
| **Ctrl+End** | Scroll to end |
| **Ctrl+O** / **Esc** | Close review |

## Modes, approvals, and scope

When a tool needs operator approval that exceeds the current mode's permissions,
a modal prompt appears showing the tool name, arguments, safety tier, and
context-specific actions.

### Scope request (Standard mode)

The engine may propose adding hosts to the session scope:

- **"Approve for this session"** — the exact hosts are added for this session only.
  Existing deny rules in the configured [scope file](/scope/) still take precedence.
- **"Reject"** — the tool does not run.

### Filesystem access request

A source-audit tool may request access to a local directory:

- **"Approve this directory"** — grants this subtree for the session only.
- **"Decline"** — tool does not run.

Nothing is persisted to disk.

### Safety gate override

When a source-audit tool is blocked by a safety gate:

- **"Enable for this session"** — lifts the restriction for the session;
  Standard or Co-pilot gates still apply.
- **"Keep disabled"** — tool stays blocked.

### Tool approval (Co-pilot mode)

Each non-read-only tool call shows:

- **"Approve this call"** — runs once; the next call asks again.
- **"Reject"** — the model continues without it.

### Operator question (`ask_operator`)

The engine may present a structured question (multiple choice, free text, or
both). This modal authorizes nothing — Esc resolves `null` (tool renders as
"dismissed"), Enter confirms the collected answer.

## Capabilities

The capability registry (`/capabilities` or `/caps`) lists every primary surface
organised by safety tier:

| Tier | Meaning |
|------|---------|
| **automatic** | Runs without operator confirmation |
| **operator-confirmed** | Requires approval per action (based on mode) |
| **blocked** | Disabled for the session (can be lifted per-session) |

Categories: engagement, findings, verification, connect, settings, evolution, automation.

## Sessions, resume, and non-interactive mode

### Session persistence

Every conversation is saved to `~/.0sec/console-sessions/<id>.json` with
owner-only permissions (`0o600`). Each saved session includes the full message
transcript (model and operator turns), the model and target used, a preview
(first message, truncated to 120 chars), an optional summary, timestamp, and
turn count.

### Resume

```bash
# Open the session picker
0sec console --resume

# Resume a specific session by id (or unique prefix)
0sec console --resume a1b2c3d4

# Resume the most recent session
0sec console --continue
```

In the TUI, `/resume` or `/sessions` opens the same picker, showing preview
text, relative age (`12s`, `5m`, `3h`, `2d`, `6w`), model, and turn count for
each saved session.

### Session management

| Command | Action |
|---------|--------|
| `/clear` / `/new` | Clear the current conversation in memory (keeps session running) |
| `/resume` | Browse saved sessions and pick one to resume |
| `/history` | Review scan history from the database |

### Pruning

The session store keeps the newest 20 sessions by default. Older sessions are
removed on the next session write. The keep count is a compile-time constant
(`DEFAULT_PRUNE_KEEP = 20`) — there is no env-var override.

### Non-interactive mode (`--print`)

```bash
# Inline prompt
0sec console --print "Check the target for CORS misconfiguration" --continue

# Piped prompt — reads from stdin
echo "Summarise the findings" | 0sec console --print --continue
```

`--print` runs one prompt through the engine and exits. Engine responses stream
to stdout as text tokens. Combine with `--continue` or `--resume <id>` to query
a saved session's context without the TUI.

## Transcript vs replay

The console distinguishes two views into past data:

| Aspect | **Transcript** | **Replay** |
|--------|----------------|------------|
| Scope | Current session's conversation turns | Any persisted scan (by scan ID or database) |
| Content | Operator + model turns, tool calls, outcomes | Event-level turn timeline: stages, tool calls, model output |
| Access | `/transcript` (Ctrl+O) | `/replay` |
| Data source | Console session store (`~/.0sec/console-sessions/`) | Scan database (`--db-path` or `~/.0sec/0sec.db`) |
| Use case | Review what was discussed in this chat | Audit every action a completed scan took |

The **transcript review** (Ctrl+O) is a scrollable, virtualised rendering of
the current conversation.

The **replay screen** (`/replay`) loads a completed scan's recorded events.
Browse scan runs, select one, and step through its events.

## Feedback and secrets

### Local feedback

`/feedback <message>` appends a Markdown entry with timestamp, version, model,
and mode metadata to `~/.0sec/feedback.md`. This file is yours — never sent
anywhere without explicit action.

### Staged submission

```text
/feedback submit This scan found an interesting edge case
/feedback send       ← transmits the staged feedback over HTTPS
/feedback cancel     ← clears the staged message without sending
```

- `/feedback submit <message>` writes the entry to the local file AND shows a
  preview of what would be sent (target URL, body, headers with auth redacted,
  any warnings).
- `/feedback send` transmits the most recently submitted message to the
  configured endpoint.
- `/feedback cancel` clears the staged message.

### Transmission

Submission is disabled by any of: `0SEC_OFFLINE=1`, `0SEC_NO_TELEMETRY=1`,
`DO_NOT_TRACK=1`. Transmission goes to the URL in `0SEC_FEEDBACK_URL`, or to
the 0cloud feedback endpoint (`/api/cli-feedback`) when the CLI is
authenticated with a compatible configured 0cloud deployment.

The feedback payload body contains: `message`, `timestamp`, `version`, `model`,
`mode`. The body is capped at 64 KB; request timeout is 5 seconds. Failure to
submit never blocks the session.

### Secret scanning

When entering an API key through the TUI's credential prompt (`/connect` or
`/providers`), the entered value is stored directly to
`~/.0sec/credentials.json`. The store's `redactSecret` function produces a
display form showing only a prefix and the last 4 characters (e.g.
`sk-ant-…a4f2`) — the full key is never echoed to the transcript.

The feedback system's `scanForSecrets` is a separate path that inspects
feedback messages for credential patterns before preview display. This does not
affect provider credential storage.

### Storable providers (API-key auth)

Credentials for these providers persist in `~/.0sec/credentials.json`:
DeepSeek, OpenRouter, Azure OpenAI, OpenAI, Z.ai GLM, Moonshot Kimi, Alibaba
Qwen, xAI Grok, OpenCode Zen. ChatGPT Codex uses OAuth and is not storable
through this path.

## Settings

Display settings are layered: **default** → **global** (`~/.0sec/tui-settings.json`)
→ **project** (`.0sec/tui-settings.json`). Use `/settings` in the TUI to toggle
them.

The full settings table lives in [Configuration](/configuration/). Key
console-specific controls include sidebar visibility (`showLeftSidebar`,
`showRightSidebar`), transcript density and style, theme, and cost display
toggles.

## TUI crash handling

If the TUI crashes, a crash panel shows the message and a short stack. Options:

| Action | Key |
|--------|-----|
| Restart | **R** (on the options panel) |
| Open crash feedback | **F** |
| Quit | **Q** |

Crash text is sanitised — credential-shaped substrings are redacted before they
reach the panel or any feedback file. The crash panel's feedback composer works
exactly like `/feedback`: local file by default, opt-in HTTPS transmission.

## Related

- [Commands reference](/commands/) — all CLI flags across every command
- [Configuration](/configuration/) — runtime, mode, and feature settings
- [API Keys](/api-keys/) — provider setup
- [Scope & Authorization](/scope/) — scope file format and matching
- [Getting Started](/getting-started/) — install and first scan