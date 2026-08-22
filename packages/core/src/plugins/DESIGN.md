# 0sec plugin system — design

Status: **stage 1 (manifest + capability model) implemented.** Loading,
isolation and dispatch are designed here but deferred. This document is the
authority on *why* the manifest looks the way it does; the code in
`manifest.ts` is the stage-1 slice.

---

## 1. What exists today (the three seams)

0sec has exactly one runtime-pluggable seam and two compile-time extension
points. Being honest about which is which is the whole reason the plugin system
is non-trivial.

### 1a. `EventSink` — the one runtime-pluggable seam

`packages/core/src/events/bus.ts` defines `interface EventSink { emit(type, payload): void }`
and a singleton `eventBus` with `subscribe(sink) → unsubscribe`. Sinks are added
at runtime, fan-out is defensive (a throwing sink is caught and logged to
stderr, never aborts a scan), and there are already two out-of-tree-shaped
consumers built on it:

- `CloudEventSink` (referenced in `bus.ts`) — opt-in cloud relay, OFF by default.
- `HerdrEventSink` in `packages/core/src/integrations/herdr.ts` — a passive,
  env-gated sink that reports agent state to the herdr workspace manager over a
  Unix socket. It is fail-soft and never prints.

This seam is **observe-only**. A sink receives events; it cannot originate a
tool call, cannot influence authorization, cannot return data to the agent. It
is the safe seam precisely because it has no authority. A plugin system that
only extended `EventSink` would be trivially safe and nearly useless for the
thing plugin authors actually want (new tools).

### 1b. The tool registry — compile-time

`packages/core/src/agent/tools/dispatch.ts` builds `TOOL_DISPATCH` by spreading
~14 per-domain `*Dispatch` maps (`reconDispatch`, `findingsDispatch`,
`systemDispatch`, …). Each maps a tool name → the *name of a private method on
`ToolExecutor`*. The header comment states the intent: adding a tool touches
only its domain module (its `*Dispatch` map + its `ToolDefinition`), never a
shared switch. Tool *definitions* (`ToolDefinition` in `agent/types.ts`: name,
description, `parameters`, `required`) live alongside, and `getToolsForRole`
(`agent/tools.ts` ~line 6163) assembles the per-role tool set from feature
flags.

This is elegant but **compile-time**: the handler bodies are private methods
compiled into `ToolExecutor`. There is no runtime registration path. A plugin
cannot add a method to a compiled class.

### 1c. The authorization gates — compile-time, and keyed on tool NAME

`packages/core/src/console/turn-engine.ts` holds three literal maps:

- `NETWORK_CAPABLE_TOOLS` (~line 480) — tools that perform engagement egress.
- `READ_ONLY_TOOLS` (~line 512) — tools that only read local state.
- `LOCAL_SCOPE_TOOLS` (~line 548) — tools whose handlers require a scoped local
  directory.

Four separate gates key their decisions on **membership in these maps by tool
name**:

- **scope-on-demand** (`maybeResolveScope`, ~line 748): only fires for
  `NETWORK_CAPABLE_TOOLS`; extracts URLs and forces scope approval.
- **yolo hard-deny** (~line 751 inside `maybeResolveScope`): a network-capable
  tool with no covering scope is denied outright in yolo mode.
- **local-filesystem gate** (`maybeResolveLocalScope`, ~line 874): only fires
  for `LOCAL_SCOPE_TOOLS`; asks the operator for a directory.
- **co-pilot approval** (`maybeApproveTool`, ~line 1007): in copilot mode,
  prompts before every non-`READ_ONLY_TOOLS` tool.

The critical property: **a tool absent from all three maps is treated as the
least-dangerous class** — not network-capable, no local scope needed, and (by
being outside `READ_ONLY_TOOLS` it still requires copilot approval, but) it
never triggers scope resolution and is never denied in yolo. It is
danger-by-omission-of-safety.

---

## 2. The gate-bypass problem (the spine of this design)

Because every gate is keyed on tool-name membership in maps that are hardcoded
to the built-ins, **a naive plugin system that simply registers a new tool name
bypasses every network and filesystem gate.** A plugin tool called
`acme_exfil` that is not in `NETWORK_CAPABLE_TOOLS` would:

- never trigger scope-on-demand — it can hit any host with no operator approval;
- never be denied in yolo mode — the hard-deny only checks network-capable
  tools;
- never trigger the local-filesystem gate — it can read outside the approved
  directory;

On a product whose entire purpose is *authorized* offensive testing, and which
(per its own docs) **does not sandbox target execution by default**, this is a
critical hole: a plugin becomes a way to run un-gated egress and filesystem
access under the operator's authority.

The naive-and-wrong designs, concretely:

1. **"Plugins declare tools; the engine gates the ones it knows."** — This is
   exactly the bypass. Unknown ⇒ ungated.
2. **"Plugins optionally declare capabilities."** — Optional means a plugin can
   omit them and land in the ungated class. Fail-open.
3. **"Plugins get their own lighter gate path."** — Two authorization paths is
   two things to keep in sync; the plugin path inevitably drifts laxer.

### The fix, enforced in stage 1

- Capability declaration is **mandatory and non-empty**
  (`validatePluginManifest` rejects missing/empty/`[]` capabilities). You
  cannot express "no capabilities."
- `gateFlagsFor` is the **single** translation from capabilities to the engine's
  three gate flags, and it is **conservative**: unknown or empty ⇒ most
  restrictive; `readOnly` is true only when *every* declared capability is a
  pure read. Proven by a power-set sweep test over all capabilities.
- The loader (stage 2) will feed those flags into the **same** three maps the
  built-ins use — one authorization path, not a parallel one. A plugin tool that
  declares `network` lands in `NETWORK_CAPABLE_TOOLS` and is gated identically
  to `http_request`.
- **Name collisions rejected**: a plugin tool may not take a reserved built-in
  name (`run_command`, `save_finding`, …), so it cannot shadow/redefine a gated
  tool. The caller supplies the reserved list (keys of `TOOL_DISPATCH` ∪ the
  gate maps).
- **Name charset constrained**: `^[a-z][a-z0-9_]*$`, ≤48 chars, no leading
  digit, and `__proto__`/`prototype`/`constructor` explicitly denied. Names
  reach the model prompt, dispatch/gate-map keys, and operator UI, so they must
  be safe as identifiers, safe as object keys (no prototype pollution), and free
  of unicode/homoglyph spoofing of a built-in.

### How capabilities map onto the existing gate maps

| capability          | → gate map(s)                       | effect                                   |
| ------------------- | ----------------------------------- | ---------------------------------------- |
| `network`           | `NETWORK_CAPABLE_TOOLS`             | scope-on-demand + yolo hard-deny         |
| `process-exec`      | `NETWORK_CAPABLE_TOOLS`             | same — a process can open any socket     |
| `filesystem-read`   | `LOCAL_SCOPE_TOOLS` (+ read-only)   | local-directory gate; copilot-exempt     |
| `filesystem-write`  | `LOCAL_SCOPE_TOOLS`                 | local-directory gate; NOT read-only      |
| `findings-write`    | (none of the three)                 | still copilot-gated; not read-only       |

`readOnly` (→ `READ_ONLY_TOOLS`, the copilot-approval exemption) is granted only
when the capability set is non-empty and consists solely of read capabilities
(today: exactly `["filesystem-read"]`). Everything else is effectful and stays
copilot-gated.

---

## 3. Loading and isolation options

The hard constraint: 0sec runs untrusted *target* code and does not sandbox by
default. A plugin author is **less** trusted than 0sec itself and **more**
trusted than a scan target — but a malicious or compromised plugin is a real
threat, and "we don't sandbox the target anyway" is not a reason to also not
contain the plugin. The isolation question is: *what does each option actually
contain?*

### Option A — in-process ESM `import()`

- **Mechanism**: dynamically import the plugin module; it registers tools whose
  handlers are plain functions running in the 0sec process.
- **Contains**: nothing. Full access to the process — env vars (API keys),
  `fs`, `net`, `child_process`, the event bus, other plugins' state, and it can
  monkey-patch the gate maps themselves. A capability declaration becomes a
  *promise*, not a *boundary*: the manifest says `filesystem-read` but the code
  can still open a socket.
- **Verdict**: simplest to build, unacceptable as the security story. The
  manifest gates the *agent's* view of the tool, but not the plugin code's
  actual authority. Acceptable only for first-party/vendored plugins the
  operator already trusts as much as core.

### Option B — subprocess speaking JSON over stdio (recommended)

- **Mechanism**: each plugin runs as a child process; core speaks a small
  newline-delimited JSON protocol (the herdr integration already demonstrates
  exactly this framing style) — `list_tools`, `invoke {tool, args}` →
  `{result | error}`. Handlers never run in-process.
- **Contains**: the plugin cannot touch core's memory, API keys, or the gate
  maps. What it *can* do to the OS is constrained by how we spawn it: a
  restricted env (no inherited secrets), and — where the platform offers it —
  OS-level confinement (seccomp/landlock on Linux, sandbox-exec on macOS, or a
  container) scoped to the declared capabilities. Even without OS confinement,
  the process boundary alone removes the in-process-authority problem: the
  plugin can only *ask* to do gated things via the protocol, and core applies
  the capability gates to those requests.
- **Cost**: an IPC protocol, lifecycle management, serialization of tool I/O,
  and per-call latency. Moderate.
- **Verdict**: the right default. It matches 0sec's existing fail-soft
  subprocess-over-stdio idiom, gives a real trust boundary, and keeps *one*
  authorization path: the child can request egress, but core's
  `NETWORK_CAPABLE_TOOLS` gate (fed by the manifest's `network` capability)
  still decides.

### Option C — WASM / worker sandbox

- **Mechanism**: compile plugin logic to WASM (or run in a locked-down Worker)
  with an explicit, capability-scoped host import surface — the plugin gets
  *only* the host functions its declared capabilities entitle it to.
- **Contains**: the most, in principle — deny-by-default host surface is the
  cleanest match to a capability manifest, and there is no ambient OS authority
  at all.
- **Cost**: highest. WASM cannot natively run the shell tools, native binaries,
  and existing JS security libraries plugin authors will want; a Worker shares
  the Node process and still needs care around what host functions are exposed.
  Toolchain and authoring friction are real.
- **Verdict**: the aspirational end-state for pure-logic plugins, overkill for
  stage 2. Revisit once there is demand for running genuinely hostile plugin
  logic with strong containment.

**Recommendation: B (subprocess + JSON/stdio), with A allowed only for
first-party vendored plugins the operator trusts as core.** B gives a real
boundary at moderate cost and preserves the single-authorization-path invariant
that stage 1 is built to protect. Note plainly: none of these options make an
*untrusted plugin* as safe as no plugin — they reduce, not eliminate, risk,
which is exactly why operator enablement (§4) is mandatory.

---

## 4. Trust and enablement

A plugin author can be assumed to be: someone who wrote code you are about to
run under your operator authority against a target you are authorized to test.
They **cannot** be assumed to be non-malicious, non-compromised, or correct
about their own capability declarations (which is why the manifest is *checked*,
and why isolation, not just declaration, matters).

Therefore a plugin is **inert until an operator explicitly enables it**, and
enablement is a deliberate, informed action:

- **Scope of enablement: per-project, with an opt-in per-user promotion.** The
  default is per-project (a plugin approved for one engagement is not silently
  active in another) because a plugin's blast radius is the target it runs
  against. A user may promote a plugin they trust to per-user (active by
  default across their projects) as an explicit, separate action.
- **Shown at approval time** (built directly from the validated manifest):
  the plugin `id`, `name`, `version`, and — the important part — a
  **capability summary aggregated across its tools**: "this plugin adds 3 tools;
  2 perform network egress, 1 executes processes, 1 writes the findings store."
  The operator approves *capabilities*, not prose. `minCoreVersion` is checked
  and surfaced if unmet.
- **What approval does NOT grant**: enabling a plugin does not waive the
  per-call gates. An approved `network` plugin tool still triggers
  scope-on-demand and the yolo hard-deny on every call; an approved
  `filesystem-*` tool still triggers the local-directory gate. Enablement is
  "this plugin may participate"; the per-call gates remain the runtime
  authority.

---

## 5. Staged plan

Each stage is independently shippable and independently useful.

- **Stage 1 — manifest + capability model (this PR).** Pure schema + validation
  in `manifest.ts`, no I/O. `validatePluginManifest` (total, actionable errors,
  collision + charset + mandatory-non-empty-capabilities checks) and
  `gateFlagsFor` (the single conservative capability→gate translation, proven by
  a power-set sweep). Ships nothing runtime; establishes the contract everything
  else depends on. **Small.**

- **Stage 2 — loader + gate wiring.** Read a manifest from disk, validate it
  (stage 1), and register its tools such that `getToolsForRole` can offer them
  and, crucially, the three gate maps in `turn-engine.ts` are extended from
  `gateFlagsFor` output through **one** registration path. No plugin *execution*
  yet — this is the wiring that makes a plugin tool gated identically to a
  built-in. Requires a small, deliberate change to how the gate maps are built
  (from static literals to "built-ins + registered plugin tools"), owned by
  whoever owns `turn-engine.ts`. **Small–medium.**

- **Stage 3 — isolation + dispatch (subprocess/stdio).** Spawn the plugin,
  speak the JSON protocol, route `invoke` through the same executor path built
  tools use so results and events look identical to the agent. Restricted env;
  OS confinement where available. **Medium–large** (this is where most of the
  real engineering is).

- **Stage 4 — enablement UX.** Per-project/per-user approval store, the
  capability-summary approval prompt, `minCoreVersion` enforcement, enable/
  disable/list commands. **Medium.**

- **Stage 5 — distribution & supply chain.** Signing, provenance, a registry or
  install flow, update/pinning. **Large — a project in its own right.**

**Honest sizing note:** full parity with a mature plugin-manifest system (à la
herdr's) — signing, sandboxed dispatch, a distribution channel, versioned host
API — is a multi-quarter effort, not a single PR. Stage 1 deliberately ships the
*security-critical foundation* (capabilities are mandatory and fail-closed)
first, so that no later stage can accidentally reintroduce the gate-bypass hole
described in §2.
