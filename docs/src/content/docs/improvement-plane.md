---
title: Improvement Plane
description: Source evolution, executable plugins, and the live self-evolving harness contract.
---

0sec's goal is **self-evolution, not only self-improvement**. An agent should
learn a codebase and its failures, write reusable executable skills, and create
or replace its own reasoning and presentation components while continuing a
long-running task. The built-in harness remains useful without requiring the
agent to build its own environment first.

These mechanisms have different activation boundaries:

- **Learning** retains revision-aware notes and execution feedback.
- **Source evolution** proposes edits to copies of source snapshots, evaluates
  them, and selects immutable worker versions.
- **Executable plugins** let an enabled agent submit, run, compose, evolve, and
  roll back its own TypeScript tools, skills, and agent-like programs. New calls
  can use a new version without restarting the session.
- **Live harness generations** extend this to the active `agent.driver` and
  `ui.view`, including view, command, and settings contributions. The shared
  contract exists; runtime and frontend integration are under implementation
  and are not yet an end-to-end qualification claim. See
  [Live harness component contract](#live-harness-component-contract).

Writing code, loading a plugin, and proving an improvement are separate events.
Source candidates execute in fresh Docker containers or local smolvm guests
with bounded resources. An accepted generation changes subsequent work at a
defined boundary; it does not overwrite the provenance of work already done.

```text
task observations and development feedback
  -> authored source or component candidate
  -> isolated execution and evaluation
  -> retained version and evidence
  -> explicit or configured automatic selection
  -> activation at the consuming runtime's boundary
  -> continued work, further feedback, or rollback
```

## Engagement boundary

An ordinary source-evolution promotion does not by itself replace a running
0sec process. Existing worker pins retain their snapshot and configuration.
Executable-plugin activation is a separate, already implemented next-call
boundary; live driver and UI replacement use the generation contract below.
Neither should be described as an app updater or a mandatory process restart.

The boundary is between **mutable agent behavior** and **authority over the
environment and evidence**, not between "rules may change" and "code may not."
Sandboxed components use host-mediated services. Workspace-trusted ESM
components are a separately authorized, more powerful execution tier; their
host permissions are not sandbox guarantees.

- Retain version identities, observations, and receipts across changes.
- Keep evaluation answers and credentials out of candidate source snapshots.
- Do not treat a candidate's own success claim as an independent verifier.
- Do not automatically replay already-issued tool effects after a driver fails.
- An automatic-promotion policy or self-extension setting is not a grant of
  trusted host execution.

Version pinning is not an attestation of immutable model weights: upstream
aliases, serving changes, or runtime fallbacks can change behavior. Record
observed outcomes and re-evaluate rather than treating a requested model name
as sufficient provenance.

### Model output is not verification

Reasoning text is a diagnostic signal, not an authorization or evidence receipt.
[CoT faithfulness varies by model and task](https://arxiv.org/abs/2307.13702);
enforce scope and promotion rules outside the model.

A source claim surviving an adversarial model pass is not a reproduction.
An empty model refutation is not proof that the claim is false, either. Both
outcomes remain **unresolved** in the shared hunt ledger; model-only rejection
must not become a known negative that anchors later research. Existing ledger
files are not rewritten: re-evaluate any older model-only disprovals before
reusing them as settled evidence.

### Revision-aware codebase learning

Scoped native-API research runs can call `remember_codebase` to retain architecture
and dataflow notes. The host selects the repository root and hashes the cited
files; the model cannot supply its own root or evidence digests. Notes use the
existing private, redacted hunt-memory store, not source edits or model training.

A fresh eligible run receives up to six still-current notes as **untrusted
hints**. Changed, missing, out-of-scope, symlinked, or multiply linked evidence
invalidates the note. File hashes establish which source the note refers to,
not whether the model's interpretation is correct.

Verification runs neither receive these notes nor get the learning capability.
`0SEC_DISABLE_HUNT_MEMORY=1` disables recall and persistence. Resumed runs keep
their existing context rather than silently receiving new notes.

### Source access consent

Because the model proposes edits to its own source tree, the operator must
explicitly opt in:

- **`allowModelSourceAccess: true`** in the evolution config — the model sees
  the source files listed in `sourcePaths` (as a digested, read-only content
  reference in the proposal prompt, never as a live filesystem path during
  generation). Without this flag, `runEvolution` refuses at startup.
- **`--allow-source-access`** on the CLI overrides the config for one-off runs.

The model receives selected snapshot text, not unrestricted host filesystem
access. Keep credentials and private evaluation data out of `sourcePaths`;
selection is not a secret-redaction mechanism.

### Setup invariants

- **Keep config JSON and private evaluation answers (expected values) outside
  all selected `sourcePaths`.** The snapshot copies every file in
  `sourcePaths` — config fields like `expected` would be readable by the model
  if placed inside a source directory.
- **Do not put hidden fixtures, oracles, or answer keys inside the worker
  source tree.** Even with `allowModelSourceAccess: false`, a snapshot
  including a file with expected answers is a data leak.
- **The CLI rejects config files that would be included in selected source.**
  This includes resolved symlink targets: if the config file resolves inside
  selected source, the CLI config loader rejects it before generation.
  Programmatic callers must keep private answers outside selected source too.

### Feedback across evolution passes

Each evaluated proposal is retained beside its execution receipt. A later pass
can recover development observations from the most recent compatible evaluated
version in the active lineage, including an active version after promotion.
Recovery checks proposal, receipt, configuration, and snapshot integrity; missing,
incompatible, or damaged history does not enter the model context.

The objective, selected/editable paths, execution contract, and fixture corpus
must remain compatible. Changing the proposal model or remaining spending
budgets does not erase otherwise compatible observations. Held-out and
negative-control attempts, scores, and expected answers are not recovery feedback.

This is durable learning context, **not durable campaign accounting**.
`evolve run --watch` accumulates spend within one process; restarting it does not
resume a campaign-wide budget ledger. It also stops after a no-change pass.
Do not supervise restarts as an unlimited, unattended improvement service.

### Trust boundary

The offline source-evaluation path isolates candidate workers from the
operator-owned controller and evolution store. Within that configured sandbox
boundary, a candidate process is not granted access to:

- the operator's network, credentials, or engagement workspace;
- writes to the evolution store (the controller publishes snapshots and receipts);
- persistence outside the disposable worker.

This trust boundary does **not** protect against a compromised host or operator
account. An attacker with root access to the host or write access to the
evolution store can tamper with snapshots, receipts, or the registry. The
hash-chained ledger detects inconsistent edits, not an attacker rewriting the
entire history. It is not an external signature or a trusted transparency log.

This describes offline evaluation, not every plugin execution tier. Operational
executable plugins can request authorized tool/model services through the host
broker. Separately granted workspace-trusted ESM plugins run with host
permissions; do not apply the offline worker's confinement claims to them.

### Automatic promotion

The config flag **`autoPromote: true`** lets source candidates advance without
per-candidate approval when every promotion gate passes. This is the configured
autonomy model — the old absolute "no automatic source-code promotion" is
replaced by explicit operator choice through the config. Default remains
`false`; a canary trial still runs before any version becomes active.

### Future-worker version pinning

Every promoted version produces a content-addressed snapshot in the evolution
store (`storePath`). The **`0sec evolve exec`** command pins and executes that
snapshot against arbitrary JSON input, with the stored backend's offline,
credential-free isolation:

```bash
0sec evolve exec --config ./evolution.json --run-id <id> --input '{"file": "src/main.ts"}'
```

The command:
1. reads the active version's snapshot from the registry;
2. copies its files into a fresh isolated worker;
3. runs the config's `command` with the provided input;
4. for known config cases, validates stdout against the stored `expected`
   answer and rolls back the active version to its parent on mismatch (operator
   cancellation excluded);
5. returns the execution result.

Unknown inputs have no ground truth and are never auto-labelled. Execution is
always offline — no provider credentials, no network, no engagement tokens.

### Deploying an evolved source finder

`deep-review` can opt into the active source version instead of its native
prompt-backed finders:

```bash
0sec deep-review ./target-repo --evolution-config ./evolution.json
```

The evolution config must evaluate the same source-finder protocol used by the
review. Each case input has exactly these fields:

```json
{
  "schemaVersion": "0sec.finder.input/v1",
  "file": { "path": "src/handler.js", "content": "db.query(req.query.sql);\n" },
  "lensId": "injection",
  "challengeHint": "Inspect whether untrusted input reaches SQL execution."
}
```

The command emits one JSON value with exactly these fields:

```json
{
  "schemaVersion": "0sec.finder.output/v1",
  "findings": [{
    "title": "Potential SQL injection",
    "severity": "high",
    "line": 1,
    "analysis": "Request input reaches the query; verify parameterization and reachability."
  }]
}
```

These are unconfirmed leads. Empty findings use `[]`; fixture `expected` values
use the same output protocol and the usual controller-owned exact-JSON oracle.
The worker cannot assign finding status, another file path, or verifier results.
The host binds each lead to the supplied file and checks its line range.
Ordinary independent verification still runs after finder execution.

The review pins the active version before starting work. Each finder invocation
gets a child pin bound to that same version and its own input. A promotion or
rollback changes future reviews, not an in-flight review. The stored version's
command, image identity, and limits remain authoritative; editing the supplied
config cannot change an already-promoted worker.

Execution uses the same configured backend as `evolve exec`, with no host
execution fallback. The worker receives one scoped file of at most 1 MiB, not a
target-directory mount. Invalid protocol output is a worker failure and enters
the existing rollback path. A missing active version fails closed.

`--models` cannot be combined with `--evolution-config`. Local compute uses the
stored `maxEvaluationCostUsd` budget for the review, separately from the model
token ledger. Reports include `evolution_version_id` and
`evolution_compute_cost_usd`. Controller records retain input digests and private
execution receipts; worker output may quote target source and remains sensitive.

### Canary and rollback

After evaluation passes, a candidate enters canary:
- **`canaryTrials`** (default 2) counts additional complete executions of the
  sealed corpus, not fresh datasets or live target traffic. All must pass.
- A canary that fails is automatically rolled back to its parent version.
- Acceptance of successive candidates leaks a weak signal about a reused held-out set.
  This is not proof against adaptive overfitting over many generations. Operators
  should periodically supply fresh, independently curated cases to each lane.
- **`0sec evolve rollback --store <path> --version <id>`** retires the
  specified version (must be the current active or canary version) and restores
  its parent. `--version` names the version to retire, not a desired historical
  destination. Rollback preserves the retired version's snapshot and receipt in
  the registry alongside the parent.

### Runtime prerequisites

With the default Docker backend, the config's `image` must be:

- available locally (pulled in advance);
- contain the runtime for the configured `command` (e.g. `node`, `python3`);
- ship no credentials, provider keys, or engagement scope.

Evolution runs resolve the image tag to an immutable image ID. Stored worker
configurations retain that ID; resumed workers do not follow a subsequently
retagged image.

Docker execution requires access to a local Docker daemon; source proposal
generation separately requires a configured model provider. The Docker sandbox uses:

- `docker create` + `docker start` lifecycle — each execution is a separate
  container; cleanup runs with a bounded timeout after the execution finishes.
- `--network none` — no egress
- Read-only root filesystem except:
  - `/workspace` — **writable, executable tmpfs** where the snapshot files are
    placed and builds run
  - `/tmp` — **noexec tmpfs** (direct execution blocked; interpreters can still read files)
- Input delivered over **stdin** — no host-side input file inside the container
- The non-root host UID/GID, `--cap-drop=ALL`, and `--security-opt no-new-privileges`
- `--pids-limit=64`, bounded memory and swap, and configured CPU limits

Containers share the host kernel. These restrictions reduce privilege; they
are not a guarantee against container escapes. Use a dedicated worker host or
VM when evaluating hostile code.

#### Local smolvm backend

Set `"backend": "smolvm"` and `"imageArchive": "/absolute/path/to/node.tar"`
in the same evolution config. Keep `image` as the image's descriptive name for
the initial run, or provide the expected `sha256:<archive-hash>` to require exact
bytes. The controller resolves it to the archive's SHA-256 before recording a
version. Stored execution and approval use that recorded identity, not a newly
resolved replacement image.

This backend is qualified for **non-root Linux, KVM, Node 24+, util-linux
`setpriv`, and smolvm 1.14.6**. Other smolvm versions and host platforms are rejected
until their lifecycle is qualified. Install the complete upstream runtime bundle,
not just `smolvm-bin`, and put its launcher on `PATH`. Existing processes need
restarting after group membership changes; do not make `/dev/kvm` world-writable.

The toolbox stays an OCI image. A `docker save` archive is one way to provision
it; Docker is not used to execute smolvm workers:

```bash
docker pull node:22-alpine
docker save node:22-alpine -o node.tar
```

That is a small Node worker image, not the security toolbox. To provision the
declared pentest/identity/Foxguard inventory without building the CLI application:

```bash
docker build --target toolbox -t 0sec-toolbox:local .
docker save 0sec-toolbox:local -o toolbox.tar
node scripts/smoke-smolvm-toolbox.mjs ./toolbox.tar
```

The `runtime` target remains the full distribution: it adds the CLI to the same
toolbox. Both targets default to non-root execution. A Docker daemon is needed
for these build/export commands, not for the subsequent smolvm run.

The toolbox qualification checks startup of 37 commands, system and AD Python
imports, Nmap TCP-connect discovery and curl against a guest-owned loopback
server, and Foxguard detection of an unsafe-eval fixture with a clean control.
It checks UID/GID 1000 and source immutability. It does not authenticate to real
identity providers, scan external targets, or establish general scanner accuracy.
The exercised profile is 2 vCPUs, 3072 MiB RAM, 4 GiB writable storage, a 1 GiB
overlay and a 180-second host deadline. Optional SecLists and browser/privileged
tooling are not covered by that qualification.

Use the toolbox archive in the same evolution config when a worker needs those
tools; set `cpus: 2`, `memoryMb: 3072` and `timeoutMs: 180000` for this profile.
The small Node image remains appropriate for narrow source-evolution fixtures.
Full toolbox import costs more than importing the small runtime image.
Neither image selection makes console/PTY execution globally sandboxed; see
[Execution isolation](/architecture/#execution-isolation-and-toolbox-packaging).

The archive must contain `/bin/sh` and the runtime/dependencies needed by the
worker. Provision it before evaluation. No automatic pull or dependency download
runs inside a candidate. Start with `cpus: 2`, `memoryMb: 2048`, and
`timeoutMs: 60000`; CPU counts must be integers. Smaller profiles are not guaranteed
to accommodate image import and guest startup.

Each invocation:

- copies and hashes the archive into a private run directory before boot;
- starts an offline, UID/GID 1000 guest with `--unprivileged`;
- mounts the sealed source read-only at `/snapshot`, then copies it to writable,
  guest-local `/tmp/0sec-workspace` for builds and execution;
- sends only the case input through stdin and returns bounded stdout/stderr;
- uses 4 GiB writable storage and a 1 GiB VM overlay, with configured CPU/RAM limits;
- ignores ambient project Smolfiles and isolates host runtime state and caches;
- enforces a host deadline covering preparation and execution, then waits for
  VM and cleanup-helper termination before deleting its private state.

Timeout, cancellation, output overflow, image mismatch, and cleanup failure are
failures, never permission to run on the host or switch to Docker. Cleanup failure
retains its private directory and reports the recovery path. `evolve exec` forwards
SIGINT/SIGTERM into this cancellation path.

These controls are not identical to Docker's: the guest has its own kernel and
a disposable writable filesystem; Docker's PID limit and `noexec` tmpfs settings
are not claimed for smolvm. VM isolation is not a proof against hypervisor escapes.
This is the evolution-worker backend, **not a global redirection of console/PTY,
replay, or exploit commands into a VM**.

### Execution protocol

The configured `command` receives the case `input` as a single JSON line on
stdin. If `buildCommand` is specified, it runs first (stdout redirected to
stderr so it never pollutes the answer channel), then `command` runs. The main
command **must** emit exactly one JSON value on stdout — that is compared
against `expected` using canonical-JSON equality.

Example: if the config specifies
```json
"command": ["node", "fixture.mjs", "--mode", "eval"]
```
the process receives `{"n": 4}\n` on stdin and must write
`{"classification":"even"}\n` to stdout (or `{"classification":"odd"}`,
`{"classification":"error"}`, etc.).

### Model for proposal generation

When `config.model` is set, source proposals are generated through that model
via `LlmApiRuntime` (the standard API runtime). When omitted, the configured
provider default is used. Model identity is used to price actual usage — the
`maxModelCostUsd` ceiling tracks real token spend.

Proposal generation can inspect up to eight recent retained versions of the
same artifact kind through `read_source(versionId)`. Archives are reference
material: reads are restricted to paths still present in the current snapshot,
and edits must match the current baseline's file digests. Archived source does
not grant access to evaluation receipts or hidden fixtures.

Within an evolution pass, the next attempt receives the previous proposal and
bounded development-lane stdout/stderr. Held-out inputs, expected answers, and
negative-control observations are not supplied to the proposal model.

## Research basis and remaining limits

[A Programming Paradigm for Spatiotemporal Composability
(Shi, Zhang, and Cui, 2026)](https://arxiv.org/abs/2608.25512) supplies the
component-lifecycle rationale. Its **temporal composability** tracks reversible
effects so removing a component removes its registrations and owned resources.
Its **spatial composability** makes dependencies explicit and reacts when
providers appear, disappear, or change. [Cordis](https://github.com/cordiverse/cordis)
implements the model with a component loader and hot module replacement;
[DSH's architecture](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md)
uses services for the agent loop, tools, model adapters, and session log.

The qualifications matter:

- The paper's sections 6.1 and 6.3 distinguish reversible, context-owned effects
  from external emissions and from sandboxing. Removing a listener can be
  reversed; sending a network request cannot simply be undone. Untrusted code
  still needs an execution boundary.
- The paradigm is language-independent (section 6.4); upstream Cordis is
  TypeScript and its API is explicitly unstable. A Python SDK client or Python
  code-execution tool is not automatically a Python component host.
- DSH's custom/web profiles support live patch reload, but its shipped
  headless, SDK, and ACP profiles apply composition at startup. Do not infer
  same-session CLI replacement merely from DSH's plugin architecture.
- This is a composability paper, not a benchmark demonstrating autonomous
  security-quality improvement or crash-safe, multi-day agent operation.

The live runtime integration pins `@deepseek-ai/cordis@4.0.2`: this is an actual
framework dependency, not only an analogy. 0sec adds its generation, guest
bridge, accounting, and frontend contracts around explicit dependencies and
owned cleanup. Integration is still being qualified; using Cordis does not
prove that every component supplies correct inverses or that external effects
can be rolled back.

Self-rewriting is a search mechanism, not evidence that the resulting scanner
is better. The relevant research supports evaluator-driven iteration:

- [Self-Harness (Zhang et al., 2026, v3)](https://arxiv.org/abs/2606.09498v3)
  connects three stages: verifier-grounded weakness mining, diverse minimal
  harness-code proposals by the same fixed model, and regression validation.
  A candidate must not reduce held-in or held-out aggregate pass counts and
  must improve at least one split. The authors report improvements for all nine
  tested model/benchmark pairs; their largest relative gain, 132%, is not a
  percentage-point gain or a cybersecurity result. The study uses bounded edits
  to a minimal harness definition, fixed benchmark subsets, and fresh task
  environments. It explicitly does not establish open-ended self-improvement.
  For 0sec, it motivates a failure-driven optimizer around the live component
  runtime, not replacing the evaluator with the candidate's self-assessment.
- [Darwin Gödel Machine (Zhang et al., 2025)](https://arxiv.org/abs/2505.22954)
  empirically improves coding agents through code changes and an archive of
  alternative agents. Its authors also report
  [objective hacking and fabricated tool-use logs](https://sakana.ai/dgm/).
  0sec therefore retains controller-produced execution receipts rather than
  trusting a candidate's claim that its tests passed. Retaining versions alone
  is not DGM's open-ended search over an archive.
- [AlphaEvolve (Google DeepMind, 2025)](https://deepmind.google/blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/)
  combines generated programs with automated evaluators. This supports a
  propose → execute → measure → select loop, not transferring its reported
  mathematical or compute gains to cybersecurity without separate evidence.
- [GEPA (Agrawal et al., 2025)](https://arxiv.org/abs/2507.19457) uses natural
  language reflection on execution trajectories and combines complementary
  candidates. Development-only execution feedback and readable source history
  support reflection in 0sec; they do not implement GEPA's Pareto search or
  establish equivalent performance.
- [The reusable holdout (Dwork et al., 2015)](https://doi.org/10.1126/science.aaa9375)
  addresses invalid inference from adaptive reuse of evaluation data. 0sec's
  repeated trials and canaries reuse the configured corpus: they measure
  repeatability, not independent generalization. 0sec does not implement that
  paper's privacy-based reusable-holdout mechanism.
- [Hierarchical Self-Improvement (Zhou, 2026)](https://arxiv.org/abs/2608.08466)
  evolves task harnesses and evolver strategies under a frozen outer anchor,
  with a DeepSeek model as the backbone. It reports limits from feedback
  quality and model capability. This is distinct from the
  [DeepSeek Harness runtime](https://github.com/deepseek-ai/deepseek-harness):
  a plugin architecture or MCP connection alone is not an improvement loop.
- [EVOHARNESSBENCH (Ke et al., 2026)](https://arxiv.org/abs/2609.04280)
  reports harness-induced forgetting and inconsistent adaptation gains.
  Expanding tools, skills, or agents therefore requires retention evaluation;
  a larger harness is not inherently a better one.
- [Post-Hoc Reasoning in Chain of Thought (Cox et al., 2026)](https://arxiv.org/html/2603.01437v2)
  finds pre-committed answers and misleading rationalization in the tested
  instruction-tuned models and tasks. A candidate's explanation is useful
  context, not evidence that its change is correct or authorized.
- [OpenAI's Astra system card](https://deploymentsafety.openai.com/gpt-6-astra)
  reports reduced monitorability alongside improved measured alignment.
  Reasoning monitoring is therefore supplementary: filesystem, credential,
  execution, and promotion boundaries must be enforced outside model output.
  Those results do not establish that recurrent depth caused the change.
- [A Little Depth Goes a Long Way (Merrill and Sabharwal, 2025)](https://arxiv.org/abs/2503.03961)
  studies transformer depth and computational expressivity. Repeating an API
  agent loop is not the same mechanism. Choose model and reasoning settings
  using measured task outcomes, latency, and cost, not assumed architecture.

The implemented boundary is fixed acceptance criteria, independently labelled
controls, restricted candidate execution, and versioned rollout. There is no
automatic oracle for curating fresh security ground truth, no automatic held-out
rotation, and no demonstrated general security-quality gain from this local
implementation. Supply fresh independently curated evaluation cases before
treating successive benchmark wins as evidence of general improvement.

Tracked implementation work:

- [Crash-safe campaigns and feedback-driven resume (#41)](https://github.com/0sec-labs/0sec/issues/41)
- [Longitudinal capability retention (#37)](https://github.com/0sec-labs/0sec/issues/37)
- [Adaptive holdout exposure and rotation (#40)](https://github.com/0sec-labs/0sec/issues/40)
- [Measured, development-only archive search (#39)](https://github.com/0sec-labs/0sec/issues/39)
- [Evidence provenance and incompatible comparisons (#38)](https://github.com/0sec-labs/0sec/issues/38)

## Autonomy and hot-reload boundaries

These paths are distinct; an accepted source candidate is not automatically a
replacement for the stock target-facing 0sec process.

| Path | What changes | What remains fixed |
| --- | --- | --- |
| Finder-lens overlay | Newly started hunts load promoted lens content without rebuilding the CLI. | Active hunts retain their captured lens content and version identity. |
| TUI evolution settings | The watcher can stop and reconfigure while the TUI remains open. | Disabling or restarting a watcher must not let stale callbacks publish a new result. |
| Source evolution | `evolve run --watch --auto-promote` can select a new accepted snapshot for subsequent `evolve exec` runs. | Existing run IDs retain their original snapshot, stored configuration, and input identity. |
| Source finder deployment | `deep-review --evolution-config` selects the active source snapshot for each new review. | Every finder call in that review inherits the parent pin; verification and host policy are not rewritten. |
| Skill/router installation | Training loops install exact authorized artifact bytes. | Authorization does not hot-swap a model already loaded by another process. |
| Executable plugin | An enabled agent submits or evolves actual code; later calls select the active retained version. | An invocation pins its version and declared capabilities; structural admission is not measured improvement. |
| Live harness generation (integration in progress) | Replace `agent.driver` and `ui.view`, including namespaced UI commands/settings, in the same session. | Session history and accounting survive; generation changes wait for a defined checkpoint. |

Observation capture is not independent truth: source consent and operator-curated
positive, held-out, and clean-control fixtures still gate automatic synthesis.
Promotion of a finder lens changes a prompt-backed detector, not FoxGuard's
compiled Rust engine or rules.

Offline lifecycle checks demonstrate orchestration, not better security
coverage. Live provider runs, actual sandbox execution, and independently
verified detection outcomes are separate validation requirements.

## Live harness component contract

**Integration status:** The unreleased shared live-harness contract defines the
wire types. This section describes the agreed runtime contract, not a claim
that every CLI, browser, and desktop path has passed live integration checks.
Desktop remains unreleased. An HTTP/event adapter and the TUI must consume the
same runtime catalog rather than maintain separate plugin registries.

### Composition and language support

`HarnessGenerationSpec` contains a label and the **complete desired provider
graph**. Each `HarnessProviderSpec` declares an `id`, required provider IDs,
services, and one execution source:

| Source | Contract | Authority |
| --- | --- | --- |
| `sandboxed` | Retained executable `pluginId`, `versionId`, and `toolName` | Guest execution; operational effects use the existing authorized SDK broker |
| `trusted` | Self-contained ESM `entry` and `files`, with optional `ui.tui` / `ui.web` entries | Explicit workspace grant; code executes with host permissions |

The current service names are `agent.driver` and `ui.view`. They are actual
implementation replacement points, not only prompt templates or static rule
lists. A shared catalog may evolve to expose more services; unimplemented
service names must not be advertised as available.

Python already works through MCP and the language-neutral source-worker
command protocol when the selected image contains Python. The current
executable-plugin admission accepts `.ts` / `.mts`, not `.py`. First-class Python
components still need a runner/SDK implementing the same lifecycle and broker
protocol; they should not get a second registry or a Python-specific harness.
Backend selection and language selection are separate from plugin composition.

### Activation, state, and UI interaction

The lifecycle contract is:

1. Submit a complete candidate graph and retain its immutable source identity.
2. Validate dependencies, services, trust, and source provenance before use.
3. At a checkpoint, wait for old-generation invocations and prepare/migrate
   candidate state in dependency order.
4. Publish one active generation only after preparation succeeds. Failed
   preparation leaves the old generation available.
5. Remove retired registrations and dispose owned resources in reverse
   dependency order. Rollback selects a retained implementation and migrates
   **current** state; it does not erase task history or undo external effects.

`HarnessControl` carries `submit`, `rollback`, `disable`, and `list`. A submitted
generation can be **pending** before it becomes active; consumers must display
that distinction. `HarnessSnapshot` carries active/previous/pending generation
IDs, status, providers, views, namespaced commands/settings, and trust state.
It is the common frontend catalog, not an alternate source of authority.

`HarnessView` supplies bounded text, Markdown, table, progress, and action
blocks. Commands and settings carry provider identity. An explicit interaction
names its generation, provider, and contribution; a stale generation must not
dispatch against a replacement provider. Returned `requestedPrompt` content is
for an explicit interaction, **never automatic submission while rendering**.
Sandboxed view data is not host JavaScript. Trusted UI modules require the
separate workspace grant and must not remove the host-owned recovery controls.

### Autonomy without a second permission system

The intended operator experience is a capable built-in agent plus unattended
iteration within the chosen authority and spending envelope. Agents can author
code, compose executable skills, compare alternatives, and replace admitted
components; the operator need not approve every ordinary iteration when an
automatic policy already authorizes it.

New sessions default to model self-extension enabled through
`DEFAULT_ALLOW_MODEL_SELF_EXTENSION = true` in
`packages/shared/src/desktop-console.ts`. An explicitly selected or persisted
`false` takes precedence. The desktop checkbox initializes from the shared
default; existing disabled sessions remain disabled and are not reconstructed.
The lower-level `SelfExtensionRegistry` requires its caller to pass
`enabled: true`; that constructor contract is not the product default.

Autonomy is a separate control. The shared `DEFAULT_AUTONOMY_MODE = "yolo"`
constant does not mean every desktop session starts in YOLO: the existing
desktop authorization flow remains unscoped-standard/scoped-YOLO.
Self-extension enablement does not change that authorization flow or grant
workspace-trusted execution.

Source evaluation has separate controls: `allowModelSourceAccess` admits selected
snapshot text into proposal generation, and `autoPromote` authorizes candidates
that pass the configured gates. Those remain explicit opt-ins. Model
self-extension does not silently enable either one.

Workspace-trusted execution defaults **off** until the operator persists a
grant for the canonical launch workspace. It is not inferred from YOLO,
self-extension, a model-submitted manifest, or project-controlled configuration.
Trusted code can access host resources, including credentials, and can crash
its process; component lifecycle management is not an OS sandbox.

### Long-horizon self-evolution

Hot replacement addresses continuity **within a live process**. Long-running
tasks additionally need:

- **Durable recovery:** checkpoints bind task progress, active generation,
  component state, pending work, and evidence. Restart must restore or
  explicitly reject incompatible state, not quietly restart with a new harness.
- **Durable accounting:** campaign budgets, usage, and evaluation exposure must
  survive restart rather than reset with an in-memory watch loop.
- **Useful learning:** revision-aware codebase notes, development feedback, and
  executable skills are retrieved when relevant and invalidated when stale.
- **Retention:** proposed changes face old capabilities as well as new tasks;
  archive search and repeated holdout reuse do not prove generalization.
- **Long-session qualification:** repeated upgrades, failed preparation,
  dependency changes, rollback, stale UI input, cancellation, and cleanup must
  preserve task state and must not duplicate model/tool effects.

Self-Harness suggests a concrete optimizer contract around this lifecycle:
group recurring development failures by verifier outcome, causal status, and
reusable mechanism; retain examples of passing behavior; then ask for distinct,
targeted candidate changes. Record the model, harness generation, environment,
targeted failure, changed surface, and expected regression risk for each
proposal. Compare candidate and baseline under compatible conditions and retain
rejected attempts. Re-evaluate the **combined** generation before publishing
multiple individually successful edits. Keep held-out traces and answers out of
proposal context; repeated acceptance still exposes information about the
holdout and needs separate exposure management. These are optimizer
requirements, not features supplied automatically by Cordis or by the current
generation wire types.

These are acceptance requirements, not claims of completed multi-day operation.
The existing source watcher is not a crash-safe campaign service; see
[feedback across passes](#feedback-across-evolution-passes) and the tracked
[campaign work](https://github.com/0sec-labs/0sec/issues/41). Live generation
types alone do not establish persistent state recovery or Python plugin parity.

## CLI reference

### 0sec evolve

```text
0sec evolve                      Autonomous self-improvement
  run          --config <path>   Run evolution: propose, evaluate, and optionally promote
                 [--watch]          source candidates. Watch mode iterates sequential passes;
                 [--json]           stops on any failed pass (cannot safely retry unmetered
                                    failed generation). Budgets are cumulative across watch passes.
                 [--auto-promote]
                 [--allow-source-access]
                 [--max-passes <N>]
  status       --store <path>    (required) Show evolution registry: active/canary/parent
                 [--json]           version, snapshot/receipt identities, and registry
                                    events. Does NOT aggregate historical costs — run
                                    output reports model and evaluation costs;
                                    histories and receipts retain them individually.
  promote      --store <path>    Run required canary trials against the pinned stored
               --version <id>      config and activate the accepted exact candidate.
               [--json]            Use for awaiting_approval results and training
                                   promotion guidance. No regeneration — activates
                                   only the named candidate version.
  rollback     --store <path>    Retire the current active/canary version and
               --version <id>      restore its parent. --version names the
               [--reason <text>]   version to retire, not a desired destination.
                                   Reason optional (default "operator rollback").
  exec         --config <path>   Execute a pinned evolution version snapshot against an
               --run-id <id>       isolated worker with no network. Pins the
               --input <json>      active snapshot from the specified run. Known config
               [--json]            cases are validated; mismatch rolls active back to parent.
  feedback
    capture    --input <path>    Capture an evidence-backed observation from a
               [--store <path>]    JSON file (CaptureObservationInput fields:
               [--allow-source-access] classHint, sinkPattern, exampleFileLine,
                                    whyMissed, source, scanId,
                                    sourceRevisionDigest). Consent in the JSON
                                    is ignored unless --allow-source-access set.
    approve    --id <id>         Approve a pending observation with operator-
               --fixtures <path>   curated ValidationFixture arrays. The curation
               [--store <path>]    JSON requires positives, heldOut, and
               [--allow-source-access] negativeControls — all real ValidationFixture
                                    objects. Verifies evidence and explicit
                                    consent before allowing synthesis.
    status     [--store <path>]  Show retained observations and their
               [--json]            approval/processing status.
    release    --id <id>         Recover a crash-held observation claim after
               --claim-token <token> stopping its previous worker.
               [--store <path>]
```

**Error codes:** 0 = success, 1 = user error, 2 = runtime error, 3 = interrupt.

### 0sec lens-synth

Finder-lens evolution remains a separate command — see [lens-synth help](/commands/#lens-synth).

```text
0sec lens-synth                   Evolve appsec finder coverage from curated misses
  --miss-input <path>                Curated miss-input JSON ({ misses, corpus })
  --registry <path>                  Durable overlay path (~/.0sec/lenses/...)
  --max-register <n>                 Cap promoted champions per input revision
  -m, --model <id>                   Synthesis model override
  --promote                          Persist a validated champion to the durable overlay
  --watch                            Poll the miss-input and process each new revision
  --poll-interval <ms>               Watch polling interval (minimum 100ms)
  --status                           Show the active durable overlay and promotion ledger
  --rollback <lens-id>               Retire one previously promoted overlay lens
  --json                             Print machine-readable output
```

## Config shape

An evolution config is a JSON file passed to `0sec evolve run --config <path>`.
Fields with defaults may be omitted.

This small example exercises the lifecycle; it is **not a cybersecurity
benchmark**. Create `worker/src/checker.cjs` with an intentionally imperfect
baseline:

```javascript
const { readFileSync } = require("node:fs");
const { n } = JSON.parse(readFileSync(0, "utf8"));
const classification = !Number.isInteger(n) ? "error"
  : n % 3 === 0 ? "odd"
  : n % 2 === 0 ? "even" : "odd";
console.log(JSON.stringify({ classification }));
```

Save this as `evolution.json` **alongside**, not inside, `worker/`. Install
`node:22-alpine` locally with Docker before running; evolution never pulls
an image automatically. Configure the usual 0sec model credentials separately.

```json
{
  "schemaVersion": 1,
  "sourceRoot": "./worker",
  "storePath": "./.evolution-store",
  "image": "node:22-alpine",
  "kind": "source",
  "sourcePaths": ["src"],
  "editablePaths": ["src/checker.cjs"],
  "command": ["node", "src/checker.cjs"],
  "objective": "Classify every integer as even or odd; classify non-integer inputs as error.",
  "allowModelSourceAccess": false,
  "autoPromote": false,
  "canaryTrials": 2,
  "repeats": 3,
  "maxIterations": 3,
  "maxModelCostUsd": 5,
  "maxEvaluationCostUsd": 5,
  "computeUsdPerSecond": 0.0005,
  "cases": [
    { "id": "dev-even", "lane": "development", "input": { "n": 4 }, "expected": { "classification": "even" } },
    { "id": "dev-multiple", "lane": "development", "input": { "n": 6 }, "expected": { "classification": "even" } },
    { "id": "dev-odd", "lane": "development", "input": { "n": 7 }, "expected": { "classification": "odd" } },
    { "id": "held-odd", "lane": "held-out", "input": { "n": 13 }, "expected": { "classification": "odd" } },
    { "id": "held-multiple", "lane": "held-out", "input": { "n": 18 }, "expected": { "classification": "even" } },
    { "id": "held-even", "lane": "held-out", "input": { "n": 22 }, "expected": { "classification": "even" } },
    { "id": "clean-null", "lane": "negative-control", "input": { "n": null }, "expected": { "classification": "error" } },
    { "id": "clean-string", "lane": "negative-control", "input": { "n": "2" }, "expected": { "classification": "error" } },
    { "id": "clean-fraction", "lane": "negative-control", "input": { "n": 1.5 }, "expected": { "classification": "error" } }
  ],
  "promotionPolicy": { "minimumCases": 3 }
}
```

The low sample floor is only for this demonstration. Real evaluation needs
larger independently curated positive, held-out, and clean-control corpora.

### Required fields

| Field | Description |
|---|---|
| `schemaVersion` | Must be `1`. |
| `sourceRoot` | Directory containing the source to evolve (resolved relative to config file). |
| `storePath` | Evolution store for snapshots, receipts, configs, and registry. Must differ from `sourceRoot` and must not overlap any selected source path. |
| `image` | Docker image reference, or initial smolvm image label / expected archive SHA-256. Stored workers retain an immutable backend-specific identity. |
| `sourcePaths` | Relative paths (files or directories) within `sourceRoot` that form the snapshot. At least 1, max 256. |
| `editablePaths` | Subset of `sourcePaths` the model may propose edits to. Each must be inside a `sourcePaths` entry. |
| `command` | Executable + arguments run in the sandbox. At least 1 argument, max 128. |
| `objective` | Free-text goal for the model (up to 16000 chars). |
| `cases` | At most 1000 total, with at least `promotionPolicy.minimumCases` distinct cases in **each** lane (10 per lane by default). No duplicate IDs or inputs. `input` and `expected` must be finite JSON. |
| `computeUsdPerSecond` | Honest compute cost estimate; used for budget tracking. |

### Optional fields with defaults

| Field | Default | Description |
|---|---|---|
| `backend` | `"docker"` when omitted | `"docker"` or `"smolvm"`; no automatic fallback between engines. |
| `imageArchive` | (none) | Required only for smolvm. Regular archive file, resolved relative to the config file; symlinked archive files are rejected. |
| `kind` | `"source"` | Artifact kind: `source`, `skill`, `router`, or `lens`. Determines allowed extensions and promotion policy defaults. |
| `buildCommand` | (none) | Optional build command run in the sandbox before evaluation. |
| `model` | (none) | Model override for proposal generation. Uses the configured runtime by default. |
| `allowModelSourceAccess` | `false` | Explicit consent: the model sees source file content in proposal prompts. `runEvolution` refuses without this. |
| `autoPromote` | `false` | When true, a candidate passing all gates advances without per-candidate approval. Default `false`. |
| `canaryTrials` | `2` | Additional evaluation repeats on the same configured corpus before the version becomes active; not fresh-data trials. |
| `repeats` | `3` | Executions per case per variant (baseline/candidate). At least 2. |
| `maxIterations` | `3` | Maximum candidate-generation iterations per run. |
| `maxModelTurns` | `12` | Maximum model turns per proposal. |
| `maxModelCostUsd` | `5` | Model cost ceiling per run (USD). |
| `maxEvaluationCostUsd` | `5` | Evaluation cost ceiling per run (USD). |
| `timeoutMs` | `60000` | Per-execution timeout (100–600000). |
| `memoryMb` | `1024` | Worker memory limit in MiB (32–16384); smolvm also needs room for its kernel and image import. |
| `cpus` | `1` | CPU limit, up to 16; smolvm requires an integer count. |
| `maxOutputBytes` | `65536` | Max retained stdout/stderr per execution. |
| `maxSourceBytes` | `67108864` | Max total source size in a snapshot. |
| `maxChangedBytes` | `262144` | Max total changed bytes across all edits in a proposal. |
| `promotionPolicy` | `{}` | Promotion gate thresholds (defaults use conservative values from `DEFAULT_IMPROVEMENT_PROMOTION_POLICY`). |

### Promotion policy defaults

```json
{
  "minimumCases": 10,
  "minimumDevelopmentLift": 0.05,
  "minimumHeldOutLift": 0.03,
  "maximumNegativeControlFpDelta": 0,
  "maximumCostMultiplier": 1.5
}
```

| Gate | Default | Requirement |
|---|---|---|
| `minimumCases` | 10 | Minimum distinct cases per lane (configurable down to 3 for small experiments). |
| `minimumDevelopmentLift` | 0.05 (5 pp) | Minimum success-rate improvement on development cases. |
| `minimumHeldOutLift` | 0.03 (3 pp) | Minimum success-rate improvement on held-out cases. |
| `maximumNegativeControlFpDelta` | 0 | Negative-control FP rate must not increase at all. |
| `maximumCostMultiplier` | 1.5 | Held-out cost per success at most 1.5× a successful champion; see zero-success recovery below. |

## Example: run the config above

```bash
# One-off run with source access and auto-promotion
0sec evolve run --config ./evolution.json \
  --allow-source-access \
  --auto-promote \
  --json
```

## Sealed evaluation lanes

Three independent case lanes must be populated in every config:

1. **Development** — calibration and candidate iteration. The model receives
   only development-case observations as feedback; it never sees held-out or
   negative-control answers.
2. **Held-out** — generalization evidence, not tuning evidence.
3. **Negative control** — false-positive tracking on known negatives. The
   candidate must not regress on these.

### Evaluation cycle

For each iteration:

1. **Snapshot** the current source into a content-addressed, immutable directory
   under `storePath/snapshots/<id>/`. Symlinks, special files, secrets, and
   nested store paths are rejected.
2. **Propose** edits via the model (isolated, source-text only, no live path
   access). The proposal must carry a rationale, individual file edits with
   before/after digests, and a model-cost receipt.
3. **Create candidate** by applying edits to a COPY of the baseline snapshot.
   Edits are validated for path boundaries, bounded changed bytes, duplicate
   prevention, and protected-code rejection.
4. **Evaluate** in a fresh, offline worker with a read-only source snapshot. Expected
   answers stay in the controller — never in the candidate or model input. The
   evaluation alternates baseline/candidate order across repeats to avoid
   warm-cache bias. Wilson 95% intervals count distinct fixtures, not repeat
   executions; unstable repeats receive an uninformative `[0, 1]` interval and
   fail the stability gate. These intervals do not correct adaptive holdout reuse.
   A candidate must also retain every case/repeat the baseline solved. Higher
   aggregate scores cannot compensate for losing established behavior; a
   retention failure rejects the candidate through the execution-check gate.
5. **Promotion assessment** — the pure function
   `evaluateImprovementPromotion` checks identity, artifact binding, evaluator
   integrity, evidence, sample size, development lift, held-out lift, precision,
   and cost. Candidates that pass become `eligible_for_canary` (policy) or
   `requires_human_approval` (source). On failure, the reason is recorded per
   gate.
6. **Canary** — if `autoPromote` is true, `canaryTrials` additional repeated
   evaluations run. If all pass, the candidate becomes `active` and the previous
   version is retired. A canary interrupted by controller restart is rolled back
   before the next evolution pass.
7. **Record** — every transition (`recorded`, `canary_started`, `promoted`,
   `rolled_back`) is appended to the registry's hash-chained event log. The
   config, evaluation receipts, and snapshots are retained under `storePath`.

```text
storePath/
  registry.json        -- version registry with hash-chained event log
  configs/             -- content-addressed evolution configs
  snapshots/<id>/      -- immutable source snapshots
  receipts/            -- evaluation receipts keyed by candidate ID
  controller.lock      -- exclusive controller lease (PID-bound)
```

## Schema version and receipts

Every persistent record carries a `schemaVersion` field:

- **`EvolutionConfig`** — `schemaVersion: 1`
- **`EvolutionEvaluation`** — `schemaVersion: 1`, contains `receiptDigest` for
  content-addressed integrity
- **`EvolutionVersion`** — `schemaVersion: 1`, stores `configDigest` and
  `receiptDigest` linking to its immutable artifacts
- **`EvolutionRegistry`** — `schemaVersion: 1`, carries a hash-chained `events`
  array

All artifacts are published atomically with O_EXCL creation, fsync, and
tamper-evident overwrite detection.

## Promotion gates

The default policy rejects a candidate unless **every** check passes:

| Gate | Requirement |
| --- | --- |
| Identity | Candidate ID matches the sealed result. |
| Artifact binding | Distinct SHA-256 base and candidate artifacts. |
| Execution checks | Complete, repeatable scenario executions, including the configured build command when present, with every baseline-successful case/repeat retained by the candidate. This is not an attestation from an external CI service. |
| Evaluator | Identical evaluator digest before and after evaluation. |
| Evidence | At least one retained evidence reference. |
| Sample size | At least 10 distinct cases per lane by default. Repeating a case does not increase the distinct-case count. |
| Development lift | ≥ +5 pp success rate. |
| Held-out lift | ≥ +3 pp success rate. |
| Precision | Negative-control FP rate rises by at most 0 pp. |
| Cost | Finite, nonnegative challenger cost per success; at most 1.5× a successful champion. |

A fully observed champion with zero successes and zero inconclusive results
has no finite cost per success. A candidate with measured finite cost can pass
this comparison; missing cost for a successful or inconclusive champion still
fails closed. Evaluation spending ceilings and every other promotion check
remain enforced.

A passing **policy** candidate is only `eligible_for_canary` — not deployed. A
passing **source** candidate always needs either explicit `autoPromote: true` or
human approval. Any failed check -> `rejected`.

## Candidate-worker contract

The promotion assessment is a pure decision over retained results. The evolution
runner executes candidate code separately under this worker contract:

- sealed input artifact and explicit command;
- fresh Docker container or local smolvm guest;
- no engagement credentials;
- no production target egress;
- bounded CPU, wall-clock, disk, and model budget;
- retained stdout, stderr, evaluator receipt, and artifact digests;
- promotion changes future worker selection, never the active process.

## Self-evolving finder lenses

Finder-lens evolution (`0sec lens-synth`) works alongside the evolve system but
remains a separate command. It evolves **additive appsec finder lenses** from
curated misses into a user-owned registry. Promotions go to
`~/.0sec/lenses/appsec-archetypes.json`, never the bundled registry. Each
promotion or retirement is recorded in the registry's hash-linked ledger.

### TUI automatic mode

The OpenTUI can own the lens-synth watcher, so launching `0` or `0sec tui`
continuously processes the curated inbox while the TUI remains open. It is
deliberately disabled by default and requires two **Security** settings:

```json
{
  "autoEvolveFinderLenses": true,
  "autoPromoteFinderLenses": true
}
```

Import with `0sec config import evolution.json --yes` or enable in the TUI.

The chat status reports `evolve:auto`, `evolve:waiting input`,
`evolve:promoted`, or `evolve:error`.

### Lens corpus and receipts

Supply separate, nonempty `positives`, `heldOut`, and `negativeControls`.
Positive and held-out fixtures need an expected CWE, normalized file path, and
an exact line or inclusive line range. A supplied range takes precedence over
the exact line; the exact line must lie within that range. File paths are
relative to the fixture directory (or a file fixture's parent), not basename
matches. Negative controls need independent `cleanProvenance`. Curation binds
content digests; evaluation uses private copies and rejects missing files,
symlinks, hardlinks, duplicate content, overlapping splits, and input drift.
The complete corpus is limited to 64 MiB, with at most 10,000 files per fixture.

The host matches CWE, full relative file path, and location independently;
the probe's `surfaced` flag cannot award itself a pass.
All findings on negative controls count toward false positives, including unrelated classes.
The baseline is the captured lens content, not a label such as “baseline.”
Repeated development and held-out results, finding evidence, cost, and latency
are retained in the receipt. Missing measurements are inconclusive, not free.
Token costs are priced usage estimates, not provider invoices.

Future hunts retain the installed lens-version digest alongside each finding
record, dropped finding, and timeout coverage gap. The JSONL hunt corpus retains
that identity with subsequent verifier outcomes. A scan copies its lens set
before dispatch: editing or retiring an overlay cannot relabel an active run.
Captured observations retain source-revision and detector-version provenance.
Refuted findings and known duplicates are not relabelled as missed coverage.
Processed observations retain installed versions, validation reports, synthesis
warnings, and rejection reasons, including runs that promoted nothing.

Automatic promotions retain the report and installed archetype under
`validation-receipts/<lens-version-digest>.json` beside the overlay registry.
Existing corpora without the required identity and control metadata must be
curated before they can pass; the old permissive format is not silently accepted.

Every probe, including an injected one, must expose the actual baseline lens
snapshot and its canonical digest. Receipts bind candidate content, corpus
metadata and byte digests, both repeated lanes, original finder evidence, and
per-probe usage. Registration checks that the receipt belongs to that exact
candidate and rejects altered receipt contents. These checks establish local
evaluation provenance, not independent proof that a discovered vulnerability
is exploitable. The usual verification process remains separate.

The TUI consumes approved observations without merging held-out fixtures into
development data. Completed evaluations, including rejections and dry runs,
retain their results rather than automatically rerunning the same input every
poll. On startup, the consumer can recover a claim whose recorded owner is
demonstrably dead in the same process scope. Live owners and unverifiable,
legacy, or different-scope claims are not automatically released. Stop the old
worker before manually recovering those claims with:

```bash
0sec evolve feedback status --json
0sec evolve feedback release --id <observation-id> --claim-token <token>
```

Queue and overlay writers fail promptly on lock contention. If a process dies
while holding a `.lockdir`, remove that empty lock directory only after
confirming no writer remains. Do not clear a live writer's lock.

Session extension snapshots restore descriptor identities atomically.
Function-valued contributed guards cannot be serialized: resume fails rather
than dropping those restrictions. Descriptors are not executable tool bodies;
source execution belongs in the isolated evolution-worker path.

## Skill and router artifact promotion (LearningPromotion bridge)

Skills and triage-router models are promoted through the evolution registry's
authorization gate. The **`artifact-bridge.mjs`** script (sibling to
`check_skill.mjs` in `packages/benchmark/scripts/train/`) shells out to the
core `authorizeEvolutionArtifact` function:

```bash
node artifact-bridge.mjs authorize \
  /path/to/evolution-store \
  <version-id> \
  /tmp/candidate-skill.yaml \
  agent/skills/vulnerabilities/sqli-advanced.yaml \
  skill
```

The skill-refine and active-learning loops require three flags when `--promote`
is passed:

| Flag | Description |
|---|---|
| `--evolution-store <path>` | Path to the evolution store (registry.json + receipts + snapshots) |
| `--evolution-version <id>` | Registry version UUID that authorized this artifact (must be currently active) |
| `--evolution-artifact <path>` | Relative path within the version's immutable snapshot |

Without all three flags and matching active-version authorization, promotion
is refused. Authorize the exact bytes to be installed, not a precursor that is
later retrained or transformed.

The Python loops install through `artifact_install.py`: it verifies the
candidate bytes against the bridge's returned digest and publishes atomically.
Changing the candidate after authorization fails instead of installing
unapproved bytes. The bridge alone authorizes; it does not install.

## Executable plugin evolution

Model-authored executable plugins (the `ExecutablePluginManager` in
`packages/core/src/plugins/executable.ts`) support their own evolution path.
Calling `manager.evolve(pluginId, profile, deps, context)` runs the improvement
loop over the plugin's active version snapshot, sharing the same sandbox
isolation, evaluation receipt, and promotion gate as the standard evolution
pipeline.

Key differences from standalone evolution:

- **Snapshot source**: the evolution source root is the plugin's sealed
  snapshot, not an operator-controlled working tree. Only the files included
  in the snapshot are visible to the model.
- **Backend locked**: the evolution profile must use the same backend (Docker or
  smolvm) and the same immutable image as the active version. Cross-backend
  promotion is refused.
- **Evidence status**: a directly submitted version has `evidenceStatus:
  "structural"`; an evolved and promoted version has `evidenceStatus:
  "measured"` with its evolution receipt digest recorded in the version record.
- **Evolution store**: each plugin gets a dedicated evolution store under
  `<manager-root>/evolution/<pluginId>/<evolutionEpoch>/<profileId>`.
- **Rollback**: a promoted evolution version can be rolled back via
  `manager.rollback()` like any other version; the evolved snapshot and receipt
  are retained.

The `evolve` method accepts an optional `maxAlternativeParents` field in the
profile to explore bounded compatible retired and rejected/staged candidates as
offline source parents, ranking development outcomes only. When set, iteration
refreshes source after promotion; the `parentId` tracks the active baseline,
`alternativeParentId` records source provenance.

## External hosts

DSH, Codex, and Claude Code are optional MCP clients. They may present a narrow
0sec tool profile, but they don't own promotion, scope, evidence, or replay. See
[Architecture](/architecture/#mcp-integration) and
[Benchmark methodology](/methodology/).

## Live lifecycle checks

After building the CLI and its dependencies, run the real provider-backed checks:

```bash
node scripts/smoke-source-evolution.mjs
node scripts/smoke-lens-evolution.mjs
node scripts/smoke-codebase-learning.mjs
node scripts/smoke-source-citation.mjs
node scripts/smoke-executable-plugins.mjs
```

By default, the source check requires a non-root account with Docker access and the
`node:22-alpine` image. It exercises generated source, independent evaluation,
approval, canaries, deployment, existing-reader pinning, and rollback using a
small credential-detector benchmark. It does not measure general scanner quality.

The executable plugin smoke check (`smoke-executable-plugins.mjs`) requires the
built `@0sec/core` package and a local Docker daemon (or smolvm with
`0SEC_SMOLVM_IMAGE_ARCHIVE`). It exercises the full lifecycle: submission,
execution, TypeScript argument passing, multi-owner plugins, skill composition
with `Promise.all` broker calls, source replacement, retained version discovery,
persisted failure counters, cold manager restore, rollback, nested call-budget
termination, and malformed-source rejection. An optional
`0SEC_EVOLVE_REAL=1` flag enables a real provider evolution stage using the
configured model.

This smoke does not yet qualify live root-driver replacement, browser/desktop
registration, workspace-trusted ESM execution, or long-horizon crash recovery.
Those need their own real integration scenarios, including a task that
continues across generation changes without reconstructing its session.

A local plugin smoke or a provider-backed candidate-generation check does not
qualify the new lifecycle with hosted inference. That integration remains
candidate-stage and production-disabled. Hosted parent SDK calls consume
inference credit, including evolution calls; child-route inheritance and
arbitrary trusted ESM clients are not covered by a blanket parent-broker
guarantee. See [hosted inference and evolution accounting](/architecture/#hosted-inference-and-evolution-accounting)
for the routing, pricing, and qualification boundaries. Self-Harness's
model-specific results establish neither universal gains nor launched billing.

If the account already has approved Docker group membership but a persistent
agent process predates it, restart the session and its broker. A single check
can use the existing group without changing socket permissions:

```bash
sg docker -c 'node scripts/smoke-executable-plugins.mjs'
```

This is not Docker provisioning or a grant of group membership. Do not make the
Docker socket or `/dev/kvm` world-writable, and do not store sudo credentials in
the repository.

To exercise that same source lifecycle with smolvm, use `env` (the setting names
start with a digit and therefore are not POSIX shell variable identifiers):

```bash
env 0SEC_EVOLUTION_BACKEND=smolvm \
  0SEC_SMOLVM_IMAGE_ARCHIVE=/absolute/path/to/node.tar \
  node scripts/smoke-source-evolution.mjs
```

The provider-free runtime qualification is separate:

```bash
node scripts/smoke-smolvm.mjs /absolute/path/to/node.tar
```

It checks real guest stdin/argv, nonzero exits, stream separation, source
protection, fresh workspaces, credentials, ambient configuration, host loopback
denial, storage exhaustion, identity mismatch, absent runtimes, cancellation,
deadlines, output floods, and process teardown. It does not skip missing runtime
prerequisites. `pnpm test:smolvm:e2e` runs it when
`0SEC_SMOLVM_IMAGE_ARCHIVE` is set in the process environment.

The lens check exercises synthesis, labelled positive/held-out/clean fixtures,
promotion, next-reader reload, and retirement. Both consume real provider usage,
disable cross-run hunt memory, and fail rather than reporting skipped work as success.
The codebase-learning check uses a separate temporary memory store and real model
runs to learn a source-grounded note, recall it in a later run, and invalidate it
after a cited file changes. It tests the lifecycle, not a measured accuracy gain.
The citation check deliberately submits an out-of-range source annotation,
verifies rejection before database persistence, and lets the real model read the
file and submit a valid source-only finding. Interactive `save_finding` returns
repairable validation errors instead of saving invalid references as false
positives. `read_file` and annotation validation agree on actual source lines:
a terminal newline does not create another line, and an empty file has zero.
Post-hoc CLI parsing still retains invalid claims as downgraded findings.

The trusted-main **Live evolution E2E** workflow accepts `lane=source`,
`lane=lens`, `lane=codebase`, `lane=citation`, or `lane=all` and retains measured
outcomes and failure logs. `pnpm test:evolution:e2e` runs all four local checks.