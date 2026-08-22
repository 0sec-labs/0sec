# Hub — peer messaging and coordination

Status: design + increment 1 (peer roster) shipped. Everything past increment 1
is proposed, not built.

The hub lets concurrently running agents — and separate 0sec sessions working the
same project directory — see one another and exchange short messages, in the
spirit of the Oh My Pi (OMP) hub (`send` / `wait` / `inbox` / `list` / `jobs` /
`cancel`). This document describes what 0sec has today, the target model, the
transport trade-offs and recommendation, the security analysis, and a staged
plan whose first increment is `registry.ts`.

---

## 1. What exists today

0sec has **no hub and no peer messaging**. The only multi-agent primitive is a
one-way, single-depth fan-out.

### `spawnAgent` / `spawnAgents` — `packages/core/src/agent/tools.ts`

- `ToolExecutor.spawnAgent(args)` (~line 4285) runs **one** child agent to
  completion synchronously: it builds a lifecycle base
  (`buildSubagentLifecycleBase`, ~4139), calls `runOneSubagent` (~4187), then
  merges the child's `findings` into `this.ctx.findings` on return.
- `ToolExecutor.spawnAgents(args)` (~4328) is the concurrent variant: it
  normalizes up to `SUBAGENT_MAX_FANOUT = 8` task specs, resolves child deps
  once (`loadSubagentDeps`, ~4180), runs them bounded-concurrently
  (`mapWithConcurrency`, default `SUBAGENT_CONCURRENCY = 4`, override
  `0SEC_SUBAGENT_CONCURRENCY`), and merges findings **after the pool joins**, in
  input order, so there are never concurrent writers to `this.ctx.findings`.
- `runOneSubagent` (~4187) calls `runNativeAgentLoop` with a **hardcoded child
  tool set `["bash", "save_finding", "done"]`** that deliberately excludes
  `spawn_agent`/`spawn_agents` — a **depth guard** (~4211) that bounds fan-out to
  a single level so agents can never recurse into an unbounded tree.
- The child **inherits** the parent's `target`, `scope`, `authConfig`, and the
  shared `costLedger`/`costCeilingUsd`/`costModel` (so child spend is on the
  parent's ledger and trips the same ceiling). The child gets `db: null` (no
  concurrent SQLite writers) and never receives the stateful auth `session`
  object (concurrent children would race its cookie state).

**Key properties / limits of today's model:**

- **One-way and terminal.** The parent talks to a child only by handing it a
  task string up front; the child talks back only via merged findings + a summary
  on completion. There is **no mid-flight messaging**, no child→child talk, no
  parent→running-child talk.
- **In-process only.** Children are async calls inside the parent process. There
  is **no notion of a second 0sec session**, and nothing is discoverable across
  processes or across a shared directory.
- **Single depth.** By design (the depth guard). A hub does not need to change
  this to add peer messaging.

### Lifecycle events — `packages/core/src/events/bus.ts`

- `SubagentLifecyclePayload` (~465) + the `subagent_lifecycle` event variant
  (~511). A child emits `queued → running → completed|failed` (or
  `queued → failed` if startup fails). The payload carries `agent_id` (unique
  within the parent scan), `parent_scan_id`, `task`, `max_turns`, and on
  terminal events `turns`/`findings`/`summary`/`error`, plus inherited
  `scope_rules` when scope is active.
- The bus is an **in-process EventEmitter**. Consumers (CLI TUI, cloud trace)
  filter by `parent_scan_id`. These events are **observability, not a channel** —
  they are fire-and-forget notifications a parent's UI renders; nothing routes a
  reply back to an agent through them, and they do not cross the process
  boundary.

Net: 0sec has a spawn-and-merge fan-out with lifecycle telemetry. It has none of
the hub's roster, addressing, mailboxes, `wait`, or cross-session discovery.

---

## 2. Target model

### Roster

A **roster** is the set of addressable peers. Two kinds (`PeerKind`):

- `session` — a top-level 0sec process. The primary session in a directory is
  named **`Main`** (matching OMP); additional sessions get suffixed ids
  (`Main-2`, …) via `nextPeerId`.
- `subagent` — a child spawned by a session; addressed by its task/agent id.

Each `PeerRecord` carries `id`, `kind`, `pid`, `cwd` (the project directory),
`lastSeen` (heartbeat epoch ms), and an optional `label` (e.g. the engagement
target). Liveness is **derived**, not stored: a peer is `stale` once
`now - lastSeen > ttl` (`DEFAULT_PEER_TTL_MS = 90s`). This is increment 1,
implemented in `registry.ts`.

### Addressing

- Peers are addressed by **exact roster id** (no globs, no broadcast-by-default),
  matching OMP. Ids are sanitized to `[A-Za-z0-9._-]`, no leading dots, ≤64
  chars, so an id can never be a path (`../…`), contain whitespace/control
  chars, or be reused as a transport-path traversal vector.
- The sender always knows its own id; `list` returns the current roster so an
  agent can discover who to address.

### Message delivery

Following OMP's shape:

- **`send`** — fire-and-forget, non-blocking. Deliver a short prose message to a
  peer's mailbox. Large payloads are passed **by URI/path reference**, never
  inlined (keeps the spool small and avoids duplicating evidence blobs).
- **`inbox`** — drain/read this peer's pending messages.
- **`wait`** — block until the FIRST of: an incoming message, a watched job
  finishing, or a timeout. Returns which of the three fired.
- **`list`** — the live roster (post-prune).
- **`jobs` / `cancel`** — inspect and cancel jobs (later increment; needs process
  supervision).

Messages are **advisory prose**. They carry no authority (see §4).

### Job lifecycle

A "job" is a running peer (a spawned subagent, or a whole session) that another
peer can watch. Minimum states: `running → done|failed|cancelled`. `wait` can
watch a job id and return when it leaves `running`. This reuses the existing
`subagent_lifecycle` transitions as the in-process source of truth and mirrors
them into the transport for cross-session visibility.

### Cross-session discovery

A **second 0sec session in the same directory** discovers the first through a
**shared rendezvous keyed by the real, canonical project path**:

1. On startup a session computes its rendezvous key from the resolved project
   directory (realpath, to defeat symlink aliasing) and its per-user state root
   (`homeStateDir` from `@0sec/shared`).
2. It reads any existing roster entries at that rendezvous, **prunes stale ones**
   (`pruneRoster`), and reconciles its own entry in (`reconcileRoster`), picking
   a unique id with `nextPeerId` (so the second session becomes `Main-2` if
   `Main` is live, or reclaims `Main` if the previous one is stale/gone).
3. It heartbeats `lastSeen` periodically; peers that stop heartbeating age out.
4. To talk to a peer it writes to that peer's mailbox under the same rendezvous.

No central daemon is required for discovery — the rendezvous location is derived
deterministically from `(user, project path)`, so two sessions independently
compute the same place to look.

---

## 3. Transport options and recommendation

Three candidates for how roster + mailboxes are persisted and gossiped across
processes.

### A. Filesystem-backed spool under the per-user state dir

Roster and per-peer mailboxes as files under
`homeStateDir()/hub/<project-hash>/` (NOT under the project tree — see §4).
Roster is a small JSON file (or a directory of one-file-per-peer); each peer has
an inbox directory into which senders write one file per message
(`<ts>-<sender>-<rand>.msg`), and the recipient reads then unlinks them.

- **Crash-safety:** excellent. State is durable across a crash; a dead peer
  leaves a stale roster entry that the next reconcile prunes by TTL. No process
  needs to be alive for the rendezvous to exist.
- **Stale-peer cleanup:** TTL + heartbeat (increment 1 already models this).
  Optionally confirm death via `pid` liveness as a belt-and-braces check.
- **Concurrent writers:** the hard part. Use **atomic single-writer patterns**:
  one file per message (create-with-`O_EXCL` + unique name → no lost writes, no
  torn reads); for the shared roster JSON, write-to-temp-then-`rename` (atomic on
  POSIX) or one-file-per-peer so each session only ever writes its OWN file. A
  message read is read-then-unlink; delivery is at-least-once, dedup by filename.
- **Security fit (best):** **no network listener at all**; permissions are
  straightforward (`0700` dir, `0600` files) and enforced by the OS per-user.

### B. Unix domain socket with a broker elected by the first session

First session binds a UDS at the rendezvous and becomes the broker; others
connect as clients; the broker routes messages and holds the roster in memory.

- **Crash-safety:** poor. If the broker (first session) dies, the whole hub dies
  — surviving sessions must detect the dead socket, race to re-elect a broker,
  and rebuild state that was only in the dead process's memory. Election races
  and stale socket files are fiddly to get right.
- **Stale-peer cleanup:** easy while the broker lives (dropped connection =
  peer gone), but useless once the broker is the thing that died.
- **Concurrent writers:** trivially serialized by the single broker — its one
  genuine advantage.
- **Security fit:** UDS with `0600` and per-user dir is local-only and safe from
  the network, but it is a **live listener** with a connection-handling
  attack surface, and the election/liveness machinery is a lot of code to get
  correct. Higher complexity, worse failure mode.

### C. In-process-only bus (no cross-session)

Extend the existing `eventBus` into a request/reply channel among agents in ONE
process.

- **Crash-safety / concurrency:** trivial (single process, single thread).
- **Fatal limitation:** **cannot satisfy the core requirement** — a second 0sec
  session in the same directory. It is a strict subset of the target.

### Recommendation: **A (filesystem spool), with C as its in-process fast path.**

The filesystem spool is the right transport because it is **brokerless and
crash-safe** — the rendezvous survives any single process dying, and stale peers
are reaped by the TTL/heartbeat the roster already models, whereas the UDS broker
(B) collapses the moment the first session exits and drags in election-race
complexity for its one benefit of serialized writes. Concurrent-writer safety on
the filesystem is a **solved problem** using one-file-per-message with `O_EXCL`
unique names plus atomic temp-then-`rename` for the roster, so we get
correctness without a central serializer. Critically for a **security tool** it
needs **no network listener of any kind**, and OS file permissions
(`0700`/`0600`) under the **per-user state dir** — never the shared, possibly
world-readable project tree — give us a message spool no other local user can
read or inject into. In-process peers still short-circuit through the existing
`eventBus` (option C) as a latency optimization, with the filesystem used only
when a message must cross the process boundary; the two share one roster.

---

## 4. Security analysis

0sec is a security tool operating against authorized targets, often on shared or
multi-user machines. The hub must add coordination **without adding authority**.

1. **A message must never widen scope or approve a tool call.** Messages are
   **inert prose data**, delivered into an agent's context as untrusted input —
   they are routed through the same untrusted-input sanitization the codebase
   already applies (`untrusted-sanitizer`), and they are NOT commands. Scope
   (`ctx.scope`) and any tool-approval/consent gates remain owned by the
   receiving session and are evaluated **exactly as today**; a peer's message is
   an input to reasoning, never an instruction that bypasses a gate. Concretely:
   there is no hub op that mutates another peer's `scope`, `authConfig`, or
   approval state — the roster and mailboxes carry data only. This must be a
   tested invariant, not just a convention: a message asking to "add
   evil.com to scope" changes nothing until a human re-approves scope in the
   receiving session.

2. **No cross-user read or injection on a shared machine.** The spool lives under
   the **per-user state dir** (`homeStateDir`), never under the project tree
   (which may be group/world-readable, a shared clone, or a container bind
   mount). The hub root is created `0700` and message/roster files `0600`, so the
   OS prevents another local user from reading or writing the spool. **No network
   listener** is ever opened by default, so there is no remote surface at all.
   The rendezvous key is derived from the **realpath** of the project dir to stop
   symlink games from pointing one user's session at another's spool.

3. **Stale / hostile roster entries.** Every roster consumer prunes by TTL
   (`pruneRoster`) before trusting the roster, so a crashed peer stops being
   addressable within `DEFAULT_PEER_TTL_MS`. Ids are **sanitized on the way in**
   (`sanitizeId` / `nextPeerId`): no path separators, no whitespace, no control
   characters, no leading dots, bounded length — so a malicious or corrupt id can
   never traverse out of the spool directory, spoof a path, or inject terminal
   control sequences into an operator's `describeRoster` output. Because the
   spool is already `0700`/per-user, the only writer of roster entries is the
   same user's own sessions; the sanitization is defense-in-depth against a
   corrupt/hand-edited file rather than a hostile remote peer. A peer id
   collision (a restarted session reusing `Main`) is resolved by
   `reconcileRoster` replacing in place — a stale entry cannot shadow or
   duplicate a live one.

Residual risks to revisit as later increments land: at-least-once delivery means
a recipient must be idempotent to duplicate messages; a compromised same-user
process is already inside the trust boundary (unchanged from today); and
message-content sanitization must keep pace with any new tool that consumes
inbox text.

---

## 5. Staged plan

Each increment is independently shippable and ordered by dependency. Honest
sizing: **full OMP parity is a large project** (mailboxes, `wait` semantics
across process + job sources, process supervision, `cancel`, broker-free liveness
— easily several focused PRs). The increments below are deliberately small so
each lands and earns its keep on its own.

- **Increment 1 — Peer roster (SHIPPED, `registry.ts`).** Pure data model +
  reconciliation: `PeerRecord`, `isStale`, `reconcileRoster`, `pruneRoster`,
  `nextPeerId`, `describeRoster`, `sanitizeId`. No I/O. Fully unit-tested. This
  is the vocabulary every later increment builds on.

- **Increment 2 — Filesystem rendezvous + heartbeat.** Persist/load the roster
  under `homeStateDir()/hub/<realpath-hash>/` with `0700`/`0600`, atomic
  temp-then-`rename` writes, a per-session heartbeat that updates `lastSeen`, and
  `list` (load → prune → describe). No messaging yet. Wires the pure core to
  disk; makes a second session **discoverable**.

- **Increment 3 — Mailboxes + `send`/`inbox`.** One inbox dir per peer; `send`
  writes one `O_EXCL` file, `inbox` reads-then-unlinks. Fire-and-forget,
  at-least-once, prose + URI references only. Route inbound messages through the
  untrusted-input sanitizer before they reach an agent's context. In-process
  peers short-circuit via `eventBus`.

- **Increment 4 — `wait`.** Block on the first of {incoming message, watched job
  terminal, timeout}. Job state sourced from the existing `subagent_lifecycle`
  transitions in-process and from the roster/mailbox cross-process.

- **Increment 5 — Jobs + supervision + `cancel`.** Full job registry, `jobs`
  listing, cooperative `cancel`, and pid-liveness confirmation layered on top of
  TTL. Largest increment; brings the hub to rough OMP parity.

The `hub/` module owns its own code; wiring the exported hub tool into the
`ToolExecutor` and the `index.ts` barrel is the integrating change that lands
alongside increment 3, when there is a tool worth exposing.
