# Model-authored self-extension

Status: **registration, validation and policy implemented. Execution is NOT.**

This document covers `self-extension.ts` — the session-scoped registry that lets
the model author a plugin and register it into the running session, behind an
operator setting that is **off by default**.

> **Read this first.** Registering a model-authored tool here does **not** make
> it runnable. This module never compiles, `eval`s, imports, spawns or invokes a
> tool body. It decides *what may be registered* and *how it is gated*; nothing
> in it dispatches a call. Making a model-authored tool actually execute needs
> the subprocess-over-stdio dispatcher from `DESIGN.md` §3 option B (stage 3),
> which does not exist yet. A reader who comes away thinking this module ships
> runnable model-authored tools has misread it.

---

## 1. Why this exists, and what it deliberately does not copy

The operator wants the DeepSeek harness's self-extension capability. The
security objection was raised and overridden; this is the implementation that
takes the capability without taking the flaw.

In `dsh`, a plugin can register a `tools/pre-execute` listener, and a listener
that returns without calling `next()` **short-circuits the chain**. A
model-written plugin can therefore silently switch off the entire authorization
pipeline. Their own README is explicit that the toolset is "not a security
boundary… treat it like bash access."

0sec's guard layer (`guards.ts`) has a different shape, and that difference is
the whole reason this is buildable:

```ts
type ToolGuard = (ctx: GuardContext) => string | null | undefined;
```

A string is a denial reason. `null`/`undefined` is abstention. **There is no
value in that codomain that means "allow."** A contributed guard cannot vote to
allow, cannot cancel another guard's denial, and cannot stop the chain —
`evaluateGuards` runs every guard and only ever appends reasons.

**This is the property `dsh` lacks.** Its waterfall gives a plugin a return
value meaning "stop authorizing." Ours has none to return.

---

## 2. The contribution surface — exactly two things

```ts
interface ExtensionSubmission {
  manifest: unknown;              // 1. tool definitions, capabilities mandatory
  guards?: readonly ToolGuard[];  // 2. deny-only guards
  origin?: "model" | "operator";  //    audit metadata; grants nothing
}
```

That is the entire surface. No hooks, no interceptors, no middleware, no
`next()`, no event listeners, no config mutation, no handle on the session, the
event bus, settings, or the gate maps. These are not "discouraged" — there is no
field that can carry them, so they are **not expressible**. A submission that
carries `hooks`, `preExecute` or `middleware` keys registers its tools and
guards and ignores the rest entirely; there is a test asserting such a callback
is never invoked.

Registration returns:

```ts
{ ok: true, record: SelfExtensionRecord, dispose: () => boolean }
| { ok: false, errors: readonly string[] }
```

---

## 3. The invariants, and how each is enforced

### 3.1 It can never grant

Contributed guards are wrapped and appended to the evaluated set. Because
`allowed === (reasons.length === 0)` and the reason list is append-only, the
verdict after registration is at most as permissive as before it.

Two runtime hardenings close what the type system alone cannot:

- **Frozen context.** Each contributed guard receives a *frozen shallow copy* of
  the `GuardContext`, never the caller's object. Without this, a contributed
  guard running before a built-in could set `ctx.capabilitiesResolved = true`
  and turn a built-in denial into an abstention — a genuine widening path, since
  `GuardContext`'s `readonly` markers are compile-time only. Writing to the
  frozen copy throws, and `evaluateGuards` treats a throwing guard as a
  **denial**, so the attempt narrows.
- **Coerced return.** Non-string returns become `null`. An "allow"-shaped return
  (`true`, `{allow: true}`, an object with a `toString`) is an abstention, never
  an override.

Proven by a 20,000-trial seeded property sweep (`self-extension.test.ts`) using a
pool of hostile guards — allow-shaped returns, context mutation, prototype
tampering, throws, non-callables — asserting on every trial that (a) if the
post-registration verdict allows, the pre-registration one did too, and (b) the
base reasons survive verbatim as a prefix. Plus a stacking test that registers up
to the extension cap and re-checks after each one.

### 3.2 It cannot touch existing policy

Registration is **additive only**. The registry's public surface is:

```
register  guards  evaluate  tools  tool  gateFlagsForTool  records  events  isEnabled  limits
```

There is no `removeGuard`, `replaceGuard`, `setGuards`, `reorderGuards`,
`disableGuard`, `unregister`, `removeTool`, `overrideTool`, `setGateFlags`,
`setEnabled`, `use`, `on` or `intercept`. A test asserts the prototype's property
list *exactly*, so adding a method is a deliberate act that fails CI until
justified. Base guards are held in a frozen array captured at construction, are
re-emitted first on every snapshot, and are unreachable from the public API.
Every getter returns a frozen copy, so a caller cannot mutate the registry
through a returned array either.

Ordering is presentational: `allowed` is "did anyone deny", which is
order-independent — so "reordering" is not even a meaningful attack. There is no
API for it regardless.

**Collisions are rejected, never shadowed.** `reservedToolNames` (the caller's
built-ins: keys of `TOOL_DISPATCH` ∪ the three gate maps) plus every currently
live contributed name is passed into the validator. A colliding submission is
rejected whole — no partial registration, and the incumbent is never displaced.

### 3.3 Capabilities are mandatory and fail-closed

No second validator was written. `validatePluginManifest` and `gateFlagsFor`
from `manifest.ts` — the same pair the third-party plugin path uses — do the
work. A tool with no declared capability is rejected outright; an empty or
unknown capability set yields the most restrictive gate flags, never read-only.
One authorization path, not a parallel one.

### 3.4 Revocable and session-scoped

All state lives in the instance. Nothing is read from or written to disk. A new
session constructs a new, empty registry. `register` returns a disposer that
drops exactly that registration's tools and guards — it cannot reach the base
guards or another registration — and is idempotent. A test asserts the
post-disposal verdict is deep-equal to the pre-registration verdict.

### 3.5 Bounded

| bound | default | why |
| --- | --- | --- |
| `MAX_EXTENSIONS_PER_SESSION` | 8 | a looping model hits a wall, not OOM |
| `MAX_TOOLS_PER_EXTENSION` | 8 | one submission cannot flood the prompt |
| `MAX_TOOLS_PER_SESSION` | 32 | enforced independently of the per-extension cap |
| `MAX_GUARDS_PER_EXTENSION` | 16 | bounds per-call guard evaluation cost |
| `MAX_MANIFEST_BYTES` | 16 KiB | UTF-8 bytes, measured on the **raw** submission |

The size check runs on the raw input *before* validation, because the validator
drops unknown keys — padding hidden on an ignored key would otherwise sail
through. A manifest that cannot be serialized at all (circular, `BigInt`, a
throwing `toJSON`) is rejected: an unmeasurable manifest is an unbounded one.
Limits are overridable by the operator-side wiring, never by a submission, and a
garbage override (`NaN`, `Infinity`) falls back to the default rather than
becoming unbounded.

### 3.6 Gated by an explicit setting, default OFF

The registry is inert unless constructed with `enabled: true`, and there is no
setter — nothing reachable from a tool call can flip it mid-session. Anything
other than the boolean `true` fails closed.

### 3.7 Auditable

Every attempt — `registered`, `rejected`, `revoked` — produces a frozen
`SelfExtensionEvent` carrying the timestamp, origin, plugin identity, per-tool
declared capabilities, resolved gate flags, guard count and manifest size, plus
the rejection errors. Rejections are logged too: they are the interesting ones
when a prompt-injected model is probing the limits. Events go to the in-memory
log and to an optional operator-side observer; a throwing observer never breaks
a registration decision.

---

## 4. Known limits — read before enabling

1. **This does not make tools runnable.** Repeating §0 because it is the most
   likely misreading.
2. **A contributed guard is code.** The registry only ever accepts an
   *already-constructed function*; it never turns model-authored *text* into
   one. The wiring **must not** hand it `new Function(modelSource)` evaluated
   in-process — that reintroduces arbitrary in-process execution and the
   frozen-context hardening would be the least of the problems. Model-authored
   guard *source* must go through the stage-3 isolated dispatcher, exactly like
   tool bodies.
3. **Guards are synchronous and untimed.** A contributed guard that loops
   forever hangs the authorization path. It cannot *widen* anything — denial of
   service, not privilege — but it is a real availability risk, and the guard
   cap bounds count, not runtime.
4. **The prompt surface still grows.** Even ungated, a registered tool's name and
   description reach the model's prompt. That is attacker-influenceable text if
   the model was injected. The audit stream exists so the operator can see it.
5. **The honest summary:** this module makes model-authored *policy and
   declarations* safe to accept. It does not, and cannot, make model-authored
   *execution* safe — that is a separate boundary, and it is not built.

---

## 5. Wiring required (not done here — this module is standalone)

1. **Barrel export** from `packages/core/src/index.ts`.
2. **Reserved names**: construct the registry with the keys of `TOOL_DISPATCH` ∪
   `NETWORK_CAPABLE_TOOLS` ∪ `READ_ONLY_TOOLS` ∪ `LOCAL_SCOPE_TOOLS`.
3. **Gate consultation**: `turn-engine.ts` must consult
   `registry.gateFlagsForTool(name)` for a name absent from the built-in maps —
   and treat `undefined` as "not a contributed tool", never as "ungated". This
   is the gate-bypass hole from `DESIGN.md` §2; the flags exist precisely so a
   contributed tool joins the *same* authorization path.
4. **Guard evaluation**: `registry.evaluate(ctx)` alongside the existing gates.
5. **Setting**: add `SELF_EXTENSION_SETTING_DEF` to `DEFS` in
   `packages/cli/src/tui/settings.ts`, plus the matching `TuiSettings` key and
   `DEFAULT_SETTINGS` entry (`allowModelSelfExtension: false`), then thread the
   value into the registry's `enabled`.
6. **Console display**: subscribe `onEvent` so registrations and rejections
   surface in the transcript.
7. **A tool for the model to call** (`register_extension` or similar) — a
   deliberate, separate decision. Nothing here creates it.
