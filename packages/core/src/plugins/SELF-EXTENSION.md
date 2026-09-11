# Model-authored self-extension registry

Status: **the session registry is implemented; executable plugin dispatch also
exists in a separate module.** This page describes `self-extension.ts`, not the
complete plugin host.

The registry validates declarations and applies registration policy. It remains
inert unless constructed with `enabled: true`; the shared session policy defaults
to self-extension enabled and supplies that choice to the registry. Do not
confuse a low-level constructor default with the product's YOLO/self-extension
defaults. `ExecutablePluginManager` in `executable.ts` supplies runnable
model-authored TypeScript tools, executable skills, composition, source
evolution, next-call activation, and rollback in configured guests.

The registry itself does not compile, evaluate, import, or invoke source code.
That separation is not a ban on live self-writing: see the
[live harness contract](../../../../docs/src/content/docs/improvement-plane.md#live-harness-component-contract)
for agent-driver and UI replacement, shared frontend contributions, and the
separate workspace-trusted execution tier.

---

## 1. Registry policy versus component composition

[DSH](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cordis-primer.md)
uses Cordis services, reversible registrations, and around-middleware to compose
the agent itself. Its waterfall listeners can delegate with `next()` or replace
the result. That flexibility is useful for behavior composition, but is not an
authorization boundary against code running with host permissions.

0sec separates those responsibilities. Live component composition can replace
agent behavior; this particular registry's guard interface remains deny-only.
Sandboxed components use brokered capabilities. Separately trusted host
components require an explicit workspace grant and are not made safe merely
by passing through a JavaScript API.

The registry's `guards.ts` interface is:

```ts
type ToolGuard = (ctx: GuardContext) => string | null | undefined;
```

A string is a denial reason. `null`/`undefined` is abstention. **There is no
value in that codomain that means "allow."** A contributed guard cannot vote to
allow, cannot cancel another guard's denial, and cannot stop the chain —
`evaluateGuards` runs every guard and only ever appends reasons.

This is a property of the registry's authorization interface, not a reason to
restrict the entire harness to tool declarations and guards.

---

## 2. This registry's contribution payload

```ts
interface ExtensionSubmission {
  manifest: unknown;              // 1. tool definitions, capabilities mandatory
  guards?: readonly ToolGuard[];  // 2. deny-only guards
  origin?: "model" | "operator";  //    audit metadata; grants nothing
}
```

Within this registry payload, there are no hooks, interceptors, middleware,
`next()`, event listeners, or mutable handles to the session and its settings.
Those are not implicit powers of a tool declaration: no field in this payload
can carry them. A submission that
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

### 3.6 Gated by an explicit construction flag

The registry is inert unless constructed with `enabled: true`, and there is no
setter — nothing reachable from a tool call can flip it mid-session. Anything
other than the boolean `true` fails closed.

Shared session defaults are declared in `packages/shared/src/desktop-console.ts`.
Workspace-trusted code execution requires a separate operator grant and is not
enabled by this registry flag.

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

1. **Registration alone does not make a tool runnable.** Use
   `ExecutablePluginManager` for the implemented generated-code execution path.
2. **A contributed guard is code.** The registry only ever accepts an
   *already-constructed function*; it never turns model-authored *text* into
   one. The wiring **must not** hand it `new Function(modelSource)` evaluated
   in-process — that reintroduces arbitrary in-process execution and the
   frozen-context hardening would be the least of the problems. Model-authored
   guard source must not be evaluated as a host callback by this registry.
   Guest execution and explicitly trusted host execution are separate contracts.
3. **Guards are synchronous and untimed.** A contributed guard that loops
   forever hangs the authorization path. It cannot *widen* anything — denial of
   service, not privilege — but it is a real availability risk, and the guard
   cap bounds count, not runtime.
4. **The prompt surface still grows.** Even ungated, a registered tool's name and
   description reach the model's prompt. That is attacker-influenceable text if
   the model was injected. The audit stream exists so the operator can see it.
5. **Scope of this module:** it accepts bounded declarations and deny-only
   guards, not arbitrary source. Executable dispatch exists in `executable.ts`;
   a registry result alone is not proof of sandboxing or measured improvement.

---

## 5. Integration responsibilities

- Construct the registry with the operator's self-extension setting and reserved
  built-in tool names. A model submission cannot enable itself.
- Resolve contributed tool capabilities through `gateFlagsForTool` and the
  existing authorization path; an unknown tool is not an ungated tool.
- Register and dispatch executable bodies through `ExecutablePluginManager`,
  not an in-process `eval` in the declaration registry.
- Use the typed registry audit events for registration/rejection/revocation.
  Executable version activation and live harness generations have distinct
  identities and lifecycle events; do not substitute an audit entry for the
  active frontend catalog.
- Keep workspace-trusted code authorization separate from model registration.
- For current controls, defaults, and qualification commands, use
  [Improvement Plane](../../../../docs/src/content/docs/improvement-plane.md).
