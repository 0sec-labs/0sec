/**
 * Structured TODOS / plan capability for agent runs (Claude Code `TodoWrite` /
 * oh-my-pi `Todos` shape).
 *
 * This is a DIFFERENT, complementary capability from the action-based task
 * ledger in `task-ledger.ts` (the `plan` tool). Where the ledger is a mutation
 * log (`add` / `start` / `complete` / `drop` a single task at a time, with
 * stable ids anchoring drift detection), this module is a FULL-STATE,
 * idempotent plan: the model re-declares the ENTIRE plan on every write
 * (`update_todos`), exactly like `TodoWrite`. The last write wins; there is no
 * per-task command surface and nothing to keep in sync across turns. That
 * shape is what the TUI wants to render as a live tree — each write is a
 * complete snapshot it can diff and repaint.
 *
 * Design deliberately mirrors `tool-health.ts` (0sec#tool-reliability): a tiny,
 * fail-soft, in-memory tracker created once per run, threaded through
 * `ToolContext`, that fans a snapshot out on the event bus on every change and
 * exposes a concise `summaryLine()` roll-up. Like the tool-health tracker it
 * holds no scan state beyond its own items, authorizes nothing, and grants no
 * capability — it only records the plan the model declared.
 *
 * Two properties matter for the consumers:
 *   - Deterministic. Ids are assigned by position (`todo-1`, `todo-2`, …), so
 *     the same declared plan always produces the same snapshot — which is what
 *     makes change-detection (and therefore "emit only on change") exact.
 *   - Fail-soft. `set` never throws, and a throwing `emit` sink is swallowed so
 *     a rendering hiccup can never abort the tool call that produced the plan.
 */

import { z } from "zod";

// ── Model ────────────────────────────────────────────────────────────────

/**
 * Lifecycle of one planned task. Closed, three-state — the minimum that lets a
 * renderer distinguish "not started" (☐) from "being worked right now" (◐)
 * from "finished" (☑). Matches the `TodoWrite` vocabulary.
 */
export type TodoStatus = "pending" | "in_progress" | "completed";

/** One item in the declared plan. */
export interface TodoItem {
  /** Position-derived stable id for this snapshot, e.g. `todo-3`. */
  id: string;
  /** One-line statement of the task. Always present, always non-empty. */
  content: string;
  status: TodoStatus;
  /** Optional phase label, e.g. "Inspection". Grouping key for the TUI tree. */
  group?: string;
}

/** A phase: the items sharing one `group`, plus per-phase progress counts. */
export interface TodoGroup {
  /** The group label. `""` for items declared without a group. */
  group: string;
  items: TodoItem[];
  /** Items in this group with status `completed`. */
  done: number;
  /** Total items in this group. */
  total: number;
}

/** Overall progress across the whole plan. */
export interface TodoProgress {
  done: number;
  total: number;
}

/** Render-ready, immutable snapshot of the plan at one revision. */
export interface TodoSnapshot {
  todos: TodoItem[];
  /** Phases in first-appearance order of their labels. */
  groups: TodoGroup[];
  progress: TodoProgress;
  /** One-line header, e.g. "Todos · 1/3". `""` when the plan is empty. */
  summaryLine: string;
  /** Monotonic revision, bumped only when a `set` actually changes the plan. */
  revision: number;
}

/** Event-bus / DB payload shape for a plan snapshot (flat, JSON-friendly). */
export interface TodosEventPayload {
  todos: Array<{ id: string; content: string; status: TodoStatus; group?: string }>;
  done: number;
  total: number;
  line: string;
  revision: number;
  /** Structural match for the bus's `TodosPayload` index signature. */
  [k: string]: unknown;
}

// ── Tunables ───────────────────────────────────────────────────────────────

/** Hard cap on plan length — a longer "plan" is a transcript, not a plan. */
export const MAX_TODOS = 50;
/** Task content longer than this is rejected. */
export const MAX_CONTENT_LEN = 200;
/** Group labels longer than this are rejected. */
export const MAX_GROUP_LEN = 60;

// ── Tool-argument schema (agent/CLAUDE.md §1: validate, reject malformed) ────

const statusSchema = z.enum(["pending", "in_progress", "completed"]);

/**
 * One declared item. `.strip()` (Zod object default) drops unknown adjacent
 * keys — models routinely emit `id`, `title`, `detail` — so they never reach
 * the tracker; ids are assigned by position, not accepted from the model.
 */
export const todoInputSchema = z.object({
  content: z
    .string()
    .trim()
    .min(1, "content must not be empty")
    .max(MAX_CONTENT_LEN, `content must be at most ${MAX_CONTENT_LEN} characters`),
  status: statusSchema.optional(),
  group: z
    .string()
    .trim()
    .max(MAX_GROUP_LEN, `group must be at most ${MAX_GROUP_LEN} characters`)
    .optional(),
});

/**
 * Full `update_todos` payload. An empty array is valid and CLEARS the plan
 * (idempotent full-state write). At-most-one-`in_progress` is recommended but
 * NOT enforced (parity with `TodoWrite`) — a renderer copes with several, and
 * rejecting the write would lose the rest of the plan over a soft rule.
 */
export const updateTodosArgsSchema = z.object({
  todos: z
    .array(todoInputSchema)
    .max(MAX_TODOS, `at most ${MAX_TODOS} todos are allowed`),
});

/** A validated, normalized declared item (status defaulted, group cleaned). */
export interface TodoInput {
  content: string;
  status: TodoStatus;
  group?: string;
}

/** Discriminated validation result, mirroring `validateKernelRunArgs`. */
export type UpdateTodosValidation =
  | { ok: true; todos: TodoInput[] }
  | { ok: false; error: string };

/**
 * Parse a raw `update_todos` payload. On success, returns normalized inputs
 * (status defaults to `pending`; a blank group becomes `undefined`). On failure
 * returns one actionable line the loop can feed straight back as an `is_error`
 * tool result so the model self-corrects.
 */
export function validateUpdateTodosArgs(raw: unknown): UpdateTodosValidation {
  const parsed = updateTodosArgsSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `${i.path.join(".") || "todos"}: ${i.message}`)
      .join("; ");
    return {
      ok: false,
      error:
        `Invalid update_todos arguments — ${issues}. ` +
        `Expected { todos: [{ content, status?, group? }] } with at most ` +
        `${MAX_TODOS} items; status is one of pending|in_progress|completed.`,
    };
  }
  const todos: TodoInput[] = parsed.data.todos.map((t) => ({
    content: t.content,
    status: t.status ?? "pending",
    ...(t.group ? { group: t.group } : {}),
  }));
  return { ok: true, todos };
}

// ── Tracker ──────────────────────────────────────────────────────────────

export interface TodoTrackerOptions {
  /**
   * Sink invoked once per CHANGE (a `set` that actually alters the plan), never
   * on an idempotent no-op re-write. Errors are swallowed so a broken renderer
   * can't abort the tool call.
   */
  emit?: (snapshot: TodoSnapshot) => void;
  /** Injectable id factory (0-based index → id). Defaults to `todo-${i+1}`. */
  idFactory?: (index: number) => string;
}

function defaultId(index: number): string {
  return `todo-${index + 1}`;
}

/**
 * Structural fingerprint of an item list, for change detection. Ids are
 * position-derived so identical declared plans fingerprint identically — the
 * property that makes "emit only on change" exact and re-writes idempotent.
 */
function fingerprint(items: TodoItem[]): string {
  return JSON.stringify(items.map((t) => [t.id, t.content, t.status, t.group ?? ""]));
}

/**
 * In-memory, fail-soft holder for the current plan. `set` performs a full
 * replace (like `TodoWrite`); `list` / `groups` / `progress` / `summaryLine`
 * are pure reads. One instance is created per run and discarded with it.
 */
export class TodoTracker {
  private items: TodoItem[] = [];
  private _revision = 0;
  private readonly emit?: (snapshot: TodoSnapshot) => void;
  private readonly idFactory: (index: number) => string;

  constructor(opts: TodoTrackerOptions = {}) {
    this.emit = opts.emit;
    this.idFactory = opts.idFactory ?? defaultId;
  }

  /**
   * Replace the entire plan with `inputs`. Idempotent: a write that produces
   * the same plan does not bump the revision or emit. Returns the resulting
   * snapshot. Never throws.
   */
  set(inputs: TodoInput[]): TodoSnapshot {
    const next: TodoItem[] = inputs.map((t, i) => ({
      id: this.idFactory(i),
      content: t.content,
      status: t.status,
      ...(t.group ? { group: t.group } : {}),
    }));

    if (fingerprint(next) === fingerprint(this.items)) {
      // Idempotent re-write — no change, no revision bump, no emit.
      return this.snapshot();
    }

    this.items = next;
    this._revision += 1;
    const snap = this.snapshot();
    if (this.emit) {
      try {
        this.emit(snap);
      } catch {
        // Rendering is best-effort; a broken sink must never abort the write.
      }
    }
    return snap;
  }

  /** The current plan, in declared order (defensive copy). */
  list(): TodoItem[] {
    return this.items.map((t) => ({ ...t }));
  }

  /**
   * The plan grouped into phases, in first-appearance order of the group
   * labels. Items declared without a group collect under the `""` label.
   */
  groups(): TodoGroup[] {
    const order: string[] = [];
    const byGroup = new Map<string, TodoItem[]>();
    for (const t of this.items) {
      const key = t.group ?? "";
      if (!byGroup.has(key)) {
        byGroup.set(key, []);
        order.push(key);
      }
      byGroup.get(key)!.push({ ...t });
    }
    return order.map((group) => {
      const items = byGroup.get(group)!;
      return {
        group,
        items,
        done: items.filter((t) => t.status === "completed").length,
        total: items.length,
      };
    });
  }

  /** Overall {done, total} across the whole plan. */
  progress(): TodoProgress {
    return {
      done: this.items.filter((t) => t.status === "completed").length,
      total: this.items.length,
    };
  }

  /** One-line header, e.g. "Todos · 1/3". Empty string when the plan is empty. */
  summaryLine(): string {
    const { done, total } = this.progress();
    if (total === 0) return "";
    return `Todos · ${done}/${total}`;
  }

  isEmpty(): boolean {
    return this.items.length === 0;
  }

  /** Monotonic revision; bumped only on a `set` that actually changed the plan. */
  get revision(): number {
    return this._revision;
  }

  /** Immutable render-ready snapshot of the current plan. */
  snapshot(): TodoSnapshot {
    return {
      todos: this.list(),
      groups: this.groups(),
      progress: this.progress(),
      summaryLine: this.summaryLine(),
      revision: this._revision,
    };
  }

  /** Drop the plan (mainly for tests / reuse). Does not emit. */
  reset(): void {
    this.items = [];
  }
}

/** Flatten a snapshot to the JSON-friendly event/DB payload shape. */
export function buildTodosPayload(snap: TodoSnapshot): TodosEventPayload {
  return {
    todos: snap.todos.map((t) => ({
      id: t.id,
      content: t.content,
      status: t.status,
      ...(t.group ? { group: t.group } : {}),
    })),
    done: snap.progress.done,
    total: snap.progress.total,
    line: snap.summaryLine,
    revision: snap.revision,
  };
}
