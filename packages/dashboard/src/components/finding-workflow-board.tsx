import { useMemo, useState } from "react";
import {
  DndContext,
  DragOverlay,
  PointerSensor,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { Clock3, GripVertical, ShieldQuestion, UserRound } from "lucide-react";
import { ConsensusBadge, ReviewBadge, SeverityBadge, SignalBadge, WorkflowBadge } from "@/components/status-badges";
import { Card, CardContent, CardDescription, CardEyebrow, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { FindingGroup, FindingWorkflowPhase } from "@/types";

const WORKFLOW_COLUMNS: Array<{
  status: FindingWorkflowPhase;
  label: string;
  description: string;
}> = [
  {
    status: "backlog",
    label: "Backlog",
    description: "New threads discovered by the pipeline.",
  },
  {
    status: "todo",
    label: "Todo",
    description: "Queued for a worker or follow-up pass.",
  },
  {
    status: "in_progress",
    label: "In Progress",
    description: "Autonomous execution is actively running now.",
  },
  {
    status: "blocked",
    label: "Blocked",
    description: "Needs more access, context, or a better PoC.",
  },
  {
    status: "done",
    label: "Done",
    description: "Accepted, verified, or reported.",
  },
  {
    status: "cancelled",
    label: "Cancelled",
    description: "Suppressed or resolved as false positive.",
  },
];

export function FindingWorkflowBoard({
  groups,
  selectedFingerprint,
  pendingFingerprint,
  onSelect,
  onMove,
}: {
  groups: FindingGroup[];
  selectedFingerprint: string | null;
  pendingFingerprint?: string | null;
  onSelect: (fingerprint: string) => void;
  onMove: (fingerprint: string, workflowStatus: FindingWorkflowPhase) => void;
}) {
  const [activeFingerprint, setActiveFingerprint] = useState<string | null>(null);
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
  );

  const byStatus = useMemo(() => {
    const grouped = new Map<FindingWorkflowPhase, FindingGroup[]>();
    for (const column of WORKFLOW_COLUMNS) grouped.set(column.status, []);
    for (const group of groups) {
      grouped.get(group.workflow.phase)?.push(group);
    }
    return grouped;
  }, [groups]);

  const activeGroup = useMemo(
    () => (activeFingerprint ? groups.find((group) => group.fingerprint === activeFingerprint) ?? null : null),
    [activeFingerprint, groups],
  );

  function handleDragStart(event: DragStartEvent) {
    setActiveFingerprint(String(event.active.id));
  }

  function handleDragEnd(event: DragEndEvent) {
    setActiveFingerprint(null);
    const { active, over } = event;
    if (!over) return;

    const fingerprint = String(active.id);
    const group = groups.find((item) => item.fingerprint === fingerprint);
    if (!group) return;

    let targetStatus: FindingWorkflowPhase | null = null;
    const overId = String(over.id);

    if (WORKFLOW_COLUMNS.some((column) => column.status === overId)) {
      targetStatus = overId as FindingWorkflowPhase;
    } else {
      const overGroup = groups.find((item) => item.fingerprint === overId);
      if (overGroup) targetStatus = overGroup.workflow.phase;
    }

    if (targetStatus && targetStatus !== group.workflow.phase) {
      onMove(fingerprint, targetStatus);
    }
  }

  return (
    <Card className="overflow-hidden">
      <CardHeader className="border-b border-border">
        <div>
          <CardEyebrow>Thread board</CardEyebrow>
          <CardTitle className="mt-2">Thread workflow board</CardTitle>
          <CardDescription>
            Use this as a secondary workflow view for threads that need intervention.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="px-0 pb-0">
        <DndContext sensors={sensors} onDragStart={handleDragStart} onDragEnd={handleDragEnd}>
          <div className="overflow-x-auto pb-4">
            <div className="flex min-w-max gap-4 px-6 pb-6">
              {WORKFLOW_COLUMNS.map((column) => (
                <WorkflowColumn
                  key={column.status}
                  column={column}
                  groups={byStatus.get(column.status) ?? []}
                  selectedFingerprint={selectedFingerprint}
                  pendingFingerprint={pendingFingerprint ?? null}
                  onSelect={onSelect}
                />
              ))}
            </div>
          </div>

          <DragOverlay>
            {activeGroup ? (
              <WorkflowCard
                group={activeGroup}
                selected={selectedFingerprint === activeGroup.fingerprint}
                onSelect={onSelect}
                isOverlay
              />
            ) : null}
          </DragOverlay>
        </DndContext>
      </CardContent>
    </Card>
  );
}

function WorkflowColumn({
  column,
  groups,
  selectedFingerprint,
  pendingFingerprint,
  onSelect,
}: {
  column: {
    status: FindingWorkflowPhase;
    label: string;
    description: string;
  };
  groups: FindingGroup[];
  selectedFingerprint: string | null;
  pendingFingerprint: string | null;
  onSelect: (fingerprint: string) => void;
}) {
  const { setNodeRef, isOver } = useDroppable({ id: column.status });

  return (
    <section className="flex w-[20rem] shrink-0 flex-col gap-3">
      <div className="rounded-md border border-border bg-muted/25 px-3 py-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              {column.label}
            </div>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">{column.description}</p>
          </div>
          <div className="rounded-sm border border-border bg-background px-2 py-1 text-xs text-muted-foreground">
            {groups.length}
          </div>
        </div>
      </div>

      <div
        ref={setNodeRef}
        className={cn(
          "flex min-h-[20rem] flex-col gap-3 rounded-md border border-dashed border-border bg-muted/15 p-2 transition-colors",
          isOver && "border-primary/40 bg-primary/7",
        )}
      >
        <SortableContext items={groups.map((group) => group.fingerprint)} strategy={verticalListSortingStrategy}>
          {groups.map((group) => (
            <WorkflowCard
              key={group.fingerprint}
              group={group}
              selected={selectedFingerprint === group.fingerprint}
              saving={pendingFingerprint === group.fingerprint}
              onSelect={onSelect}
            />
          ))}
        </SortableContext>

        {groups.length === 0 ? (
          <div className="flex flex-1 items-center justify-center rounded-md border border-dashed border-border/70 bg-background/70 px-4 py-8 text-center text-xs text-muted-foreground">
            Drop a thread here.
          </div>
        ) : null}
      </div>
    </section>
  );
}

function WorkflowCard({
  group,
  selected,
  saving = false,
  onSelect,
  isOverlay = false,
}: {
  group: FindingGroup;
  selected: boolean;
  saving?: boolean;
  onSelect: (fingerprint: string) => void;
  isOverlay?: boolean;
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id: group.fingerprint,
    data: { group },
  });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };
  const updatedLabel = saving
    ? "Syncing workflow update..."
    : group.workflow.updatedAt
      ? `Updated ${new Date(group.workflow.updatedAt).toLocaleString()}`
      : "No workflow activity yet";
  const ownerLabel = group.workflow.assignee ?? group.workflow.activeAgentRoles[0] ?? "Unassigned";
  const showManualWorkflow =
    group.workflow.persistedStatus !== group.workflow.phase
    && group.workflow.persistedStatus !== group.workflow.reviewGate;
  const summaryLabel =
    group.workflow.reviewGate === "human_review"
      ? "Waiting on human review"
      : group.workflow.reviewGate === "agent_review"
        ? "Waiting on agent review"
        : group.workflow.phase === "in_progress"
          ? "Execution running"
          : group.workflow.phase === "blocked"
            ? "Blocked"
            : `${group.count} hit${group.count > 1 ? "s" : ""} · ${group.scanCount} scan${group.scanCount > 1 ? "s" : ""}`;

  return (
    <button
      ref={setNodeRef}
      type="button"
      style={style}
      onClick={() => onSelect(group.fingerprint)}
      {...attributes}
      {...listeners}
      className={cn(
        "rounded-md border border-border bg-card p-3 text-left transition-[border-color,background-color,box-shadow]",
        "cursor-grab active:cursor-grabbing hover:border-primary/20 hover:bg-primary/4 hover:shadow-sm",
        selected && "border-primary/35 bg-primary/6 shadow-sm ring-1 ring-primary/15",
        isDragging && !isOverlay && "opacity-30",
        isOverlay && "shadow-lg ring-1 ring-primary/20",
        saving && "border-primary/30 bg-primary/6",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            <GripVertical className="size-3.5" />
            {group.latest.category}
            {selected ? (
              <span className="rounded-sm bg-primary/10 px-1.5 py-0.5 text-primary">
                Open
              </span>
            ) : null}
          </div>
          <div className="line-clamp-2 text-sm font-semibold leading-5 text-foreground">
            {group.latest.title}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            {summaryLabel}
          </div>
        </div>
        <SeverityBadge severity={group.latest.severity} />
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        {group.workflow.reviewGate !== "none" ? (
          <ReviewBadge value={group.workflow.reviewGate} />
        ) : null}
        <ConsensusBadge value={group.workflow.consensus} />
        <SignalBadge value={group.workflow.evidenceSignal} />
        {showManualWorkflow ? (
          <WorkflowBadge value={group.workflow.persistedStatus} />
        ) : null}
      </div>

      <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-3">
        <div className="flex items-center gap-2 rounded-sm bg-muted/35 px-2.5 py-2">
          <ShieldQuestion className="size-3.5" />
          <span>{group.count} hit{group.count > 1 ? "s" : ""}</span>
        </div>
        <div className="flex items-center gap-2 rounded-sm bg-muted/35 px-2.5 py-2">
          <UserRound className="size-3.5" />
          <span>{ownerLabel}</span>
        </div>
        <div className="flex items-center gap-2 rounded-sm bg-muted/35 px-2.5 py-2">
          <Clock3 className="size-3.5" />
          <span>{updatedLabel}</span>
        </div>
      </div>
    </button>
  );
}
