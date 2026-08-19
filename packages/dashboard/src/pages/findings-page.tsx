import { useDeferredValue, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bot,
  Clock3,
  Search,
  ShieldCheck,
  ShieldOff,
  ShieldQuestion,
  SlidersHorizontal,
  UserRound,
  WandSparkles,
} from "lucide-react";
import { getFindingFamily, updateFindingFamilyTriage, updateFindingFamilyWorkflow } from "@/api";
import { EvidenceTabs } from "@/components/evidence-tabs";
import { FindingWorkflowBoard } from "@/components/finding-workflow-board";
import { InspectorPane } from "@/components/inspector-pane";
import { MetaTile } from "@/components/meta-tile";
import { PageHeader } from "@/components/page-header";
import { useDashboardPanel } from "@/components/dashboard-panel";
import { EmptyState, ErrorState, LoadingState } from "@/components/state-panel";
import {
  ConsensusBadge,
  PhaseBadge,
  ReviewBadge,
  SeverityBadge,
  SignalBadge,
  StatusBadge,
  WorkflowBadge,
} from "@/components/status-badges";
import {
  Card,
  CardContent,
  CardDescription,
  CardEyebrow,
  CardHeader,
  CardList,
  CardListItem,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { formatTime } from "@/lib/format";
import { usePersistentState } from "@/lib/use-persistent-state";
import type {
  DashboardResponse,
  FindingGroup,
  FindingConsensus,
  FindingFamilyResponse,
  FindingReviewGate,
  FindingWorkflowPhase,
  FindingWorkflowStatus,
  FindingWorkflowSummary,
} from "@/types";

const WORKFLOW_ACTIONS: Array<{
  value: FindingWorkflowPhase;
  label: string;
}> = [
  { value: "backlog", label: "Backlog" },
  { value: "todo", label: "Todo" },
  { value: "in_progress", label: "In progress" },
  { value: "blocked", label: "Blocked" },
  { value: "done", label: "Done" },
  { value: "cancelled", label: "Cancelled" },
];

const CONSENSUS_OPTIONS: Array<{ value: "all" | FindingConsensus; label: string }> = [
  { value: "all", label: "All consensus" },
  { value: "pending", label: "Pending" },
  { value: "verified", label: "Verified" },
  { value: "disputed", label: "Disputed" },
  { value: "false-positive", label: "False positive" },
];

type WorkflowMutationInput = {
  fingerprint: string;
  workflowStatus: FindingWorkflowStatus;
  workflowAssignee: string;
  optimisticStatus?: FindingWorkflowStatus;
};

type ThreadViewMode = "inbox" | "review" | "board";
type QueueSortMode = "attention" | "newest" | "severity";
type ThreadConsoleState = {
  search: string;
  workflowFilter: "all" | FindingWorkflowPhase;
  reviewFilter: "all" | FindingReviewGate;
  severityFilter: string;
  consensusFilter: "all" | FindingConsensus;
  assigneeFilter: string;
  activeOnly: boolean;
  viewMode: ThreadViewMode;
  queueSort: QueueSortMode;
};

const DEFAULT_THREAD_CONSOLE_STATE: ThreadConsoleState = {
  search: "",
  workflowFilter: "all",
  reviewFilter: "all",
  severityFilter: "all",
  consensusFilter: "all",
  assigneeFilter: "all",
  activeOnly: false,
  viewMode: "inbox",
  queueSort: "attention",
};

function matchesSearch(haystack: DashboardResponse["groups"][number], normalized: string) {
  return [
    haystack.latest.title,
    haystack.latest.category,
    haystack.latest.severity,
    haystack.latest.triageStatus,
    haystack.workflow.status,
    haystack.workflow.phase,
    haystack.workflow.reviewGate,
    haystack.workflow.persistedStatus,
    haystack.workflow.recommendedStatus,
    haystack.workflow.reviewReason ?? "",
    haystack.workflow.consensus,
    haystack.workflow.assignee ?? "",
    haystack.workflow.activeAgentRoles.join(" "),
    haystack.fingerprint,
  ]
    .join(" ")
    .toLowerCase()
    .includes(normalized);
}

function patchWorkflowSummary(
  workflow: FindingWorkflowSummary,
  variables: WorkflowMutationInput,
): FindingWorkflowSummary {
  const nextAssignee = variables.workflowAssignee.trim() || null;
  const nextRecommendedStatus =
    variables.workflowStatus === "done" || variables.workflowStatus === "cancelled"
      ? variables.workflowStatus
      : workflow.recommendedStatus;
  const optimisticStatus =
    variables.optimisticStatus
    ?? (variables.workflowStatus === "done" || variables.workflowStatus === "cancelled"
      ? variables.workflowStatus
      : workflow.status);
  const nextPhase = workflowPhaseFromStatus(variables.workflowStatus);

  return {
    ...workflow,
    status: optimisticStatus,
    persistedStatus: variables.workflowStatus,
    recommendedStatus: nextRecommendedStatus,
    phase: nextPhase,
    assignee: nextAssignee,
    updatedAt: new Date().toISOString(),
  };
}

function patchDashboardWorkflow(
  dashboard: DashboardResponse,
  variables: WorkflowMutationInput,
): DashboardResponse {
  return {
    ...dashboard,
    groups: dashboard.groups.map((group) => {
      if (group.fingerprint !== variables.fingerprint) return group;
      return {
        ...group,
        latest: {
          ...group.latest,
          workflowStatus: variables.workflowStatus,
          workflowAssignee: variables.workflowAssignee.trim() || null,
          workflowUpdatedAt: new Date().toISOString(),
        },
        workflow: patchWorkflowSummary(group.workflow, variables),
      };
    }),
  };
}

function patchFindingFamilyWorkflow(
  family: FindingFamilyResponse,
  variables: WorkflowMutationInput,
): FindingFamilyResponse {
  if (family.fingerprint !== variables.fingerprint) return family;

  return {
    ...family,
    latest: {
      ...family.latest,
      workflowStatus: variables.workflowStatus,
      workflowAssignee: variables.workflowAssignee.trim() || null,
      workflowUpdatedAt: new Date().toISOString(),
    },
    workflow: patchWorkflowSummary(family.workflow, variables),
  };
}

export function FindingsPage({ dashboard }: { dashboard: DashboardResponse }) {
  const { fingerprint } = useParams<{ fingerprint?: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { openPanel, clearPanel } = useDashboardPanel();
  const [dismissedFingerprint, setDismissedFingerprint] = useState<string | null>(null);
  const [consoleState, setConsoleState] = usePersistentState<ThreadConsoleState>(
    "pwnkit:threads:console-state",
    DEFAULT_THREAD_CONSOLE_STATE,
  );
  const {
    search,
    workflowFilter,
    reviewFilter,
    severityFilter,
    consensusFilter,
    assigneeFilter,
    activeOnly,
    viewMode,
    queueSort,
  } = consoleState;
  const [filtersOpen, setFiltersOpen] = useState(false);
  const deferredSearch = useDeferredValue(search);

  const severityOptions = useMemo(
    () => ["all", ...new Set(dashboard.groups.map((group) => group.latest.severity.toLowerCase()))],
    [dashboard.groups],
  );

  const assigneeOptions = useMemo(
    () => ["all", ...new Set(dashboard.groups.map((group) => group.workflow.assignee).filter(Boolean))] as string[],
    [dashboard.groups],
  );

  const assigneeSuggestions = useMemo(() => {
    const values = new Set<string>();
    for (const group of dashboard.groups) {
      if (group.workflow.assignee) values.add(group.workflow.assignee);
      for (const role of group.workflow.activeAgentRoles) values.add(role);
    }
    return [...values].sort((left, right) => left.localeCompare(right));
  }, [dashboard.groups]);

  const filteredGroups = useMemo(() => {
    const normalized = deferredSearch.trim().toLowerCase();

    return dashboard.groups.filter((group) => {
      if (normalized && !matchesSearch(group, normalized)) return false;
      if (workflowFilter !== "all" && group.workflow.phase !== workflowFilter) return false;
      if (reviewFilter !== "all" && group.workflow.reviewGate !== reviewFilter) return false;
      if (severityFilter !== "all" && group.latest.severity.toLowerCase() !== severityFilter) return false;
      if (consensusFilter !== "all" && group.workflow.consensus !== consensusFilter) return false;
      if (
        assigneeFilter !== "all"
        && (group.workflow.assignee ?? "") !== assigneeFilter
        && !group.workflow.activeAgentRoles.includes(assigneeFilter)
      ) {
        return false;
      }
      if (activeOnly && group.workflow.activeAgentRoles.length === 0) return false;
      return true;
    });
  }, [activeOnly, assigneeFilter, consensusFilter, dashboard.groups, deferredSearch, reviewFilter, severityFilter, workflowFilter]);

  const reviewGroups = useMemo(
    () => filteredGroups.filter((group) => group.workflow.reviewGate !== "none"),
    [filteredGroups],
  );

  const queueGroups = useMemo(() => {
    const ranked = [...filteredGroups];
    ranked.sort((left, right) => {
      if (queueSort === "newest") return right.latest.timestamp - left.latest.timestamp;
      if (queueSort === "severity") return severityRank(right.latest.severity) - severityRank(left.latest.severity);
      return attentionRank(right) - attentionRank(left);
    });
    return ranked;
  }, [filteredGroups, queueSort]);

  const readyGroups = useMemo(
    () =>
      queueGroups.filter(
        (group) =>
          group.workflow.reviewGate === "none"
          && (group.workflow.phase === "todo" || group.workflow.phase === "backlog"),
      ),
    [queueGroups],
  );

  const activeGroups = useMemo(
    () =>
      queueGroups.filter(
        (group) => group.workflow.phase === "in_progress" || group.workflow.activeAgentRoles.length > 0,
      ),
    [queueGroups],
  );

  const blockedGroups = useMemo(
    () => queueGroups.filter((group) => group.workflow.phase === "blocked"),
    [queueGroups],
  );

  const agentReviewGroups = useMemo(
    () => reviewGroups.filter((group) => group.workflow.reviewGate === "agent_review"),
    [reviewGroups],
  );

  const humanReviewGroups = useMemo(
    () => reviewGroups.filter((group) => group.workflow.reviewGate === "human_review"),
    [reviewGroups],
  );

  const visibleGroups = viewMode === "review" ? reviewGroups : viewMode === "board" ? filteredGroups : queueGroups;
  const selectedFingerprint = fingerprint ?? null;

  const familyQuery = useQuery({
    queryKey: ["finding-family", selectedFingerprint],
    queryFn: () => getFindingFamily(selectedFingerprint!),
    enabled: Boolean(selectedFingerprint),
  });

  const triageMutation = useMutation({
    mutationFn: ({
      triageStatus,
      triageNote,
    }: {
      triageStatus: "new" | "accepted" | "suppressed";
      triageNote: string;
    }) => updateFindingFamilyTriage(selectedFingerprint!, triageStatus, triageNote),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
        queryClient.invalidateQueries({ queryKey: ["finding-family", selectedFingerprint] }),
      ]);
    },
  });

  const workflowMutation = useMutation({
    mutationFn: ({ fingerprint: familyFingerprint, workflowStatus, workflowAssignee }: WorkflowMutationInput) =>
      updateFindingFamilyWorkflow(familyFingerprint, workflowStatus, workflowAssignee),
    onMutate: async (variables) => {
      await Promise.all([
        queryClient.cancelQueries({ queryKey: ["dashboard"] }),
        queryClient.cancelQueries({ queryKey: ["finding-family", variables.fingerprint] }),
      ]);

      const previousDashboard = queryClient.getQueryData<DashboardResponse>(["dashboard"]);
      const previousFamily = queryClient.getQueryData<FindingFamilyResponse>(["finding-family", variables.fingerprint]);

      queryClient.setQueryData<DashboardResponse>(["dashboard"], (current) =>
        current ? patchDashboardWorkflow(current, variables) : current,
      );
      queryClient.setQueryData<FindingFamilyResponse>(["finding-family", variables.fingerprint], (current) =>
        current ? patchFindingFamilyWorkflow(current, variables) : current,
      );

      return { previousDashboard, previousFamily, fingerprint: variables.fingerprint };
    },
    onError: (_error, _variables, context) => {
      if (context?.previousDashboard) {
        queryClient.setQueryData(["dashboard"], context.previousDashboard);
      }
      if (context?.previousFamily) {
        queryClient.setQueryData(["finding-family", context.fingerprint], context.previousFamily);
      }
    },
    onSettled: async (_data, _error, variables) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
        queryClient.invalidateQueries({ queryKey: ["finding-family", variables.fingerprint] }),
      ]);
    },
  });

  const selectedGroup = dashboard.groups.find((group) => group.fingerprint === selectedFingerprint) ?? null;
  const selectedVisible = visibleGroups.some((group) => group.fingerprint === selectedFingerprint);
  const filtersActive =
    search.trim().length > 0
    || workflowFilter !== "all"
    || reviewFilter !== "all"
    || severityFilter !== "all"
    || consensusFilter !== "all"
    || assigneeFilter !== "all"
    || activeOnly;
  const activeFilterLabels = [
    workflowFilter !== "all" ? WORKFLOW_ACTIONS.find((action) => action.value === workflowFilter)?.label ?? workflowFilter : null,
    reviewFilter !== "all" ? reviewFilter.replaceAll("_", " ") : null,
    severityFilter !== "all" ? severityFilter : null,
    consensusFilter !== "all" ? consensusFilter.replaceAll("-", " ") : null,
    assigneeFilter !== "all" ? assigneeFilter : null,
    activeOnly ? "active agents" : null,
  ].filter(Boolean) as string[];
  const resultLabel =
    viewMode === "review"
      ? `${reviewGroups.length} review threads`
      : viewMode === "board"
        ? `${filteredGroups.length} board threads`
        : `${queueGroups.length} inbox threads`;

  function clearFilters() {
    setConsoleState((current) => ({
      ...current,
      search: "",
      workflowFilter: "all",
      reviewFilter: "all",
      severityFilter: "all",
      consensusFilter: "all",
      assigneeFilter: "all",
      activeOnly: false,
    }));
  }

  useEffect(() => {
    if (selectedFingerprint !== dismissedFingerprint) {
      setDismissedFingerprint(null);
    }
  }, [dismissedFingerprint, selectedFingerprint]);

  useEffect(() => {
    if (!selectedFingerprint || selectedFingerprint === dismissedFingerprint) {
      clearPanel();
      return;
    }

    let content: React.ReactNode;
    if (familyQuery.isLoading) {
      content = <LoadingState label="Thread detail" />;
    } else if (familyQuery.error) {
      content = <ErrorState error={familyQuery.error} />;
    } else if (familyQuery.data) {
      content = (
        <FindingFamilyInspector
          data={familyQuery.data}
          assigneeSuggestions={assigneeSuggestions}
          selectedSummary={selectedGroup?.workflow ?? null}
          isSaving={triageMutation.isPending || workflowMutation.isPending}
          onTriage={(triageStatus, triageNote) =>
            triageMutation.mutate({ triageStatus, triageNote })
          }
          onWorkflow={(familyFingerprint, workflowStatus, workflowAssignee, optimisticStatus) =>
            workflowMutation.mutate({
              fingerprint: familyFingerprint,
              workflowStatus,
              workflowAssignee,
              optimisticStatus,
            })
          }
        />
      );
    } else {
      content = (
        <EmptyState
          title="Thread unavailable"
          body="The selected thread could not be loaded from the local database."
        />
      );
    }

    openPanel({
      title: selectedGroup?.latest.title ?? "Thread detail",
      description: "Inspect the selected thread as a persistent execution record with ownership, evidence, and review posture in one place.",
      content: <div className="p-6">{content}</div>,
      onClose: () => {
        setDismissedFingerprint(selectedFingerprint);
        navigate("/threads");
      },
    });

    return () => {
      clearPanel();
    };
  }, [
    assigneeSuggestions,
    clearPanel,
    familyQuery.data,
    familyQuery.error,
    familyQuery.isLoading,
    navigate,
    openPanel,
    selectedFingerprint,
    selectedGroup?.latest.title,
    selectedGroup?.workflow,
    dismissedFingerprint,
    triageMutation.isPending,
    workflowMutation.isPending,
  ]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Threads"
        title="Thread console"
        summary="Threads are the persistent attack issues that survive across runs. Use this surface to steer automation, inspect evidence, and make the human calls only when the pipeline cannot."
        actions={(
          <>
            <Button variant="outline" onClick={() => setFiltersOpen(true)}>
              <SlidersHorizontal className="size-4" />
              Filters
              {filtersActive ? <Badge variant="neutral">{activeFilterLabels.length + (search.trim() ? 1 : 0)}</Badge> : null}
            </Button>
            {selectedFingerprint ? (
              <Button variant="outline" onClick={() => navigate("/threads")}>
                Close thread
              </Button>
            ) : null}
          </>
        )}
      />

      <Card>
        <CardHeader>
          <div className="space-y-3">
            <div>
              <CardEyebrow>Views</CardEyebrow>
              <CardTitle className="mt-2">Inbox first</CardTitle>
              <CardDescription>
                Prioritize runnable, active, blocked, and review-ready threads before dropping to the board.
              </CardDescription>
            </div>
            <Tabs value={viewMode} onValueChange={(value) => setConsoleState((current) => ({ ...current, viewMode: value as ThreadViewMode }))}>
              <TabsList>
                <TabsTrigger value="inbox">Inbox</TabsTrigger>
                <TabsTrigger value="review">Review</TabsTrigger>
                <TabsTrigger value="board">Board</TabsTrigger>
              </TabsList>
            </Tabs>
          </div>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <ModeStat label="Ready now" value={`${readyGroups.length}`} meta="Queued for the next autonomous step." />
          <ModeStat label="Running now" value={`${activeGroups.length}`} meta="Threads with live worker activity." />
          <ModeStat label="Blocked" value={`${blockedGroups.length}`} meta="Need more access, context, or a better PoC." />
          <ModeStat label="Review" value={`${reviewGroups.length}`} meta="Waiting on agent or human sign-off." />
        </CardContent>
      </Card>

      <Card size="sm">
        <CardContent className="space-y-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
            <div className="relative">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(event) => setConsoleState((current) => ({ ...current, search: event.target.value }))}
                placeholder="Search threads, workflow state, assignee, severity, consensus, or fingerprint"
                className="pl-9"
              />
            </div>
            <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <div className="flex items-center gap-2">
                <Bot className="size-4" />
                {resultLabel}
              </div>
              <Badge variant="neutral">{dashboard.groups.length} total</Badge>
              {selectedFingerprint ? (
                <Badge variant={selectedVisible ? "accent" : "warning"}>
                  {selectedVisible ? "Thread open" : "Selected thread hidden by filters"}
                </Badge>
              ) : null}
            </div>
          </div>

          {filtersActive || search.trim() ? (
            <div className="flex flex-wrap items-center gap-2">
              {search.trim() ? <Badge variant="outline">query: {search.trim()}</Badge> : null}
              {activeFilterLabels.map((label) => (
                <Badge key={label} variant="outline">
                  {label}
                </Badge>
              ))}
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                Clear filters
              </Button>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <div className="min-w-0 space-y-4">
        {viewMode === "board" ? (
          <FindingWorkflowBoard
            groups={filteredGroups}
            selectedFingerprint={selectedFingerprint}
            pendingFingerprint={workflowMutation.isPending ? workflowMutation.variables?.fingerprint ?? null : null}
            onSelect={(nextFingerprint) => navigate(`/threads/${nextFingerprint}`)}
            onMove={(nextFingerprint, workflowStatus) => {
              if (selectedFingerprint !== nextFingerprint) {
                navigate(`/threads/${nextFingerprint}`);
              }

              workflowMutation.mutate({
                fingerprint: nextFingerprint,
                workflowStatus,
                workflowAssignee:
                  dashboard.groups.find((group) => group.fingerprint === nextFingerprint)?.workflow.assignee ?? "",
                optimisticStatus: workflowStatus,
              });
            }}
          />
        ) : viewMode === "review" ? (
          <ThreadReviewDeck
            agentReviewGroups={agentReviewGroups}
            humanReviewGroups={humanReviewGroups}
            selectedFingerprint={selectedFingerprint}
            pendingFingerprint={workflowMutation.isPending ? workflowMutation.variables?.fingerprint ?? null : null}
            onSelect={(nextFingerprint) => navigate(`/threads/${nextFingerprint}`)}
          />
        ) : (
          <ThreadInbox
            groups={queueGroups}
            readyGroups={readyGroups}
            activeGroups={activeGroups}
            blockedGroups={blockedGroups}
            selectedFingerprint={selectedFingerprint}
            queueSort={queueSort}
            pendingFingerprint={workflowMutation.isPending ? workflowMutation.variables?.fingerprint ?? null : null}
            onSortChange={(value) => setConsoleState((current) => ({ ...current, queueSort: value }))}
            onSelect={(nextFingerprint) => navigate(`/threads/${nextFingerprint}`)}
          />
        )}
      </div>

      <Sheet open={filtersOpen} onOpenChange={setFiltersOpen}>
        <SheetContent side="right" className="w-full overflow-y-auto p-0 sm:max-w-xl">
          <SheetHeader className="border-b border-border pr-12">
            <SheetTitle>Thread filters</SheetTitle>
            <SheetDescription>
              Scope the thread console by phase, review gate, severity, ownership, or live worker activity.
            </SheetDescription>
          </SheetHeader>

          <div className="space-y-5 p-6">
            <label className="block space-y-2">
              <CardEyebrow>Search</CardEyebrow>
              <Input
                value={search}
                onChange={(event) => setConsoleState((current) => ({ ...current, search: event.target.value }))}
                placeholder="Search workflow, evidence, assignee, or fingerprint"
              />
            </label>

            <div className="grid gap-4 md:grid-cols-2">
              <FilterRow label="Workflow">
                <FilterChip active={workflowFilter === "all"} onClick={() => setConsoleState((current) => ({ ...current, workflowFilter: "all" }))}>
                  All phases
                </FilterChip>
                {WORKFLOW_ACTIONS.map((action) => (
                  <FilterChip
                    key={action.value}
                    active={workflowFilter === action.value}
                    onClick={() => setConsoleState((current) => ({ ...current, workflowFilter: action.value }))}
                  >
                    {action.label}
                  </FilterChip>
                ))}
              </FilterRow>

              <FilterRow label="Review gate">
                <FilterChip active={reviewFilter === "all"} onClick={() => setConsoleState((current) => ({ ...current, reviewFilter: "all" }))}>
                  All review states
                </FilterChip>
                <FilterChip active={reviewFilter === "agent_review"} onClick={() => setConsoleState((current) => ({ ...current, reviewFilter: "agent_review" }))}>
                  Agent review
                </FilterChip>
                <FilterChip active={reviewFilter === "human_review"} onClick={() => setConsoleState((current) => ({ ...current, reviewFilter: "human_review" }))}>
                  Human review
                </FilterChip>
              </FilterRow>

              <FilterRow label="Severity">
                {severityOptions.map((option) => (
                  <FilterChip
                    key={option}
                    active={severityFilter === option}
                    onClick={() => setConsoleState((current) => ({ ...current, severityFilter: option }))}
                  >
                    {option === "all" ? "All severities" : option[0]?.toUpperCase() + option.slice(1)}
                  </FilterChip>
                ))}
              </FilterRow>

              <FilterRow label="Consensus">
                {CONSENSUS_OPTIONS.map((option) => (
                  <FilterChip
                    key={option.value}
                    active={consensusFilter === option.value}
                    onClick={() => setConsoleState((current) => ({ ...current, consensusFilter: option.value }))}
                  >
                    {option.label}
                  </FilterChip>
                ))}
              </FilterRow>

              <FilterRow label="Ownership" className="md:col-span-2">
                <FilterChip active={assigneeFilter === "all"} onClick={() => setConsoleState((current) => ({ ...current, assigneeFilter: "all" }))}>
                  All assignees
                </FilterChip>
                {assigneeOptions
                  .filter((option) => option !== "all")
                  .map((option) => (
                    <FilterChip
                      key={option}
                      active={assigneeFilter === option}
                      onClick={() => setConsoleState((current) => ({ ...current, assigneeFilter: option }))}
                    >
                      {option}
                    </FilterChip>
                  ))}
                <FilterChip active={activeOnly} onClick={() => setConsoleState((current) => ({ ...current, activeOnly: !current.activeOnly }))}>
                  Active agents only
                </FilterChip>
              </FilterRow>
            </div>

            <div className="flex items-center justify-between gap-3 border-t border-border pt-4">
              <div className="text-sm text-muted-foreground">
                {visibleGroups.length} of {dashboard.groups.length} threads visible
              </div>
              <div className="flex items-center gap-2">
                <Button variant="ghost" size="sm" onClick={clearFilters}>
                  Reset
                </Button>
                <Button size="sm" onClick={() => setFiltersOpen(false)}>
                  Apply
                </Button>
              </div>
            </div>
          </div>
        </SheetContent>
      </Sheet>

    </div>
  );
}

function FindingFamilyInspector({
  data,
  assigneeSuggestions,
  selectedSummary,
  onTriage,
  onWorkflow,
  isSaving,
}: {
  data: FindingFamilyResponse;
  assigneeSuggestions: string[];
  selectedSummary: FindingWorkflowSummary | null;
  onTriage: (triageStatus: "new" | "accepted" | "suppressed", triageNote: string) => void;
  onWorkflow: (fingerprint: string, workflowStatus: FindingWorkflowPhase, workflowAssignee: string, optimisticStatus?: FindingWorkflowStatus) => void;
  isSaving: boolean;
}) {
  const [note, setNote] = useState(data.latest.triageNote ?? "");
  const [assignee, setAssignee] = useState(data.workflow.assignee ?? "");
  const datalistId = `assignee-suggestions-${data.fingerprint}`;
  const operatorSuggestions = useMemo(() => {
    const values = new Set<string>();
    if (data.workflow.assignee) values.add(data.workflow.assignee);
    for (const role of data.workflow.activeAgentRoles) values.add(role);
    for (const suggestion of assigneeSuggestions) values.add(suggestion);
    return [...values].slice(0, 8);
  }, [assigneeSuggestions, data.workflow.activeAgentRoles, data.workflow.assignee]);
  const activeWorkItem = data.workItems.find((item) => item.status === "in_progress") ?? null;
  const blockedWorkItem = data.workItems.find((item) => item.status === "blocked") ?? null;
  const nextQueuedWorkItem = data.workItems.find((item) => item.status === "todo" || item.status === "backlog") ?? null;
  const liveOwner =
    activeWorkItem?.owner
    ?? data.workflow.assignee
    ?? data.workflow.activeAgentRoles[0]
    ?? blockedWorkItem?.owner
    ?? "Unassigned";
  const executionHeadline = blockedWorkItem
    ? "Execution is blocked."
    : activeWorkItem
      ? "Execution is actively running."
      : nextQueuedWorkItem
        ? "Execution is queued for the next step."
        : data.workflow.reviewGate !== "none"
          ? "Execution is waiting on review."
          : "Execution has no active work item yet.";
  const executionDetail = blockedWorkItem
    ? blockedWorkItem.summary || data.workflow.reviewReason || "A blocked step needs operator intervention."
    : activeWorkItem
      ? activeWorkItem.summary || data.workflow.reviewReason || "An agent-owned execution step is in progress."
      : nextQueuedWorkItem
        ? nextQueuedWorkItem.summary || "The next queued step is ready to run."
        : data.workflow.reviewReason || "No explicit runbook activity is available yet.";

  useEffect(() => {
    setNote(data.latest.triageNote ?? "");
  }, [data.fingerprint, data.latest.triageNote]);

  useEffect(() => {
    setAssignee(data.workflow.assignee ?? "");
  }, [data.fingerprint, data.workflow.assignee]);

  return (
    <div className="space-y-5">
      <InspectorPane
        eyebrow="Operator"
        title="Thread controls"
        description="Keep ownership, workflow, review posture, and disposition in one place instead of scattering the control state across separate panes."
      >
        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity={data.latest.severity} />
          <PhaseBadge value={data.workflow.phase} />
          <ReviewBadge value={data.workflow.reviewGate} />
          <ConsensusBadge value={data.workflow.consensus} />
          <SignalBadge value={data.workflow.evidenceSignal} />
          <StatusBadge value={data.latest.triageStatus} />
        </div>

        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <SummaryMetric label="Case" value={data.case?.target ?? "Unlinked"} />
          <SummaryMetric
            label="Case type"
            value={data.case ? formatCaseTargetTypeLabel(data.case.targetType) : "Unknown"}
          />
          <SummaryMetric label="Fingerprint" value={data.fingerprint} mono />
          <SummaryMetric label="Category" value={data.latest.category} />
          <SummaryMetric label="Occurrences" value={String(data.rows.length)} />
          <SummaryMetric label="Review gate" value={data.workflow.reviewGate.replaceAll("_", " ")} />
          <SummaryMetric
            label="Active agents"
            value={data.workflow.activeAgentRoles.length > 0 ? data.workflow.activeAgentRoles.join(", ") : "None"}
          />
        </div>

        <div className="rounded-md border border-border bg-muted/20 p-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <CardEyebrow>Execution snapshot</CardEyebrow>
              <div className="mt-2 text-sm font-medium text-foreground">{executionHeadline}</div>
              <div className="mt-1 text-sm leading-6 text-muted-foreground">{executionDetail}</div>
              {nextQueuedWorkItem ? (
                <div className="mt-3 text-xs leading-5 text-muted-foreground">
                  Queued autonomous stages are claimed automatically by a live daemon once dependencies clear. If a thread stalls here, check `Operations` for queue health or worker heartbeats.
                </div>
              ) : null}
            </div>
            {blockedWorkItem ? <TaskStatusBadge value={blockedWorkItem.status} /> : activeWorkItem ? <TaskStatusBadge value={activeWorkItem.status} /> : null}
          </div>

          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <SummaryMetric
              label="Current step"
              value={activeWorkItem ? activeWorkItem.title : blockedWorkItem ? blockedWorkItem.title : "No live step"}
            />
            <SummaryMetric label="Owner" value={liveOwner} />
            <SummaryMetric
              label="Next step"
              value={nextQueuedWorkItem ? nextQueuedWorkItem.title : data.workflow.reviewGate !== "none" ? "Review gate" : "No queued step"}
            />
            <SummaryMetric
              label="Blocked by"
              value={blockedWorkItem ? blockedWorkItem.title : data.workflow.phase === "blocked" ? data.workflow.reviewReason ?? "Operator input" : "Clear"}
            />
          </div>
        </div>

        <label className="block space-y-2">
          <CardEyebrow>Thread owner</CardEyebrow>
          <div className="flex gap-2">
            <Input
              list={datalistId}
              value={assignee}
              onChange={(event) => setAssignee(event.target.value)}
              placeholder="security-verifier / model owner / person"
            />
            <datalist id={datalistId}>
              {operatorSuggestions.map((suggestion) => (
                <option key={suggestion} value={suggestion} />
              ))}
            </datalist>
            <Button
              variant="outline"
              onClick={() => onWorkflow(data.fingerprint, data.workflow.phase, assignee)}
              disabled={isSaving}
            >
              <UserRound className="size-4" />
              Assign
            </Button>
          </div>
        </label>

        {operatorSuggestions.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {operatorSuggestions.map((suggestion) => (
              <Button
                key={suggestion}
                variant={assignee === suggestion ? "default" : "outline"}
                size="sm"
                onClick={() => setAssignee(suggestion)}
                disabled={isSaving}
              >
                {suggestion}
              </Button>
            ))}
          </div>
        ) : null}

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
          <div className="space-y-2">
            <CardEyebrow>Workflow phase</CardEyebrow>
            <div className="grid grid-cols-2 gap-2">
              {WORKFLOW_ACTIONS.map((action) => (
                <Button
                  key={action.value}
                  variant={data.workflow.phase === action.value ? "default" : "outline"}
                  onClick={() => onWorkflow(data.fingerprint, action.value, assignee, action.value)}
                  disabled={isSaving}
                  className="justify-start"
                >
                  {action.label}
                </Button>
              ))}
            </div>
          </div>

          <div className="rounded-md border border-border bg-muted/20 p-4">
            <CardEyebrow>Disposition</CardEyebrow>
            <div className="mt-3 grid gap-2">
              <Button
                variant="success"
                onClick={() => onTriage("accepted", note)}
                disabled={isSaving}
              >
                <ShieldCheck className="size-4" />
                Accept
              </Button>
              <Button
                variant="warning"
                onClick={() => onTriage("suppressed", note)}
                disabled={isSaving}
              >
                <ShieldOff className="size-4" />
                Suppress
              </Button>
              <Button
                variant="outline"
                onClick={() => onTriage("new", note)}
                disabled={isSaving}
              >
                <ShieldQuestion className="size-4" />
                Reset triage
              </Button>
            </div>
          </div>
        </div>

        {data.workflow.reviewGate !== "none" || data.workflow.persistedStatus !== data.workflow.phase ? (
          <div className="rounded-lg border border-border bg-muted/35 px-3 py-3 text-sm text-muted-foreground">
            <div className="flex items-center gap-2 font-medium text-foreground">
              <WandSparkles className="size-4 text-primary" />
              Autonomous workflow signal
            </div>
            <div className="mt-1">
              Live execution is currently in <span className="text-foreground">{data.workflow.phase}</span>
              {data.workflow.reviewGate !== "none" ? ` with ${data.workflow.reviewGate.replaceAll("_", " ")}.` : "."}
              {data.workflow.reviewReason ? ` ${data.workflow.reviewReason}` : ""}
              {selectedSummary && selectedSummary.persistedStatus !== selectedSummary.phase
                ? ` The saved operator workflow is ${selectedSummary.persistedStatus}.`
                : ""}
            </div>
          </div>
        ) : null}

        <div className="grid gap-3 md:grid-cols-3">
          <MetaTile label="Consensus" value={data.workflow.consensus} />
          <MetaTile label="Evidence signal" value={data.workflow.evidenceSignal} />
          <MetaTile label="True positive votes" value={String(data.workflow.verdictCounts.truePositive)} />
          <MetaTile label="False positive votes" value={String(data.workflow.verdictCounts.falsePositive)} />
          <MetaTile label="Unsure votes" value={String(data.workflow.verdictCounts.unsure)} />
          <MetaTile label="Assignee" value={data.workflow.assignee ?? "Unassigned"} />
        </div>

        <label className="block space-y-2">
          <CardEyebrow>Triage note</CardEyebrow>
          <Textarea
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Capture why this thread is actionable, benign, needs another agent pass, or is waiting on a human call."
          />
        </label>
      </InspectorPane>

      <InspectorPane
        eyebrow="Execution"
        title="Execution record"
        description="Open the runbook, evidence, and occurrence detail only when the current thread needs deeper inspection."
      >
        <Tabs defaultValue="runbook" className="gap-4">
          <TabsList>
            <TabsTrigger value="runbook">Runbook</TabsTrigger>
            <TabsTrigger value="evidence">Evidence</TabsTrigger>
            <TabsTrigger value="occurrences">Occurrences</TabsTrigger>
          </TabsList>

          <TabsContent value="runbook" className="space-y-5">
            <div className="space-y-3">
              <CardEyebrow>Work chain</CardEyebrow>
              {data.workItems.length === 0 ? (
                <div className="rounded-md border border-dashed border-border bg-muted/20 px-4 py-8 text-sm text-muted-foreground">
                  No persisted work graph exists yet for this thread.
                </div>
              ) : (
                <ExecutionGraph
                  items={data.workItems}
                  activeWorkItemId={activeWorkItem?.id ?? null}
                  blockedWorkItemId={blockedWorkItem?.id ?? null}
                />
              )}
            </div>

            <div className="space-y-3">
              <CardEyebrow>Shared artifacts</CardEyebrow>
              {data.artifacts.length === 0 ? (
                <div className="rounded-md border border-dashed border-border bg-muted/20 px-4 py-8 text-sm text-muted-foreground">
                  No shared artifacts have been persisted for this thread yet.
                </div>
              ) : (
                <div className="grid gap-3">
                  {data.artifacts.map((artifact) => (
                    <div key={artifact.id} className="rounded-md border border-border bg-card px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-foreground">{artifact.label}</div>
                          <div className="mt-1 text-xs leading-5 text-muted-foreground">{artifact.summary}</div>
                        </div>
                        <Badge variant="outline">{formatArtifactKindLabel(artifact.kind)}</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="evidence">
            <div className="space-y-3">
              <CardEyebrow>Thread evidence</CardEyebrow>
              <EvidenceTabs
                request={data.latest.evidenceRequest}
                response={data.latest.evidenceResponse}
                analysis={data.latest.evidenceAnalysis}
              />
            </div>
          </TabsContent>

          <TabsContent value="occurrences">
            <Card className="overflow-hidden">
              <CardHeader>
                <div>
                  <CardEyebrow>Occurrences</CardEyebrow>
                  <CardTitle className="mt-2">Matching findings</CardTitle>
                  <CardDescription>Each row is an occurrence grouped into this thread.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead>Finding</TableHead>
                      <TableHead>Scan</TableHead>
                      <TableHead>Time</TableHead>
                      <TableHead className="w-[8rem]">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.rows.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell className="font-mono text-xs text-foreground">{row.id.slice(0, 8)}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{row.scanId.slice(0, 8)}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatTime(row.timestamp)}</TableCell>
                        <TableCell><StatusBadge value={row.status} /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </InspectorPane>
    </div>
  );
}

function ThreadInbox({
  groups,
  readyGroups,
  activeGroups,
  blockedGroups,
  selectedFingerprint,
  queueSort,
  pendingFingerprint,
  onSortChange,
  onSelect,
}: {
  groups: FindingGroup[];
  readyGroups: FindingGroup[];
  activeGroups: FindingGroup[];
  blockedGroups: FindingGroup[];
  selectedFingerprint: string | null;
  queueSort: QueueSortMode;
  pendingFingerprint: string | null;
  onSortChange: (value: QueueSortMode) => void;
  onSelect: (fingerprint: string) => void;
}) {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <Card className="overflow-hidden">
        <CardHeader>
          <div>
            <CardEyebrow>Runnable surface</CardEyebrow>
            <CardTitle className="mt-2">Autonomous inbox</CardTitle>
            <CardDescription>
              The inbox is the operational surface: what can run now, what is already running, and what is blocked.
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant={queueSort === "attention" ? "default" : "outline"} size="xs" onClick={() => onSortChange("attention")}>
              Needs attention
            </Button>
            <Button variant={queueSort === "newest" ? "default" : "outline"} size="xs" onClick={() => onSortChange("newest")}>
              Newest
            </Button>
            <Button variant={queueSort === "severity" ? "default" : "outline"} size="xs" onClick={() => onSortChange("severity")}>
              Severity
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {groups.length === 0 ? (
            <EmptyState
              title="No threads in the inbox"
              body="Adjust filters or launch a run to populate the thread queue."
            />
          ) : (
            <>
              <ThreadSectionCard
                eyebrow="Ready"
                title="Ready to claim"
                description="Runnable threads with no review gate. These are the next autonomous work candidates."
                count={readyGroups.length}
                emptyLabel="No ready threads under the active filters."
              >
                {readyGroups.map((group) => (
                  <ThreadListItem
                    key={group.fingerprint}
                    group={group}
                    selected={selectedFingerprint === group.fingerprint}
                    saving={pendingFingerprint === group.fingerprint}
                    mode="inbox"
                    onSelect={onSelect}
                  />
                ))}
              </ThreadSectionCard>

              <ThreadSectionCard
                eyebrow="Running"
                title="Live execution"
                description="Threads currently owned by a worker or marked in progress."
                count={activeGroups.length}
                emptyLabel="No live execution right now."
              >
                {activeGroups.map((group) => (
                  <ThreadListItem
                    key={group.fingerprint}
                    group={group}
                    selected={selectedFingerprint === group.fingerprint}
                    saving={pendingFingerprint === group.fingerprint}
                    mode="inbox"
                    onSelect={onSelect}
                  />
                ))}
              </ThreadSectionCard>
            </>
          )}
        </CardContent>
      </Card>

      <div className="space-y-4">
        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Blocked work</CardEyebrow>
              <CardTitle className="mt-2">Needs intervention</CardTitle>
              <CardDescription>
                Threads that need context, access, or a better exploit path before the worker can continue.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            {blockedGroups.length === 0 ? (
              <div className="px-6 pb-6">
                <EmptyState
                  title="Nothing is blocked"
                  body="The current thread set has no blocked execution paths."
                />
              </div>
            ) : (
              <ScrollArea className="max-h-[38rem]">
                <CardList>
                  {blockedGroups.map((group) => (
                    <ThreadListItem
                      key={group.fingerprint}
                      group={group}
                      selected={selectedFingerprint === group.fingerprint}
                      saving={pendingFingerprint === group.fingerprint}
                      mode="review"
                      onSelect={onSelect}
                    />
                  ))}
                </CardList>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardEyebrow>Reading model</CardEyebrow>
              <CardTitle className="mt-2">How to use threads</CardTitle>
              <CardDescription>
                Runs create evidence. Threads cluster repeated evidence over time. Workers claim runnable thread work until a review gate or blocker stops them.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-3">
            <ModeStat label="Filtered threads" value={`${groups.length}`} meta="Current inbox scope after search and filters." />
            <ModeStat label="Ready plus running" value={`${readyGroups.length + activeGroups.length}`} meta="Threads automation can touch without human sign-off." />
            <ModeStat label="Blocked plus review" value={`${blockedGroups.length}`} meta="Threads drifting out of the autonomous happy path." />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ThreadReviewDeck({
  agentReviewGroups,
  humanReviewGroups,
  selectedFingerprint,
  pendingFingerprint,
  onSelect,
}: {
  agentReviewGroups: FindingGroup[];
  humanReviewGroups: FindingGroup[];
  selectedFingerprint: string | null;
  pendingFingerprint: string | null;
  onSelect: (fingerprint: string) => void;
}) {
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card className="overflow-hidden">
        <CardHeader>
          <div>
            <CardEyebrow>Agent review</CardEyebrow>
            <CardTitle className="mt-2">Consensus and replication</CardTitle>
            <CardDescription>
              Threads that need another autonomous pass, conflict resolution, or a stronger PoC before operator review.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          {agentReviewGroups.length === 0 ? (
            <div className="px-6 pb-6">
              <EmptyState
                title="No agent review threads"
                body="Nothing currently needs another agent pass under the active filters."
              />
            </div>
          ) : (
            <ScrollArea className="max-h-[70vh]">
              <CardList>
                {agentReviewGroups.map((group) => (
                  <ThreadListItem
                    key={group.fingerprint}
                    group={group}
                    selected={selectedFingerprint === group.fingerprint}
                    saving={pendingFingerprint === group.fingerprint}
                    mode="review"
                    onSelect={onSelect}
                  />
                ))}
              </CardList>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      <Card className="overflow-hidden">
        <CardHeader>
          <div>
            <CardEyebrow>Human review</CardEyebrow>
            <CardTitle className="mt-2">Operator sign-off</CardTitle>
            <CardDescription>
              Threads that already have enough signal and now need a final human call on disposition or reporting.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          {humanReviewGroups.length === 0 ? (
            <div className="px-6 pb-6">
              <EmptyState
                title="No human review threads"
                body="No threads currently require operator sign-off under the active filters."
              />
            </div>
          ) : (
            <ScrollArea className="max-h-[70vh]">
              <CardList>
                {humanReviewGroups.map((group) => (
                  <ThreadListItem
                    key={group.fingerprint}
                    group={group}
                    selected={selectedFingerprint === group.fingerprint}
                    saving={pendingFingerprint === group.fingerprint}
                    mode="review"
                    onSelect={onSelect}
                  />
                ))}
              </CardList>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ThreadSectionCard({
  eyebrow,
  title,
  description,
  count,
  emptyLabel,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  count: number;
  emptyLabel: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="overflow-hidden" size="sm">
      <CardHeader className="border-b border-border">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardEyebrow>{eyebrow}</CardEyebrow>
            <CardTitle className="mt-2">{title}</CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
          <Badge variant="neutral">{count}</Badge>
        </div>
      </CardHeader>
      <CardContent className="px-0 pb-0">
        {count === 0 ? (
          <div className="px-4 pb-4">
            <EmptyState title={emptyLabel} body="The queue will repopulate here as runs produce thread work." />
          </div>
        ) : (
          <CardList>{children}</CardList>
        )}
      </CardContent>
    </Card>
  );
}

function ThreadListItem({
  group,
  selected,
  saving,
  mode,
  onSelect,
}: {
  group: FindingGroup;
  selected: boolean;
  saving: boolean;
  mode: "inbox" | "review";
  onSelect: (fingerprint: string) => void;
}) {
  const helperText =
    mode === "review"
      ? group.workflow.reviewGate === "agent_review"
        ? "Needs agent replication or conflict resolution."
        : "Needs operator decision before final disposition."
      : group.workflow.reviewReason
        ? group.workflow.reviewReason
        : group.workflow.phase === "in_progress"
          ? "Execution is active now."
          : group.workflow.phase === "blocked"
            ? "Execution is blocked and needs intervention."
            : "Ready for the next autonomous step.";

  return (
    <CardListItem interactive selected={selected} className="p-0">
      <button
        type="button"
        onClick={() => onSelect(group.fingerprint)}
        className="w-full px-4 py-4 text-left"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 space-y-1">
            <div className="text-sm font-semibold leading-5 text-foreground">{group.latest.title}</div>
            <div className="text-xs leading-5 text-muted-foreground">{helperText}</div>
          </div>
          <div className="flex shrink-0 flex-wrap justify-end gap-2">
            {group.workflow.reviewGate !== "none" ? <ReviewBadge value={group.workflow.reviewGate} /> : null}
            <SeverityBadge severity={group.latest.severity} />
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <PhaseBadge value={group.workflow.phase} />
          <ConsensusBadge value={group.workflow.consensus} />
          <SignalBadge value={group.workflow.evidenceSignal} />
          <StatusBadge value={group.latest.triageStatus} />
          {group.workflow.persistedStatus !== group.workflow.phase && group.workflow.persistedStatus !== group.workflow.reviewGate ? (
            <WorkflowBadge value={group.workflow.persistedStatus} />
          ) : null}
        </div>

        <div className="mt-3 grid gap-2 text-xs text-muted-foreground md:grid-cols-4">
          <div>Owner: {group.workflow.assignee ?? "Unassigned"}</div>
          <div>Coverage: {group.count} hits · {group.scanCount} scans</div>
          <div>Agents: {group.workflow.activeAgentRoles.length > 0 ? group.workflow.activeAgentRoles.join(", ") : "None"}</div>
          <div className="inline-flex items-center gap-1.5">
            <Clock3 className="size-3.5" />
            {saving ? "Saving workflow..." : `Updated ${formatTime(group.workflow.updatedAt ?? group.latest.timestamp)}`}
          </div>
        </div>
      </button>
    </CardListItem>
  );
}

function ModeStat({
  label,
  value,
  meta,
}: {
  label: string;
  value: string;
  meta: string;
}) {
  return (
    <div className="rounded-md border border-border bg-card px-4 py-3">
      <div className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-foreground">{value}</div>
      <div className="mt-1 text-xs text-muted-foreground">{meta}</div>
    </div>
  );
}

function TaskStatusBadge({
  value,
}: {
  value: "backlog" | "todo" | "in_progress" | "blocked" | "done" | "cancelled";
}) {
  const variant =
    value === "done"
      ? "success"
      : value === "blocked" || value === "cancelled"
        ? "danger"
        : value === "in_progress"
          ? "accent"
          : value === "todo"
            ? "warning"
            : "neutral";

  return <Badge variant={variant}>{value.replaceAll("_", " ")}</Badge>;
}

function ExecutionGraph({
  items,
  activeWorkItemId,
  blockedWorkItemId,
}: {
  items: FindingFamilyResponse["workItems"];
  activeWorkItemId: string | null;
  blockedWorkItemId: string | null;
}) {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {items.map((item) => {
        const isCurrent = activeWorkItemId === item.id;
        const isBlocked = blockedWorkItemId === item.id;
        const toneClass = isBlocked
          ? "border-destructive/30 bg-destructive/5"
          : isCurrent
            ? "border-primary/30 bg-primary/5"
            : "border-border bg-card";

        return (
          <div key={item.id} className={`rounded-md border px-4 py-3 ${toneClass}`}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-sm font-medium text-foreground">{item.title}</div>
                  {isCurrent ? <Badge variant="accent">Current</Badge> : null}
                  {isBlocked ? <Badge variant="danger">Blocked</Badge> : null}
                </div>
                <div className="mt-1 text-xs leading-5 text-muted-foreground">{item.summary}</div>
              </div>
              <TaskStatusBadge value={item.status} />
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <Badge variant="outline">{formatWorkItemKindLabel(item.kind)}</Badge>
              <Badge variant="outline">{item.owner ?? "Unassigned"}</Badge>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SummaryMetric({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-md border border-border bg-card px-4 py-3">
      <div className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">{label}</div>
      <div className={mono ? "mt-2 truncate font-mono text-xs text-foreground" : "mt-2 text-sm font-medium text-foreground"}>
        {value}
      </div>
    </div>
  );
}

function formatArtifactKindLabel(kind: FindingFamilyResponse["artifacts"][number]["kind"]) {
  return kind.replaceAll("_", " ");
}

function formatWorkItemKindLabel(kind: FindingFamilyResponse["workItems"][number]["kind"]) {
  return kind.replaceAll("_", " ");
}

function formatCaseTargetTypeLabel(value: NonNullable<FindingFamilyResponse["case"]>["targetType"]) {
  return value.replaceAll("-", " ");
}

function severityRank(severity: string) {
  const normalized = severity.toLowerCase();
  if (normalized === "critical") return 5;
  if (normalized === "high") return 4;
  if (normalized === "medium") return 3;
  if (normalized === "low") return 2;
  return 1;
}

function attentionRank(group: FindingGroup) {
  let rank = 0;
  if (group.workflow.reviewGate === "human_review") rank += 100;
  else if (group.workflow.reviewGate === "agent_review") rank += 90;
  else if (group.workflow.phase === "blocked") rank += 80;
  else if (group.workflow.phase === "in_progress") rank += 70;
  else if (group.workflow.phase === "todo") rank += 60;
  else if (group.workflow.phase === "backlog") rank += 50;

  if (!group.workflow.assignee) rank += 15;
  if (group.workflow.consensus === "disputed") rank += 12;
  if (group.workflow.activeAgentRoles.length > 0) rank += 8;

  return rank * 1_000_000 + group.latest.timestamp + severityRank(group.latest.severity) * 1_000;
}

function workflowPhaseFromStatus(status: FindingWorkflowStatus): FindingWorkflowPhase {
  if (status === "done" || status === "cancelled" || status === "blocked" || status === "in_progress" || status === "todo") {
    return status;
  }
  return "backlog";
}

function FilterRow({
  label,
  className,
  children,
}: {
  label: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={`space-y-3 rounded-md border border-border bg-card px-4 py-4 ${className ?? ""}`}>
      <CardEyebrow>{label}</CardEyebrow>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <Button
      variant={active ? "default" : "outline"}
      size="xs"
      onClick={onClick}
    >
      {children}
    </Button>
  );
}
