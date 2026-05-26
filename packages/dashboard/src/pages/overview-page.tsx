import { useMemo, useState, type ComponentType } from "react";
import { NavLink } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertCircle, Bot, Clock3, Database, Play, Power, RefreshCcw, Siren, Trash2, Workflow } from "lucide-react";
import { getRecentEvents, launchRun, pruneStoppedWorkers, recoverStaleWorkers, resetDatabase, startDaemon, stopDaemon } from "@/api";
import { PageHeader } from "@/components/page-header";
import { ConsensusBadge, PhaseBadge, ReviewBadge, SeverityBadge, StatusBadge } from "@/components/status-badges";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardEmpty, CardEyebrow, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatDuration, formatTime } from "@/lib/format";
import type { DashboardResponse } from "@/types";

export function OverviewPage({ data }: { data: DashboardResponse }) {
  const queryClient = useQueryClient();
  const [controlMessage, setControlMessage] = useState<string | null>(null);
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<"deep" | "web" | "mcp">("deep");
  const [depth, setDepth] = useState<"quick" | "default" | "deep">("default");
  const [runtime, setRuntime] = useState<"auto" | "api" | "codex" | "claude" | "gemini">("auto");
  const recentEventsQuery = useQuery({
    queryKey: ["recent-events"],
    queryFn: () => getRecentEvents(12),
    refetchInterval: 5000,
  });

  const reviewQueue = data.groups.filter((group) => group.workflow.reviewGate !== "none");
  const blockedThreads = data.groups.filter((group) => group.workflow.phase === "blocked");
  const runningThreads = data.groups.filter((group) => group.workflow.phase === "in_progress");
  const unassignedThreads = data.groups.filter((group) => !group.workflow.assignee);
  const activeScans = data.scans.filter((scan) => scan.status === "running");
  const activeWorkers = data.workers.filter((worker) => worker.isActive && worker.status !== "stopped");
  const stoppedWorkers = data.workers.filter((worker) => worker.status === "stopped");
  const hasLiveDaemon = activeWorkers.length > 0;
  const isEmptyWorkspace = data.scans.length === 0 && data.groups.length === 0 && data.workers.length === 0;

  const refreshDashboard = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
      queryClient.invalidateQueries({ queryKey: ["scans"] }),
      queryClient.invalidateQueries({ queryKey: ["recent-events"] }),
    ]);
  };

  const recoverMutation = useMutation({
    mutationFn: () => recoverStaleWorkers(),
    onSuccess: async (result) => {
      setControlMessage(
        result.recovered > 0
          ? `Recovered ${result.recovered} stale work item${result.recovered === 1 ? "" : "s"}.`
          : "No stale worker claims needed recovery.",
      );
      await refreshDashboard();
    },
    onError: (error) => {
      setControlMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const pruneMutation = useMutation({
    mutationFn: () => pruneStoppedWorkers(),
    onSuccess: async (result) => {
      setControlMessage(
        result.deleted > 0
          ? `Pruned ${result.deleted} stopped worker row${result.deleted === 1 ? "" : "s"}.`
          : "No stopped worker rows were left to prune.",
      );
      await refreshDashboard();
    },
    onError: (error) => {
      setControlMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const resetMutation = useMutation({
    mutationFn: () => resetDatabase("empty"),
    onSuccess: async (result) => {
      setControlMessage(`Reset local state at ${result.path}.`);
      await refreshDashboard();
    },
    onError: (error) => {
      setControlMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const startDaemonMutation = useMutation({
    mutationFn: () => startDaemon({ label: "control-plane-1", pollIntervalMs: 2000 }),
    onSuccess: async () => {
      setControlMessage("Started local control-plane daemon.");
      await refreshDashboard();
    },
    onError: (error) => {
      setControlMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const stopDaemonMutation = useMutation({
    mutationFn: () => stopDaemon(),
    onSuccess: async (result) => {
      setControlMessage(
        result.stopped > 0
          ? `Stopped ${result.stopped} local daemon process${result.stopped === 1 ? "" : "es"}.`
          : "No live local daemon process needed stopping.",
      );
      await refreshDashboard();
    },
    onError: (error) => {
      setControlMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const launchMutation = useMutation({
    mutationFn: () => launchRun({
      target: target.trim(),
      depth,
      mode,
      runtime,
      ensureDaemon: true,
    }),
    onSuccess: async () => {
      setControlMessage(`Launched ${mode} run for ${target.trim()}.`);
      setTarget("");
      await refreshDashboard();
    },
    onError: (error) => {
      setControlMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const isMutating =
    recoverMutation.isPending
    || pruneMutation.isPending
    || resetMutation.isPending
    || startDaemonMutation.isPending
    || stopDaemonMutation.isPending
    || launchMutation.isPending;

  const needsAttention = [...data.groups]
    .filter(
      (group) =>
        group.workflow.reviewGate !== "none"
        || group.workflow.phase === "blocked"
        || !group.workflow.assignee,
    )
    .sort((left, right) => right.latest.timestamp - left.latest.timestamp)
    .slice(0, 8);

  const activeThreads = [...data.groups]
    .filter((group) => group.workflow.phase === "in_progress" || group.workflow.activeAgentRoles.length > 0)
    .sort((left, right) => right.latest.timestamp - left.latest.timestamp)
    .slice(0, 8);

  const recentRuns = [...data.scans]
    .sort((left, right) => right.startedAt.localeCompare(left.startedAt))
    .slice(0, 8);
  const recentIncidents = useMemo(() => {
    const rows = recentEventsQuery.data?.events ?? [];
    const byScan = new Map<string, {
      scanId: string;
      scanTarget: string;
      stage: string;
      actor: string | null;
      headline: string;
      timestamp: number;
    }>();

    for (const event of rows) {
      const payload = event.payload ?? {};
      const summaryText =
        typeof payload.summary === "string" && payload.summary.trim()
          ? payload.summary.trim()
          : event.summary;
      const isExecutionStall =
        ["stage_complete", "agent_complete", "runtime_incompatible"].includes(event.eventType)
        && /max turns|did not emit required tool_call/i.test(summaryText);
      if (!["agent_error", "scan_error", "worker_failed"].includes(event.eventType) && !isExecutionStall) continue;
      if (byScan.has(event.scanId)) continue;
      const headline =
        typeof payload.error === "string" && payload.error.trim()
          ? payload.error.trim()
          : typeof payload.summary === "string" && payload.summary.trim()
            ? payload.summary.trim()
            : event.summary;

      byScan.set(event.scanId, {
        scanId: event.scanId,
        scanTarget: event.scanTarget,
        stage: event.stage,
        actor: event.agentRole ?? null,
        headline,
        timestamp: event.timestamp,
      });
    }

    return [...byScan.values()].slice(0, 4);
  }, [recentEventsQuery.data?.events]);

  const latestThreads = [...data.groups]
    .sort(
      (left, right) =>
        Number(new Date(right.workflow.updatedAt ?? right.latest.timestamp))
        - Number(new Date(left.workflow.updatedAt ?? left.latest.timestamp)),
    )
    .slice(0, 8);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Control"
        title="Operations control"
        summary="Launch new targets, watch the autonomous queue, and jump to the threads or runs that actually need intervention."
        actions={(
          <>
            <Button asChild variant="outline">
              <NavLink to="/runs">Open runs</NavLink>
            </Button>
            <Button asChild variant="accent">
              <NavLink to="/threads">Open thread console</NavLink>
            </Button>
          </>
        )}
      />

      {isEmptyWorkspace ? (
        <section className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
          <Card className="overflow-hidden">
            <CardHeader>
              <div>
                <CardEyebrow>First run</CardEyebrow>
                <CardTitle className="mt-2">Launch the first target</CardTitle>
                <CardDescription>
                  A thread is the clustered underlying issue behind repeated hits across runs. Start a target, let the pipeline decompose the work, then review only the threads that survive automation.
                </CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="space-y-2">
                <div className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">Target</div>
                <Input
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder={mode === "mcp" ? "mcp://assistant-endpoint" : mode === "web" ? "https://app.example.com" : "https://api.example.com"}
                />
              </div>

              <div className="grid gap-4 lg:grid-cols-3">
                <SelectionField
                  label="Mode"
                  value={mode}
                  onValueChange={(value) => setMode(value as typeof mode)}
                  options={[
                    { value: "deep", label: "API/URL" },
                    { value: "web", label: "Web app" },
                    { value: "mcp", label: "MCP" },
                  ]}
                />
                <SelectionField
                  label="Depth"
                  value={depth}
                  onValueChange={(value) => setDepth(value as typeof depth)}
                  options={[
                    { value: "quick", label: "Quick" },
                    { value: "default", label: "Default" },
                    { value: "deep", label: "Deep" },
                  ]}
                />
                <SelectionField
                  label="Runtime"
                  value={runtime}
                  onValueChange={(value) => setRuntime(value as typeof runtime)}
                  options={[
                    { value: "auto", label: "Auto" },
                    { value: "api", label: "API" },
                    { value: "codex", label: "Codex" },
                    { value: "claude", label: "Claude" },
                    { value: "gemini", label: "Gemini" },
                  ]}
                />
              </div>

              <div className="flex flex-wrap gap-3">
                <Button
                  variant="accent"
                  onClick={() => launchMutation.mutate()}
                  disabled={!target.trim() || isMutating}
                >
                  <Play />
                  Launch target
                </Button>
                <Button
                  variant="outline"
                  onClick={() => startDaemonMutation.mutate()}
                  disabled={hasLiveDaemon || isMutating}
                >
                  <Power />
                  Start daemon
                </Button>
                <Button
                  variant="outline"
                  onClick={() => stopDaemonMutation.mutate()}
                  disabled={!hasLiveDaemon || isMutating}
                >
                  <Power />
                  Stop daemon
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="overflow-hidden">
            <CardHeader>
              <div>
                <CardEyebrow>Execution model</CardEyebrow>
                <CardTitle className="mt-2">How the system works</CardTitle>
                <CardDescription>
                  This is not meant to be a human-driven kanban first. The control plane should run autonomously until a thread needs review, override, or more access.
                </CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <div className="rounded-md border border-border bg-background px-4 py-3">
                A `run` is one pipeline execution against a target.
              </div>
              <div className="rounded-md border border-border bg-background px-4 py-3">
                A `thread` is one underlying issue clustered across repeated hits or follow-up evidence.
              </div>
              <div className="rounded-md border border-border bg-background px-4 py-3">
                A `worker` is a local autonomous daemon claiming runnable stages from persisted state.
              </div>
              <div className="rounded-md border border-border bg-background px-4 py-3">
                Humans should mostly work the review inbox, blocked access, and final disposition.
              </div>
            </CardContent>
          </Card>
        </section>
      ) : null}

      <section className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <Card className="overflow-hidden">
          <CardHeader>
              <div>
                <CardEyebrow>Launch</CardEyebrow>
                <CardTitle className="mt-2">Control strip</CardTitle>
                <CardDescription>
                  Launch a new target, keep the daemon healthy, and clear local state without dropping to the CLI.
                </CardDescription>
              </div>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_repeat(3,minmax(0,0.8fr))]">
              <label className="space-y-2">
                <div className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">Target</div>
                <Input
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder={mode === "mcp" ? "mcp://assistant-endpoint" : mode === "web" ? "https://app.example.com" : "https://api.example.com"}
                />
              </label>
              <SelectionField
                label="Mode"
                value={mode}
                onValueChange={(value) => setMode(value as typeof mode)}
                options={[
                  { value: "deep", label: "API/URL" },
                  { value: "web", label: "Web app" },
                  { value: "mcp", label: "MCP" },
                ]}
              />
              <SelectionField
                label="Depth"
                value={depth}
                onValueChange={(value) => setDepth(value as typeof depth)}
                options={[
                  { value: "quick", label: "Quick" },
                  { value: "default", label: "Default" },
                  { value: "deep", label: "Deep" },
                ]}
              />
              <SelectionField
                label="Runtime"
                value={runtime}
                onValueChange={(value) => setRuntime(value as typeof runtime)}
                options={[
                  { value: "auto", label: "Auto" },
                  { value: "api", label: "API" },
                  { value: "codex", label: "Codex" },
                  { value: "claude", label: "Claude" },
                  { value: "gemini", label: "Gemini" },
                ]}
              />
            </div>

            <div className="flex flex-wrap gap-3">
              <Button
                variant="accent"
                onClick={() => launchMutation.mutate()}
                disabled={!target.trim() || isMutating}
              >
                <Play />
                Launch target
              </Button>
              <Button
                variant={hasLiveDaemon ? "outline" : "default"}
                onClick={() => (hasLiveDaemon ? stopDaemonMutation.mutate() : startDaemonMutation.mutate())}
                disabled={isMutating}
              >
                <Power />
                {hasLiveDaemon ? "Stop daemon" : "Start daemon"}
              </Button>
              <Button variant="outline" onClick={() => recoverMutation.mutate()} disabled={isMutating}>
                <RefreshCcw />
                Recover stale
              </Button>
              <Button variant="outline" onClick={() => pruneMutation.mutate()} disabled={isMutating}>
                <Trash2 />
                Prune stopped
              </Button>
              <Button
                variant="warning"
                onClick={() => resetMutation.mutate()}
                disabled={isMutating || hasLiveDaemon}
              >
                <Database />
                Reset local state
              </Button>
            </div>

            <div className="rounded-md border border-border bg-muted/20 px-4 py-3 text-sm text-muted-foreground">
              {controlMessage ?? "The daemon can be started from here. Local state reset stays guarded while a live daemon is heartbeating."}
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Situation</CardEyebrow>
              <CardTitle className="mt-2">Live system state</CardTitle>
              <CardDescription>
                Read the queue, worker fleet, and review backlog at a glance before drilling into threads or runs.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2">
            <SituationStat icon={Workflow} label="Runnable now" value={data.queue.runnable} hint="Work items ready to claim." />
            <SituationStat icon={Activity} label="Workers" value={activeWorkers.length} hint="Live orchestration daemons." />
            <SituationStat icon={AlertCircle} label="Review" value={reviewQueue.length} hint="Threads waiting on sign-off." />
            <SituationStat icon={Siren} label="Blocked" value={blockedThreads.length} hint="Threads outside the happy path." />
            <SituationStat icon={Bot} label="Running threads" value={runningThreads.length} hint="Threads with live worker activity." />
            <SituationStat icon={Clock3} label="Unassigned" value={unassignedThreads.length} hint="Threads without an owner." />
            <SituationStat icon={Play} label="Active runs" value={activeScans.length} hint="Runs still executing." />
            <SituationStat icon={Trash2} label="Stopped workers" value={stoppedWorkers.length} hint="Rows safe to prune." />
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Queue</CardEyebrow>
              <CardTitle className="mt-2">Operations inbox</CardTitle>
              <CardDescription>
                Threads that most likely need a human decision next: blocked execution, review gates, or ownership gaps.
              </CardDescription>
            </div>
            <Button asChild variant="ghost" size="sm">
              <NavLink to="/threads">Open threads</NavLink>
            </Button>
          </CardHeader>
          <CardContent>
            {needsAttention.length === 0 ? (
              <CardEmpty className="text-left">No threads currently need intervention.</CardEmpty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Thread</TableHead>
                    <TableHead>Ownership</TableHead>
                    <TableHead>Signal</TableHead>
                    <TableHead className="w-[14rem]">State</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {needsAttention.map((group) => (
                    <TableRow key={group.fingerprint}>
                      <TableCell className="font-medium">
                        <NavLink to={`/threads/${group.fingerprint}`} className="text-foreground hover:text-primary">
                          {group.latest.title}
                        </NavLink>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {group.workflow.assignee ?? "Unassigned"}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <SeverityBadge severity={group.latest.severity} />
                          <ConsensusBadge value={group.workflow.consensus} />
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <PhaseBadge value={group.workflow.phase} />
                          {group.workflow.reviewGate !== "none" ? <ReviewBadge value={group.workflow.reviewGate} /> : null}
                          <StatusBadge value={group.latest.triageStatus} />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Execution</CardEyebrow>
              <CardTitle className="mt-2">Queue and daemons</CardTitle>
              <CardDescription>
                Use this column to understand what automation is doing right now and where the queue is getting stuck.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {activeThreads.length === 0 ? (
              <CardEmpty className="text-left">No live worker activity right now.</CardEmpty>
            ) : (
              <div className="space-y-3">
                {activeThreads.map((group) => (
                  <div key={group.fingerprint} className="rounded-lg border border-border bg-background px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <NavLink to={`/threads/${group.fingerprint}`} className="text-sm font-medium text-foreground hover:text-primary">
                          {group.latest.title}
                        </NavLink>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {group.workflow.activeAgentRoles.length > 0
                            ? group.workflow.activeAgentRoles.join(", ")
                            : "Waiting for worker activity"}
                        </div>
                      </div>
                      <PhaseBadge value={group.workflow.phase} />
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="space-y-3">
              <div>
                <CardEyebrow>Autonomous queue</CardEyebrow>
                <CardTitle className="mt-2">Worker-ready state</CardTitle>
                <CardDescription>
                  Real queue health from persisted work items, not inferred status labels.
                </CardDescription>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <QueueStat label="Runnable now" value={data.queue.runnable} hint="Dependencies satisfied and no sibling claim is active." />
                <QueueStat label="Active claims" value={data.queue.active} hint="Currently held by a running case worker." />
                <QueueStat label="Blocked by deps" value={data.queue.blockedByDependency} hint="Waiting on an earlier stage to complete first." />
                <QueueStat label="Manual review" value={data.queue.manualReview} hint="Queued for operator sign-off, not autonomous execution." />
                <QueueStat label="Recovered claims" value={data.queue.recoveredClaims} hint="Requeued after a stale worker heartbeat expired." />
                <QueueStat label="Stale workers" value={data.queue.staleWorkers} hint="Workers marked errored after heartbeat expiry." />
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <CardEyebrow>Autonomous workers</CardEyebrow>
                <CardTitle className="mt-2">Daemon state</CardTitle>
              </div>
              {activeWorkers.length === 0 ? (
                <CardEmpty className="text-left">No orchestration daemons are heartbeating right now.</CardEmpty>
              ) : (
                <div className="space-y-3">
                  {activeWorkers.slice(0, 4).map((worker) => (
                    <div key={worker.id} className="rounded-lg border border-border bg-background px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-foreground">{worker.label}</div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {worker.currentWorkItemTitle ?? worker.currentWorkItemId ?? "Idle"}
                            {worker.currentCaseTarget ? ` · ${worker.currentCaseTarget}` : ""}
                            {` · heartbeat ${formatTime(worker.heartbeatAt)}`}
                          </div>
                          {worker.lastError ? <div className="mt-1 text-xs text-destructive">{worker.lastError}</div> : null}
                        </div>
                        <StatusBadge value={worker.status} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Runs</CardEyebrow>
              <CardTitle className="mt-2">Recent execution</CardTitle>
              <CardDescription>
                Recent and still-running runs. Use this to jump into provenance without leaving operations.
              </CardDescription>
            </div>
            <Button asChild variant="ghost" size="sm">
              <NavLink to="/runs">Open runs</NavLink>
            </Button>
          </CardHeader>
          <CardContent>
            {recentRuns.length === 0 ? (
              <CardEmpty className="text-left">No runs recorded yet.</CardEmpty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Target</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Profile</TableHead>
                    <TableHead className="w-[12rem]">State</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentRuns.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell className="font-medium">
                        <NavLink to={`/runs/${scan.id}`} className="text-foreground hover:text-primary">
                          {scan.target}
                        </NavLink>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{formatTime(scan.startedAt)}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {scan.runtime} · {scan.mode} · {scan.depth}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <StatusBadge value={scan.status} />
                          <span className="text-xs text-muted-foreground">
                            {formatDuration(scan.durationMs)}
                          </span>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Threads</CardEyebrow>
              <CardTitle className="mt-2">Latest movement</CardTitle>
              <CardDescription>
                Most recent thread changes across automation, triage, and review.
              </CardDescription>
            </div>
            <Button asChild variant="ghost" size="sm">
              <NavLink to="/threads">Open threads</NavLink>
            </Button>
          </CardHeader>
          <CardContent>
            {latestThreads.length === 0 ? (
              <CardEmpty className="text-left">No threads recorded yet.</CardEmpty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Thread</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead>Coverage</TableHead>
                    <TableHead className="w-[16rem]">State</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {latestThreads.map((group) => (
                    <TableRow key={group.fingerprint}>
                      <TableCell className="font-medium">
                        <NavLink to={`/threads/${group.fingerprint}`} className="text-foreground hover:text-primary">
                          {group.latest.title}
                        </NavLink>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatTime(group.workflow.updatedAt ?? group.latest.timestamp)}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {group.count} hits · {group.scanCount} scans
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <PhaseBadge value={group.workflow.phase} />
                          {group.workflow.reviewGate !== "none" ? <ReviewBadge value={group.workflow.reviewGate} /> : null}
                          <SeverityBadge severity={group.latest.severity} />
                          <ConsensusBadge value={group.workflow.consensus} />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </section>

      {recentIncidents.length > 0 ? (
        <Card className="overflow-hidden border-destructive/20">
          <CardHeader>
            <div>
              <CardEyebrow>Incidents</CardEyebrow>
              <CardTitle className="mt-2">Runtime incidents</CardTitle>
              <CardDescription>
                Provider failures, worker crashes, and stalled agent executions that need operator attention.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {recentIncidents.map((incident) => (
              <div key={`${incident.scanId}:${incident.timestamp}`} className="rounded-md border border-destructive/20 bg-destructive/5 px-4 py-3">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <NavLink to={`/runs/${incident.scanId}`} className="text-sm font-medium text-foreground hover:text-primary">
                      {incident.scanTarget}
                    </NavLink>
                    <div className="mt-1 text-sm leading-6 text-muted-foreground">{incident.headline}</div>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
                      <SeverityBadge severity="high" />
                      <span>{incident.stage}</span>
                      {incident.actor ? <span>{incident.actor}</span> : null}
                      <span>{formatTime(incident.timestamp)}</span>
                    </div>
                  </div>
                  <AlertCircle className="mt-0.5 size-5 shrink-0 text-destructive" />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      <Card className="overflow-hidden">
        <CardHeader>
          <div>
            <CardEyebrow>Events</CardEyebrow>
            <CardTitle className="mt-2">Recent pipeline activity</CardTitle>
            <CardDescription>
              Live audit events across runs, useful for seeing where the system is actually spending time.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          {recentEventsQuery.isLoading ? (
            <CardEmpty>Loading recent events...</CardEmpty>
          ) : recentEventsQuery.error ? (
            <CardEmpty>{recentEventsQuery.error instanceof Error ? recentEventsQuery.error.message : "Failed to load recent events."}</CardEmpty>
          ) : (recentEventsQuery.data?.events.length ?? 0) === 0 ? (
            <CardEmpty>No pipeline events recorded yet.</CardEmpty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Target</TableHead>
                  <TableHead>Summary</TableHead>
                  <TableHead>Stage</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead className="w-[12rem]">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentEventsQuery.data?.events.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="font-medium">
                      <div className="space-y-1">
                        <NavLink to={`/runs/${event.scanId}`} className="text-foreground hover:text-primary">
                          {event.scanTarget}
                        </NavLink>
                        {event.findingFingerprint ? (
                          <div>
                            <NavLink to={`/threads/${event.findingFingerprint}`} className="text-xs text-muted-foreground hover:text-primary">
                              Open thread
                            </NavLink>
                          </div>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{event.summary}</TableCell>
                    <TableCell className="text-muted-foreground">{event.stage}</TableCell>
                    <TableCell className="text-muted-foreground">{event.eventType}</TableCell>
                    <TableCell className="text-muted-foreground">{event.agentRole ?? "system"}</TableCell>
                    <TableCell className="text-muted-foreground">{formatTime(event.timestamp)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SituationStat({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: ComponentType<{ className?: string }>;
  label: string;
  value: number;
  hint: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-background px-4 py-3">
      <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">
        <Icon className="size-3.5" />
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold text-foreground">{value}</div>
      <div className="mt-1 text-xs leading-5 text-muted-foreground">{hint}</div>
    </div>
  );
}

function QueueStat({
  label,
  value,
  hint,
}: {
  label: string;
  value: number;
  hint: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-background px-4 py-3">
      <div className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-foreground">{value}</div>
      <div className="mt-1 text-xs leading-5 text-muted-foreground">{hint}</div>
    </div>
  );
}

function SelectionField({
  label,
  value,
  onValueChange,
  options,
}: {
  label: string;
  value: string;
  onValueChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <div className="space-y-2">
      <div className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      <Tabs value={value} onValueChange={onValueChange}>
        <TabsList className="w-full flex-wrap justify-start">
          {options.map((option) => (
            <TabsTrigger key={option.value} value={option.value} className="flex-1">
              {option.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
    </div>
  );
}
