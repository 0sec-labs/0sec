import { useCallback, useDeferredValue, useEffect, useMemo, useState } from "react";
import { NavLink, useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Activity, AlertCircle, Siren, Sparkles } from "lucide-react";
import { getScanEvents, getScanFindings } from "@/api";
import { useDashboardPanel } from "@/components/dashboard-panel";
import { EntityList, EntityListItem } from "@/components/entity-list";
import { EventTimeline } from "@/components/event-timeline";
import { InspectorPane } from "@/components/inspector-pane";
import { MetaTile } from "@/components/meta-tile";
import { MetricCard } from "@/components/metric-card";
import { EmptyState, ErrorState, LoadingState } from "@/components/state-panel";
import { ConsensusBadge, PhaseBadge, ReviewBadge, SeverityBadge, StatusBadge } from "@/components/status-badges";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardEmpty, CardEyebrow, CardHeader, CardList, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Workspace, WorkspaceMain, WorkspaceSidebar } from "@/components/workspace";
import { formatDuration, formatTime } from "@/lib/format";
import type { ScanEventsResponse, ScanFindingsResponse, ScanRecord } from "@/types";

type TargetRunGroup = {
  target: string;
  scans: ScanRecord[];
  latestScan: ScanRecord;
  activeRunCount: number;
  totalFindings: number;
};

export function ScansPage({ scans }: { scans: ScanRecord[] }) {
  const { scanId } = useParams<{ scanId?: string }>();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);

  const groupedTargets = useMemo(() => {
    const grouped = new Map<string, ScanRecord[]>();
    for (const scan of scans) {
      const existing = grouped.get(scan.target) ?? [];
      existing.push(scan);
      grouped.set(scan.target, existing);
    }

    return [...grouped.entries()]
      .map(([target, entries]) => {
        const sortedScans = [...entries].sort((left, right) => right.startedAt.localeCompare(left.startedAt));
        return {
          target,
          scans: sortedScans,
          latestScan: sortedScans[0]!,
          activeRunCount: sortedScans.filter((scan) => scan.status === "running").length,
          totalFindings: sortedScans.reduce((sum, scan) => sum + scan.summary.totalFindings, 0),
        } satisfies TargetRunGroup;
      })
      .sort((left, right) => right.latestScan.startedAt.localeCompare(left.latestScan.startedAt));
  }, [scans]);

  const filteredTargets = useMemo(() => {
    const normalized = deferredSearch.trim().toLowerCase();
    if (!normalized) return groupedTargets;
    return groupedTargets.filter((group) =>
      [group.target, ...group.scans.flatMap((scan) => [scan.depth, scan.runtime, scan.mode, scan.status, scan.id])]
        .join(" ")
        .toLowerCase()
        .includes(normalized),
    );
  }, [deferredSearch, groupedTargets]);

  const selectedScan = useMemo(
    () => scans.find((scan) => scan.id === scanId) ?? filteredTargets[0]?.latestScan ?? null,
    [filteredTargets, scanId, scans],
  );
  const selectedScanId = selectedScan?.id ?? null;
  const selectedTarget = useMemo(
    () => (selectedScan ? groupedTargets.find((group) => group.target === selectedScan.target) ?? null : null),
    [groupedTargets, selectedScan],
  );

  useEffect(() => {
    if (!scanId && selectedScanId) {
      navigate(`/runs/${selectedScanId}`, { replace: true });
    }
  }, [navigate, scanId, selectedScanId]);

  const eventsQuery = useQuery({
    queryKey: ["scan-events", selectedScanId],
    queryFn: () => getScanEvents(selectedScanId!),
    enabled: Boolean(selectedScanId),
  });

  const findingsQuery = useQuery({
    queryKey: ["scan-findings", selectedScanId],
    queryFn: () => getScanFindings(selectedScanId!),
    enabled: Boolean(selectedScanId),
  });

  return (
    <div className="space-y-6">
      <Workspace className="xl:grid-cols-[22rem_minmax(0,1fr)]">
        <WorkspaceSidebar>
          <EntityList
            title={`${groupedTargets.length} targets`}
            description="Search by target, runtime, mode, depth, status, or run id."
            searchValue={search}
            onSearchChange={setSearch}
            searchPlaceholder="Filter targets and runs"
          >
            {filteredTargets.length === 0 ? (
              <CardEmpty className="py-8">No targets match the current filter.</CardEmpty>
            ) : (
              filteredTargets.map((group) => (
                <NavLink key={group.target} to={`/runs/${group.latestScan.id}`}>
                  {({ isActive }) => (
                    <EntityListItem
                      selected={isActive}
                      title={group.target}
                      description={`${group.scans.length} runs · latest ${group.latestScan.runtime} · ${group.latestScan.mode}`}
                      meta={formatTime(group.latestScan.startedAt)}
                      badges={
                        <>
                          <StatusBadge value={group.latestScan.status} />
                          {group.activeRunCount > 0 ? <Badge variant="accent">{group.activeRunCount} active</Badge> : null}
                          <Badge>{group.totalFindings} findings</Badge>
                        </>
                      }
                    />
                  )}
                </NavLink>
              ))
            )}
          </EntityList>
        </WorkspaceSidebar>

        {!selectedScanId ? (
          <WorkspaceMain span>
            <EmptyState
              title="No scan selected"
              body="Choose a run from the run history to inspect details."
            />
          </WorkspaceMain>
        ) : eventsQuery.isLoading || findingsQuery.isLoading ? (
          <WorkspaceMain span>
            <LoadingState label="Scan detail" />
          </WorkspaceMain>
        ) : eventsQuery.error ? (
          <WorkspaceMain span>
            <ErrorState error={eventsQuery.error} />
          </WorkspaceMain>
        ) : findingsQuery.error ? (
          <WorkspaceMain span>
            <ErrorState error={findingsQuery.error} />
          </WorkspaceMain>
        ) : eventsQuery.data && findingsQuery.data ? (
          <ScanDetail events={eventsQuery.data} findings={findingsQuery.data} targetRuns={selectedTarget?.scans ?? []} />
        ) : (
          <WorkspaceMain span>
            <EmptyState
              title="Scan unavailable"
              body="The selected run could not be loaded from the local database."
            />
          </WorkspaceMain>
        )}
      </Workspace>
    </div>
  );
}

function ScanDetail({
  events,
  findings,
  targetRuns,
}: {
  events: ScanEventsResponse;
  findings: ScanFindingsResponse;
  targetRuns: ScanRecord[];
}) {
  const scan = events.scan;
  const navigate = useNavigate();
  const { openPanel, clearPanel } = useDashboardPanel();
  const otherRuns = useMemo(
    () => targetRuns.filter((entry) => entry.id !== scan.id),
    [scan.id, targetRuns],
  );
  const activeTargetRuns = useMemo(
    () => targetRuns.filter((entry) => entry.status === "running").length,
    [targetRuns],
  );
  const latestIncident = useMemo(() => findLatestIncident(events.events), [events.events]);
  const panelContent = useMemo(
    () => (
      <div className="space-y-4 p-6">
        <InspectorPane
          eyebrow="Target"
          title="Target dossier"
          description="Shared context for the selected run across the full target history."
        >
          <CardList>
            <MetaTile label="Target" value={scan.target} />
            <MetaTile label="Runs on target" value={String(targetRuns.length)} />
            <MetaTile label="Running now" value={String(activeTargetRuns)} />
            <MetaTile label="Scan id" value={scan.id} mono />
            <MetaTile label="Started" value={formatTime(scan.startedAt)} />
            <MetaTile
              label="Completed"
              value={scan.completedAt ? formatTime(scan.completedAt) : "In progress"}
            />
            <MetaTile label="Mode" value={`${scan.mode} / ${scan.depth}`} />
            <MetaTile label="Runtime" value={scan.runtime} />
          </CardList>
        </InspectorPane>

        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Target history</CardEyebrow>
              <CardTitle className="mt-2">Recent passes</CardTitle>
              <CardDescription>Open another run on the same target without leaving the current dossier.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            {otherRuns.length === 0 ? (
              <div className="px-6 pb-6">
                <CardEmpty>No other runs for this target yet.</CardEmpty>
              </div>
            ) : (
              <CardList>
                {otherRuns.slice(0, 5).map((entry) => (
                  <button
                    key={entry.id}
                    type="button"
                    onClick={() => navigate(`/runs/${entry.id}`)}
                    className="w-full text-left"
                  >
                    <EntityListItem
                      title={formatTime(entry.startedAt)}
                      description={`${entry.runtime} · ${entry.mode} · ${entry.depth}`}
                      meta={entry.id.slice(0, 8)}
                      badges={(
                        <>
                          <StatusBadge value={entry.status} />
                          <Badge>{entry.summary.totalFindings}</Badge>
                        </>
                      )}
                    />
                  </button>
                ))}
              </CardList>
            )}
          </CardContent>
        </Card>
      </div>
    ),
    [activeTargetRuns, navigate, otherRuns, scan.completedAt, scan.depth, scan.id, scan.mode, scan.runtime, scan.startedAt, scan.target, targetRuns.length],
  );

  useEffect(() => {
    clearPanel();
    return () => clearPanel();
  }, [clearPanel, scan.id]);

  const openTargetPanel = useCallback(() => {
    openPanel({
      title: `${scan.target} target dossier`,
      description: "Shared context for the selected run across the full target history.",
      content: panelContent,
    });
  }, [openPanel, panelContent, scan.target]);

  return (
    <WorkspaceMain span className="space-y-4">
      <InspectorPane
        eyebrow="Run dossier"
        title={scan.target}
        description={`Started ${formatTime(scan.startedAt)} · ${scan.runtime} runtime · ${scan.mode} mode · ${targetRuns.length} total runs on this target`}
        actions={(
          <Button variant="outline" size="sm" onClick={openTargetPanel}>
            Open target dossier
          </Button>
        )}
      >
        <div className="flex flex-wrap gap-2">
          <StatusBadge value={scan.status} />
          <Badge>{scan.depth}</Badge>
          <Badge>{scan.runtime}</Badge>
          <Badge>{scan.mode}</Badge>
        </div>

        {latestIncident ? (
          <Card className="border-destructive/25 bg-destructive/5">
            <CardContent className="space-y-3 p-4">
              <div className="flex items-start gap-3">
                <AlertCircle className="mt-0.5 size-5 text-destructive" />
                <div className="min-w-0">
                  <div className="text-sm font-medium text-foreground">Execution incident</div>
                  <div className="mt-1 text-sm leading-6 text-muted-foreground">
                    {latestIncident.headline}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
                    <Badge variant="outline">{latestIncident.stage}</Badge>
                    {latestIncident.actor ? <Badge variant="outline">{latestIncident.actor}</Badge> : null}
                    <span>{formatTime(latestIncident.timestamp)}</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : null}

        <section className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-4">
          <MetricCard
            icon={Activity}
            label="Findings"
            value={scan.summary.totalFindings}
            hint="Grouped and raw findings"
            tone="accent"
          />
          <MetricCard
            icon={Siren}
            label="Critical"
            value={scan.summary.critical}
            hint="Critical-severity findings"
            tone="danger"
          />
          <MetricCard
            icon={AlertCircle}
            label="High"
            value={scan.summary.high}
            hint="High-severity findings"
            tone="warning"
          />
          <MetricCard
            icon={Sparkles}
            label="Duration"
            value={formatDuration(scan.durationMs)}
            hint="Elapsed runtime"
            tone="success"
          />
        </section>

        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Run output</CardEyebrow>
              <CardTitle className="mt-2">Threads in this run</CardTitle>
              <CardDescription>Deduplicated issue threads produced by the selected run.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {findings.groups.length === 0 ? (
              <CardEmpty>No threads recorded for this run.</CardEmpty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Thread</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Count</TableHead>
                    <TableHead className="w-[12rem]">Posture</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.groups.map((group) => (
                    <TableRow key={group.fingerprint}>
                      <TableCell className="font-medium text-foreground">{group.latest.title}</TableCell>
                      <TableCell className="text-muted-foreground">{group.latest.category}</TableCell>
                      <TableCell className="text-muted-foreground">{group.count}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <SeverityBadge severity={group.latest.severity} />
                          <PhaseBadge value={group.workflow.phase} />
                          {group.workflow.reviewGate !== "none" ? <ReviewBadge value={group.workflow.reviewGate} /> : null}
                          <StatusBadge value={group.latest.triageStatus} />
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

        <Card className="overflow-hidden">
          <CardHeader>
            <div>
              <CardEyebrow>Target provenance</CardEyebrow>
              <CardTitle className="mt-2">Other runs on this target</CardTitle>
              <CardDescription>
                Use neighboring runs to understand whether this run is the first hit, a regression, or another pass over the same surface.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {targetRuns.length <= 1 ? (
              <CardEmpty>No adjacent runs recorded for this target yet.</CardEmpty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Started</TableHead>
                    <TableHead>Mode</TableHead>
                    <TableHead>Runtime</TableHead>
                    <TableHead>Findings</TableHead>
                    <TableHead className="w-[10rem]">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {targetRuns.slice(0, 6).map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="font-medium">
                        <NavLink to={`/runs/${entry.id}`} className="text-foreground hover:text-primary">
                          {formatTime(entry.startedAt)}
                        </NavLink>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {entry.mode} · {entry.depth}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{entry.runtime}</TableCell>
                      <TableCell className="text-muted-foreground">{entry.summary.totalFindings}</TableCell>
                      <TableCell>
                        <StatusBadge value={entry.status} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <EventTimeline events={events.events} />
      </InspectorPane>
    </WorkspaceMain>
  );
}

function findLatestIncident(events: ScanEventsResponse["events"]) {
  const isExecutionStall = (event: ScanEventsResponse["events"][number]) => {
    const payload = event.payload ?? {};
    const summary =
      typeof payload.summary === "string" && payload.summary.trim()
        ? payload.summary.trim()
        : event.eventType;
    return /max turns|did not emit required tool_call/i.test(summary);
  };

  const incident = [...events]
    .reverse()
    .find((event) =>
      ["agent_error", "scan_error", "worker_failed"].includes(event.eventType)
      || ((event.eventType === "stage_complete" || event.eventType === "agent_complete") && isExecutionStall(event)),
    );

  if (!incident) return null;

  const payload = incident.payload ?? {};
  const headline =
    typeof payload.error === "string" && payload.error.trim()
      ? payload.error.trim()
      : typeof payload.summary === "string" && payload.summary.trim()
        ? payload.summary.trim()
        : `${incident.stage} ${incident.eventType}`.replaceAll("_", " ");

  return {
    stage: incident.stage,
    actor: incident.agentRole ?? null,
    headline,
    timestamp: incident.timestamp,
  };
}
