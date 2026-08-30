import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity, Command, LayoutDashboard, Menu, Radar, Radio, ShieldAlert } from "lucide-react";
import { NavLink, useLocation } from "react-router-dom";
import { getRecentEvents } from "@/api";
import type { DashboardResponse, RecentEventsResponse, ScanRecord } from "@/types";
import { BrandMark } from "@/components/brand-mark";
import { useDashboardPanel } from "@/components/dashboard-panel";
import { Badge } from "@/components/ui/badge";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { formatTime } from "@/lib/format";
import { cn } from "@/lib/utils";

type ShellTone = "default" | "success" | "warning" | "danger";

type RuntimeIncident = {
  scanId: string;
  scanTarget: string;
  stage: string;
  actor: string | null;
  headline: string;
  timestamp: number;
};

type ShellContextSection = {
  label: string;
  items: Array<{
    label: string;
    value: string;
    meta: string;
    tone?: ShellTone;
  }>;
  note?: string;
};

function routeLabel(pathname: string): string {
  if (pathname.startsWith("/dashboard")) return "Operations center";
  if (pathname.startsWith("/threads") || pathname.startsWith("/findings")) return "Findings workspace";
  if (pathname.startsWith("/runs") || pathname.startsWith("/scans")) return "Run dossier";
  return "Operations center";
}

function routePage(pathname: string): string {
  if (pathname.startsWith("/dashboard")) return "Operations";
  if (pathname.startsWith("/threads") || pathname.startsWith("/findings")) return "Findings";
  if (pathname.startsWith("/runs") || pathname.startsWith("/scans")) return "Runs";
  return "Control";
}

function toneClassName(tone: ShellTone = "default"): string {
  if (tone === "success") return "text-emerald-700 dark:text-emerald-300";
  if (tone === "warning") return "text-amber-700 dark:text-amber-300";
  if (tone === "danger") return "text-destructive";
  return "text-foreground";
}

function parseRuntimeIncidents(events: RecentEventsResponse["events"], scans?: ScanRecord[]): RuntimeIncident[] {
  const scanRuntimeById = new Map((scans ?? []).map((scan) => [scan.id, scan.runtime]));
  return events
    .filter((event) => {
      if (["agent_error", "scan_error", "worker_failed"].includes(event.eventType)) return true;
      const payload = event.payload ?? {};
      const summary =
        typeof payload.summary === "string" && payload.summary.trim()
          ? payload.summary.trim()
          : event.summary;
      return ["stage_complete", "agent_complete", "runtime_incompatible"].includes(event.eventType) && /max turns|did not emit required tool_call/i.test(summary);
    })
    .sort((left, right) => right.timestamp - left.timestamp)
    .map((event) => {
      const payload = event.payload ?? {};
      const runtime = scanRuntimeById.get(event.scanId);
      const headline =
        typeof payload.error === "string" && payload.error.trim()
          ? payload.error.trim()
          : typeof payload.summary === "string" && payload.summary.trim()
            ? payload.summary.trim()
            : event.summary;

      return {
        scanId: event.scanId,
        scanTarget: event.scanTarget,
        stage: runtime ? `${event.stage} · ${runtime}` : event.stage,
        actor: event.agentRole ?? null,
        headline,
        timestamp: event.timestamp,
      } satisfies RuntimeIncident;
    });
}

function buildShellContext({
  pathname,
  dashboard,
  scans,
  incidents,
}: {
  pathname: string;
  dashboard?: DashboardResponse;
  scans?: ScanRecord[];
  incidents: RuntimeIncident[];
}): {
  title: string;
  summary: string;
  sections: ShellContextSection[];
} {
  const groups = dashboard?.groups ?? [];
  const runs = scans ?? [];
  const activeWorkers = dashboard?.workers.filter((worker) => worker.isActive && worker.status !== "stopped").length ?? 0;
  const runnableQueue = dashboard?.queue.runnable ?? 0;
  const blockedThreads = groups.filter((group) => group.workflow.phase === "blocked").length;
  const humanReview = groups.filter((group) => group.workflow.reviewGate === "human_review").length;
  const agentReview = groups.filter((group) => group.workflow.reviewGate === "agent_review").length;
  const unassigned = groups.filter((group) => !group.workflow.assignee).length;
  const newThreads = groups.filter((group) => group.latest.triageStatus === "new").length;
  const activeThreads = groups.filter((group) => group.workflow.phase === "in_progress" || group.workflow.activeAgentRoles.length > 0).length;
  const verifiedThreads = groups.filter((group) => group.workflow.consensus === "verified").length;
  const activeRuns = runs.filter((scan) => scan.status === "running").length;
  const completedRuns = runs.filter((scan) => scan.status === "completed").length;
  const uniqueTargets = new Set(runs.map((scan) => scan.target)).size;
  const uniqueRuntimes = [...new Set(runs.map((scan) => scan.runtime))];
  const latestRun = [...runs].sort((left, right) => right.startedAt.localeCompare(left.startedAt))[0] ?? null;
  const latestIncident = incidents[0] ?? null;
  const providerIncidentCount = incidents.filter((incident) =>
    /quota|provider|model|rate limit|openai|anthropic|gemini|claude/i.test(
      `${incident.headline} ${incident.stage} ${incident.actor ?? ""}`,
    ),
  ).length;

  if (pathname.startsWith("/threads") || pathname.startsWith("/findings")) {
    return {
      title: "Findings workspace",
      summary: "Review deduplicated evidence, continue the few cases that need judgment, and keep execution in the scoped terminal chat.",
      sections: [
        {
          label: "Queue",
          items: [
            { label: "Finding families", value: String(groups.length), meta: "deduplicated observations across runs" },
            { label: "New", value: String(newThreads), meta: "awaiting a first decision or investigation" },
            { label: "Human review", value: String(humanReview), meta: "ready for operator disposition", tone: humanReview > 0 ? "warning" : "default" },
            { label: "Agent review", value: String(agentReview), meta: "needs another evidence pass" },
          ],
        },
        {
          label: "Execution",
          items: [
            { label: "In progress", value: String(activeThreads), meta: "families with active worker movement", tone: activeThreads > 0 ? "success" : "default" },
            { label: "Blocked", value: String(blockedThreads), meta: "needs access, context, or stronger proof", tone: blockedThreads > 0 ? "danger" : "default" },
            { label: "Unassigned", value: String(unassigned), meta: "no explicit owner attached yet" },
            { label: "Verified", value: String(verifiedThreads), meta: "consensus supports a true positive" },
          ],
          note: latestIncident
            ? `Runtime pressure is visible elsewhere too: ${latestIncident.scanTarget} failed ${formatTime(latestIncident.timestamp)}.`
            : "Open a finding to copy a context-preserving console handoff.",
        },
      ],
    };
  }

  if (pathname.startsWith("/runs") || pathname.startsWith("/scans")) {
    return {
      title: "Run dossiers",
      summary: "Inspect provenance by target, then drill into a selected execution and its output findings.",
      sections: [
        {
          label: "Inventory",
          items: [
            { label: "Targets", value: String(uniqueTargets), meta: "unique targets in local history" },
            { label: "Runs", value: String(runs.length), meta: "persisted executions across all targets" },
            { label: "Active", value: String(activeRuns), meta: "runs still executing now", tone: activeRuns > 0 ? "success" : "default" },
            { label: "Completed", value: String(completedRuns), meta: "finished without staying in running state" },
          ],
        },
        {
          label: "Runtime",
          items: [
            { label: "Incidents", value: String(incidents.length), meta: providerIncidentCount > 0 ? `${providerIncidentCount} provider/runtime failures` : "no recent failures", tone: incidents.length > 0 ? "danger" : "success" },
            { label: "Workers", value: String(activeWorkers), meta: runnableQueue > 0 ? `${runnableQueue} runnable work items queued` : "no runnable backlog" },
            { label: "Runtimes", value: uniqueRuntimes.length > 0 ? uniqueRuntimes.slice(0, 3).join(", ") : "none", meta: uniqueRuntimes.length > 3 ? `${uniqueRuntimes.length} runtimes observed` : "runtime mix in run history" },
            { label: "Latest target", value: latestRun?.target ?? "none", meta: latestRun ? formatTime(latestRun.startedAt) : "launch a target to create the first dossier" },
          ],
          note: latestIncident
            ? `${latestIncident.scanTarget}: ${latestIncident.headline}`
            : "Provider and worker failures should surface here before you dive into a single run.",
        },
      ],
    };
  }

  return {
    title: "Operations control",
    summary: "Run the autonomous control plane, watch queue health, and intervene only when automation hits a real boundary.",
    sections: [
      {
        label: "Runtime",
        items: [
          { label: "Daemon", value: activeWorkers > 0 ? "live" : "offline", meta: activeWorkers > 0 ? `${activeWorkers} active workers heartbeating` : "launch a target or start a daemon", tone: activeWorkers > 0 ? "success" : "warning" },
          { label: "Runnable", value: String(runnableQueue), meta: "work items ready to claim next" },
          { label: "Active runs", value: String(activeRuns), meta: "pipeline executions still in flight", tone: activeRuns > 0 ? "success" : "default" },
          { label: "Incidents", value: String(incidents.length), meta: providerIncidentCount > 0 ? `${providerIncidentCount} provider/runtime failures` : "clean recent event window", tone: incidents.length > 0 ? "danger" : "success" },
        ],
      },
      {
        label: "Review",
        items: [
          { label: "Human review", value: String(humanReview), meta: "findings waiting on operator sign-off", tone: humanReview > 0 ? "warning" : "default" },
          { label: "Blocked", value: String(blockedThreads), meta: "access or context gap in execution", tone: blockedThreads > 0 ? "danger" : "default" },
          { label: "Unassigned", value: String(unassigned), meta: "findings without a named owner" },
          { label: "Targets", value: String(uniqueTargets), meta: "real target history in this workspace" },
        ],
        note: latestIncident
          ? `${latestIncident.scanTarget}: ${latestIncident.headline}`
          : "No recent runtime failures. Launch the next target from operations.",
      },
    ],
  };
}

export function AppShell({
  children,
  dashboard,
  scans,
  onOpenPalette,
}: {
  children: React.ReactNode;
  dashboard?: DashboardResponse;
  scans?: ScanRecord[];
  onOpenPalette: () => void;
}) {
  const location = useLocation();
  const { panel, dismissPanel } = useDashboardPanel();
  const [isDesktop, setIsDesktop] = useState(() => {
    if (typeof window === "undefined") return true;
    return window.matchMedia("(min-width: 1280px)").matches;
  });
  const newFamilies = dashboard?.groups.filter((group) => group.latest.triageStatus === "new").length ?? 0;
  const activeRuns = scans?.filter((scan) => scan.status === "running").length ?? 0;
  const activeWorkers = dashboard?.workers.filter((worker) => worker.isActive).length ?? 0;
  const runnableQueue = dashboard?.queue.runnable ?? 0;
  const recentEventsQuery = useQuery({
    queryKey: ["shell-recent-events"],
    queryFn: () => getRecentEvents(18),
    refetchInterval: 5000,
  });
  const recentIncidents = useMemo(
    () => parseRuntimeIncidents(recentEventsQuery.data?.events ?? [], scans).slice(0, 6),
    [recentEventsQuery.data?.events, scans],
  );
  const latestIncident = recentIncidents[0] ?? null;
  const shellContext = useMemo(
    () => buildShellContext({ pathname: location.pathname, dashboard, scans, incidents: recentIncidents }),
    [dashboard, location.pathname, recentIncidents, scans],
  );
  const providerIncidentCount = recentIncidents.filter((incident) =>
    /quota|provider|model|rate limit|openai|anthropic|gemini|claude/i.test(
      `${incident.headline} ${incident.stage} ${incident.actor ?? ""}`,
    ),
  ).length;

  useEffect(() => {
    const mediaQuery = window.matchMedia("(min-width: 1280px)");
    const update = () => setIsDesktop(mediaQuery.matches);
    update();
    mediaQuery.addEventListener("change", update);
    return () => mediaQuery.removeEventListener("change", update);
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="flex min-h-screen">
        <aside className="sticky top-0 hidden h-screen w-[22rem] shrink-0 border-r border-border bg-background xl:grid xl:grid-cols-[4.5rem_minmax(0,1fr)]">
          <div className="flex h-screen flex-col items-center border-r border-border px-2 py-3">
            <BrandMark compact className="size-9" />

            <nav className="mt-6 flex flex-1 flex-col items-center gap-2">
              <RailNavItem to="/dashboard" label="Operations" icon={LayoutDashboard} />
              <RailNavItem to="/findings" label="Findings" icon={ShieldAlert} badge={newFamilies} />
              <RailNavItem to="/runs" label="Runs" icon={Radar} badge={activeRuns} />
              <RailNavItem to="/live" label="Live workflow" icon={Radio} />
            </nav>

            <div className="flex flex-col items-center gap-3">
              <div className="flex flex-col items-center gap-1 text-center">
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="text-muted-foreground"
                  onClick={onOpenPalette}
                  aria-label="Open launchpad"
                >
                  <Command className="size-4" />
                </Button>
                <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">Cmd K</div>
              </div>
              <div className="w-full rounded-md bg-muted/40 px-2 py-2 text-center">
                <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">Queue</div>
                <div className="mt-1 text-sm font-medium text-foreground">{runnableQueue}</div>
              </div>
            </div>
          </div>

          <div className="flex min-h-0 flex-col">
            <div className="border-b border-border px-4 py-4">
              <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                {routePage(location.pathname)}
              </div>
              <div className="mt-2 text-base font-medium text-foreground">{shellContext.title}</div>
              <div className="mt-1 text-sm leading-6 text-muted-foreground">{shellContext.summary}</div>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto px-3 py-3">
              <div className="space-y-5">
                {shellContext.sections.map((section) => (
                  <ShellSection key={section.label} label={section.label}>
                    {section.items.map((item) => (
                      <SidebarInsight
                        key={item.label}
                        label={item.label}
                        value={item.value}
                        meta={item.meta}
                        tone={item.tone}
                      />
                    ))}
                    {section.note ? <SidebarNote text={section.note} /> : null}
                  </ShellSection>
                ))}

                <ShellSection label="Hotkeys">
                  <SidebarMeta text="Cmd/Ctrl+K launchpad" />
                  <SidebarMeta text="/ search" />
                  <SidebarMeta text="Esc close overlays" />
                </ShellSection>
              </div>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 border-b border-border bg-background/95 backdrop-blur">
            <div className="mx-auto flex max-w-[1800px] flex-col gap-3 px-4 py-3 sm:px-6 xl:flex-row xl:items-center xl:justify-between">
              <div className="space-y-2">
                <div className="flex items-center gap-2 xl:hidden">
                  <Sheet>
                    <SheetTrigger asChild>
                      <Button variant="ghost" size="icon-sm" aria-label="Open navigation">
                        <Menu className="size-4" />
                      </Button>
                    </SheetTrigger>
                  <SheetContent side="left" className="w-72 p-0">
                      <SheetHeader className="border-b border-border px-4 py-4 pr-12 text-left">
                      <div className="mb-2">
                          <BrandMark />
                        </div>
                        <SheetTitle className="text-base font-semibold text-foreground">Operator shell</SheetTitle>
                        <SheetDescription className="text-sm text-muted-foreground">
                          Navigation, runtime posture, and route-specific context.
                        </SheetDescription>
                      </SheetHeader>
                      <div className="flex flex-col gap-5 px-3 py-3">
                        <div className="flex flex-col gap-0.5">
                          <SidebarNavItem
                            to="/dashboard"
                            label="Operations"
                            meta="Launch, queue, worker control"
                            icon={LayoutDashboard}
                          />
                          <SidebarNavItem
                            to="/findings"
                            label="Findings"
                            meta="Evidence, chat handoff, disposition"
                            icon={ShieldAlert}
                            badge={newFamilies}
                          />
                          <SidebarNavItem
                            to="/runs"
                            label="Runs"
                            meta="Runs, provenance, timelines"
                            icon={Radar}
                            badge={activeRuns}
                          />
                          <SidebarNavItem
                            to="/live"
                            label="Live workflow"
                            meta="GemmaForge probe → leads → hunt"
                            icon={Radio}
                          />
                        </div>
                        {shellContext.sections.map((section) => (
                          <ShellSection key={section.label} label={section.label}>
                            {section.items.map((item) => (
                              <SidebarInsight
                                key={item.label}
                                label={item.label}
                                value={item.value}
                                meta={item.meta}
                                tone={item.tone}
                              />
                            ))}
                            {section.note ? <SidebarNote text={section.note} /> : null}
                          </ShellSection>
                        ))}
                      </div>
                    </SheetContent>
                  </Sheet>
                  <BrandMark compact className="size-8 rounded-sm" />
                </div>

                <Breadcrumb>
                  <BreadcrumbList>
                    <BreadcrumbItem>
                      <BreadcrumbPage>{routeLabel(location.pathname)}</BreadcrumbPage>
                    </BreadcrumbItem>
                    <BreadcrumbSeparator />
                    <BreadcrumbItem>
                      <BreadcrumbPage>{routePage(location.pathname)}</BreadcrumbPage>
                    </BreadcrumbItem>
                  </BreadcrumbList>
                </Breadcrumb>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="hidden flex-wrap items-center gap-2 lg:flex">
                  <HeaderPill tone={activeWorkers > 0 ? "success" : "warning"}>
                    <Activity className="size-3.5" />
                    {activeWorkers > 0 ? `${activeWorkers} daemon live` : "daemon offline"}
                  </HeaderPill>
                  <HeaderPill tone={recentIncidents.length > 0 ? "danger" : "success"}>
                    {recentIncidents.length > 0 ? `${recentIncidents.length} incidents` : "runtime clean"}
                  </HeaderPill>
                  {providerIncidentCount > 0 ? (
                    <HeaderPill tone="danger">{providerIncidentCount} provider</HeaderPill>
                  ) : null}
                  {latestIncident ? (
                    <div className="max-w-[24rem] truncate text-sm text-muted-foreground">
                      {latestIncident.scanTarget}: {latestIncident.headline}
                    </div>
                  ) : (
                    <div className="text-sm text-muted-foreground">{dashboard?.groups.length ?? 0} finding families tracked</div>
                  )}
                </div>
                <Button variant="default" onClick={onOpenPalette}>
                  <Command className="size-4" />
                  Launchpad
                </Button>
              </div>
            </div>
          </header>

          <div className="mx-auto flex w-full max-w-[1800px] flex-1 min-h-0">
            <main className="min-w-0 flex-1 px-4 py-5 sm:px-6">
              <div className="flex min-h-full min-w-0 flex-col gap-5">
                {children}
              </div>
            </main>

            {panel ? (
              <aside className="hidden w-[32rem] shrink-0 border-l border-border bg-background xl:flex xl:flex-col">
                <div className="sticky top-[4.5625rem] flex h-[calc(100vh-4.5625rem)] flex-col">
                  <div className="border-b border-border px-6 py-6 pr-12">
                    <div className="font-heading text-base font-medium text-foreground">{panel.title}</div>
                    <div className="mt-1 text-sm text-muted-foreground">{panel.description}</div>
                  </div>
                  <div className="min-h-0 flex-1 overflow-y-auto">
                    {panel.content}
                  </div>
                  <div className="border-t border-border p-4">
                    <Button variant="outline" size="sm" onClick={dismissPanel}>
                      Close panel
                    </Button>
                  </div>
                </div>
              </aside>
            ) : null}
          </div>
        </div>
      </div>

      <Sheet open={Boolean(panel) && !isDesktop} onOpenChange={(open) => {
        if (!open) dismissPanel();
      }}>
        <SheetContent side="right" className="w-full overflow-y-auto p-0 sm:max-w-2xl">
          {panel ? (
            <>
              <SheetHeader className="border-b border-border pr-12">
                <SheetTitle>{panel.title}</SheetTitle>
                <SheetDescription>{panel.description}</SheetDescription>
              </SheetHeader>
              {panel.content}
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function RailNavItem({
  to,
  label,
  icon: Icon,
  badge = 0,
}: {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
}) {
  return (
    <NavLink to={to} aria-label={label}>
      {({ isActive }) => (
        <div
          className={cn(
            "relative flex size-11 items-center justify-center rounded-md transition-colors",
            isActive
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:bg-muted hover:text-foreground",
          )}
        >
          <Icon className="size-4" />
          {badge > 0 ? (
            <span className="absolute right-1 top-1 min-w-4 rounded-sm bg-destructive px-1 text-center text-[9px] font-semibold leading-4 text-destructive-foreground">
              {badge}
            </span>
          ) : null}
          <span className="sr-only">{label}</span>
        </div>
      )}
    </NavLink>
  );
}

function SidebarNavItem({
  to,
  label,
  meta,
  icon: Icon,
  badge = 0,
}: {
  to: string;
  label: string;
  meta: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
}) {
  return (
    <NavLink to={to}>
      {({ isActive }) => (
        <div
          className={cn(
            "flex items-start gap-2.5 rounded-sm px-3 py-2 text-[13px] font-medium transition-colors",
            isActive
              ? "bg-primary/8 text-foreground"
              : "text-foreground/80 hover:bg-primary/6 hover:text-foreground",
          )}
        >
          <Icon className={cn("mt-0.5 size-4 shrink-0", isActive && "text-primary")} />
          <div className="min-w-0 flex-1">
            <div className="truncate">{label}</div>
            <div
              className={cn(
                "truncate text-xs",
                isActive ? "text-foreground/70" : "text-muted-foreground",
              )}
            >
              {meta}
            </div>
          </div>
          {badge > 0 ? (
            <span className="mt-0.5 rounded-sm bg-primary px-1.5 py-0.5 text-[10px] leading-none text-primary-foreground">
              {badge}
            </span>
          ) : null}
        </div>
      )}
    </NavLink>
  );
}

function ShellSection({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-2">
      <div className="px-3 text-[10px] font-medium uppercase tracking-widest text-muted-foreground/70">
        {label}
      </div>
      <div className="flex flex-col gap-1">{children}</div>
    </section>
  );
}

function SidebarInsight({
  label,
  value,
  meta,
  tone = "default",
}: {
  label: string;
  value: string;
  meta: string;
  tone?: ShellTone;
}) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm text-foreground">{label}</div>
          <div className="mt-1 text-xs leading-5 text-muted-foreground">{meta}</div>
        </div>
        <div className={cn("shrink-0 text-sm font-medium", toneClassName(tone))}>{value}</div>
      </div>
    </div>
  );
}

function SidebarMeta({ text }: { text: string }) {
  return <div className="px-3 py-2 text-sm text-muted-foreground">{text}</div>;
}

function SidebarNote({ text }: { text: string }) {
  return (
    <div className="rounded-md border border-dashed border-border px-3 py-3 text-xs leading-5 text-muted-foreground">
      {text}
    </div>
  );
}

function HeaderPill({
  children,
  tone = "default",
}: {
  children: React.ReactNode;
  tone?: ShellTone;
}) {
  const variant =
    tone === "success"
      ? "success"
      : tone === "warning"
        ? "warning"
        : tone === "danger"
          ? "danger"
          : "neutral";

  return (
    <Badge variant={variant} className="gap-1.5">
      {children}
    </Badge>
  );
}
