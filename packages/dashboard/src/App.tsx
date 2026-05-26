import { useEffect, useEffectEvent, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getDashboard, getScans } from "@/api";
import { AppShell } from "@/components/app-shell";
import { CommandPalette } from "@/components/command-palette";
import { DashboardPanelProvider } from "@/components/dashboard-panel";
import { EmptyState, ErrorState, LoadingState } from "@/components/state-panel";
import { FindingsPage } from "@/pages/findings-page";
import { LivePage } from "@/pages/live-page";
import { OverviewPage } from "@/pages/overview-page";
import { ScansPage } from "@/pages/scans-page";
import type { DashboardResponse, ScanRecord } from "@/types";

function isTypingTarget(target: EventTarget | null): boolean {
  const element = target as HTMLElement | null;
  if (!element) return false;
  return ["INPUT", "TEXTAREA", "SELECT"].includes(element.tagName) || element.isContentEditable;
}

function AppRoutes({
  dashboard,
  scans,
}: {
  dashboard: DashboardResponse;
  scans: ScanRecord[];
}) {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={<OverviewPage data={dashboard} />} />
      <Route path="/threads" element={<FindingsPage dashboard={dashboard} />} />
      <Route path="/threads/:fingerprint" element={<FindingsPage dashboard={dashboard} />} />
      <Route path="/runs" element={<ScansPage scans={scans} />} />
      <Route path="/runs/:scanId" element={<ScansPage scans={scans} />} />
      <Route path="/findings" element={<FindingsPage dashboard={dashboard} />} />
      <Route path="/findings/:fingerprint" element={<FindingsPage dashboard={dashboard} />} />
      <Route path="/scans" element={<ScansPage scans={scans} />} />
      <Route path="/scans/:scanId" element={<ScansPage scans={scans} />} />
      <Route path="/live" element={<LivePage />} />
      <Route
        path="*"
        element={
          <EmptyState
            title="Unknown route"
            body="This dashboard view does not exist yet."
          />
        }
      />
    </Routes>
  );
}

export function App() {
  const [paletteOpen, setPaletteOpen] = useState(false);

  const dashboardQuery = useQuery({
    queryKey: ["dashboard"],
    queryFn: getDashboard,
    refetchInterval: 5000,
  });

  const scansQuery = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
    refetchInterval: 5000,
  });

  const handleHotkey = useEffectEvent((event: KeyboardEvent) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      setPaletteOpen((value) => !value);
      return;
    }

    if (!paletteOpen && event.key === "/" && !isTypingTarget(event.target)) {
      event.preventDefault();
      setPaletteOpen(true);
    }
  });

  useEffect(() => {
    const listener = (event: KeyboardEvent) => handleHotkey(event);
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, [handleHotkey]);

  return (
    <DashboardPanelProvider>
      <AppShell
        dashboard={dashboardQuery.data}
        scans={scansQuery.data}
        onOpenPalette={() => setPaletteOpen(true)}
      >
        <CommandPalette
          open={paletteOpen}
          onOpenChange={setPaletteOpen}
          dashboard={dashboardQuery.data}
          scans={scansQuery.data}
        />
        {dashboardQuery.isLoading || scansQuery.isLoading ? (
          <LoadingState label="Mission control" />
        ) : dashboardQuery.error ? (
          <ErrorState error={dashboardQuery.error} />
        ) : scansQuery.error ? (
          <ErrorState error={scansQuery.error} />
        ) : dashboardQuery.data && scansQuery.data ? (
          <AppRoutes dashboard={dashboardQuery.data} scans={scansQuery.data} />
        ) : (
          <EmptyState
            title="No scan data available"
            body="Run a scan first, then reopen the dashboard."
          />
        )}
      </AppShell>
    </DashboardPanelProvider>
  );
}
