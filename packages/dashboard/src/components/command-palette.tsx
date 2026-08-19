import { useDeferredValue, useEffect, useMemo, useState } from "react";
import { FileSearch, LayoutDashboard, PlayCircle, ShieldCheck, ShieldOff } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getFindingFamily, updateFindingFamilyTriage } from "@/api";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { DashboardResponse, ScanRecord } from "@/types";

type PaletteAction = {
  id: string;
  group: "Actions" | "Pages" | "Threads" | "Runs";
  label: string;
  meta: string;
  icon: React.ComponentType<{ className?: string }>;
  run: () => void;
  keywords: string[];
  shortcut?: string;
};

const GROUPS: PaletteAction["group"][] = ["Actions", "Pages", "Threads", "Runs"];

export function CommandPalette({
  open,
  onOpenChange,
  dashboard,
  scans,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  dashboard?: DashboardResponse;
  scans?: ScanRecord[];
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const selectedFingerprint = location.pathname.match(/^\/(?:threads|findings)\/([^/]+)/)?.[1] ?? null;
  const selectedScanId = location.pathname.match(/^\/(?:runs|scans)\/([^/]+)/)?.[1] ?? null;

  const selectedFamilyQuery = useQuery({
    queryKey: ["finding-family", selectedFingerprint],
    queryFn: () => getFindingFamily(selectedFingerprint!),
    enabled: open && Boolean(selectedFingerprint),
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

  const items = useMemo<PaletteAction[]>(() => {
    const base: PaletteAction[] = [
      {
        id: "page-threads",
        group: "Pages",
        label: "Open thread console",
        meta: "Threads, review, evidence",
        icon: FileSearch,
        keywords: ["threads console review evidence operator"],
        run: () => navigate("/threads"),
      },
      {
        id: "page-control",
        group: "Pages",
        label: "Open operations home",
        meta: "Launch, queue, worker control",
        icon: LayoutDashboard,
        keywords: ["operations dashboard overview launch workers queue"],
        run: () => navigate("/dashboard"),
      },
      {
        id: "page-scans",
        group: "Pages",
        label: "Open runs",
        meta: "Run history and provenance",
        icon: PlayCircle,
        keywords: ["scans runs timeline history"],
        run: () => navigate("/runs"),
      },
    ];

    if (selectedFingerprint) {
      base.unshift(
        {
          id: "triage-accept",
          group: "Actions",
          label: "Accept selected thread",
          meta: "Mark as accepted",
          icon: ShieldCheck,
          keywords: ["accept finding triage"],
          shortcut: "Enter",
          run: () => triageMutation.mutate({
            triageStatus: "accepted",
            triageNote: selectedFamilyQuery.data?.latest.triageNote ?? "",
          }),
        },
        {
          id: "triage-suppress",
          group: "Actions",
          label: "Suppress selected thread",
          meta: "Mark as suppressed",
          icon: ShieldOff,
          keywords: ["suppress finding triage"],
          shortcut: "Shift+S",
          run: () => triageMutation.mutate({
            triageStatus: "suppressed",
            triageNote: selectedFamilyQuery.data?.latest.triageNote ?? "",
          }),
        },
      );
    }

    if (selectedScanId) {
      base.unshift({
        id: "scan-detail",
        group: "Actions",
        label: "Focus selected scan timeline",
        meta: "Open current run detail",
        icon: PlayCircle,
        keywords: ["scan timeline detail current"],
        run: () => navigate(`/runs/${selectedScanId}`),
      });
    }

    for (const group of dashboard?.groups.slice(0, 14) ?? []) {
      base.push({
        id: `finding-${group.fingerprint}`,
        group: "Threads",
        label: group.latest.title,
        meta: `${group.latest.severity} · ${group.latest.triageStatus}`,
        icon: FileSearch,
        keywords: [group.latest.title, group.latest.category, group.latest.severity, group.latest.triageStatus],
        run: () => navigate(`/threads/${group.fingerprint}`),
      });
    }

    for (const scan of scans?.slice(0, 14) ?? []) {
      base.push({
        id: `scan-${scan.id}`,
        group: "Runs",
        label: scan.target,
        meta: `${scan.status} · ${scan.depth} · ${scan.runtime}`,
        icon: PlayCircle,
        keywords: [scan.target, scan.status, scan.depth, scan.runtime, scan.mode],
        run: () => navigate(`/runs/${scan.id}`),
      });
    }

    return base;
  }, [
    dashboard?.groups,
    navigate,
    queryClient,
    scans,
    selectedFingerprint,
    selectedFamilyQuery.data?.latest.triageNote,
    selectedScanId,
    triageMutation,
  ]);

  const filteredItems = useMemo(() => {
    const normalized = deferredQuery.trim().toLowerCase();
    if (!normalized) return items;

    return items.filter((item) =>
      [item.label, item.meta, ...item.keywords]
        .join(" ")
        .toLowerCase()
        .includes(normalized),
    );
  }, [deferredQuery, items]);

  useEffect(() => {
    if (!open) {
      setQuery("");
    }
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="overflow-hidden p-0 sm:max-w-2xl" showCloseButton={false}>
        <DialogHeader className="border-b border-border px-5 py-4 pr-12">
          <DialogTitle className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
            Mission command
          </DialogTitle>
          <DialogDescription className="pt-2 text-sm text-muted-foreground">
            Search operations views, threads, runs, and control actions.
          </DialogDescription>
        </DialogHeader>

        <div className="border-b border-border px-4 py-3">
          <Input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Jump to a page, run, thread, or action"
          />
        </div>

        <ScrollArea className="max-h-[60vh]">
          <div className="space-y-1 p-2">
            {GROUPS.map((group) => {
              const entries = filteredItems.filter((item) => item.group === group);
              if (entries.length === 0) return null;

              return (
                <section key={group} className="space-y-1">
                  <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                    {group}
                  </div>
                  {entries.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        item.run();
                        onOpenChange(false);
                      }}
                      className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-left transition-colors hover:bg-accent"
                    >
                      <div className="inline-flex size-9 items-center justify-center rounded-md border border-border bg-muted text-primary">
                        <item.icon className="size-4" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="font-medium text-foreground">{item.label}</div>
                        <div className="truncate text-xs text-muted-foreground">{item.meta}</div>
                      </div>
                      {item.shortcut ? (
                        <div className="text-xs tracking-widest text-muted-foreground">{item.shortcut}</div>
                      ) : null}
                    </button>
                  ))}
                </section>
              );
            })}

            {filteredItems.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                No matching commands.
              </div>
            ) : null}
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
