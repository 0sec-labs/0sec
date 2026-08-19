import {
  Activity,
  Bot,
  CheckCircle2,
  CircleAlert,
  Radar,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import type { ScanEventsResponse } from "@/types";
import { formatTime, summarizePayload } from "@/lib/format";
import { StatusBadge } from "@/components/status-badges";
import { Card, CardContent, CardEmpty, CardEyebrow, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function EventTimeline({
  events,
}: {
  events: ScanEventsResponse["events"];
}) {
  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <div>
          <CardEyebrow>Activity</CardEyebrow>
          <CardTitle className="mt-2">Timeline</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {events.length === 0 ? (
          <CardEmpty>No pipeline events recorded.</CardEmpty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Event</TableHead>
                <TableHead>Summary</TableHead>
                <TableHead className="w-[10rem]">Time</TableHead>
                <TableHead className="w-[14rem]">Payload</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((event) => {
                const Icon = iconForEvent(event.stage, event.eventType);

                return (
                  <TableRow key={event.id}>
                    <TableCell>
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5 inline-flex size-8 items-center justify-center rounded-md border border-border bg-muted text-primary">
                          <Icon className="size-4" />
                        </div>
                        <div className="space-y-1">
                          <div className="font-medium text-foreground">
                            {event.stage} · {event.eventType}
                          </div>
                          {event.agentRole ? <StatusBadge value={event.agentRole} /> : null}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <div className="space-y-1">
                        <div>{summarizePayload(event.payload)}</div>
                        {event.findingId ? (
                          <div className="font-mono text-xs text-muted-foreground">
                            finding {event.findingId.slice(0, 8)}
                          </div>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {formatTime(event.timestamp)}
                    </TableCell>
                    <TableCell>
                      {event.payload ? (
                        <details className="rounded-md border border-border bg-muted/50 p-2 text-sm text-muted-foreground">
                          <summary className="cursor-pointer list-none font-medium text-foreground">View raw</summary>
                          <pre className="mt-3 text-xs text-muted-foreground">
                            {JSON.stringify(event.payload, null, 2)}
                          </pre>
                        </details>
                      ) : (
                        <span className="text-xs text-muted-foreground">No payload</span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function iconForEvent(stage: string, eventType: string) {
  const value = `${stage}:${eventType}`.toLowerCase();
  if (value.includes("attack")) return ShieldAlert;
  if (value.includes("agent")) return Bot;
  if (value.includes("verify")) return CheckCircle2;
  if (value.includes("finding")) return CircleAlert;
  if (value.includes("scan")) return Radar;
  if (value.includes("analysis")) return Sparkles;
  return Activity;
}
