import type { LucideIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function MetricCard({
  icon: Icon,
  label,
  value,
  hint,
  tone = "neutral",
}: {
  icon: LucideIcon;
  label: string;
  value: number | string;
  hint: string;
  tone?: "neutral" | "danger" | "warning" | "success" | "accent";
}) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="space-y-4 p-4">
        <div className="flex items-center justify-between">
          <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
            {label}
          </div>
          <div
            className={cn(
              "inline-flex size-9 items-center justify-center rounded-md border border-border bg-muted text-muted-foreground",
              tone === "danger" && "border-destructive/20 bg-destructive/10 text-destructive",
              tone === "warning" && "border-amber-500/20 bg-amber-500/10 text-amber-300",
              tone === "success" && "border-emerald-500/20 bg-emerald-500/10 text-emerald-300",
              tone === "accent" && "border-primary/20 bg-primary/12 text-primary",
            )}
          >
            <Icon className="size-5" />
          </div>
        </div>
        <div className="space-y-1">
          <div className="text-3xl font-bold tracking-tight text-foreground">{value}</div>
          <div className="text-xs leading-5 text-muted-foreground">{hint}</div>
        </div>
      </CardContent>
    </Card>
  );
}
