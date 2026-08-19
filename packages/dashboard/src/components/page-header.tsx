import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function PageHeader({
  eyebrow,
  title,
  summary,
  actions,
  className,
}: {
  eyebrow: string;
  title: string;
  summary: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between", className)}>
      <div className="space-y-1.5">
        <div className="text-[10px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
          {eyebrow}
        </div>
        <div>
          <h1 className="text-[2rem] font-bold tracking-tight text-foreground">{title}</h1>
          <p className="mt-1.5 max-w-3xl text-sm leading-6 text-muted-foreground">{summary}</p>
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}
