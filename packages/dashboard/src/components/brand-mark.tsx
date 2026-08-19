import iconUrl from "../../../../assets/pwnkit-icon.gif";
import { cn } from "@/lib/utils";

export function BrandMark({
  compact = false,
  animated: _animated = false,
  className,
}: {
  compact?: boolean;
  animated?: boolean;
  className?: string;
}) {
  if (compact) {
    return (
      <img
        alt="pwnkit"
        src={iconUrl}
        className={cn("size-9 object-contain", className)}
      />
    );
  }

  return (
    <div className={cn("flex items-center gap-3", className)}>
      <img
        alt="pwnkit"
        src={iconUrl}
        className="size-10 object-contain"
      />
      <div className="space-y-0.5">
        <div className="text-[10px] font-semibold uppercase tracking-[0.24em] text-primary">
          pwnkit
        </div>
        <div className="text-sm font-medium text-foreground">pwnkit operator shell</div>
      </div>
    </div>
  );
}
