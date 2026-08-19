import type { ReactNode } from "react";
import { Search } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Card, CardContent, CardDescription, CardEyebrow, CardHeader, CardList, CardListItem, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export function EntityList({
  title,
  description,
  searchValue,
  onSearchChange,
  searchPlaceholder,
  children,
}: {
  title: string;
  description: string;
  searchValue: string;
  onSearchChange: (value: string) => void;
  searchPlaceholder: string;
  children: ReactNode;
}) {
  return (
    <Card className="flex min-h-[36rem] flex-col overflow-hidden">
      <CardHeader className="space-y-3">
        <div>
          <CardEyebrow>Queue</CardEyebrow>
          <CardTitle className="mt-2">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
        <label className="flex items-center gap-3">
          <Search className="size-4 text-muted-foreground" />
          <Input
            value={searchValue}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder={searchPlaceholder}
            className="h-9"
          />
        </label>
      </CardHeader>
      <CardContent className="flex min-h-0 flex-1 flex-col pt-3">
        <ScrollArea className="min-h-0 flex-1">
          <CardList>{children}</CardList>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

export function EntityListItem({
  title,
  description,
  meta,
  badges,
  selected = false,
}: {
  title: string;
  description: string;
  meta?: string;
  badges?: ReactNode;
  selected?: boolean;
}) {
  return (
    <CardListItem interactive selected={selected}>
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-0.5">
          <div className="text-sm font-semibold leading-5 text-foreground">{title}</div>
          <div className="text-xs leading-5 text-muted-foreground">{description}</div>
          {meta ? <div className="text-xs text-muted-foreground">{meta}</div> : null}
        </div>
        {badges ? <div className="flex max-w-[12rem] flex-wrap justify-end gap-2">{badges}</div> : null}
      </div>
    </CardListItem>
  );
}
