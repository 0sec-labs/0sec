import type { ReactNode } from "react";
import { Card, CardContent, CardDescription, CardEyebrow, CardHeader, CardTitle } from "@/components/ui/card";

export function InspectorPane({
  eyebrow,
  title,
  description,
  actions,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <div className="min-w-0">
          <CardEyebrow>{eyebrow}</CardEyebrow>
          <CardTitle className="mt-2">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </CardHeader>
      <CardContent className="space-y-4">{children}</CardContent>
    </Card>
  );
}
