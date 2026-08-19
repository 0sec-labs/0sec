import { Badge } from "@/components/ui/badge";
import type { FindingConsensus, FindingReviewGate, FindingWorkflowPhase, FindingWorkflowStatus } from "@/types";

function formatWorkflowLabel(value: FindingWorkflowStatus) {
  return value.replaceAll("_", " ");
}

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const variant =
    normalized === "critical" || normalized === "high"
      ? "danger"
      : normalized === "medium"
        ? "warning"
        : normalized === "low"
          ? "info"
          : "neutral";

  return <Badge variant={variant}>{severity}</Badge>;
}

export function StatusBadge({
  value,
}: {
  value: string;
}) {
  const normalized = value.toLowerCase();
  const variant =
    normalized === "accepted" || normalized === "complete" || normalized === "completed"
      ? "success"
      : normalized === "suppressed"
        ? "warning"
        : normalized === "running" || normalized === "claiming"
          ? "accent"
          : normalized === "failed" || normalized === "critical" || normalized === "error"
            ? "danger"
            : normalized === "sleeping"
              ? "warning"
            : "neutral";

  return <Badge variant={variant}>{value}</Badge>;
}

export function WorkflowBadge({
  value,
}: {
  value: FindingWorkflowStatus;
}) {
  const variant =
    value === "done"
      ? "success"
      : value === "cancelled" || value === "blocked"
        ? "danger"
        : value === "human_review"
          ? "warning"
          : value === "agent_review" || value === "in_progress"
            ? "accent"
            : "neutral";

  return <Badge variant={variant}>{formatWorkflowLabel(value)}</Badge>;
}

export function PhaseBadge({
  value,
}: {
  value: FindingWorkflowPhase;
}) {
  const variant =
    value === "done"
      ? "success"
      : value === "cancelled" || value === "blocked"
        ? "danger"
        : value === "in_progress"
          ? "accent"
          : "neutral";

  return <Badge variant={variant}>{formatWorkflowLabel(value)}</Badge>;
}

export function ReviewBadge({
  value,
}: {
  value: FindingReviewGate;
}) {
  if (value === "none") return <Badge variant="neutral">no review gate</Badge>;

  return (
    <Badge variant={value === "human_review" ? "warning" : "accent"}>
      {formatWorkflowLabel(value)}
    </Badge>
  );
}

export function ConsensusBadge({
  value,
}: {
  value: FindingConsensus;
}) {
  const variant =
    value === "verified"
      ? "success"
      : value === "false-positive"
        ? "danger"
        : value === "disputed"
          ? "warning"
          : "neutral";

  return <Badge variant={variant}>{value.replaceAll("-", " ")}</Badge>;
}

export function SignalBadge({
  value,
}: {
  value: "weak" | "medium" | "strong";
}) {
  const variant =
    value === "strong"
      ? "success"
      : value === "medium"
        ? "warning"
        : "neutral";

  return <Badge variant={variant}>{value} signal</Badge>;
}
