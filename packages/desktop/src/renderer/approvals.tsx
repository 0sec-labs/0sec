import { useCallback, useState, type JSX } from "react";
import type {
  DesktopConsoleDecision,
  DesktopConsoleDecisionKind,
  DesktopConsoleDecisionResponse,
  DesktopConsoleOperatorAnswer,
  DesktopConsoleOperatorQuestion,
  DesktopConsoleToolCall,
} from "@0sec/shared";
import {
  Check,
  ChevronDown,
  FileCode,
  Globe,
  MessageSquare,
  Shield,
  ShieldAlert,
  Wrench,
  X,
} from "lucide-react";
import type { Workspace } from "./use-workspace.js";
import type { DecisionState } from "./transcript.js";

// ── Operator Question Block ───────────────────────────────────────

function QuestionBlock({
  question,
  selectedLabels,
  customText,
  onSelectChange,
  onCustomChange,
}: {
  question: DesktopConsoleOperatorQuestion;
  selectedLabels: string[];
  customText: string;
  onSelectChange: (labels: string[]) => void;
  onCustomChange: (text: string) => void;
}): JSX.Element {
  const toggleLabel = useCallback(
    (label: string) => {
      if (question.multiSelect) {
        const next = selectedLabels.includes(label)
          ? selectedLabels.filter((l) => l !== label)
          : [...selectedLabels, label];
        onSelectChange(next);
      } else {
        onSelectChange(selectedLabels[0] === label ? [] : [label]);
      }
    },
    [question.multiSelect, selectedLabels, onSelectChange],
  );

  return (
    <div className="question-item">
      <div className="question-header">{question.header}</div>
      {question.question && (
        <div className="question-text">{question.question}</div>
      )}
      {question.options && question.options.length > 0 && (
        <div className="question-options">
          {question.options.map((opt, i) => (
            <button
              key={i}
              className={`question-option${selectedLabels.includes(opt.label) ? " selected" : ""}`}
              onClick={() => toggleLabel(opt.label)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
      {question.allowCustom && (
        <textarea
          className="question-custom-input"
          value={customText}
          onChange={(e) => onCustomChange(e.target.value)}
          placeholder="Custom answer…"
          rows={2}
        />
      )}
    </div>
  );
}

// ── Approval Panel ────────────────────────────────────────────────

function kindIcon(kind: string) {
  switch (kind) {
    case "tool":
      return <Wrench size={16} />;
    case "scope":
      return <Globe size={16} />;
    case "local-scope":
      return <FileCode size={16} />;
    case "audit-escalation":
      return <Shield size={16} />;
    case "operator-question":
      return <MessageSquare size={16} />;
    default:
      return <ShieldAlert size={16} />;
  }
}

export function ApprovalPanel({
  decision,
  workspace,
}: {
  decision: DecisionState;
  workspace: Workspace;
}): JSX.Element {
  const [selectedLabels, setSelectedLabels] = useState<
    Record<string, string[]>
  >({});
  const [customTexts, setCustomTexts] = useState<Record<string, string>>({});

  const buildDecision = useCallback((): DesktopConsoleDecision => {
    return {
      id: decision.id,
      kind: decision.kind,
      title: decision.title,
      detail: decision.detail,
      call: decision.call,
      requestedUrls: decision.requestedUrls,
      requestedPath: decision.requestedPath,
      questions: decision.questions,
    };
  }, [decision]);

  const handleApprove = useCallback(() => {
    const response: DesktopConsoleDecisionResponse = { approve: true };

    if (decision.questions && decision.questions.length > 0) {
      response.answers = decision.questions.map((q) => {
        const answer: DesktopConsoleOperatorAnswer = {
          header: q.header,
        };
        const labels = selectedLabels[q.header];
        if (labels && labels.length > 0) answer.selectedLabels = labels;
        const custom = customTexts[q.header];
        if (custom?.trim()) answer.customText = custom.trim();
        return answer;
      });
    }

    workspace.resolveDecision(buildDecision(), response);
  }, [decision, workspace, selectedLabels, customTexts, buildDecision]);

  const handleDecline = useCallback(() => {
    workspace.resolveDecision(buildDecision(), { approve: false });
  }, [workspace, buildDecision]);

  // Already resolved
  if (decision.resolved) {
    return (
      <div
        className={`approval-panel resolved${decision.approved ? " approved" : " declined"}`}
      >
        <div className="approval-header">
          <span className="approval-icon">
            {decision.approved ? (
              <Check size={16} color="#22c55e" />
            ) : (
              <X size={16} color="var(--danger)" />
            )}
          </span>
          <span className="approval-title">{decision.title}</span>
          <span className="approval-kind">{decision.kind}</span>
        </div>
        <div
          className={`approval-resolved-badge${decision.approved ? " approved" : " declined"}`}
        >
          {decision.approved === undefined
            ? "Closed"
            : decision.approved
              ? "Approved"
              : "Declined"}
        </div>
      </div>
    );
  }

  return (
    <div className="approval-panel">
      <div className="approval-header">
        <span className="approval-icon">{kindIcon(decision.kind)}</span>
        <span className="approval-title">{decision.title}</span>
        <span className="approval-kind">{decision.kind}</span>
      </div>

      <div className="approval-detail">{decision.detail}</div>

      {/* Tool call preview */}
      {decision.call && (
        <div className="approval-tool-preview">
          <pre>
            <code>
              {decision.call.name}({JSON.stringify(decision.call.arguments)})
            </code>
          </pre>
        </div>
      )}

      {/* Scope URLs */}
      {decision.requestedUrls && decision.requestedUrls.length > 0 && (
        <div className="approval-tool-preview">
          {decision.requestedUrls.map((url, i) => (
            <div
              key={i}
              style={{
                fontSize: 11,
                fontFamily: "var(--mono)",
                padding: "2px 0",
              }}
            >
              {url}
            </div>
          ))}
        </div>
      )}

      {/* Scope path */}
      {decision.requestedPath && (
        <div className="approval-tool-preview">
          <code style={{ fontSize: 11 }}>{decision.requestedPath}</code>
        </div>
      )}

      {/* Operator questions */}
      {decision.questions && decision.questions.length > 0 && (
        <div className="question-group">
          {decision.questions.map((q, qi) => {
            const qSelected = selectedLabels[q.header] ?? [];
            const qCustom = customTexts[q.header] ?? "";
            return (
              <QuestionBlock
                key={qi}
                question={q}
                selectedLabels={qSelected}
                customText={qCustom}
                onSelectChange={(labels) =>
                  setSelectedLabels((prev) => ({
                    ...prev,
                    [q.header]: labels,
                  }))
                }
                onCustomChange={(text) =>
                  setCustomTexts((prev) => ({
                    ...prev,
                    [q.header]: text,
                  }))
                }
              />
            );
          })}
        </div>
      )}

      <div className="approval-actions">
        <button
          className="decline-btn"
          disabled={workspace.busy}
          onClick={handleDecline}
        >
          Decline
        </button>
        <button
          className="approve-btn"
          disabled={
            workspace.busy ||
            decision.questions?.some(
              (q) =>
                !(
                  selectedLabels[q.header]?.length ||
                  (q.allowCustom && customTexts[q.header]?.trim())
                ),
            )
          }
          onClick={handleApprove}
        >
          {decision.kind === "operator-question" ? "Submit" : "Approve"}
        </button>
      </div>
    </div>
  );
}
