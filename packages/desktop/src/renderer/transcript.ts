import type {
  DesktopConsoleDecisionKind,
  DesktopConsoleEvent,
  DesktopConsoleOperatorQuestion,
  DesktopConsoleToolCall,
  DesktopConsoleTurnBudget,
  DesktopConsoleUsage,
} from "@0sec/shared";

// ── Reduced Turn Types ───────────────────────────────────────────

export interface ToolCallState {
  id: string;
  name: string;
  arguments: unknown;
  result?: unknown;
  isRunning: boolean;
}

export interface DecisionState {
  id: string;
  kind: DesktopConsoleDecisionKind;
  title: string;
  detail: string;
  call?: DesktopConsoleToolCall;
  requestedUrls?: string[];
  requestedPath?: string;
  questions?: DesktopConsoleOperatorQuestion[];
  resolved: boolean;
  approved?: boolean;
}

export interface ReducedTurn {
  id: string;
  user: { text: string; sequence: number };
  assistantText: string;
  reasoningText: string;
  toolCalls: ToolCallState[];
  decisions: DecisionState[];
  notices: string[];
  usage?: DesktopConsoleUsage;
  budget?: DesktopConsoleTurnBudget;
  stopReason?: string;
  error?: string;
  isComplete: boolean;
  isWorking: boolean;
}

// ── Turn Reduction ────────────────────────────────────────────────

export function reduceTurns(events: DesktopConsoleEvent[]): ReducedTurn[] {
  const turns: ReducedTurn[] = [];
  let current: ReducedTurn | null = null;

  for (const event of events) {
    switch (event.type) {
      case "user": {
        // Close incomplete turn (interrupted by new user message)
        if (current && !current.isComplete) {
          current.isComplete = true;
          current.isWorking = false;
          for (const decision of current.decisions) decision.resolved = true;
          for (const tool of current.toolCalls) tool.isRunning = false;
        }
        current = {
          id: `turn-${event.sequence}`,
          user: { text: event.text, sequence: event.sequence },
          assistantText: "",
          reasoningText: "",
          toolCalls: [],
          decisions: [],
          notices: [],
          isComplete: false,
          isWorking: false,
        };
        turns.push(current);
        break;
      }
      case "assistant-delta": {
        if (current) current.assistantText += event.text;
        break;
      }
      case "reasoning-delta": {
        if (current) current.reasoningText += event.text;
        break;
      }
      case "tool-start": {
        if (current) {
          current.isWorking = true;
          const id = event.call.id ?? `tool-${current.toolCalls.length}`;
          current.toolCalls.push({
            id,
            name: event.call.name,
            arguments: event.call.arguments,
            isRunning: true,
          });
        }
        break;
      }
      case "tool-result": {
        if (current) {
          const tool = event.call.id
            ? current.toolCalls.find((t) => t.id === event.call.id)
            : current.toolCalls.find(
                (t) => t.name === event.call.name && t.isRunning,
              );
          if (tool) {
            tool.result = event.result;
            tool.isRunning = false;
          }
        }
        break;
      }
      case "usage": {
        if (current) current.usage = event.usage;
        break;
      }
      case "notice": {
        if (current) current.notices.push(event.text);
        break;
      }
      case "decision": {
        if (current) {
          current.decisions.push({
            id: event.decision.id,
            kind: event.decision.kind,
            title: event.decision.title,
            detail: event.decision.detail,
            call: event.decision.call,
            requestedUrls: event.decision.requestedUrls,
            requestedPath: event.decision.requestedPath,
            questions: event.decision.questions,
            resolved: false,
          });
          current.isWorking = true;
        }
        break;
      }
      case "decision-resolved": {
        if (current) {
          const d = current.decisions.find((d) => d.id === event.decisionId);
          if (d) {
            d.resolved = true;
            d.approved = event.approved;
          }
        }
        break;
      }
      case "turn-complete": {
        if (current) {
          current.isComplete = true;
          current.isWorking = false;
          current.budget = event.budget;
          current.stopReason = event.stopReason;
          if (event.error) current.error = event.error;
          for (const decision of current.decisions) decision.resolved = true;
          for (const tool of current.toolCalls) tool.isRunning = false;
        }
        break;
      }
      case "error": {
        if (current) {
          if (!current.error) current.error = event.message;
        }
        break;
      }
      // session events don't affect turn building
    }
  }

  // Last turn is working if still streaming
  if (current && !current.isComplete) {
    current.isWorking = true;
  }

  return turns;
}
