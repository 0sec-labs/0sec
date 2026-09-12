/** Wire-only contracts. Generated UI data never carries host functions or credentials. */
export type HarnessService = "agent.driver" | "ui.view";

export interface HarnessProviderSpec {
  id: string;
  requires?: string[];
  services: HarnessService[];
  source:
    | { kind: "sandboxed"; pluginId: string; versionId: string; toolName: string }
    | {
        kind: "trusted";
        /** Self-contained ESM entry exporting activate(context, previousState). */
        entry: string;
        files: Record<string, string>;
        /** Self-contained ESM modules exporting a React component factory. */
        ui?: { tui?: string; web?: string };
      };
}

/** Complete replacement graph, not an incremental mutation of the active graph. */
export interface HarnessGenerationSpec {
  label: string;
  providers: HarnessProviderSpec[];
}

export type HarnessViewBlock =
  | { type: "text"; text: string; tone?: "normal" | "muted" | "success" | "warning" | "error" }
  | { type: "markdown"; text: string }
  | { type: "table"; columns: string[]; rows: string[][] }
  | { type: "progress"; label: string; value: number; max: number }
  | { type: "action"; label: string; prompt: string };

export interface HarnessCommand {
  id: string;
  label: string;
  description?: string;
}

export interface HarnessSetting {
  id: string;
  label: string;
  description?: string;
  type: "boolean" | "text" | "select";
  value: boolean | string;
  options?: Array<{ label: string; value: string }>;
}

export type HarnessUiEvent =
  | { kind: "command"; id: string }
  | { kind: "setting"; id: string; value: boolean | string };

export interface HarnessView {
  title: string;
  blocks: HarnessViewBlock[];
  commands?: HarnessCommand[];
  settings?: HarnessSetting[];
  /** Returned only by an explicit UI interaction; never auto-submitted by rendering. */
  requestedPrompt?: string;
}

export interface HarnessSnapshot {
  generationId: string | null;
  previousGenerationId: string | null;
  pendingGenerationId: string | null;
  label: string;
  status: "builtin" | "pending" | "preparing" | "active" | "failed" | "closed";
  trusted: boolean;
  providers: Array<{ id: string; services: HarnessService[]; kind: "sandboxed" | "trusted" }>;
  views: Array<{ providerId: string; view: HarnessView }>;
  commands: Array<HarnessCommand & { providerId: string }>;
  settings: Array<HarnessSetting & { providerId: string }>;
  /** Available only after explicit workspace trust; never evaluate sandboxed output as code. */
  trustedUi: Array<{ providerId: string; tui?: string; web?: string }>;
  error?: string;
}

export type HarnessControl =
  | { action: "submit"; generation: HarnessGenerationSpec }
  | { action: "rollback"; generationId?: string }
  | { action: "disable" }
  | { action: "list" };

export interface HarnessUiInput {
  sessionId: string;
  phase: "idle" | "working";
  iterations: number;
  tokensUsed: number;
  /** Zero when the engine uses turn/cost limits rather than a token budget. */
  tokenBudget: number;
  event?: HarnessUiEvent;
}
