// PR-shaped finding output (0sec#377).
export {
  emitFindingsAsPRs,
  isReproduced,
  buildBranchName,
  buildPrTitle,
  buildPrBody,
  buildReproReadme,
  buildHypothesesMarkdown,
} from "./pr-emitter.js";
export type {
  EmitFindingsAsPRsOptions,
  EmitFindingsAsPRsReport,
  EvidenceArtifact,
  FsClient,
  GhClient,
  GitClient,
  PrEmitOutcome,
  PrEmitResult,
} from "./pr-emitter.js";

export {
  FixTemplateRegistry,
  createDefaultFixTemplateRegistry,
  hardCodedSecretTemplate,
  missingInputValidationTemplate,
  integerTruncationGuardTemplate,
  renderUnifiedDiff,
  templateIdForCategory,
} from "./fix-templates.js";
export type {
  FixTemplate,
  UnifiedDiff,
  UnifiedDiffHunk,
} from "./fix-templates.js";
