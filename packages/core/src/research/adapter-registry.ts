import type {
  ResearchRunResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "./target-research-adapter.js";
import { runResearch, type RunResearchOptions } from "./research-runner.js";
import { HuntResearchAdapter } from "./adapters/hunt-adapter.js";
import { LiveAgenticScanResearchAdapter } from "./adapters/live-agentic-scan-adapter.js";
import { LinuxKernelResearchAdapter } from "./adapters/linux-kernel-adapter.js";
import { LinuxBootMatrixImportAdapter } from "./adapters/linux-boot-matrix-adapter.js";
import { MobileStaticResearchAdapter } from "./adapters/mobile-static-adapter.js";
import { ProtocolHttpResearchAdapter } from "./adapters/protocol-http-adapter.js";
import { UnifiedPipelineResearchAdapter } from "./adapters/unified-pipeline-adapter.js";
import { UserspaceMemSafetyResearchAdapter } from "./adapters/userspace-memsafety-adapter.js";
import { XnuIokitResearchAdapter } from "./adapters/xnu-iokit-adapter.js";
import { WindowsHyperVImportAdapter } from "./adapters/windows-hyperv-adapter.js";

type AdapterFactory = () => TargetResearchAdapter<any, any, any, any>;

export class ResearchAdapterRegistry {
  private readonly factories = new Map<string, AdapterFactory>();

  register(kind: string, factory: AdapterFactory): this {
    if (this.factories.has(kind)) throw new Error(`research adapter already registered: ${kind}`);
    this.factories.set(kind, factory);
    return this;
  }

  kinds(): string[] {
    return [...this.factories.keys()].sort();
  }

  async run(target: ResearchTarget, opts: RunResearchOptions<ResearchTarget> = {}): Promise<ResearchRunResult> {
    const factory = this.factories.get(target.kind);
    if (!factory) throw new Error(`no research adapter registered for target kind ${target.kind}`);
    return runResearch(factory(), target as any, opts as any);
  }
}

export function createDefaultResearchRegistry(): ResearchAdapterRegistry {
  return new ResearchAdapterRegistry()
    .register("protocol.http-conformance", () => new ProtocolHttpResearchAdapter())
    .register("userspace.memsafety", () => new UserspaceMemSafetyResearchAdapter())
    .register("hunt.agentic", () => new HuntResearchAdapter())
    .register("live.agentic-scan", () => new LiveAgenticScanResearchAdapter())
    .register("linux.kernel-reproducer", () => new LinuxKernelResearchAdapter())
    .register("linux.kernel-boot-matrix-import", () => new LinuxBootMatrixImportAdapter())
    .register("mobile.static-intake", () => new MobileStaticResearchAdapter())
    .register("xnu.iokit-fuzz", () => new XnuIokitResearchAdapter())
    .register("windows.hyperv-prover-import", () => new WindowsHyperVImportAdapter())
    .register("pipeline.unified", () => new UnifiedPipelineResearchAdapter());
}
