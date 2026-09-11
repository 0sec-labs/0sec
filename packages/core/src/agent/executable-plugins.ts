import { join } from "node:path";
import { homeStateDir } from "@0sec/shared";
import { z } from "zod";
import {
  ExecutablePluginManager,
  type ExecutablePluginOptions,
} from "../plugins/executable.js";
import type { SelfExtensionRegistry } from "../plugins/self-extension.js";
import type { NativeRuntimeResult } from "../runtime/types.js";
import { loadEvolutionConfigFile } from "../improvement/index.js";
import type { EvolutionConfig } from "../improvement/types.js";

export type ExecutablePluginConfiguration = Partial<Omit<ExecutablePluginOptions, "registry">>;

/** Operator configuration only. A tool call cannot select its backend or mounts. */
export function createExecutablePlugins(
  registry: SelfExtensionRegistry,
  configuration: ExecutablePluginConfiguration = {},
): ExecutablePluginManager {
  const backend = configuration.backend ?? process.env["0SEC_PLUGIN_BACKEND"] ?? "docker";
  if (backend !== "docker" && backend !== "smolvm") {
    throw new Error("0SEC_PLUGIN_BACKEND must be docker or smolvm");
  }
  return new ExecutablePluginManager({
    root: join(homeStateDir(), "executable-plugins"),
    image: process.env["0SEC_PLUGIN_IMAGE"] ?? "0sec-toolbox:local",
    imageArchive: backend === "smolvm" ? process.env["0SEC_SMOLVM_IMAGE_ARCHIVE"] : undefined,
    ...configuration,
    backend,
    registry,
  });
}

/** Reuse the CLI's validated operator contract; generated source cannot define its oracle. */
export function resolveExecutableEvolutionProfiles(
  profiles?: Record<string, EvolutionConfig>,
): Record<string, EvolutionConfig> {
  if (profiles) return profiles;
  const configFile = process.env["0SEC_PLUGIN_EVOLUTION_CONFIG"];
  return configFile ? { default: loadEvolutionConfigFile(configFile) } : {};
}

const contentBlock = z.discriminatedUnion("type", [
  z.object({ type: z.literal("text"), text: z.string() }).strict(),
  z.object({
    type: z.literal("tool_use"), id: z.string().min(1), name: z.string().min(1),
    input: z.record(z.unknown()),
  }).strict(),
  z.object({
    type: z.literal("tool_result"), tool_use_id: z.string().min(1),
    content: z.string(), is_error: z.boolean().optional(),
  }).strict(),
]);
const modelRequest = z.object({
  system: z.string().default(""),
  messages: z.array(z.object({
    role: z.enum(["user", "assistant"]),
    content: z.array(contentBlock).min(1).max(128),
  }).strict()).min(1).max(128),
  tools: z.array(z.object({
    name: z.string().min(1).max(128), description: z.string(),
    input_schema: z.object({
      type: z.literal("object"), properties: z.record(z.unknown()),
      required: z.array(z.string()).optional(),
    }).strict(),
  }).strict()).max(128).default([]),
}).strict();

/** No provider, credential, transport, or opaque reasoning fields cross this ABI. */
export function parseExecutableModelRequest(request: unknown): z.infer<typeof modelRequest> {
  const json = JSON.stringify(request);
  if (!json || Buffer.byteLength(json) > 256 * 1024) {
    throw new Error("Executable agent model request exceeds 256 KiB");
  }
  return modelRequest.parse(request);
}

export function executableModelResult(result: NativeRuntimeResult): Omit<NativeRuntimeResult, "providerRaw"> {
  const { providerRaw: _providerRaw, ...visible } = result;
  return visible;
}
