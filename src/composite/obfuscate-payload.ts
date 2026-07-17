import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { obfuscateTools } from "../providers/obfuscate.js";

const METHOD_TOOLS: Record<string, string> = {
  glob: "obfuscate_glob",
  encode: "obfuscate_encode",
  alternative_binary: "obfuscate_alt_binary",
  string_concat: "obfuscate_string_concat",
  env_var: "obfuscate_env_var",
};

export const obfuscatePayloadComposite: ToolDef = {
  name: "obfuscate_payload",
  description:
    "Obfuscate commands using LOL techniques — glob wildcards, encoding, alternative binaries, string concatenation, environment variable substitution",
  schema: {
    command: z
      .string()
      .describe("Command string to obfuscate"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .describe("Target platform for obfuscation"),
    method: z
      .enum(["glob", "encode", "alternative_binary", "string_concat", "env_var"])
      .describe("Obfuscation method to apply"),
    iterations: z
      .number()
      .optional()
      .default(1)
      .describe("Number of obfuscation iterations to apply"),
    avoid_patterns: z
      .array(z.string())
      .optional()
      .describe("Patterns to avoid in the obfuscated output"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform, method, iterations, avoid_patterns } = args;

    const baseArgs: Record<string, unknown> = { command, platform };
    if (iterations !== undefined) baseArgs.iterations = iterations;
    if (avoid_patterns) baseArgs.avoid_patterns = avoid_patterns;

    const toolName = METHOD_TOOLS[method];
    if (!toolName) {
      return {
        content: [
          { type: "text", text: `Unknown obfuscation method: ${method}` },
        ],
      };
    }

    const result = await callTool(obfuscateTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "obfuscate_payload",
      method,
      platform,
      iterations,
    });
  },
};
