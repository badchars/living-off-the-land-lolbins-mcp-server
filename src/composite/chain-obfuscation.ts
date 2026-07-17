import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { chainObfuscationTools } from "../providers/chain-obfuscation.js";

const MODE_TOOLS: Record<string, string> = {
  multi_layer: "obf_multi_layer",
  custom: "obf_custom_chain",
  test_detection: "obf_test_detection",
  optimal: "obf_optimal_layers",
};

export const chainObfuscationComposite: ToolDef = {
  name: "chain_obfuscation",
  description:
    "Chain multiple obfuscation layers together for multi-layer command obfuscation",
  schema: {
    command: z
      .string()
      .describe("Command string to obfuscate with chained layers"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .describe("Target platform for obfuscation"),
    layers: z
      .number()
      .optional()
      .default(3)
      .describe("Number of obfuscation layers to chain"),
    mode: z
      .enum(["all", "multi_layer", "custom", "test_detection", "optimal"])
      .optional()
      .default("multi_layer")
      .describe("Chaining strategy to use"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform, layers, mode } = args;

    const baseArgs: Record<string, unknown> = { command, platform };
    if (layers !== undefined) baseArgs.layers = layers;

    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return {
          content: [{ type: "text", text: `Unknown mode: ${mode}` }],
        };
      }
      const result = await callTool(
        chainObfuscationTools,
        toolName,
        baseArgs,
        ctx,
      );
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "chain_obfuscation",
        mode,
        platform,
        layers,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(
      chainObfuscationTools,
      calls,
      ctx,
    );

    return buildCompositeResponse(results, {
      composite: "chain_obfuscation",
      mode: "all",
      platform,
      layers,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
