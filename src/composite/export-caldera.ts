import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { calderaTools } from "../providers/caldera.js";

const MODE_TOOLS: Record<string, string> = {
  adversary_profile: "caldera_adversary_profile",
  ability_set: "caldera_ability_set",
  operation_plan: "caldera_operation_plan",
};

export const exportCalderaComposite: ToolDef = {
  name: "export_caldera_profile",
  description:
    "Export MITRE Caldera-compatible profiles — adversary profiles, ability sets, operation plans.",
  schema: {
    mode: z
      .enum(["adversary_profile", "ability_set", "operation_plan"])
      .describe("Caldera export mode"),
    environment_id: z.string().optional().describe("Environment session ID"),
    actor_name: z.string().optional().describe("Adversary actor name"),
    operation_name: z.string().optional().describe("Operation name for plan export"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(calderaTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "export_caldera_profile", mode });
  },
};
