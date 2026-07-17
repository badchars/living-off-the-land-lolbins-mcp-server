import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { redVsBlueTools } from "../providers/red-vs-blue.js";

const MODE_TOOLS: Record<string, string> = {
  coverage: "score_coverage",
  blind_spots: "score_blind_spots",
  overall: "score_overall_posture",
  improvement_plan: "score_improvement_plan",
};

export const scoreRedVsBlueComposite: ToolDef = {
  name: "score_red_vs_blue",
  description:
    "Score red team vs blue team posture — detection coverage scoring, blind spot severity, overall security posture, improvement plan.",
  schema: {
    mode: z
      .enum(["coverage", "blind_spots", "overall", "improvement_plan"])
      .describe("Scoring mode"),
    environment_id: z.string().optional().describe("Environment session ID"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(redVsBlueTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "score_red_vs_blue", mode });
  },
};
