import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { purpleTeamTools } from "../providers/purple-team.js";

const MODE_TOOLS: Record<string, string> = {
  red_plan: "purple_red_plan",
  blue_detection: "purple_blue_detection",
  validation: "purple_validation_steps",
  combined: "purple_combined_exercise",
};

export const generatePurpleTeamComposite: ToolDef = {
  name: "generate_purple_team_plan",
  description:
    "Generate purple team exercise plans — red team plan, blue team detection, validation steps, combined exercise.",
  schema: {
    mode: z
      .enum(["red_plan", "blue_detection", "validation", "combined"])
      .describe("Purple team mode"),
    environment_id: z.string().optional().describe("Environment session ID"),
    objectives: z.array(z.string()).optional().describe("Exercise objectives"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(purpleTeamTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "generate_purple_team_plan", mode });
  },
};
