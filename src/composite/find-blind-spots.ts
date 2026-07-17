import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { detectionBlindSpotsTools } from "../providers/detection-blind-spots.js";

const MODE_TOOLS: Record<string, string> = {
  zero_coverage: "blind_zero_coverage",
  partial_coverage: "blind_partial_coverage",
  evasion_possible: "blind_evasion_possible",
  priority_ranking: "blind_priority_ranking",
};

export const findBlindSpotsComposite: ToolDef = {
  name: "find_detection_blind_spots",
  description:
    "Find detection blind spots — zero coverage techniques, partial coverage gaps, evasion-possible techniques, priority-ranked blind spots.",
  schema: {
    mode: z
      .enum(["zero_coverage", "partial_coverage", "evasion_possible", "priority_ranking"])
      .describe("Blind spot analysis mode"),
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z
      .enum(["linux", "windows", "macos", "all"])
      .optional()
      .describe("Platform filter"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(detectionBlindSpotsTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "find_detection_blind_spots", mode });
  },
};
