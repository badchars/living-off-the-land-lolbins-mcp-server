import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { attckTools } from "../providers/attck.js";

const MODE_TOOLS: Record<string, string> = {
  lookup: "attck_technique_lookup",
  coverage: "attck_coverage_map",
  navigator: "attck_navigator_export",
  heatmap: "attck_heatmap",
  gaps: "attck_gap_analysis",
};

export const mapAttckComposite: ToolDef = {
  name: "map_attck",
  description:
    "Map LOL techniques to MITRE ATT&CK framework — technique lookup, coverage map, Navigator layer export, heatmap, gap analysis.",
  schema: {
    mode: z
      .enum(["lookup", "coverage", "navigator", "heatmap", "gaps"])
      .describe("ATT&CK mapping mode"),
    technique_id: z.string().optional().describe("ATT&CK technique ID (e.g. T1059.006)"),
    environment_id: z.string().optional().describe("Environment session ID"),
    tactic_filter: z
      .string()
      .optional()
      .describe("Filter by tactic: initial-access, execution, persistence, etc."),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(attckTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "map_attck", mode });
  },
};
