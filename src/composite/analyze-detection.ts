import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { detectionEffectivenessTools } from "../providers/detection-effectiveness.js";

const MODE_TOOLS: Record<string, string> = {
  rule_vs_technique: "det_rule_vs_technique",
  false_positive: "det_false_positive_rate",
  bypass_probability: "det_bypass_probability",
  rule_quality: "det_rule_quality",
};

export const analyzeDetectionComposite: ToolDef = {
  name: "analyze_detection_effectiveness",
  description:
    "Analyze detection rule effectiveness — rule vs technique coverage, false positive estimation, bypass probability, overall rule quality scoring.",
  schema: {
    mode: z
      .enum(["rule_vs_technique", "false_positive", "bypass_probability", "rule_quality"])
      .describe("Effectiveness analysis mode"),
    rule_name: z.string().optional().describe("Detection rule name or ID to analyze"),
    technique_id: z.string().optional().describe("LOL technique ID"),
    binary: z.string().optional().describe("Binary name"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(detectionEffectivenessTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "analyze_detection_effectiveness", mode });
  },
};
