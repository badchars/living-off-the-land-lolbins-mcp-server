import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { detectionTools } from "../providers/detection.js";

const MODE_TOOLS: Record<string, string> = {
  sigma_coverage: "detection_sigma_coverage",
  edr_coverage: "detection_edr_coverage",
  sysmon_events: "detection_sysmon_events",
  priority_gaps: "detection_priority_gaps",
  recommend_rules: "detection_recommend_rules",
  blind_spots: "detection_blind_spots",
};

export const assessDetectionComposite: ToolDef = {
  name: "assess_detection_gaps",
  description:
    "Assess detection coverage gaps for LOL techniques — Sigma coverage, EDR coverage, Sysmon events, priority gaps, rule recommendations, blind spots.",
  schema: {
    mode: z
      .enum(["sigma_coverage", "edr_coverage", "sysmon_events", "priority_gaps", "recommend_rules", "blind_spots"])
      .describe("Detection assessment mode"),
    environment_id: z.string().optional().describe("Environment session ID"),
    edr_product: z.string().optional().describe("Deployed EDR product"),
    focus_area: z
      .enum(["all", "escalation", "persistence", "lateral", "evasion", "credential", "exfil"])
      .optional()
      .describe("Focus area"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(detectionTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "assess_detection_gaps", mode });
  },
};
