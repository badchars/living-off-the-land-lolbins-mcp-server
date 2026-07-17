import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { incidentTimelineTools } from "../providers/incident-timeline.js";

const MODE_TOOLS: Record<string, string> = {
  map_events: "timeline_map_events",
  identify_sequence: "timeline_identify_sequence",
  reconstruct_chain: "timeline_reconstruct_chain",
};

export const correlateTimelineComposite: ToolDef = {
  name: "correlate_incident_timeline",
  description:
    "Correlate incident timeline events to LOL techniques — map events, identify attack sequences, reconstruct attack chains from evidence.",
  schema: {
    mode: z
      .enum(["map_events", "identify_sequence", "reconstruct_chain"])
      .describe("Timeline correlation mode"),
    events: z
      .array(
        z.object({
          timestamp: z.string().optional().describe("Event timestamp"),
          command: z.string().optional().describe("Command executed"),
          process: z.string().optional().describe("Process name"),
          description: z.string().optional().describe("Event description"),
        }),
      )
      .optional()
      .describe("List of timeline events to analyze"),
    evidence: z.string().optional().describe("Partial evidence text to reconstruct chain from"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };

    const result = await callTool(incidentTimelineTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, { composite: "correlate_incident_timeline", mode });
  },
};
