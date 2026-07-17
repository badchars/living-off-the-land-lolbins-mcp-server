import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { forensicArtifactTools } from "../providers/forensic-artifact.js";

const MODE_TOOLS: Record<string, string> = {
  event_log: "forensic_event_log",
  procmon: "forensic_procmon",
  edr_alert: "forensic_edr_alert",
  network_capture: "forensic_network_capture",
};

export const analyzeForensicComposite: ToolDef = {
  name: "analyze_forensic_artifact",
  description:
    "Analyze forensic artifacts for LOL technique indicators — Windows Event Logs, Process Monitor traces, EDR alerts, network captures.",
  schema: {
    mode: z
      .enum(["event_log", "procmon", "edr_alert", "network_capture"])
      .describe("Forensic artifact type"),
    event_id: z.number().optional().describe("Windows Event Log ID (e.g. 4688, 4104)"),
    command_line: z.string().optional().describe("Command line from forensic artifact"),
    alert_data: z.string().optional().describe("EDR alert data to analyze"),
    network_data: z.string().optional().describe("Network capture summary to analyze"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };

    const result = await callTool(forensicArtifactTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, { composite: "analyze_forensic_artifact", mode });
  },
};
