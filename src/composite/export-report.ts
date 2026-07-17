import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { reportTools } from "../providers/report.js";

const MODE_TOOLS: Record<string, string> = {
  json: "export_json",
  markdown: "export_markdown",
  navigator_layer: "export_navigator_layer",
  csv: "export_csv",
  executive_summary: "export_executive_summary",
};

export const exportReportComposite: ToolDef = {
  name: "export_report",
  description:
    "Export findings and analysis as reports — JSON, Markdown, ATT&CK Navigator layer, CSV, executive summary.",
  schema: {
    mode: z
      .enum(["json", "markdown", "navigator_layer", "csv", "executive_summary"])
      .describe("Export format"),
    environment_id: z.string().optional().describe("Environment session ID"),
    include_sections: z.array(z.string()).optional().describe("Sections to include"),
    classification: z
      .enum(["public", "internal", "confidential", "restricted"])
      .optional()
      .describe("Report classification"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, ...rest } = args;
    const toolName = MODE_TOOLS[mode];
    if (!toolName) return { content: [{ type: "text", text: `Unknown mode: ${mode}` }] };
    const result = await callTool(reportTools, toolName, rest, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);
    return buildCompositeResponse(results, { composite: "export_report", mode });
  },
};
