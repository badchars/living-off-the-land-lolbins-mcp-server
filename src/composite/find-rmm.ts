import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { rmmTools } from "../providers/rmm.js";

const MODE_TOOLS: Record<string, string> = {
  check_installed: "rmm_installed_check",
  persistence: "rmm_persistence_paths",
  detection: "rmm_detection_artifacts",
  lateral_pivot: "rmm_lateral_pivot",
  silent_install: "rmm_silent_install",
};

export const findRmmComposite: ToolDef = {
  name: "find_rmm_abuse",
  description:
    "Find RMM (Remote Monitoring & Management) tool abuse techniques — installed tool check, persistence paths, detection artifacts, lateral pivoting, silent installation.",
  schema: {
    mode: z
      .enum(["check_installed", "persistence", "detection", "lateral_pivot", "silent_install"])
      .optional()
      .default("check_installed")
      .describe("RMM analysis mode"),
    rmm_tools: z
      .array(z.string())
      .optional()
      .describe("List of installed RMM tools to check"),
    environment_id: z.string().optional().describe("Environment session ID"),
    target_rmm: z.string().optional().describe("Specific RMM tool for silent install"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, rmm_tools, environment_id, target_rmm } = args;

    const baseArgs: Record<string, unknown> = {};
    if (rmm_tools) baseArgs.rmm_tools = rmm_tools;
    if (environment_id) baseArgs.environment_id = environment_id;
    if (target_rmm) baseArgs.target_rmm = target_rmm;

    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown RMM mode: ${mode}` }] };
    }

    const result = await callTool(rmmTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "find_rmm_abuse",
      mode,
      environment_id,
      target_rmm,
    });
  },
};
