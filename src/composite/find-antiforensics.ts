import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { antiforensicsTools } from "../providers/antiforensics.js";

const MODE_TOOLS: Record<string, string> = {
  clear_logs: "antiforensic_clear_logs",
  delete_artifacts: "antiforensic_delete_artifacts",
  timestomp: "antiforensic_timestomp",
  disable_logging: "antiforensic_disable_logging",
  cover_tracks: "antiforensic_cover_tracks",
  shadow_copy: "antiforensic_shadow_copy",
};

export const findAntiforensicsComposite: ToolDef = {
  name: "find_antiforensics",
  description:
    "Find anti-forensics techniques — log clearing, artifact deletion, timestomping, logging disable, track covering, shadow copy manipulation",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    mode: z
      .enum([
        "all",
        "clear_logs",
        "delete_artifacts",
        "timestomp",
        "disable_logging",
        "cover_tracks",
        "shadow_copy",
      ])
      .optional()
      .default("all")
      .describe("Type of anti-forensics technique to search for"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .optional()
      .describe("Target platform to filter techniques for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, mode, platform } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;
    if (platform) baseArgs.platform = platform;

    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return {
          content: [{ type: "text", text: `Unknown mode: ${mode}` }],
        };
      }
      const result = await callTool(
        antiforensicsTools,
        toolName,
        baseArgs,
        ctx,
      );
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_antiforensics",
        environment_id,
        mode,
        platform,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(antiforensicsTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_antiforensics",
      environment_id,
      mode: "all",
      platform,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
