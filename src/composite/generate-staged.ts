import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { stagedPayloadTools } from "../providers/staged-payload.js";

const MODE_TOOLS: Record<string, string> = {
  compress: "stage_compress",
  encode: "stage_encode",
  hide: "stage_hide",
  schedule: "stage_schedule_extract",
};

export const generateStagedComposite: ToolDef = {
  name: "generate_staged_payload",
  description:
    "Staged payload techniques — compression, encoding, filesystem hiding, scheduled extraction using native OS tools",
  schema: {
    mode: z
      .enum(["all", "compress", "encode", "hide", "schedule"])
      .optional()
      .default("all")
      .describe("Type of staging technique to use"),
    data_path: z
      .string()
      .optional()
      .describe("Path to data or payload to stage"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .optional()
      .describe("Target platform for staging techniques"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, data_path, platform } = args;

    const baseArgs: Record<string, unknown> = {};
    if (data_path) baseArgs.data_path = data_path;
    if (platform) baseArgs.platform = platform;

    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return {
          content: [{ type: "text", text: `Unknown mode: ${mode}` }],
        };
      }
      const result = await callTool(
        stagedPayloadTools,
        toolName,
        baseArgs,
        ctx,
      );
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "generate_staged_payload",
        mode,
        platform,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(stagedPayloadTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "generate_staged_payload",
      mode: "all",
      platform,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
