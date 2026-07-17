import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { envvarAbuseTools } from "../providers/envvar-abuse.js";

const MODE_TOOLS: Record<string, string> = {
  path_hijack: "envvar_path_hijack",
  ld_preload: "envvar_ld_preload",
  dyld_insert: "envvar_dyld_insert",
  dll_search_order: "envvar_dll_search_order",
  comspec: "envvar_comspec",
};

export const findEnvvarAbuseComposite: ToolDef = {
  name: "find_environment_variable_abuse",
  description:
    "Find environment variable abuse techniques — PATH hijacking, LD_PRELOAD, DYLD_INSERT_LIBRARIES, DLL search order, COMSPEC abuse",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    mode: z
      .enum([
        "all",
        "path_hijack",
        "ld_preload",
        "dyld_insert",
        "dll_search_order",
        "comspec",
      ])
      .optional()
      .default("all")
      .describe("Type of environment variable abuse technique to search for"),
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
      const result = await callTool(envvarAbuseTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_environment_variable_abuse",
        environment_id,
        mode,
        platform,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(envvarAbuseTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_environment_variable_abuse",
      environment_id,
      mode: "all",
      platform,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
