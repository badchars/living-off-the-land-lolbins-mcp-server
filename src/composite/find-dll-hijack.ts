import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { dllHijackTools } from "../providers/dll-hijack.js";

const MODE_TOOLS: Record<string, string> = {
  search_order: "dll_search_order",
  known_vulnerable: "dll_known_vulnerable",
  phantom: "dll_phantom",
  sideload: "dll_sideload_candidates",
  proxying: "dll_proxying",
  validate: "dll_hijack_validate",
};

export const findDllHijackComposite: ToolDef = {
  name: "find_dll_hijack",
  description:
    "Find DLL hijacking techniques — search order hijacking, known vulnerable apps, phantom DLLs, sideloading, proxying, validation",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    mode: z
      .enum([
        "all",
        "search_order",
        "known_vulnerable",
        "phantom",
        "sideload",
        "proxying",
        "validate",
      ])
      .optional()
      .default("all")
      .describe("Type of DLL hijacking technique to search for"),
    application: z
      .string()
      .optional()
      .describe("Specific application to find DLL hijacking vectors for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, mode, application } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;
    if (application) baseArgs.application = application;

    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return {
          content: [{ type: "text", text: `Unknown mode: ${mode}` }],
        };
      }
      const result = await callTool(dllHijackTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_dll_hijack",
        environment_id,
        mode,
        application,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(dllHijackTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_dll_hijack",
      environment_id,
      mode: "all",
      application,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
