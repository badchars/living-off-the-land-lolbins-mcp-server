import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { initialAccessTools } from "../providers/initial-access.js";

const TYPE_TOOLS: Record<string, string> = {
  download_exec: "initial_download_exec",
  compile_exec: "initial_compile_exec",
  script_host: "initial_script_host",
  macro: "initial_macro",
  hta: "initial_hta",
};

export const findInitialAccessComposite: ToolDef = {
  name: "find_initial_access",
  description:
    "Find initial access techniques using LOL binaries — download-and-execute, compile, script hosts, macro execution, HTA execution.",
  schema: {
    platform: z
      .enum(["linux", "windows", "macos", "all"])
      .optional()
      .default("all")
      .describe("Target platform for initial access techniques"),
    access_type: z
      .enum(["all", "download_exec", "compile_exec", "script_host", "macro", "hta"])
      .optional()
      .default("all")
      .describe("Type of initial access technique to search for"),
    delivery_method: z
      .enum(["web", "email", "usb", "network"])
      .optional()
      .describe("Delivery method for the initial access payload"),
    bypass_required: z
      .array(z.string())
      .optional()
      .describe("List of security controls that need to be bypassed (e.g. AMSI, AppLocker, SmartScreen)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { platform, access_type, delivery_method, bypass_required } = args;

    const baseArgs: Record<string, unknown> = {};
    if (platform && platform !== "all") baseArgs.platform = platform;
    if (delivery_method) baseArgs.delivery_method = delivery_method;
    if (bypass_required) baseArgs.bypass_required = bypass_required;

    // Dispatch to specific type or all
    if (access_type && access_type !== "all") {
      const toolName = TYPE_TOOLS[access_type];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown access type: ${access_type}` }] };
      }
      const result = await callTool(initialAccessTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_initial_access",
        platform,
        access_type,
        delivery_method,
      });
    }

    const calls = Object.values(TYPE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(initialAccessTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_initial_access",
      platform,
      access_type: "all",
      delivery_method,
      bypass_required,
      tools_called: Object.values(TYPE_TOOLS),
    });
  },
};
