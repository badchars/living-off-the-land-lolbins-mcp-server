import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { discoveryTools } from "../providers/discovery.js";

const TYPE_TOOLS: Record<string, string> = {
  native_enum: "discover_native_enum",
  network: "discover_network_scan",
  services: "discover_service_enum",
  users: "discover_user_enum",
  files: "discover_file_enum",
};

export const findDiscoveryComposite: ToolDef = {
  name: "find_discovery",
  description:
    "Find discovery and enumeration techniques using LOL binaries — native enumeration, network scanning, service/user/file enumeration.",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    platform: z
      .enum(["linux", "windows", "macos", "all"])
      .optional()
      .default("all")
      .describe("Target platform for discovery techniques"),
    discovery_type: z
      .enum(["all", "native_enum", "network", "services", "users", "files"])
      .optional()
      .default("all")
      .describe("Type of discovery technique to search for"),
    stealth_priority: z
      .boolean()
      .optional()
      .default(false)
      .describe("Prioritize stealthier discovery techniques"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, platform, discovery_type, stealth_priority } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;
    if (platform && platform !== "all") baseArgs.platform = platform;
    if (stealth_priority) baseArgs.stealth_priority = stealth_priority;

    // Dispatch to specific type or all
    if (discovery_type && discovery_type !== "all") {
      const toolName = TYPE_TOOLS[discovery_type];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown discovery type: ${discovery_type}` }] };
      }
      const result = await callTool(discoveryTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_discovery",
        environment_id,
        platform,
        discovery_type,
        stealth_priority,
      });
    }

    const calls = Object.values(TYPE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(discoveryTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_discovery",
      environment_id,
      platform,
      discovery_type: "all",
      stealth_priority,
      tools_called: Object.values(TYPE_TOOLS),
    });
  },
};
