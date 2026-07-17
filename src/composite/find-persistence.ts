import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { persistenceTools } from "../providers/persistence.js";

const MECHANISM_TOOLS: Record<string, string> = {
  cron: "persist_cron",
  service: "persist_service",
  registry: "persist_registry",
  startup: "persist_startup",
  launchd: "persist_launchd",
  scheduled_task: "persist_scheduled_task",
  dll: "persist_dll",
};

export const findPersistenceComposite: ToolDef = {
  name: "find_persistence_paths",
  description:
    "Find persistence mechanisms using LOL binaries — cron jobs, services, registry keys, startup items, launch agents, scheduled tasks, and DLL persistence.",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    assume_privilege: z
      .string()
      .optional()
      .describe("Privilege level to assume post-escalation (e.g. root, SYSTEM)"),
    survive_reboot: z
      .boolean()
      .optional()
      .default(true)
      .describe("Only include mechanisms that survive reboot"),
    mechanism_type: z
      .enum([
        "all",
        "cron",
        "service",
        "registry",
        "startup",
        "launchd",
        "scheduled_task",
        "dll",
      ])
      .optional()
      .default("all")
      .describe("Type of persistence mechanism to search for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, assume_privilege, survive_reboot, mechanism_type } =
      args;

    const baseArgs: Record<string, unknown> = { environment_id };
    if (assume_privilege) baseArgs.assume_privilege = assume_privilege;
    if (survive_reboot !== undefined) baseArgs.survive_reboot = survive_reboot;

    // Determine which tools to call
    if (mechanism_type && mechanism_type !== "all") {
      const toolName = MECHANISM_TOOLS[mechanism_type];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown mechanism type: ${mechanism_type}` }] };
      }
      const result = await callTool(persistenceTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_persistence_paths",
        environment_id,
        mechanism_type,
        survive_reboot,
      });
    }

    // Call all persistence tools in parallel
    const calls = Object.values(MECHANISM_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(persistenceTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_persistence_paths",
      environment_id,
      mechanism_type: "all",
      survive_reboot,
      tools_called: Object.values(MECHANISM_TOOLS),
    });
  },
};
