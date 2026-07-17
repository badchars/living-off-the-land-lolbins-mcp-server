import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { packageManagerTools } from "../providers/package-manager.js";

const MODE_TOOLS: Record<string, string> = {
  npm: "pkg_npm_hooks",
  pip: "pkg_pip_setup",
  gem: "pkg_gem_hooks",
  cargo: "pkg_cargo_build",
};

export const findPackageManagerComposite: ToolDef = {
  name: "find_package_manager_abuse",
  description:
    "Find package manager abuse techniques — npm lifecycle hooks, pip setup.py, gem hooks, cargo build scripts.",
  schema: {
    mode: z
      .enum(["all", "npm", "pip", "gem", "cargo"])
      .optional()
      .default("all")
      .describe("Package manager to search for abuse techniques"),
    target_registry: z
      .string()
      .optional()
      .describe("Target package registry URL"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, target_registry } = args;

    const baseArgs: Record<string, unknown> = {};
    if (target_registry) baseArgs.target_registry = target_registry;

    // Dispatch to specific mode or all
    if (mode && mode !== "all") {
      const toolName = MODE_TOOLS[mode];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown package manager mode: ${mode}` }] };
      }
      const result = await callTool(packageManagerTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_package_manager_abuse",
        mode,
        target_registry,
      });
    }

    const calls = Object.values(MODE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(packageManagerTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_package_manager_abuse",
      mode: "all",
      target_registry,
      tools_called: Object.values(MODE_TOOLS),
    });
  },
};
