import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { containerEscapeTools } from "../providers/container-escape.js";

const MODE_TOOLS: Record<string, string> = {
  docker_socket: "container_docker_socket",
  privileged: "container_privileged",
  cap_sys_admin: "container_cap_sys_admin",
  nsenter: "container_nsenter",
  cgroup: "container_cgroup",
};

export const findContainerEscapeComposite: ToolDef = {
  name: "find_container_escape",
  description:
    "Find container and Docker escape techniques — Docker socket abuse, privileged container escape, CAP_SYS_ADMIN abuse, nsenter breakout, cgroup escape.",
  schema: {
    mode: z
      .enum(["docker_socket", "privileged", "cap_sys_admin", "nsenter", "cgroup"])
      .optional()
      .default("docker_socket")
      .describe("Container escape technique type"),
    environment_id: z.string().optional().describe("Environment session ID"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, environment_id } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;

    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown container escape mode: ${mode}` }] };
    }

    const result = await callTool(containerEscapeTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "find_container_escape",
      mode,
      environment_id,
    });
  },
};
