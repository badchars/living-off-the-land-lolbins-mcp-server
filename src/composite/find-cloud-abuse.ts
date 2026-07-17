import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { cloudAbuseTools } from "../providers/cloud-abuse.js";

const MODE_TOOLS: Record<string, string> = {
  aws: "cloud_aws_cli",
  gcloud: "cloud_gcloud",
  azure: "cloud_az_cli",
  kubectl: "cloud_kubectl",
  terraform: "cloud_terraform",
};

export const findCloudAbuseComposite: ToolDef = {
  name: "find_cloud_abuse",
  description:
    "Find cloud CLI abuse techniques — AWS CLI, gcloud, Azure CLI, kubectl, and Terraform for reconnaissance, privilege escalation, persistence, and data access.",
  schema: {
    mode: z
      .enum(["aws", "gcloud", "azure", "kubectl", "terraform"])
      .optional()
      .default("aws")
      .describe("Cloud provider/tool"),
    technique: z.string().optional().describe("Specific technique to look up"),
    environment_id: z.string().optional().describe("Environment session ID"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, technique, environment_id } = args;

    const baseArgs: Record<string, unknown> = {};
    if (technique) baseArgs.technique = technique;
    if (environment_id) baseArgs.environment_id = environment_id;

    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown cloud mode: ${mode}` }] };
    }

    const result = await callTool(cloudAbuseTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "find_cloud_abuse",
      mode,
      technique,
      environment_id,
    });
  },
};
