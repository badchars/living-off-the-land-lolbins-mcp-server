import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { lateralTools } from "../providers/lateral.js";

const PROTOCOL_TOOLS: Record<string, string> = {
  ssh: "lateral_ssh",
  winrm: "lateral_winrm",
  smb: "lateral_smb",
  rdp: "lateral_rdp",
  wmi: "lateral_wmi",
};

const CREDENTIAL_REUSE_TOOL = "lateral_credential_reuse";

export const findLateralComposite: ToolDef = {
  name: "find_lateral_movement",
  description:
    "Find lateral movement techniques using LOL binaries — SSH, WinRM, SMB, RDP, credential reuse, and WMI.",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    target_hosts: z
      .array(z.string())
      .optional()
      .describe("List of target hosts/IPs for lateral movement"),
    protocol_filter: z
      .enum(["all", "ssh", "winrm", "smb", "rdp", "wmi"])
      .optional()
      .default("all")
      .describe("Filter by lateral movement protocol"),
    available_credentials: z
      .array(
        z.object({
          type: z.string().describe("Credential type (e.g. password, hash, ticket, key)"),
          username: z.string().describe("Username associated with the credential"),
          domain: z.string().optional().describe("Domain for the credential"),
        }),
      )
      .optional()
      .describe("Available credentials for lateral movement"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, target_hosts, protocol_filter, available_credentials } =
      args;

    const baseArgs: Record<string, unknown> = { environment_id };
    if (target_hosts) baseArgs.target_hosts = target_hosts;
    if (available_credentials) baseArgs.available_credentials = available_credentials;

    // Dispatch to specific protocol or all
    if (protocol_filter && protocol_filter !== "all") {
      const toolName = PROTOCOL_TOOLS[protocol_filter];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown protocol filter: ${protocol_filter}` }] };
      }
      const result = await callTool(lateralTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_lateral_movement",
        environment_id,
        protocol_filter,
      });
    }

    // Call all lateral movement tools + credential reuse in parallel
    const allToolNames = [...Object.values(PROTOCOL_TOOLS), CREDENTIAL_REUSE_TOOL];
    const calls = allToolNames.map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(lateralTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_lateral_movement",
      environment_id,
      protocol_filter: "all",
      target_hosts: target_hosts ?? [],
      tools_called: allToolNames,
    });
  },
};
