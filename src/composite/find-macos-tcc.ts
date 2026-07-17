import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { macosTccTools } from "../providers/macos-tcc.js";

const MODE_TOOLS: Record<string, string> = {
  bypass: "tcc_bypass_technique",
  entitlement: "tcc_entitlement_abuse",
  sip: "tcc_sip_circumvent",
  gatekeeper: "tcc_gatekeeper_bypass",
};

export const findMacosTccComposite: ToolDef = {
  name: "find_macos_tcc_bypass",
  description:
    "Find macOS TCC (Transparency, Consent, and Control) bypass techniques — TCC bypass, entitlement abuse, SIP circumvention, Gatekeeper bypass.",
  schema: {
    mode: z
      .enum(["bypass", "entitlement", "sip", "gatekeeper"])
      .optional()
      .default("bypass")
      .describe("macOS security bypass type"),
    target_permission: z
      .string()
      .optional()
      .describe("Target TCC permission: full_disk_access, camera, microphone, screen_recording"),
    environment_id: z.string().optional().describe("Environment session ID"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, target_permission, environment_id } = args;

    const baseArgs: Record<string, unknown> = {};
    if (target_permission) baseArgs.target_permission = target_permission;
    if (environment_id) baseArgs.environment_id = environment_id;

    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown macOS TCC mode: ${mode}` }] };
    }

    const result = await callTool(macosTccTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "find_macos_tcc_bypass",
      mode,
      target_permission,
      environment_id,
    });
  },
};
