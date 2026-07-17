import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, buildCompositeResponse } from "./helpers.js";
import { driversTools } from "../providers/drivers.js";

const MODE_TOOLS: Record<string, string> = {
  hash_lookup: "driver_hash_lookup",
  name_lookup: "driver_name_lookup",
  byovd_candidates: "driver_byovd_candidates",
  cert_check: "driver_cert_check",
  vulnerable_match: "driver_vulnerable_match",
};

export const scanDriversComposite: ToolDef = {
  name: "scan_drivers",
  description:
    "Scan and analyze drivers against LOLDrivers database — hash lookup, name lookup, BYOVD candidates, certificate checking, vulnerable driver matching.",
  schema: {
    mode: z
      .enum(["hash_lookup", "name_lookup", "byovd_candidates", "cert_check", "vulnerable_match"])
      .describe("Driver scan mode"),
    driver_list: z
      .array(
        z.object({
          filename: z.string(),
          hash: z.string().optional(),
          signer: z.string().optional(),
        }),
      )
      .optional()
      .describe("List of loaded drivers to check"),
    target_edr: z.string().optional().describe("Target EDR to find BYOVD candidates for"),
    include_malicious: z
      .boolean()
      .optional()
      .default(true)
      .describe("Include malicious drivers"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, driver_list, target_edr, include_malicious } = args;

    const baseArgs: Record<string, unknown> = {};
    if (driver_list) baseArgs.driver_list = driver_list;
    if (target_edr) baseArgs.target_edr = target_edr;
    if (include_malicious !== undefined) baseArgs.include_malicious = include_malicious;

    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown driver scan mode: ${mode}` }] };
    }

    const result = await callTool(driversTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "scan_drivers",
      mode,
      target_edr,
      include_malicious,
    });
  },
};
