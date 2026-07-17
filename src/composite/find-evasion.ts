import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { evasionTools } from "../providers/evasion.js";

const EVASION_TOOLS: Record<string, string> = {
  disable_edr: "evasion_bypass_edr",
  bypass_amsi: "evasion_amsi_bypass",
  bypass_applocker: "evasion_applocker",
  obfuscate: "evasion_obfuscate",
  dll_sideload: "evasion_dll_sideload",
  driver_load: "evasion_driver_load",
  ads_hide: "evasion_ads_hide",
  timestomp: "evasion_timestomp",
};

export const findEvasionComposite: ToolDef = {
  name: "find_defense_evasion",
  description:
    "Find defense evasion techniques — EDR bypass, AMSI bypass, AppLocker bypass, obfuscation, DLL sideloading, driver loading, ADS hiding, timestomping",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR product to target bypass techniques for"),
    evasion_type: z
      .enum([
        "all",
        "disable_edr",
        "bypass_amsi",
        "bypass_applocker",
        "obfuscate",
        "dll_sideload",
        "driver_load",
        "ads_hide",
        "timestomp",
      ])
      .optional()
      .default("all")
      .describe("Type of defense evasion technique to search for"),
    target_binary: z
      .string()
      .optional()
      .describe("Specific LOL binary to find evasion techniques for"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, edr_product, evasion_type, target_binary } = args;

    const baseArgs: Record<string, unknown> = {};
    if (environment_id) baseArgs.environment_id = environment_id;
    if (edr_product) baseArgs.edr_product = edr_product;
    if (target_binary) baseArgs.target_binary = target_binary;

    if (evasion_type && evasion_type !== "all") {
      const toolName = EVASION_TOOLS[evasion_type];
      if (!toolName) {
        return {
          content: [
            { type: "text", text: `Unknown evasion type: ${evasion_type}` },
          ],
        };
      }
      const result = await callTool(evasionTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_defense_evasion",
        environment_id,
        evasion_type,
      });
    }

    const calls = Object.values(EVASION_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(evasionTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_defense_evasion",
      environment_id,
      evasion_type: "all",
      tools_called: Object.values(EVASION_TOOLS),
    });
  },
};
