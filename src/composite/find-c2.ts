import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { c2Tools } from "../providers/c2.js";

const MODE_TOOLS: Record<string, string> = {
  service: "c2_lolc2_lookup",
  domain: "c2_lots_lookup",
  tunnel: "c2_tunnel_lookup",
  webhook: "c2_webhook",
  dns: "c2_dns",
  protocol: "c2_protocol_abuse",
};

export const findC2Composite: ToolDef = {
  name: "find_c2_channels",
  description:
    "Find C2 communication channels using LOL binaries and trusted services — LOLC2, LOTS, tunneling, webhooks, DNS, protocol abuse.",
  schema: {
    mode: z
      .enum(["service", "domain", "tunnel", "webhook", "dns", "protocol"])
      .optional()
      .default("service")
      .describe("C2 channel mode: service (LOLC2), domain (LOTS), tunnel, webhook, dns, protocol abuse"),
    service_name: z
      .string()
      .optional()
      .describe("Specific service name to look up for C2 potential"),
    domain: z
      .string()
      .optional()
      .describe("Domain to check for LOTS (Living off Trusted Sites) potential"),
    available_binaries: z
      .array(z.string())
      .optional()
      .describe("List of available binaries on the target system"),
    stealth_priority: z
      .boolean()
      .optional()
      .default(false)
      .describe("Prioritize stealthier C2 channels"),
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID returned by enumerate_host"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { mode, service_name, domain, available_binaries, stealth_priority, environment_id } =
      args;

    const baseArgs: Record<string, unknown> = {};
    if (service_name) baseArgs.service_name = service_name;
    if (domain) baseArgs.domain = domain;
    if (available_binaries) baseArgs.available_binaries = available_binaries;
    if (stealth_priority) baseArgs.stealth_priority = stealth_priority;
    if (environment_id) baseArgs.environment_id = environment_id;

    // Dispatch to specific mode
    const toolName = MODE_TOOLS[mode];
    if (!toolName) {
      return { content: [{ type: "text", text: `Unknown C2 mode: ${mode}` }] };
    }

    const result = await callTool(c2Tools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "find_c2_channels",
      mode,
      service_name,
      domain,
      stealth_priority,
      environment_id,
    });
  },
};
