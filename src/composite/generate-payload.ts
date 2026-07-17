import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import {
  callTool,
  callToolsParallel,
  buildCompositeResponse,
} from "./helpers.js";
import { payloadTools } from "../providers/payload.js";

const PAYLOAD_TOOLS: Record<string, string> = {
  command: "payload_command",
  reverse_shell: "payload_reverse_shell",
  bind_shell: "payload_bind_shell",
  file_read: "payload_file_read",
  file_write: "payload_file_write",
};

export const generatePayloadComposite: ToolDef = {
  name: "generate_payload",
  description:
    "Generate LOL binary payload information — command execution, reverse shells, bind shells, file read, file write payloads from the knowledge base",
  schema: {
    technique_id: z
      .string()
      .describe("Technique ID to generate payload for"),
    context: z
      .enum([
        "sudo",
        "suid",
        "capabilities",
        "unprivileged",
        "user",
        "admin",
        "system",
        "kernel",
      ])
      .optional()
      .describe("Execution context or privilege level"),
    payload_type: z
      .enum(["command", "reverse_shell", "bind_shell", "file_read", "file_write"])
      .describe("Type of payload to generate"),
    attacker_ip: z
      .string()
      .optional()
      .describe("Attacker IP address for reverse/bind shell payloads"),
    attacker_port: z
      .number()
      .optional()
      .describe("Attacker port for reverse/bind shell payloads"),
    target_file: z
      .string()
      .optional()
      .describe("Target file path for file read/write payloads"),
    output_file: z
      .string()
      .optional()
      .describe("Output file path for file write payloads"),
    encode: z
      .boolean()
      .optional()
      .default(false)
      .describe("Whether to encode the generated payload"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const {
      technique_id,
      context,
      payload_type,
      attacker_ip,
      attacker_port,
      target_file,
      output_file,
      encode,
    } = args;

    const baseArgs: Record<string, unknown> = { technique_id };
    if (context) baseArgs.context = context;
    if (attacker_ip) baseArgs.attacker_ip = attacker_ip;
    if (attacker_port !== undefined) baseArgs.attacker_port = attacker_port;
    if (target_file) baseArgs.target_file = target_file;
    if (output_file) baseArgs.output_file = output_file;
    if (encode !== undefined) baseArgs.encode = encode;

    const toolName = PAYLOAD_TOOLS[payload_type];
    if (!toolName) {
      return {
        content: [
          { type: "text", text: `Unknown payload type: ${payload_type}` },
        ],
      };
    }

    const result = await callTool(payloadTools, toolName, baseArgs, ctx);
    const results = new Map<string, ToolResult>();
    results.set(toolName, result);

    return buildCompositeResponse(results, {
      composite: "generate_payload",
      technique_id,
      payload_type,
      context,
    });
  },
};
