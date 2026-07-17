import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { credentialTools } from "../providers/credential.js";

const TYPE_TOOLS: Record<string, string> = {
  files: "cred_file_harvest",
  memory: "cred_memory_dump",
  keychain: "cred_keychain",
  registry: "cred_registry",
  token: "cred_token_theft",
  cached: "cred_cached",
};

export const findCredentialComposite: ToolDef = {
  name: "find_credential_access",
  description:
    "Find credential access techniques — file harvesting, memory dumps, keychain access, registry credentials, token theft, and cached credentials.",
  schema: {
    environment_id: z
      .string()
      .describe("Environment session ID returned by enumerate_host"),
    credential_type: z
      .enum(["all", "files", "memory", "keychain", "registry", "token", "cached"])
      .optional()
      .default("all")
      .describe("Type of credential access technique to search for"),
    target_user: z
      .string()
      .optional()
      .describe("Specific user to target for credential access"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { environment_id, credential_type, target_user } = args;

    const baseArgs: Record<string, unknown> = { environment_id };
    if (target_user) baseArgs.target_user = target_user;

    // Dispatch to specific type or all
    if (credential_type && credential_type !== "all") {
      const toolName = TYPE_TOOLS[credential_type];
      if (!toolName) {
        return { content: [{ type: "text", text: `Unknown credential type: ${credential_type}` }] };
      }
      const result = await callTool(credentialTools, toolName, baseArgs, ctx);
      const results = new Map<string, ToolResult>();
      results.set(toolName, result);
      return buildCompositeResponse(results, {
        composite: "find_credential_access",
        environment_id,
        credential_type,
        target_user,
      });
    }

    const calls = Object.values(TYPE_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(credentialTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_credential_access",
      environment_id,
      credential_type: "all",
      target_user,
      tools_called: Object.values(TYPE_TOOLS),
    });
  },
};
