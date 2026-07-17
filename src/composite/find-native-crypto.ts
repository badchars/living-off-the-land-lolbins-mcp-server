import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { callTool, callToolsParallel, buildCompositeResponse } from "./helpers.js";
import { nativeCryptoTools } from "../providers/native-crypto.js";

const BINARY_TOOLS: Record<string, string> = {
  certutil: "crypto_certutil",
  openssl: "crypto_openssl",
  gpg: "crypto_gpg",
  base64: "crypto_base64_variants",
  powershell: "crypto_powershell",
};

export const findNativeCryptoComposite: ToolDef = {
  name: "find_native_crypto",
  description:
    "Find native cryptographic and encoding techniques using LOL binaries — certutil, openssl, gpg, base64, PowerShell.",
  schema: {
    platform: z
      .enum(["linux", "windows", "macos", "all"])
      .optional()
      .default("all")
      .describe("Target platform for cryptographic techniques"),
    operation: z
      .enum(["encode", "decode", "encrypt", "decrypt", "hash"])
      .optional()
      .default("encode")
      .describe("Cryptographic operation to search for"),
    target_binary: z
      .string()
      .optional()
      .describe("Specific binary to search for cryptographic capabilities"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { platform, operation, target_binary } = args;

    const baseArgs: Record<string, unknown> = {};
    if (platform && platform !== "all") baseArgs.platform = platform;
    if (operation) baseArgs.operation = operation;

    // If a specific target binary is requested, dispatch to that tool only
    if (target_binary) {
      const normalizedBinary = target_binary.toLowerCase();
      const toolName = BINARY_TOOLS[normalizedBinary];
      if (toolName) {
        const result = await callTool(nativeCryptoTools, toolName, baseArgs, ctx);
        const results = new Map<string, ToolResult>();
        results.set(toolName, result);
        return buildCompositeResponse(results, {
          composite: "find_native_crypto",
          platform,
          operation,
          target_binary,
        });
      }
      // If the binary is not in our mapping, still try all tools
    }

    // Call all crypto tools in parallel
    const calls = Object.values(BINARY_TOOLS).map((name) => ({
      name,
      args: baseArgs,
    }));

    const results = await callToolsParallel(nativeCryptoTools, calls, ctx);

    return buildCompositeResponse(results, {
      composite: "find_native_crypto",
      platform,
      operation,
      target_binary,
      tools_called: Object.values(BINARY_TOOLS),
    });
  },
};
