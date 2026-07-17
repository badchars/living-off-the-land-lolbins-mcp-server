import type { z } from "zod";
import type { KnowledgeBase } from "../knowledge-base/store.js";
import type { EnvironmentModel } from "../schema/environment.js";

export interface ToolDef {
  name: string;
  description: string;
  schema: z.ZodRawShape;
  execute: (args: any, ctx: ToolContext) => Promise<ToolResult>;
}

export interface ToolContext {
  config: {
    dataDir: string;
  };
  knowledgeBase: KnowledgeBase;
  sessions: Map<string, EnvironmentModel>;
}

export interface ToolResult {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
}

export function text(msg: string): ToolResult {
  return { content: [{ type: "text", text: msg }] };
}

export function json(data: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}
