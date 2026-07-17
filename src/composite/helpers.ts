import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { text } from "../types/index.js";

export async function callTool(
  tools: ToolDef[],
  name: string,
  args: any,
  ctx: ToolContext,
): Promise<ToolResult> {
  const tool = tools.find(t => t.name === name);
  if (!tool) return text(`Tool not found: ${name}`);
  return tool.execute(args, ctx);
}

export async function callToolsParallel(
  tools: ToolDef[],
  calls: { name: string; args: any }[],
  ctx: ToolContext,
): Promise<Map<string, ToolResult>> {
  const results = new Map<string, ToolResult>();
  const promises = calls.map(async ({ name, args }) => {
    const result = await callTool(tools, name, args, ctx);
    results.set(name, result);
  });
  await Promise.all(promises);
  return results;
}

export function buildCompositeResponse(
  results: Map<string, ToolResult>,
  summary: Record<string, unknown> = {},
): ToolResult {
  const sections: string[] = [];

  if (Object.keys(summary).length > 0) {
    sections.push(JSON.stringify(summary, null, 2));
  }

  for (const [toolName, result] of results) {
    if (result.content && result.content[0]) {
      const content = result.content[0].text;
      sections.push(`--- ${toolName} ---\n${content}`);
    }
  }

  return { content: [{ type: "text", text: sections.join("\n\n") }] };
}

export function mergeToolResults(results: Map<string, ToolResult>): any {
  const merged: Record<string, any> = {};
  for (const [name, result] of results) {
    if (result.content?.[0]?.text) {
      try {
        merged[name] = JSON.parse(result.content[0].text);
      } catch {
        merged[name] = result.content[0].text;
      }
    }
  }
  return merged;
}
