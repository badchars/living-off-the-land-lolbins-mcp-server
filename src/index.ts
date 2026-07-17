#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ToolContext } from "./types/index.js";
import { startMcpStdio } from "./protocol/mcp-server.js";
import { allTools, individualTools, allToolsCombined } from "./protocol/tools.js";
import { KnowledgeBase } from "./knowledge-base/store.js";
import { loadFromDataDir } from "./knowledge-base/loader.js";
import type { EnvironmentModel } from "./schema/environment.js";

// ─── Resolve data directory ───

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const dataDir = resolve(__dirname, "../data");

// ─── Build ToolContext ───

async function buildToolContext(): Promise<ToolContext> {
  const knowledgeBase = new KnowledgeBase();

  try {
    const entries = await loadFromDataDir(dataDir);
    knowledgeBase.load(entries);
    console.error(`[kb] Loaded ${knowledgeBase.totalEntries} entries from ${dataDir}`);
  } catch (err) {
    console.error(`[kb] Warning: Could not load data from ${dataDir}: ${(err as Error).message}`);
    console.error("[kb] Run 'bun run snapshot' to fetch catalog data");
  }

  return {
    config: { dataDir },
    knowledgeBase,
    sessions: new Map<string, EnvironmentModel>(),
  };
}

// ─── CLI: --help ───

function printHelp(): void {
  console.log(`living-off-the-land-lolbins-mcp — LOL Binary Intelligence MCP Server

USAGE:
  living-off-the-land-lolbins-mcp-server              Start MCP server on stdio
  living-off-the-land-lolbins-mcp-server --help       Show this help
  living-off-the-land-lolbins-mcp-server --list       List composite tools (MCP-exposed)
  living-off-the-land-lolbins-mcp-server --list-all   List all individual techniques
  living-off-the-land-lolbins-mcp-server --tool <name> '<json>'  Run a tool directly

CATALOGS:
  GTFOBins (478)  — Linux privilege escalation binaries
  LOLBAS (117)    — Windows living off the land binaries
  LOOBins (62)    — macOS living off the orchard binaries
  LOLDrivers (660) — Vulnerable/malicious Windows drivers

SETUP:
  bun run snapshot   Fetch all catalog data (required for first use)

EXAMPLES:
  --tool lookup_binary '{"binary":"python"}'
  --tool search_techniques '{"mode":"function","function":"reverse_shell"}'
  --tool update_knowledge_base '{"mode":"stats"}'
`);
}

// ─── CLI: --list ───

function printToolList(): void {
  console.log(`\nliving-off-the-land-lolbins-mcp — ${allTools.length} composite tools\n`);
  console.log("━━━ Composite Tools (MCP-exposed) ━━━");
  for (const tool of allTools) {
    const schemaKeys = typeof tool.schema === "object" && "shape" in tool.schema
      ? Object.keys((tool.schema as any).shape || {})
      : Object.keys(tool.schema);
    const params = schemaKeys.length > 0 ? `(${schemaKeys.join(", ")})` : "()";
    console.log(`  ${tool.name}${params}`);
    console.log(`    ${tool.description.split(".")[0]}.`);
  }
  console.log();
}

// ─── CLI: --list-all ───

function printAllTools(): void {
  console.log(`\nliving-off-the-land-lolbins-mcp — ${allToolsCombined.length} total tools\n`);
  console.log(`━━━ Composite Tools (${allTools.length}) ━━━`);
  for (const tool of allTools) {
    console.log(`  ${tool.name} — ${tool.description.split(".")[0]}`);
  }
  console.log(`\n━━━ Individual Techniques (${individualTools.length}) ━━━`);
  for (const tool of individualTools) {
    console.log(`  ${tool.name} — ${tool.description.split(".")[0]}`);
  }
  console.log();
}

// ─── CLI: --tool ───

async function runTool(name: string, argsJson: string): Promise<void> {
  const tool = allToolsCombined.find(t => t.name === name);
  if (!tool) {
    console.error(`Error: Tool "${name}" not found`);
    console.error(`Available tools: ${allToolsCombined.map(t => t.name).join(", ")}`);
    process.exit(1);
  }

  let args: any;
  try {
    args = JSON.parse(argsJson);
  } catch {
    console.error(`Error: Invalid JSON: ${argsJson}`);
    process.exit(1);
  }

  const ctx = await buildToolContext();
  const result = await tool.execute(args, ctx);

  if (result.content && result.content[0]) {
    console.log(result.content[0].text);
  }
}

// ─── Main ───

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return;
  }

  if (args.includes("--list-all")) {
    printAllTools();
    return;
  }

  if (args.includes("--list") || args.includes("-l")) {
    printToolList();
    return;
  }

  const toolIdx = args.indexOf("--tool");
  if (toolIdx !== -1) {
    const toolName = args[toolIdx + 1];
    const toolArgs = args[toolIdx + 2] || "{}";
    if (!toolName) {
      console.error("Error: --tool requires a tool name");
      process.exit(1);
    }
    await runTool(toolName, toolArgs);
    return;
  }

  // Default: start MCP server on stdio
  const ctx = await buildToolContext();
  await startMcpStdio(ctx);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
