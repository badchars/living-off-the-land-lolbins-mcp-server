# Contributing to living-off-the-land-lolbins-mcp-server

Thank you for your interest in contributing to living-off-the-land-lolbins-mcp-server! This document provides guidelines and instructions to help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/badchars/living-off-the-land-lolbins-mcp-server.git
cd living-off-the-land-lolbins-mcp-server

# Install dependencies (Bun 1.3.9+ required)
bun install

# Build the project
bun run build

# Start in development mode (watch for changes)
bun run dev
```

## Project Structure

```
src/
├── index.ts                    # Entry point, CLI flags, MCP server bootstrap
├── protocol/
│   ├── mcp-server.ts           # MCP server setup (stdio transport)
│   └── tools.ts                # Tool registry — all 59 composite + 321 total tools
├── types/
│   └── index.ts                # ToolDef, ToolContext, ToolResult, CatalogEntry
├── schema/
│   ├── catalog.ts              # Unified catalog schema (Zod)
│   ├── technique.ts            # ATT&CK technique schema
│   └── binary.ts               # Binary/tool schema
├── utils/
│   ├── cache.ts                # TTL cache implementation
│   ├── rate-limiter.ts         # Per-catalog rate limiter
│   ├── loader.ts               # Catalog data loader (fetch + parse + normalize)
│   └── updater.ts              # Catalog auto-updater
├── catalogs/
│   ├── gtfobins/               # GTFOBins parser and normalizer
│   ├── lolbas/                 # LOLBAS parser and normalizer
│   ├── loobins/                # LOOBins parser and normalizer
│   ├── loldrivers/             # LOLDrivers parser and normalizer
│   ├── lolrmm/                 # LOLRMM parser and normalizer
│   ├── lolesxi/                # LOLESXi parser and normalizer
│   ├── lotp/                   # LOTP parser and normalizer
│   ├── lolc2/                  # LOLC2 parser and normalizer
│   ├── loflcab/                # LOFLCAB parser and normalizer
│   ├── wadcoms/                # WADComs parser and normalizer
│   └── index.ts                # Catalog registry and loader index
├── knowledge-base/
│   ├── attack-map.ts           # MITRE ATT&CK mapping engine
│   ├── binary-db.ts            # Unified binary database
│   └── technique-db.ts         # Technique database with cross-references
├── environment/
│   ├── enumerator.ts           # Platform environment enumeration
│   └── platform-profiles.ts    # Default binary inventories per OS/version
├── graph/
│   ├── attack-graph.ts         # Attack graph data structure
│   ├── pathfinder.ts           # BFS/DFS path finding algorithms
│   └── visualizer.ts           # Mermaid, Graphviz, ASCII rendering
├── providers/
│   ├── core/                   # Core lookup, search, list (3 tools)
│   ├── environment/            # Environment & graph (4 tools)
│   ├── privesc/                # Privilege escalation (3 tools)
│   ├── persistence/            # Persistence (2 tools)
│   ├── lateral/                # Lateral movement (2 tools)
│   ├── evasion/                # Defense evasion (5 tools)
│   ├── credential/             # Credential access (2 tools)
│   ├── execution/              # Execution (3 tools)
│   ├── discovery/              # Discovery & collection (2 tools)
│   ├── exfiltration/           # Exfiltration & C2 (3 tools)
│   ├── payload/                # Payload & obfuscation (4 tools)
│   ├── drivers/                # Drivers, RMM, CI/CD (3 tools)
│   ├── platform/               # Platform deep dives (3 tools)
│   ├── opsec/                  # OPSEC & planning (2 tools)
│   ├── threat-intel/           # Threat intelligence (3 tools)
│   ├── forensics/              # Forensics & IR (3 tools)
│   ├── detection/              # Detection engineering (4 tools)
│   ├── blue-team/              # Blue team analytics (3 tools)
│   ├── ad/                     # AD & WADComs (1 tool)
│   ├── reporting/              # Reporting & visualization (3 tools)
│   └── integration/            # Integration export (1 tool)
├── composite/
│   └── index.ts                # Composite tool orchestrator
└── scripts/
    ├── update-catalogs.ts      # Fetch and update all catalog data
    └── build-knowledge-base.ts # Rebuild the unified knowledge base
```

## Adding a New Tool

Each tool is defined using the `ToolDef` interface. Every tool has a name, description, a Zod input schema, and an async `execute` function.

### 1. Define the tool

Create or edit a file in the appropriate provider directory:

```typescript
import { z } from "zod";
import type { ToolDef, ToolContext } from "../../types/index.js";
import { json, text } from "../../types/index.js";

export const myNewTool: ToolDef = {
  name: "lol_my_new_tool",
  description: "Short description of what the tool does",
  schema: {
    binary: z.string().describe("The binary name to look up"),
    platform: z.enum(["linux", "windows", "macos", "esxi"]).optional().describe("Target platform filter"),
  },
  execute: async (args, ctx) => {
    const { binary, platform } = args as { binary: string; platform?: string };

    const results = ctx.knowledgeBase.search(binary, { platform });
    if (!results.length) {
      return text(`No entries found for "${binary}" in any catalog.`);
    }

    return json(results);
  },
};
```

### 2. Register the tool

Import and add the tool to the `allTools` array in `src/protocol/tools.ts`:

```typescript
import { myNewTool } from "../providers/myprovider/index.js";

// Add to the allTools array
export const allTools: ToolDef[] = [
  // ... existing tools
  myNewTool,
];
```

### 3. Test the tool

```bash
bun run src/index.ts --tool lol_my_new_tool '{"binary": "curl", "platform": "linux"}'
```

## Adding a New Catalog

1. Create a new directory under `src/catalogs/` named after the catalog (e.g., `src/catalogs/newcatalog/`).
2. Create an `index.ts` that exports a catalog parser implementing the `CatalogParser` interface:
   - `fetch()` -- download the catalog data from its source (GitHub raw YAML/JSON, API, etc.)
   - `parse()` -- parse the raw data into the catalog-specific format
   - `normalize()` -- convert to the unified `CatalogEntry` schema
3. Register the catalog in `src/catalogs/index.ts`.
4. Add the catalog to the loader in `src/utils/loader.ts` so it gets fetched on startup.
5. Add the catalog to the updater in `src/utils/updater.ts` for auto-refresh.
6. Update the knowledge base builder in `src/scripts/build-knowledge-base.ts`.
7. Update tool counts in the README and CHANGELOG if applicable.

## Guidelines

- **TypeScript strict mode** -- the project uses strict compiler settings. Fix all type errors before submitting.
- **Zod schemas** -- every tool input field must use Zod for validation with a `.describe()` call explaining the field.
- **Native `fetch()`** -- use the built-in `fetch()` for all HTTP API calls. Do not add HTTP client libraries.
- **Minimal dependencies** -- avoid adding new dependencies unless strictly necessary. The project uses only `@modelcontextprotocol/sdk`, `zod`, and `cheerio`.
- **Catalog normalization** -- all catalog data must be normalized to the unified `CatalogEntry` schema before being added to the knowledge base.
- **Conventional Commits** -- use the [Conventional Commits](https://www.conventionalcommits.org/) format for all commit messages:
  - `feat:` for new features, tools, or catalog integrations
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `refactor:` for code refactoring
  - `chore:` for build/tooling changes
- **ESM imports** -- always use `.js` extensions in import paths (TypeScript ESM requirement).
- **No console.log in tool output** -- tool results go through the `text()` or `json()` helpers only.
- **Graceful errors** -- if a catalog is unreachable or data is malformed, return a clear error message instead of throwing.

## Submitting a Pull Request

1. Fork the repository and create a feature branch from `main`.
2. Make your changes following the guidelines above.
3. Ensure the project builds cleanly: `bun run build`
4. Test your changes with the CLI: `bun run src/index.ts --tool <tool_name> '<json_args>'`
5. Commit using Conventional Commits format.
6. Open a pull request against `main` with a clear description of what you changed and why.

## Reporting Issues

- Use [GitHub Issues](https://github.com/badchars/living-off-the-land-lolbins-mcp-server/issues) for bug reports and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) -- do **not** open a public issue.
- Include reproduction steps, expected behavior, and your environment details (OS, Bun/Node version).
