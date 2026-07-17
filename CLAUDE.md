# living-off-the-land-lolbins-mcp — LOL Binary Intelligence MCP Server

## Overview
59 composite tools (290 techniques) MCP server for Living off the Land binary intelligence: GTFOBins, LOLBAS, LOOBins, LOLDrivers, LOLRMM, LOLESXi, LOTP, LOLC2, LOFLCAB, WADComs catalogs with attack graph reasoning, privilege escalation paths, defense evasion, detection engineering, threat actor mapping, and purple team planning.

## Architecture
- **Runtime:** Bun 1.3.9+ (dev), Node.js (publish)
- **Dependencies:** @modelcontextprotocol/sdk, yaml, zod
- **Transport:** stdio only
- **Pattern:** 59 composite tools in src/composite/ orchestrate 290 individual techniques from providers under src/providers/

## Key Rules
- TypeScript strict mode, English code/comments
- Native `fetch()` for all HTTP APIs
- Every tool schema field must have `.describe()`
- API keys always optional — graceful error when missing
- Rate limiter + TTL cache per provider
- Import paths use `.js` extension (ESM)

## Catalogs (10)
gtfobins (478), lolbas (117), loobins (62), loldrivers (660), lolrmm (317), lolesxi (19), lotp (60), lolc2 (55), loflcab (394), wadcoms (100)

## Commands
```bash
bun install          # Install deps
bun run dev          # Dev mode (watch)
bun run build        # Build for npm
bun run snapshot     # Fetch catalog data → data/
bun run src/index.ts --help       # CLI help
bun run src/index.ts --list       # 59 composite tools
bun run src/index.ts --list-all   # 290 individual techniques
bun run src/index.ts --tool <name> '<json>'  # Run tool (composite or individual)
```
