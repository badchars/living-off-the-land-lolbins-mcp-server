import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

function deduplicateByBinary(entries: UnifiedLOLEntry[]): UnifiedLOLEntry[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    const key = `${e.binary}-${e.platform}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function getEntries(args: { session_id?: string }, ctx: ToolContext): UnifiedLOLEntry[] | null {
  if (args.session_id) {
    const session = ctx.sessions.get(args.session_id);
    if (!session) return null;
    return session.matchedEntries.map(m => m.entry);
  }
  return ctx.knowledgeBase.allEntries;
}

function buildGraph(entries: UnifiedLOLEntry[], pathType?: string): { nodes: Map<string, { type: string; label: string }>; edges: Array<{ from: string; to: string; label: string }> } {
  const nodes = new Map<string, { type: string; label: string }>();
  const edges: Array<{ from: string; to: string; label: string }> = [];

  const functionFilter = new Set<string>();
  if (pathType === "escalation") {
    functionFilter.add("privilege_escalation");
    functionFilter.add("uac_bypass");
    functionFilter.add("inherit");
  } else if (pathType === "persistence") {
    functionFilter.add("persistence");
    functionFilter.add("library_load");
  } else if (pathType === "lateral") {
    functionFilter.add("lateral_movement");
    functionFilter.add("command_execution");
    functionFilter.add("shell");
  }

  const deduplicated = deduplicateByBinary(entries);
  const filtered = pathType && pathType !== "full"
    ? deduplicated.filter(e => e.functions.some(f => functionFilter.has(f)))
    : deduplicated.slice(0, 50);

  for (const e of filtered) {
    const binaryId = `bin_${e.binary}`;
    nodes.set(binaryId, { type: "binary", label: e.binary });

    for (const fn of e.functions) {
      if (pathType && pathType !== "full" && !functionFilter.has(fn)) continue;
      const fnId = `fn_${fn}`;
      if (!nodes.has(fnId)) {
        nodes.set(fnId, { type: "function", label: fn });
      }
      edges.push({ from: binaryId, to: fnId, label: "provides" });
    }

    for (const t of e.attckTechniques) {
      const tId = `attck_${t}`;
      if (!nodes.has(tId)) {
        nodes.set(tId, { type: "technique", label: t });
      }
      edges.push({ from: binaryId, to: tId, label: "maps_to" });
    }
  }

  return { nodes, edges };
}

// ━━━ Tools ━━━

const viz_mermaid_diagram: ToolDef = {
  name: "viz_mermaid_diagram",
  description: "Generate a Mermaid flowchart diagram showing attack paths via LOL binaries. Visualizes binary-to-function-to-technique relationships.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to visualize"),
    path_type: z.enum(["escalation", "persistence", "lateral", "full"]).optional().describe("Type of attack path to visualize (default: full)"),
  },
  async execute(args: { session_id?: string; path_type?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const { nodes, edges } = buildGraph(entries, args.path_type);
    const lines: string[] = [];
    lines.push("flowchart LR");

    for (const [id, node] of nodes) {
      if (node.type === "binary") {
        lines.push(`  ${id}[["${node.label}"]]`);
      } else if (node.type === "function") {
        lines.push(`  ${id}("${node.label}")`);
      } else {
        lines.push(`  ${id}{{"${node.label}"}}`);
      }
    }

    for (const edge of edges) {
      lines.push(`  ${edge.from} -->|${edge.label}| ${edge.to}`);
    }

    lines.push("");
    lines.push("  classDef binary fill:#e74c3c,stroke:#c0392b,color:#fff");
    lines.push("  classDef function fill:#f39c12,stroke:#d68910,color:#fff");
    lines.push("  classDef technique fill:#3498db,stroke:#2980b9,color:#fff");

    const binaryNodes = Array.from(nodes.entries()).filter(([, n]) => n.type === "binary").map(([id]) => id);
    const fnNodes = Array.from(nodes.entries()).filter(([, n]) => n.type === "function").map(([id]) => id);
    const techNodes = Array.from(nodes.entries()).filter(([, n]) => n.type === "technique").map(([id]) => id);

    if (binaryNodes.length > 0) lines.push(`  class ${binaryNodes.join(",")} binary`);
    if (fnNodes.length > 0) lines.push(`  class ${fnNodes.join(",")} function`);
    if (techNodes.length > 0) lines.push(`  class ${techNodes.join(",")} technique`);

    return text(lines.join("\n"));
  },
};

const viz_graphviz_dot: ToolDef = {
  name: "viz_graphviz_dot",
  description: "Generate Graphviz DOT language representation of the attack graph. Can be rendered with dot, neato, or circo layout engines.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to visualize"),
    layout: z.enum(["dot", "neato", "circo"]).optional().describe("Graphviz layout engine to use (default: dot)"),
  },
  async execute(args: { session_id?: string; layout?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const layout = args.layout || "dot";
    const { nodes, edges } = buildGraph(entries);
    const lines: string[] = [];

    lines.push(`digraph LOLAttackGraph {`);
    lines.push(`  layout="${layout}";`);
    lines.push(`  rankdir=LR;`);
    lines.push(`  node [fontname="Helvetica", fontsize=10];`);
    lines.push(`  edge [fontname="Helvetica", fontsize=8];`);
    lines.push(``);
    lines.push(`  // Binary nodes`);
    lines.push(`  node [shape=box, style=filled, fillcolor="#e74c3c", fontcolor=white];`);
    for (const [id, node] of nodes) {
      if (node.type === "binary") {
        lines.push(`  "${id}" [label="${node.label}"];`);
      }
    }
    lines.push(``);
    lines.push(`  // Function nodes`);
    lines.push(`  node [shape=ellipse, style=filled, fillcolor="#f39c12", fontcolor=white];`);
    for (const [id, node] of nodes) {
      if (node.type === "function") {
        lines.push(`  "${id}" [label="${node.label}"];`);
      }
    }
    lines.push(``);
    lines.push(`  // Technique nodes`);
    lines.push(`  node [shape=diamond, style=filled, fillcolor="#3498db", fontcolor=white];`);
    for (const [id, node] of nodes) {
      if (node.type === "technique") {
        lines.push(`  "${id}" [label="${node.label}"];`);
      }
    }
    lines.push(``);
    lines.push(`  // Edges`);
    for (const edge of edges) {
      lines.push(`  "${edge.from}" -> "${edge.to}" [label="${edge.label}"];`);
    }
    lines.push(`}`);

    return text(lines.join("\n"));
  },
};

const viz_ascii_tree: ToolDef = {
  name: "viz_ascii_tree",
  description: "Generate an ASCII tree representation of attack chains. Shows hierarchical relationship between binaries, functions, and techniques.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to visualize"),
    max_depth: z.number().optional().describe("Maximum tree depth to render (default: 3)"),
  },
  async execute(args: { session_id?: string; max_depth?: number }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const maxDepth = args.max_depth || 3;
    const deduplicated = deduplicateByBinary(entries)
      .sort((a, b) => b.stealthScore - a.stealthScore)
      .slice(0, 20);

    const lines: string[] = [];
    lines.push("LOL Attack Chains");
    lines.push("=================");

    for (let i = 0; i < deduplicated.length; i++) {
      const e = deduplicated[i];
      const isLast = i === deduplicated.length - 1;
      const prefix = isLast ? "\\-- " : "|-- ";
      const childPrefix = isLast ? "    " : "|   ";

      lines.push(`${prefix}[${e.binary}] (stealth: ${e.stealthScore}/5, platform: ${e.platform})`);

      if (maxDepth >= 2) {
        const functions = e.functions;
        for (let j = 0; j < functions.length; j++) {
          const fnIsLast = j === functions.length - 1 && (maxDepth < 3 || e.attckTechniques.length === 0);
          const fnPrefix = fnIsLast ? "\\-- " : "|-- ";
          lines.push(`${childPrefix}${fnPrefix}fn: ${functions[j]}`);
        }

        if (maxDepth >= 3) {
          const techniques = e.attckTechniques;
          for (let k = 0; k < techniques.length; k++) {
            const tIsLast = k === techniques.length - 1;
            const tPrefix = tIsLast ? "\\-- " : "|-- ";
            lines.push(`${childPrefix}${tPrefix}attck: ${techniques[k]}`);
          }
        }
      }
    }

    return text(lines.join("\n"));
  },
};

const viz_json_graph: ToolDef = {
  name: "viz_json_graph",
  description: "Generate JSON graph data with nodes and edges for custom visualization tools. Compatible with D3.js, Cytoscape.js, and similar libraries.",
  schema: {
    session_id: z.string().optional().describe("Environment session ID to visualize"),
    include_metadata: z.boolean().optional().describe("Include extended metadata on nodes and edges (default: false)"),
  },
  async execute(args: { session_id?: string; include_metadata?: boolean }, ctx: ToolContext): Promise<ToolResult> {
    const entries = getEntries(args, ctx);
    if (entries === null) return text(`Session not found: ${args.session_id}`);

    const includeMetadata = args.include_metadata || false;
    const { nodes, edges } = buildGraph(entries);

    const graphNodes = Array.from(nodes.entries()).map(([id, node]) => {
      const base: Record<string, unknown> = {
        id,
        label: node.label,
        type: node.type,
      };
      if (includeMetadata && node.type === "binary") {
        const entry = entries.find(e => e.binary === node.label);
        if (entry) {
          base.platform = entry.platform;
          base.stealthScore = entry.stealthScore;
          base.catalog = entry.catalogSource;
          base.edrCoverage = entry.detection.edrCoverage;
        }
      }
      return base;
    });

    const graphEdges = edges.map((edge, idx) => {
      const base: Record<string, unknown> = {
        id: `edge_${idx}`,
        source: edge.from,
        target: edge.to,
        label: edge.label,
      };
      return base;
    });

    return json({
      graph: {
        directed: true,
        nodes: graphNodes,
        edges: graphEdges,
        metadata: {
          totalNodes: graphNodes.length,
          totalEdges: graphEdges.length,
          nodeTypes: {
            binaries: graphNodes.filter(n => n.type === "binary").length,
            functions: graphNodes.filter(n => n.type === "function").length,
            techniques: graphNodes.filter(n => n.type === "technique").length,
          },
        },
      },
    });
  },
};

export const visualizeTools: ToolDef[] = [
  viz_mermaid_diagram,
  viz_graphviz_dot,
  viz_ascii_tree,
  viz_json_graph,
];
