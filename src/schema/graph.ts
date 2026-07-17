import type { CatalogSource } from "./unified-entry.js";
import type { DetectionInfo } from "./unified-entry.js";

export type NodeType = "CurrentUser" | "TargetPrivilege" | "Binary" | "Configuration"
  | "Service" | "File" | "Network" | "Driver";

export type EdgeType = "CanEscalateVia" | "CanSpawnShell" | "CanReadFile" | "CanWriteFile"
  | "CanDownload" | "CanUpload" | "CanExecuteAs" | "EnablesPersistence"
  | "CanReach" | "CanLoadDriver" | "CanDisableEDR" | "CanChainTo";

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  type: EdgeType;
  from: string;
  to: string;
  entryId: string;
  command: string;
  stealthScore: number;
  certainty: number;
  attckTechniques: string[];
}

export interface AttackGraph {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  adjacency: Map<string, GraphEdge[]>;
}

export interface PathStep {
  action: string;
  binary: string;
  sourceCatalog: CatalogSource;
  sourceEntryId: string;
  result: string;
  attck: string[];
  stealthScore: number;
  detection: DetectionInfo;
}

export interface AttackPath {
  rank: number;
  name: string;
  steps: PathStep[];
  totalStealth: number;
  certainty: number;
  impact: number;
  score: number;
  chainReasoning: string;
  isChain: boolean;
}

export function createEmptyGraph(): AttackGraph {
  return {
    nodes: new Map(),
    edges: [],
    adjacency: new Map(),
  };
}

export function addNode(graph: AttackGraph, id: string, type: NodeType, label: string, metadata: Record<string, unknown> = {}): void {
  if (!graph.nodes.has(id)) {
    graph.nodes.set(id, { id, type, label, metadata });
    graph.adjacency.set(id, []);
  }
}

export function addEdge(graph: AttackGraph, edge: Omit<GraphEdge, "id">): void {
  const id = `edge-${graph.edges.length}`;
  const fullEdge: GraphEdge = { ...edge, id };
  graph.edges.push(fullEdge);
  const adj = graph.adjacency.get(edge.from);
  if (adj) adj.push(fullEdge);
  else graph.adjacency.set(edge.from, [fullEdge]);
}
