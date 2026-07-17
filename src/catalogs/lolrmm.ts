import type { UnifiedLOLEntry, LOLFunction } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";

// ━━━ RMM Capability → LOLFunction ━━━
const CAPABILITY_MAP: Record<string, LOLFunction> = {
  "remote access": "lateral_movement",
  "remote control": "lateral_movement",
  "remote desktop": "lateral_movement",
  "remote shell": "shell",
  "remote terminal": "shell",
  "file transfer": "download",
  "file management": "file_write",
  "file browsing": "file_read",
  "command execution": "command_execution",
  "command line": "command_execution",
  "script execution": "command_execution",
  "scripting": "command_execution",
  "powershell": "command_execution",
  "screen sharing": "reconnaissance",
  "screen capture": "reconnaissance",
  "monitoring": "reconnaissance",
  "inventory": "reconnaissance",
  "persistence": "persistence",
  "service management": "persistence",
  "registry": "persistence",
  "deployment": "download",
  "patch management": "download",
  "software deployment": "download",
  "credential": "credential_access",
  "authentication": "credential_access",
  "tunneling": "c2",
  "vpn": "c2",
  "proxy": "c2",
};

function mapCapabilities(capabilities: any[]): LOLFunction[] {
  if (!Array.isArray(capabilities)) return ["lateral_movement"];
  const funcs = new Set<LOLFunction>();
  for (const cap of capabilities) {
    const capLower = (typeof cap === "string" ? cap : String(cap)).toLowerCase();
    for (const [keyword, func] of Object.entries(CAPABILITY_MAP)) {
      if (capLower.includes(keyword)) {
        funcs.add(func);
      }
    }
  }
  if (funcs.size === 0) funcs.add("lateral_movement");
  return Array.from(funcs);
}

interface RMMArtifacts {
  disk: string[];
  registry: string[];
  network: { domains: string[]; ports: number[] };
  eventLog: string[];
}

function parseArtifacts(entry: any): RMMArtifacts {
  const artifacts = entry.Artifacts || entry.artifacts || {};
  return {
    disk: Array.isArray(artifacts.disk) ? artifacts.disk.filter(Boolean) : [],
    registry: Array.isArray(artifacts.registry) ? artifacts.registry.filter(Boolean) : [],
    network: {
      domains: Array.isArray(artifacts.network?.domains) ? artifacts.network.domains.filter(Boolean) : [],
      ports: Array.isArray(artifacts.network?.ports)
        ? artifacts.network.ports.map(Number).filter((n: number) => !isNaN(n))
        : [],
    },
    eventLog: Array.isArray(artifacts.eventlog || artifacts.eventLog)
      ? (artifacts.eventlog || artifacts.eventLog).filter(Boolean)
      : [],
  };
}

export function parseLOLRMMEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const rmmEntry of data) {
    if (!rmmEntry) continue;
    const name = rmmEntry.Name || rmmEntry.name;
    if (!name) continue;

    const capabilities = rmmEntry.Capabilities || rmmEntry.capabilities || [];
    const functions = mapCapabilities(capabilities);
    const rmmArtifacts = parseArtifacts(rmmEntry);
    const detection = emptyDetection();

    // Build IOCs from artifacts
    if (rmmArtifacts.network.domains.length > 0) {
      detection.iocs.push(...rmmArtifacts.network.domains);
    }
    if (rmmArtifacts.eventLog.length > 0) {
      detection.logSources.push(...rmmArtifacts.eventLog);
    }
    if (rmmArtifacts.disk.length > 0 || rmmArtifacts.registry.length > 0) {
      detection.edrCoverage = "medium";
    }

    const description = rmmEntry.Description || rmmEntry.description || "";
    const website = rmmEntry.Website || rmmEntry.website || "";

    const entry: UnifiedLOLEntry = {
      id: `lolrmm-${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
      binary: name,
      aliases: [],
      platform: "windows",
      catalogSource: "lolrmm",
      category: "rmm",
      description: description || `${name} remote management tool`,
      functions,
      executionContexts: [{
        context: "user",
        prerequisite: `${name} installed on target`,
        command: "",
        result: "Remote management access",
        oneLiner: true,
      }],
      attckTechniques: ["T1219"],
      detection,
      stealthScore: 2,
      stealthNotes: "Legitimate RMM tool — often allowed by security policies",
      fullPaths: rmmArtifacts.disk.filter(p => p.endsWith(".exe") || p.endsWith(".dll")),
      resources: website ? [website] : [],
      relatedEntries: [],
      chainPotential: [
        `${name} can be abused for persistent remote access`,
        `${name} can transfer tools to target`,
      ],
      rmmArtifacts,
    };

    entries.push(entry);
  }

  return entries;
}
