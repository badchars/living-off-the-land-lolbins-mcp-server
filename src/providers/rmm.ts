import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

function deduplicateByBinary(entries: any[]): any[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    if (seen.has(e.id)) return false;
    seen.add(e.id);
    return true;
  });
}

function summarizeKbEntry(e: any): Record<string, unknown> {
  return {
    id: e.id, binary: e.binary, platform: e.platform, catalog: e.catalogSource,
    functions: e.functions, stealth_score: e.stealthScore, description: e.description,
    attck_techniques: e.attckTechniques,
    rmm_artifacts: e.rmmArtifacts ?? null,
  };
}

// ━━━ Hardcoded RMM Data ━━━

interface RmmEntry {
  name: string;
  description: string;
  silentInstall: string;
  persistencePaths: { disk: string[]; registry: string[] };
  networkArtifacts: { domains: string[]; ports: number[] };
  lateralCapability: string;
  detectionNotes: string;
}

const RMM_TOOLS: Record<string, RmmEntry> = {
  anydesk: {
    name: "AnyDesk",
    description: "Remote desktop tool frequently abused for persistent remote access",
    silentInstall: "anydesk.exe --install \"C:\\ProgramData\\AnyDesk\" --start-with-win --silent",
    persistencePaths: {
      disk: ["C:\\ProgramData\\AnyDesk\\", "C:\\Program Files (x86)\\AnyDesk\\"],
      registry: ["HKLM\\SOFTWARE\\AnyDesk", "HKCU\\SOFTWARE\\AnyDesk"],
    },
    networkArtifacts: { domains: ["*.net.anydesk.com"], ports: [7070, 443] },
    lateralCapability: "File transfer, clipboard sharing, remote shell, unattended access with password",
    detectionNotes: "Monitor for AnyDesk process, network connections to anydesk.com, service installation.",
  },
  teamviewer: {
    name: "TeamViewer",
    description: "Popular remote support tool abused for persistent access and lateral movement",
    silentInstall: "TeamViewer_Setup.exe /S",
    persistencePaths: {
      disk: ["C:\\Program Files\\TeamViewer\\", "C:\\Program Files (x86)\\TeamViewer\\"],
      registry: ["HKLM\\SOFTWARE\\TeamViewer", "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer"],
    },
    networkArtifacts: { domains: ["*.teamviewer.com", "router*.teamviewer.com"], ports: [5938, 443] },
    lateralCapability: "File transfer, remote control, VPN mode, unattended access",
    detectionNotes: "Monitor for TeamViewer service and process. Check for non-standard installation paths.",
  },
  screenconnect: {
    name: "ConnectWise ScreenConnect",
    description: "Remote support and access tool commonly used by threat actors for persistent backdoors",
    silentInstall: "ScreenConnect.ClientSetup.msi /quiet /norestart",
    persistencePaths: {
      disk: ["C:\\Program Files (x86)\\ScreenConnect Client*\\"],
      registry: ["HKLM\\SOFTWARE\\WOW6432Node\\ScreenConnect Client"],
    },
    networkArtifacts: { domains: ["*.screenconnect.com", "*.connectwise.com"], ports: [443, 8040, 8041] },
    lateralCapability: "Remote shell, file transfer, backstage mode, relay connections",
    detectionNotes: "Monitor for ScreenConnect processes and relay connections. High threat actor usage.",
  },
  meshagent: {
    name: "MeshAgent (MeshCentral)",
    description: "Open source remote management agent used by threat actors for covert access",
    silentInstall: "meshagent -install --msh=<MESH_CONFIG>",
    persistencePaths: {
      disk: ["/usr/local/mesh_services/", "C:\\Program Files\\Mesh Agent\\"],
      registry: ["HKLM\\SOFTWARE\\Mesh Agent"],
    },
    networkArtifacts: { domains: ["<custom_server>"], ports: [443, 4433] },
    lateralCapability: "Remote terminal, file transfer, remote desktop, plugin execution",
    detectionNotes: "Monitor for meshagent process. Open source so no fixed domain signature.",
  },
  rustdesk: {
    name: "RustDesk",
    description: "Open source remote desktop with self-hosted option, abused for stealthy access",
    silentInstall: "rustdesk --install-service --silent",
    persistencePaths: {
      disk: ["C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\RustDesk\\"],
      registry: ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\RustDesk"],
    },
    networkArtifacts: { domains: ["<custom_relay>", "rs-ny.rustdesk.com"], ports: [21116, 21117, 21118] },
    lateralCapability: "Remote desktop, file transfer, TCP tunneling",
    detectionNotes: "Monitor for RustDesk service and non-standard ports. Self-hosted makes domain detection harder.",
  },
};

// ━━━ Tools ━━━

const rmm_installed_check: ToolDef = {
  name: "rmm_installed_check",
  description: "Check if specific RMM tools are present in the LOLRMM catalog and find installation indicators",
  schema: {
    rmm_name: z.string().describe("RMM tool name to check (e.g. 'anydesk', 'teamviewer', 'screenconnect')"),
  },
  async execute(args: { rmm_name: string }, ctx: ToolContext): Promise<ToolResult> {
    const name = args.rmm_name.toLowerCase().trim();

    // Check hardcoded data
    const hardcoded = RMM_TOOLS[name];

    // Search LOLRMM catalog
    const rmmEntries = ctx.knowledgeBase.searchByCatalog("lolrmm");
    const matches = deduplicateByBinary(
      rmmEntries.filter(e =>
        e.binary.toLowerCase().includes(name) ||
        e.description.toLowerCase().includes(name),
      ),
    );

    // Also keyword search across all catalogs
    const kwResults = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(name));

    const seen = new Set(matches.map(e => e.id));
    for (const e of kwResults) {
      if (!seen.has(e.id) && e.category === "rmm") {
        seen.add(e.id);
        matches.push(e);
      }
    }

    return json({
      rmm_name: args.rmm_name,
      hardcoded_data: hardcoded ? {
        name: hardcoded.name,
        description: hardcoded.description,
        persistence_paths: hardcoded.persistencePaths,
        network_artifacts: hardcoded.networkArtifacts,
      } : null,
      kb_matches: matches.slice(0, 15).map(summarizeKbEntry),
      total_kb_matches: matches.length,
    });
  },
};

const rmm_persistence_paths: ToolDef = {
  name: "rmm_persistence_paths",
  description: "Find persistence paths (disk, registry) for RMM tools from LOLRMM catalog",
  schema: {
    rmm_name: z.string().optional().describe("Specific RMM tool name, or omit for all known RMM tools"),
  },
  async execute(args: { rmm_name?: string }, ctx: ToolContext): Promise<ToolResult> {
    if (args.rmm_name) {
      const name = args.rmm_name.toLowerCase().trim();
      const hardcoded = RMM_TOOLS[name];

      const rmmEntries = ctx.knowledgeBase.searchByCatalog("lolrmm")
        .filter(e => e.binary.toLowerCase().includes(name));

      return json({
        rmm_name: args.rmm_name,
        hardcoded_paths: hardcoded ? hardcoded.persistencePaths : null,
        kb_entries: rmmEntries.slice(0, 10).map(e => ({
          binary: e.binary,
          full_paths: e.fullPaths,
          rmm_artifacts: e.rmmArtifacts ?? null,
        })),
      });
    }

    // Return all known persistence paths
    const allPaths = Object.entries(RMM_TOOLS).map(([key, rmm]) => ({
      rmm_key: key,
      name: rmm.name,
      disk: rmm.persistencePaths.disk,
      registry: rmm.persistencePaths.registry,
    }));

    const rmmEntries = ctx.knowledgeBase.searchByCatalog("lolrmm");

    return json({
      total_hardcoded: allPaths.length,
      persistence_paths: allPaths,
      total_kb_rmm_entries: rmmEntries.length,
    });
  },
};

const rmm_detection_artifacts: ToolDef = {
  name: "rmm_detection_artifacts",
  description: "Get detection artifacts for RMM tools: disk, registry, network, and event log indicators",
  schema: {
    rmm_name: z.string().describe("RMM tool name to get detection artifacts for"),
    artifact_type: z.enum(["disk", "registry", "network", "eventlog", "all"]).default("all")
      .describe("Type of detection artifact to retrieve"),
  },
  async execute(args: { rmm_name: string; artifact_type?: string }, ctx: ToolContext): Promise<ToolResult> {
    const name = args.rmm_name.toLowerCase().trim();
    const artifactType = args.artifact_type || "all";
    const hardcoded = RMM_TOOLS[name];

    const rmmEntries = ctx.knowledgeBase.searchByCatalog("lolrmm")
      .filter(e => e.binary.toLowerCase().includes(name));

    const kbArtifacts = rmmEntries.map(e => ({
      binary: e.binary,
      rmm_artifacts: e.rmmArtifacts ?? null,
      detection: {
        edr_coverage: e.detection.edrCoverage,
        sigma_rules: e.detection.sigmaRules,
        log_sources: e.detection.logSources,
        iocs: e.detection.iocs,
      },
    }));

    const result: Record<string, unknown> = { rmm_name: args.rmm_name };

    if (hardcoded) {
      const artifacts: Record<string, unknown> = {};
      if (artifactType === "all" || artifactType === "disk") {
        artifacts.disk = hardcoded.persistencePaths.disk;
      }
      if (artifactType === "all" || artifactType === "registry") {
        artifacts.registry = hardcoded.persistencePaths.registry;
      }
      if (artifactType === "all" || artifactType === "network") {
        artifacts.network = hardcoded.networkArtifacts;
      }
      if (artifactType === "all" || artifactType === "eventlog") {
        artifacts.detection_notes = hardcoded.detectionNotes;
      }
      result.hardcoded_artifacts = artifacts;
    }

    result.kb_artifacts = kbArtifacts.slice(0, 10);
    result.total_kb_matches = kbArtifacts.length;

    return json(result);
  },
};

const rmm_lateral_pivot: ToolDef = {
  name: "rmm_lateral_pivot",
  description: "Find lateral movement capabilities provided by RMM tools (file transfer, remote shell, tunneling)",
  schema: {
    rmm_name: z.string().optional().describe("Specific RMM tool, or omit for all known RMM lateral capabilities"),
  },
  async execute(args: { rmm_name?: string }, ctx: ToolContext): Promise<ToolResult> {
    if (args.rmm_name) {
      const name = args.rmm_name.toLowerCase().trim();
      const hardcoded = RMM_TOOLS[name];

      const kbEntries = deduplicateByBinary(
        ctx.knowledgeBase.searchByKeyword(name).filter(e =>
          e.functions.includes("lateral_movement") || e.category === "rmm",
        ),
      );

      return json({
        rmm_name: args.rmm_name,
        lateral_capability: hardcoded ? hardcoded.lateralCapability : "No hardcoded data available",
        kb_lateral_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      });
    }

    const allLateral = Object.entries(RMM_TOOLS).map(([key, rmm]) => ({
      rmm_key: key,
      name: rmm.name,
      lateral_capability: rmm.lateralCapability,
    }));

    return json({
      total: allLateral.length,
      rmm_lateral_capabilities: allLateral,
    });
  },
};

const rmm_silent_install: ToolDef = {
  name: "rmm_silent_install",
  description: "Find silent/unattended installation methods for RMM tools from the LOLRMM catalog",
  schema: {
    rmm_name: z.string().optional().describe("Specific RMM tool, or omit for all known silent install commands"),
  },
  async execute(args: { rmm_name?: string }, ctx: ToolContext): Promise<ToolResult> {
    if (args.rmm_name) {
      const name = args.rmm_name.toLowerCase().trim();
      const hardcoded = RMM_TOOLS[name];

      const kbEntries = ctx.knowledgeBase.searchByCatalog("lolrmm")
        .filter(e => e.binary.toLowerCase().includes(name));

      return json({
        rmm_name: args.rmm_name,
        silent_install: hardcoded ? hardcoded.silentInstall : "No hardcoded silent install data available",
        description: hardcoded ? hardcoded.description : null,
        kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
      });
    }

    const allInstalls = Object.entries(RMM_TOOLS).map(([key, rmm]) => ({
      rmm_key: key,
      name: rmm.name,
      silent_install: rmm.silentInstall,
      description: rmm.description,
    }));

    return json({
      total: allInstalls.length,
      silent_install_methods: allInstalls,
    });
  },
};

export const rmmTools: ToolDef[] = [
  rmm_installed_check,
  rmm_persistence_paths,
  rmm_detection_artifacts,
  rmm_lateral_pivot,
  rmm_silent_install,
];
