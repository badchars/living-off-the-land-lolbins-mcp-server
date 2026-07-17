import type { UnifiedLOLEntry, LOLFunction } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";

// ━━━ ATT&CK ID → LOLFunction ━━━
const ATTCK_FUNC_MAP: Record<string, LOLFunction> = {
  "T1059": "command_execution",
  "T1053": "persistence",
  "T1070": "defense_evasion",
  "T1082": "reconnaissance",
  "T1083": "file_read",
  "T1105": "download",
  "T1562": "edr_disable",
  "T1543": "persistence",
  "T1548": "privilege_escalation",
  "T1005": "file_read",
  "T1036": "defense_evasion",
  "T1047": "command_execution",
  "T1222": "file_write",
  "T1490": "command_execution",
  "T1529": "command_execution",
};

function mapAttckToFunctions(attckIds: string[]): LOLFunction[] {
  const funcs = new Set<LOLFunction>();
  for (const id of attckIds) {
    // Try exact match first, then base technique
    const func = ATTCK_FUNC_MAP[id] || ATTCK_FUNC_MAP[id.split(".")[0]];
    if (func) funcs.add(func);
  }
  if (funcs.size === 0) funcs.add("command_execution");
  return Array.from(funcs);
}

export function parseLOLESXiEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const esxiEntry of data) {
    if (!esxiEntry) continue;
    const name = esxiEntry.Name || esxiEntry.name;
    if (!name) continue;

    const description = esxiEntry.Description || esxiEntry.description || "";
    const attckRaw = esxiEntry["ATT&CK IDs"] || esxiEntry.attck_ids || esxiEntry.attck || [];
    const attckIds: string[] = Array.isArray(attckRaw)
      ? attckRaw.filter(Boolean).map(String)
      : typeof attckRaw === "string"
        ? attckRaw.split(",").map((s: string) => s.trim()).filter(Boolean)
        : [];

    const functions = mapAttckToFunctions(attckIds);

    const commands = esxiEntry.Commands || esxiEntry.commands || [];
    const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];

    if (Array.isArray(commands)) {
      for (const cmd of commands) {
        if (!cmd) continue;
        const command = typeof cmd === "string" ? cmd : (cmd.Command || cmd.command || "");
        const desc = typeof cmd === "string" ? "" : (cmd.Description || cmd.description || "");
        if (!command) continue;
        contexts.push({
          context: "admin",
          prerequisite: "ESXi shell or SSH access",
          command,
          result: desc || "ESXi command execution",
          oneLiner: !command.includes("\n"),
        });
      }
    }

    if (contexts.length === 0) {
      contexts.push({
        context: "admin",
        prerequisite: "ESXi shell or SSH access",
        command: name,
        result: description || "ESXi binary execution",
        oneLiner: true,
      });
    }

    const entry: UnifiedLOLEntry = {
      id: `lolesxi-${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
      binary: name,
      aliases: [],
      platform: "esxi",
      catalogSource: "lolesxi",
      category: "binary",
      description,
      functions,
      executionContexts: contexts,
      attckTechniques: attckIds,
      detection: emptyDetection(),
      stealthScore: 2,
      stealthNotes: "ESXi native binary — rarely monitored by EDR",
      fullPaths: [`/bin/${name}`, `/sbin/${name}`],
      resources: [`https://lolesxi-project.github.io/LOLESXi/binaries/${name}/`],
      relatedEntries: [],
      chainPotential: functions.includes("command_execution")
        ? [`${name} can execute commands on ESXi host`]
        : [],
    };

    entries.push(entry);
  }

  return entries;
}
