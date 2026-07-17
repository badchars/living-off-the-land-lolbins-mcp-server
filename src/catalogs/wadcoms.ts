import { parse as parseYAML } from "yaml";
import type { UnifiedLOLEntry, LOLFunction, Platform, EntryCategory } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";

// ━━━ WADComs Attack Type → LOLFunction ━━━
const ATTACK_TYPE_MAP: Record<string, LOLFunction> = {
  "enumeration": "reconnaissance",
  "exploitation": "command_execution",
  "lateral movement": "lateral_movement",
  "persistence": "persistence",
  "credential access": "credential_access",
  "credential theft": "credential_access",
  "credential dumping": "credential_access",
  "privilege escalation": "privilege_escalation",
  "defense evasion": "defense_evasion",
  "execution": "command_execution",
  "discovery": "reconnaissance",
  "collection": "file_read",
  "exfiltration": "upload",
  "command and control": "c2",
};

// ━━━ Attack Type → ATT&CK ━━━
const ATTACK_ATTCK_MAP: Record<string, string> = {
  "enumeration": "T1087",
  "exploitation": "T1059",
  "lateral movement": "T1021",
  "persistence": "T1543",
  "credential access": "T1003",
  "credential theft": "T1003",
  "credential dumping": "T1003",
  "privilege escalation": "T1548",
  "defense evasion": "T1036",
  "execution": "T1059",
  "discovery": "T1082",
};

function detectPlatform(entry: any): Platform {
  const os = (entry.OS || entry.os || "").toLowerCase();
  if (os.includes("linux")) return "linux";
  if (os.includes("mac")) return "macos";
  return "windows";
}

function determineCategory(entry: any): EntryCategory {
  const items = entry.Items || entry.items || [];
  for (const item of items) {
    const itemLower = String(item).toLowerCase();
    if (itemLower.endsWith(".ps1") || itemLower.includes("powershell") || itemLower.includes("script")) {
      return "script";
    }
  }
  return "binary";
}

export function parseWADComsEntry(filename: string, content: string): UnifiedLOLEntry | null {
  // Extract YAML frontmatter
  const fmMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (!fmMatch) return null;

  let yaml: any;
  try {
    yaml = parseYAML(fmMatch[1]);
  } catch {
    return null;
  }

  if (!yaml) return null;

  const name = yaml.Name || yaml.name || filename.replace(/\.(md|yml|yaml)$/i, "");
  if (!name) return null;

  const description = yaml.Description || yaml.description || "";
  const command = yaml.Command || yaml.command || "";
  const attackTypes = yaml["Attack Type"] || yaml.attack_type || [];
  const items = yaml.Items || yaml.items || [];
  const services = yaml.Services || yaml.services || [];

  const funcsSet = new Set<LOLFunction>();
  const attckSet = new Set<string>();

  const types = Array.isArray(attackTypes) ? attackTypes : [attackTypes];
  for (const at of types) {
    const atLower = String(at).toLowerCase();
    const func = ATTACK_TYPE_MAP[atLower];
    if (func) funcsSet.add(func);
    const attck = ATTACK_ATTCK_MAP[atLower];
    if (attck) attckSet.add(attck);
  }

  if (funcsSet.size === 0) funcsSet.add("command_execution");

  const platform = detectPlatform(yaml);
  const category = determineCategory(yaml);

  const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];
  if (command) {
    contexts.push({
      context: "unprivileged",
      prerequisite: items.length > 0 ? `Requires: ${items.join(", ")}` : "",
      command,
      result: description || "WADComs attack technique",
      oneLiner: !command.includes("\n"),
    });
  }

  return {
    id: `wadcoms-${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
    binary: name,
    aliases: items.map(String).filter(Boolean),
    platform,
    catalogSource: "wadcoms",
    category,
    description,
    functions: Array.from(funcsSet),
    executionContexts: contexts,
    attckTechniques: Array.from(attckSet),
    detection: emptyDetection(),
    stealthScore: 3,
    stealthNotes: "AD attack technique — may trigger security monitoring",
    fullPaths: [],
    resources: [
      `https://wadcoms.github.io/wadcoms/${encodeURIComponent(name)}/`,
      ...services.map((s: any) => String(s)),
    ].filter(Boolean),
    relatedEntries: [],
    chainPotential: funcsSet.has("credential_access")
      ? [`${name} credentials can enable lateral movement`]
      : [],
  };
}

export function parseWADComsEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const item of data) {
    if (!item) continue;
    const name = item.Name || item.name;
    if (!name) continue;

    const description = item.Description || item.description || "";
    const command = item.Command || item.command || "";
    const attackTypes = item["Attack Type"] || item.attack_type || [];
    const items = item.Items || item.items || [];
    const services = item.Services || item.services || [];

    const funcsSet = new Set<LOLFunction>();
    const attckSet = new Set<string>();

    const types = Array.isArray(attackTypes) ? attackTypes : [attackTypes];
    for (const at of types) {
      const atLower = String(at).toLowerCase();
      const func = ATTACK_TYPE_MAP[atLower];
      if (func) funcsSet.add(func);
      const attck = ATTACK_ATTCK_MAP[atLower];
      if (attck) attckSet.add(attck);
    }

    if (funcsSet.size === 0) funcsSet.add("command_execution");

    const platform = detectPlatform(item);
    const category = determineCategory(item);

    const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];
    if (command) {
      contexts.push({
        context: "unprivileged",
        prerequisite: items.length > 0 ? `Requires: ${items.join(", ")}` : "",
        command,
        result: description || "WADComs attack technique",
        oneLiner: !command.includes("\n"),
      });
    }

    entries.push({
      id: `wadcoms-${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
      binary: name,
      aliases: items.map(String).filter(Boolean),
      platform,
      catalogSource: "wadcoms",
      category,
      description,
      functions: Array.from(funcsSet),
      executionContexts: contexts,
      attckTechniques: Array.from(attckSet),
      detection: emptyDetection(),
      stealthScore: 3,
      stealthNotes: "AD attack technique — may trigger security monitoring",
      fullPaths: [],
      resources: [
        `https://wadcoms.github.io/wadcoms/${encodeURIComponent(name)}/`,
        ...services.map((s: any) => String(s)),
      ].filter(Boolean),
      relatedEntries: [],
      chainPotential: funcsSet.has("credential_access")
        ? [`${name} credentials can enable lateral movement`]
        : [],
    });
  }

  return entries;
}
