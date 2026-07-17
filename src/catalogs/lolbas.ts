import type {
  UnifiedLOLEntry, LOLFunction, ContextType, EntryCategory,
} from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";
import type { DetectionInfo } from "../schema/unified-entry.js";
import { normalizeBinaryName } from "../utils/normalize.js";

// ━━━ LOLBAS Category → LOLFunction ━━━
const CATEGORY_MAP: Record<string, LOLFunction> = {
  "Execute": "command_execution",
  "Download": "download",
  "Upload": "upload",
  "ADS": "ads",
  "AWL Bypass": "awl_bypass",
  "Copy": "copy",
  "Credentials": "credential_access",
  "Compile": "compile",
  "Decode": "encode_decode",
  "Encode": "encode_decode",
  "Dump": "dump",
  "Tamper": "tamper",
  "Conceal": "conceal",
  "UAC Bypass": "uac_bypass",
  "Reconnaissance": "reconnaissance",
};

// ━━━ LOLBAS Privileges → ContextType ━━━
const PRIVILEGE_MAP: Record<string, ContextType> = {
  "User": "user",
  "Administrator": "admin",
  "Admin": "admin",
  "Local Admin": "admin",
  "System": "system",
  "DNS admin": "admin",
  "SYSTEM": "system",
};

// ━━━ Stealth score heuristics ━━━
function computeStealthScore(entry: any, detection: DetectionInfo): number {
  if (detection.blockRules.length > 0) return 5;
  if (detection.sigmaRules.length >= 3) return 4;
  if (detection.sigmaRules.length >= 1) return 3;

  const name = (entry.Name || "").toLowerCase();
  const wellKnown = ["mshta", "regsvr32", "rundll32", "certutil", "bitsadmin", "wmic"];
  if (wellKnown.some(w => name.includes(w))) return 4;

  const dotNetTools = ["csc", "installutil", "regsvcs", "regasm", "msbuild"];
  if (dotNetTools.some(t => name.includes(t))) return 3;

  if (detection.sigmaRules.length === 0 && detection.iocs.length === 0) return 2;

  return 3;
}

function determineLOLBASCategory(entry: any): EntryCategory {
  const paths = entry.Full_Path?.map((p: any) => (p.Path || "").toLowerCase()) || [];
  const name = (entry.Name || "").toLowerCase();

  if (name.endsWith(".dll")) return "library";
  if (name.endsWith(".ps1") || name.endsWith(".vbs") || name.endsWith(".js")) return "script";
  if (paths.some((p: string) => p.includes("\\drivers\\"))) return "driver";
  return "binary";
}

function parseDetection(detections: any[]): DetectionInfo {
  const det = emptyDetection();
  if (!Array.isArray(detections)) return det;

  for (const d of detections) {
    if (!d || typeof d !== "object") continue;
    const keys = Object.keys(d);
    for (const key of keys) {
      const value = d[key];
      if (!value || typeof value !== "string") continue;

      switch (key) {
        case "Sigma": det.sigmaRules.push(value); break;
        case "Elastic": det.elasticRules.push(value); break;
        case "Splunk": det.splunkRules.push(value); break;
        case "BlockRule": det.blockRules.push(value); break;
        case "IOC": det.iocs.push(value); break;
      }
    }
  }

  // Determine EDR coverage level
  const totalRules = det.sigmaRules.length + det.elasticRules.length + det.splunkRules.length;
  if (totalRules >= 3) det.edrCoverage = "high";
  else if (totalRules >= 1) det.edrCoverage = "medium";
  else if (det.blockRules.length > 0) det.edrCoverage = "medium";
  else det.edrCoverage = "none";

  return det;
}

export function parseLOLBASEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const lolbasEntry of data) {
    if (!lolbasEntry || !lolbasEntry.Name) continue;

    const functionsSet = new Set<LOLFunction>();
    const attckSet = new Set<string>();
    const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];

    const commands = lolbasEntry.Commands || [];
    for (const cmd of commands) {
      if (!cmd) continue;
      const func = CATEGORY_MAP[cmd.Category];
      if (func) functionsSet.add(func);

      if (cmd.MitreID) {
        const ids = cmd.MitreID.split(",").map((s: string) => s.trim()).filter(Boolean);
        for (const id of ids) attckSet.add(id);
      }

      const privilege = cmd.Privileges || "User";
      const contextType = PRIVILEGE_MAP[privilege] || "user";

      contexts.push({
        context: contextType,
        prerequisite: `${privilege} privileges required`,
        command: cmd.Command || "",
        result: cmd.Description || "",
        oneLiner: !(cmd.Command || "").includes("\n"),
        operatingSystem: cmd.OperatingSystem || undefined,
      });
    }

    if (functionsSet.size === 0) continue;

    const detection = parseDetection(lolbasEntry.Detection || []);
    const stealthScore = computeStealthScore(lolbasEntry, detection);
    const binaryBase = normalizeBinaryName(lolbasEntry.Name);

    const entry: UnifiedLOLEntry = {
      id: `lolbas-${binaryBase}`,
      binary: lolbasEntry.Name,
      aliases: [binaryBase],
      platform: "windows",
      catalogSource: "lolbas",
      category: determineLOLBASCategory(lolbasEntry),
      description: lolbasEntry.Description || "",
      functions: [...functionsSet],
      executionContexts: contexts,
      attckTechniques: [...attckSet],
      detection,
      stealthScore,
      stealthNotes: `LOLBAS Windows binary`,
      fullPaths: (lolbasEntry.Full_Path || []).map((p: any) => p.Path).filter(Boolean),
      resources: (lolbasEntry.Resources || []).map((r: any) => r.Link).filter(Boolean),
      relatedEntries: [],
      chainPotential: [],
    };

    entries.push(entry);
  }

  return entries;
}
