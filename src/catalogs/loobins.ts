import type { UnifiedLOLEntry, LOLFunction } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";

// ━━━ LOOBins Tactic → LOLFunction ━━━
const TACTIC_MAP: Record<string, LOLFunction> = {
  "Execution": "command_execution",
  "Defense Evasion": "defense_evasion",
  "Persistence": "persistence",
  "Privilege Escalation": "privilege_escalation",
  "Credential Access": "credential_access",
  "Discovery": "reconnaissance",
  "Collection": "file_read",
  "Lateral Movement": "lateral_movement",
  "Exfiltration": "upload",
  "Command and Control": "c2",
  "Impact": "command_execution",
  "Initial Access": "download",
};

// ━━━ Tactic → ATT&CK ━━━
const TACTIC_ATTCK_MAP: Record<string, string> = {
  "Execution": "T1059",
  "Defense Evasion": "T1036",
  "Persistence": "T1543",
  "Privilege Escalation": "T1548",
  "Credential Access": "T1552",
  "Discovery": "T1082",
  "Collection": "T1005",
  "Lateral Movement": "T1021",
  "Exfiltration": "T1048",
  "Command and Control": "T1071",
  "Impact": "T1485",
  "Initial Access": "T1105",
};

export function parseLOOBinsEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const loobinEntry of data) {
    if (!loobinEntry || !loobinEntry.name) continue;

    const functionsSet = new Set<LOLFunction>();
    const attckSet = new Set<string>();
    const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];
    const allTactics: string[] = [];

    const useCases = loobinEntry.example_use_cases || [];
    for (const useCase of useCases) {
      const tactics = useCase.tactics || [];
      for (const tactic of tactics) {
        const func = TACTIC_MAP[tactic];
        if (func) functionsSet.add(func);
        const attck = TACTIC_ATTCK_MAP[tactic];
        if (attck) attckSet.add(attck);
        allTactics.push(tactic);
      }

      contexts.push({
        context: "unprivileged" as const,
        prerequisite: "",
        command: useCase.code || "",
        result: useCase.description || "",
        oneLiner: !(useCase.code || "").includes("\n"),
      });
    }

    if (functionsSet.size === 0) continue;

    const detection = emptyDetection();
    const detections = loobinEntry.detections || [];
    for (const det of detections) {
      if (det && det.name) {
        detection.logSources.push(det.name);
      }
    }

    const entry: UnifiedLOLEntry = {
      id: `loobins-${loobinEntry.name.toLowerCase().replace(/\s+/g, "_")}`,
      binary: loobinEntry.name,
      aliases: [],
      platform: "macos",
      catalogSource: "loobins",
      category: "binary",
      description: loobinEntry.short_description || loobinEntry.description || "",
      functions: [...functionsSet],
      executionContexts: contexts,
      attckTechniques: [...attckSet],
      detection,
      stealthScore: 2, // macOS binaries are generally less monitored
      stealthNotes: "macOS native binary",
      fullPaths: (loobinEntry.paths || []).filter(Boolean),
      resources: (loobinEntry.resources || []).map((r: any) => r.url || r.link || r).filter(Boolean),
      relatedEntries: [],
      chainPotential: [],
      tactics: allTactics,
    };

    entries.push(entry);
  }

  return entries;
}
