import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Known Attack Sequences ━━━

interface AttackPhase {
  name: string;
  attckTactic: string;
  typicalBinaries: string[];
  description: string;
}

interface AttackSequence {
  name: string;
  description: string;
  phases: AttackPhase[];
  attckIds: string[];
  commonActors: string[];
}

const ATTACK_SEQUENCES: AttackSequence[] = [
  {
    name: "Macro Dropper Chain",
    description: "Office macro drops and executes payload via scripting host and PowerShell",
    phases: [
      { name: "Initial Access", attckTactic: "TA0001", typicalBinaries: ["winword.exe", "excel.exe"], description: "User opens malicious Office document with macro" },
      { name: "Execution", attckTactic: "TA0002", typicalBinaries: ["cmd.exe", "wscript.exe", "cscript.exe"], description: "Macro launches scripting host or cmd" },
      { name: "Download", attckTactic: "TA0011", typicalBinaries: ["powershell.exe", "certutil.exe", "bitsadmin.exe"], description: "Download second-stage payload from C2" },
      { name: "Persistence", attckTactic: "TA0003", typicalBinaries: ["reg.exe", "schtasks.exe"], description: "Establish persistence via registry or scheduled task" },
    ],
    attckIds: ["T1204.002", "T1059.003", "T1059.005", "T1059.001", "T1105", "T1547.001", "T1053.005"],
    commonActors: ["FIN7", "APT28", "Lazarus"],
  },
  {
    name: "AWL Bypass to Beacon",
    description: "Application whitelisting bypass followed by C2 beacon deployment",
    phases: [
      { name: "AWL Bypass", attckTactic: "TA0005", typicalBinaries: ["regsvr32.exe", "mshta.exe", "cmstp.exe"], description: "Bypass application whitelisting using signed binary proxy" },
      { name: "Execution", attckTactic: "TA0002", typicalBinaries: ["powershell.exe", "rundll32.exe"], description: "Execute second-stage loader in memory" },
      { name: "C2 Setup", attckTactic: "TA0011", typicalBinaries: ["powershell.exe", "rundll32.exe"], description: "Establish C2 channel via HTTPS or DNS" },
      { name: "Discovery", attckTactic: "TA0007", typicalBinaries: ["cmd.exe", "powershell.exe", "nltest.exe"], description: "Enumerate domain, users, and network" },
    ],
    attckIds: ["T1218.010", "T1218.005", "T1218.003", "T1059.001", "T1218.011", "T1071.001", "T1082", "T1016"],
    commonActors: ["Cobalt Group", "APT29"],
  },
  {
    name: "Lateral Movement Chain",
    description: "Credential harvest followed by lateral movement via WMI/PsExec and LOL binaries",
    phases: [
      { name: "Credential Access", attckTactic: "TA0006", typicalBinaries: ["rundll32.exe", "powershell.exe"], description: "Dump credentials via comsvcs.dll or mimikatz" },
      { name: "Lateral Movement", attckTactic: "TA0008", typicalBinaries: ["wmic.exe", "powershell.exe", "cmd.exe"], description: "Move laterally via WMI or remote PowerShell" },
      { name: "Execution", attckTactic: "TA0002", typicalBinaries: ["rundll32.exe", "regsvr32.exe"], description: "Execute payload on remote system via LOL binary" },
      { name: "Persistence", attckTactic: "TA0003", typicalBinaries: ["schtasks.exe", "reg.exe", "bitsadmin.exe"], description: "Establish persistence on newly compromised host" },
    ],
    attckIds: ["T1003.001", "T1047", "T1021.006", "T1218.011", "T1218.010", "T1053.005", "T1547.001"],
    commonActors: ["APT29", "APT28", "Turla"],
  },
  {
    name: "Download and Execute",
    description: "Simple payload download and execution using trusted binaries",
    phases: [
      { name: "Download", attckTactic: "TA0011", typicalBinaries: ["certutil.exe", "bitsadmin.exe", "curl.exe", "powershell.exe"], description: "Download payload using trusted download utility" },
      { name: "Decode", attckTactic: "TA0005", typicalBinaries: ["certutil.exe", "powershell.exe"], description: "Decode obfuscated payload" },
      { name: "Execute", attckTactic: "TA0002", typicalBinaries: ["rundll32.exe", "regsvr32.exe", "mshta.exe"], description: "Execute payload via proxy execution binary" },
    ],
    attckIds: ["T1105", "T1197", "T1140", "T1218.011", "T1218.010", "T1218.005"],
    commonActors: ["Lazarus", "APT28", "Cobalt Group"],
  },
  {
    name: "Data Staging and Exfiltration",
    description: "Collect, stage, and exfiltrate sensitive data using LOL binaries",
    phases: [
      { name: "Collection", attckTactic: "TA0009", typicalBinaries: ["cmd.exe", "powershell.exe"], description: "Enumerate and collect files of interest" },
      { name: "Staging", attckTactic: "TA0009", typicalBinaries: ["cmd.exe", "powershell.exe", "certutil.exe"], description: "Compress and encode data for transfer" },
      { name: "Exfiltration", attckTactic: "TA0010", typicalBinaries: ["curl.exe", "powershell.exe", "bitsadmin.exe"], description: "Transfer data to attacker-controlled destination" },
    ],
    attckIds: ["T1560.001", "T1074.001", "T1041", "T1567.001", "T1048"],
    commonActors: ["APT29", "Turla"],
  },
  {
    name: "Privilege Escalation Chain",
    description: "Escalate from user to admin/SYSTEM using LOL techniques",
    phases: [
      { name: "Discovery", attckTactic: "TA0007", typicalBinaries: ["cmd.exe", "powershell.exe"], description: "Enumerate privileges, services, and misconfigurations" },
      { name: "UAC Bypass", attckTactic: "TA0004", typicalBinaries: ["cmstp.exe", "fodhelper.exe", "eventvwr.exe"], description: "Bypass UAC using auto-elevating binaries" },
      { name: "Privilege Escalation", attckTactic: "TA0004", typicalBinaries: ["powershell.exe", "cmd.exe", "sc.exe"], description: "Exploit service misconfiguration or token manipulation" },
      { name: "Persistence", attckTactic: "TA0003", typicalBinaries: ["schtasks.exe", "reg.exe", "sc.exe"], description: "Establish elevated persistence" },
    ],
    attckIds: ["T1082", "T1548.002", "T1218.003", "T1574.001", "T1053.005", "T1543.003"],
    commonActors: ["Cobalt Group", "FIN7"],
  },
];

// ━━━ Phase Classification ━━━

interface PhaseClassification {
  binary: string;
  possiblePhases: Array<{
    phase: string;
    tactic: string;
    confidence: "high" | "medium" | "low";
    description: string;
  }>;
}

const PHASE_CLASSIFICATIONS: Map<string, PhaseClassification> = new Map([
  ["certutil", { binary: "certutil", possiblePhases: [
    { phase: "Download", tactic: "TA0011", confidence: "high", description: "File download via -urlcache" },
    { phase: "Decode", tactic: "TA0005", confidence: "high", description: "Base64 decode via -decode" },
    { phase: "Encode", tactic: "TA0005", confidence: "medium", description: "Payload encoding via -encode" },
  ]}],
  ["powershell", { binary: "powershell", possiblePhases: [
    { phase: "Execution", tactic: "TA0002", confidence: "high", description: "Script/command execution" },
    { phase: "Download", tactic: "TA0011", confidence: "high", description: "Download cradle" },
    { phase: "Discovery", tactic: "TA0007", confidence: "medium", description: "System enumeration" },
    { phase: "Collection", tactic: "TA0009", confidence: "medium", description: "Data collection" },
    { phase: "Exfiltration", tactic: "TA0010", confidence: "medium", description: "Data transfer" },
    { phase: "C2 Setup", tactic: "TA0011", confidence: "high", description: "C2 beacon/agent execution" },
  ]}],
  ["rundll32", { binary: "rundll32", possiblePhases: [
    { phase: "Execution", tactic: "TA0002", confidence: "high", description: "DLL proxy execution" },
    { phase: "AWL Bypass", tactic: "TA0005", confidence: "high", description: "Signed binary proxy execution" },
    { phase: "Credential Access", tactic: "TA0006", confidence: "medium", description: "comsvcs.dll MiniDump" },
  ]}],
  ["mshta", { binary: "mshta", possiblePhases: [
    { phase: "Initial Access", tactic: "TA0001", confidence: "high", description: "HTA payload execution" },
    { phase: "AWL Bypass", tactic: "TA0005", confidence: "high", description: "Signed binary proxy execution" },
    { phase: "Execution", tactic: "TA0002", confidence: "high", description: "Inline script execution" },
  ]}],
  ["regsvr32", { binary: "regsvr32", possiblePhases: [
    { phase: "AWL Bypass", tactic: "TA0005", confidence: "high", description: "Squiblydoo technique" },
    { phase: "Execution", tactic: "TA0002", confidence: "high", description: "COM scriptlet execution" },
  ]}],
  ["bitsadmin", { binary: "bitsadmin", possiblePhases: [
    { phase: "Download", tactic: "TA0011", confidence: "high", description: "BITS file transfer" },
    { phase: "Persistence", tactic: "TA0003", confidence: "high", description: "BITS job persistence" },
  ]}],
  ["cmd", { binary: "cmd", possiblePhases: [
    { phase: "Execution", tactic: "TA0002", confidence: "medium", description: "Command execution" },
    { phase: "Discovery", tactic: "TA0007", confidence: "medium", description: "System enumeration" },
    { phase: "Collection", tactic: "TA0009", confidence: "medium", description: "Data staging" },
  ]}],
  ["reg", { binary: "reg", possiblePhases: [
    { phase: "Persistence", tactic: "TA0003", confidence: "high", description: "Registry persistence" },
    { phase: "Discovery", tactic: "TA0007", confidence: "medium", description: "Registry enumeration" },
    { phase: "Defense Evasion", tactic: "TA0005", confidence: "medium", description: "Registry modification" },
  ]}],
  ["schtasks", { binary: "schtasks", possiblePhases: [
    { phase: "Persistence", tactic: "TA0003", confidence: "high", description: "Scheduled task persistence" },
    { phase: "Execution", tactic: "TA0002", confidence: "medium", description: "Scheduled execution" },
    { phase: "Lateral Movement", tactic: "TA0008", confidence: "medium", description: "Remote task creation" },
  ]}],
  ["wmic", { binary: "wmic", possiblePhases: [
    { phase: "Lateral Movement", tactic: "TA0008", confidence: "high", description: "Remote process creation" },
    { phase: "Discovery", tactic: "TA0007", confidence: "medium", description: "System information gathering" },
    { phase: "AWL Bypass", tactic: "TA0005", confidence: "high", description: "XSL script execution" },
  ]}],
  ["cmstp", { binary: "cmstp", possiblePhases: [
    { phase: "UAC Bypass", tactic: "TA0004", confidence: "high", description: "CMSTP UAC bypass" },
    { phase: "AWL Bypass", tactic: "TA0005", confidence: "high", description: "CMSTP application bypass" },
  ]}],
  ["curl", { binary: "curl", possiblePhases: [
    { phase: "Download", tactic: "TA0011", confidence: "high", description: "Payload download" },
    { phase: "Exfiltration", tactic: "TA0010", confidence: "medium", description: "Data upload" },
    { phase: "C2 Setup", tactic: "TA0011", confidence: "medium", description: "C2 communication" },
  ]}],
  ["wscript", { binary: "wscript", possiblePhases: [
    { phase: "Execution", tactic: "TA0002", confidence: "high", description: "VBScript/JScript execution" },
    { phase: "Initial Access", tactic: "TA0001", confidence: "medium", description: "Script-based dropper" },
  ]}],
]);

// ━━━ Helper Functions ━━━

function deduplicateByBinary(entries: UnifiedLOLEntry[]): UnifiedLOLEntry[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    const key = `${e.binary}-${e.platform}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function summarizeKbEntry(e: UnifiedLOLEntry): Record<string, unknown> {
  return {
    binary: e.binary,
    platform: e.platform,
    catalog: e.catalogSource,
    functions: e.functions,
    stealthScore: e.stealthScore,
    attck: e.attckTechniques,
    commands: e.executionContexts.slice(0, 2).map(c => ({
      context: c.context,
      command: c.command,
    })),
  };
}

function normalizeBinaryName(name: string): string {
  return name.toLowerCase().replace(/\.exe$/i, "").trim();
}

// ━━━ Tools ━━━

const timeline_map_events: ToolDef = {
  name: "timeline_map_events",
  description: "Map a list of observed events/commands to a LOL technique timeline, classifying each into attack phases",
  schema: {
    events: z.array(z.object({
      timestamp: z.string().describe("Event timestamp (ISO 8601 or relative)"),
      binary: z.string().describe("Binary/process name observed"),
      command: z.string().optional().describe("Command line if available"),
      source: z.string().optional().describe("Event source (e.g. Sysmon, Security, EDR)"),
    })).describe("Ordered list of observed events to map onto timeline"),
    platform: z.string().optional().describe("Target platform for KB enrichment"),
  },
  async execute(args: {
    events: Array<{ timestamp: string; binary: string; command?: string; source?: string }>;
    platform?: string;
  }, ctx: ToolContext): Promise<ToolResult> {
    const timeline = args.events.map((event, index) => {
      const binName = normalizeBinaryName(event.binary);
      const classification = PHASE_CLASSIFICATIONS.get(binName);
      const kbEntries = ctx.knowledgeBase.lookupBinary(binName, args.platform as Platform);

      // Try to determine phase from command line content
      let inferredPhase = classification?.possiblePhases[0] || null;

      if (event.command && classification) {
        const cmdLower = event.command.toLowerCase();
        // Refine phase based on command content
        if (cmdLower.includes("urlcache") || cmdLower.includes("downloadstring") || cmdLower.includes("/transfer")) {
          inferredPhase = classification.possiblePhases.find(p => p.phase === "Download") || inferredPhase;
        } else if (cmdLower.includes("-decode") || cmdLower.includes("-encode")) {
          inferredPhase = classification.possiblePhases.find(p => p.phase === "Decode" || p.phase === "Encode") || inferredPhase;
        } else if (cmdLower.includes("run") && cmdLower.includes("reg")) {
          inferredPhase = classification.possiblePhases.find(p => p.phase === "Persistence") || inferredPhase;
        } else if (cmdLower.includes("systeminfo") || cmdLower.includes("ipconfig") || cmdLower.includes("whoami") || cmdLower.includes("net user")) {
          inferredPhase = classification.possiblePhases.find(p => p.phase === "Discovery") || inferredPhase;
        }
      }

      return {
        order: index + 1,
        timestamp: event.timestamp,
        binary: event.binary,
        command: event.command,
        source: event.source,
        classification: inferredPhase ? {
          phase: inferredPhase.phase,
          tactic: inferredPhase.tactic,
          confidence: inferredPhase.confidence,
          description: inferredPhase.description,
        } : { phase: "Unknown", tactic: "Unknown", confidence: "low" as const, description: "Binary not in classification database" },
        allPossiblePhases: classification?.possiblePhases || [],
        kbMatchCount: kbEntries.length,
      };
    });

    // Identify overall attack pattern
    const phaseSequence = timeline.map(t => t.classification.phase);
    const uniquePhases = Array.from(new Set(phaseSequence));
    const uniqueBinaries = Array.from(new Set(args.events.map(e => normalizeBinaryName(e.binary))));

    // Try to match to known attack sequences
    const matchedSequences = ATTACK_SEQUENCES.filter(seq => {
      const seqBinaries = new Set(seq.phases.flatMap(p => p.typicalBinaries.map(b => normalizeBinaryName(b))));
      const overlap = uniqueBinaries.filter(b => seqBinaries.has(b));
      return overlap.length >= 2;
    }).map(seq => ({
      name: seq.name,
      description: seq.description,
      matchingBinaries: uniqueBinaries.filter(b =>
        seq.phases.some(p => p.typicalBinaries.some(tb => normalizeBinaryName(tb) === b)),
      ),
    }));

    return json({
      totalEvents: args.events.length,
      timeline,
      summary: {
        uniqueBinaries,
        phaseSequence,
        uniquePhases,
        matchedAttackSequences: matchedSequences,
      },
    });
  },
};

const timeline_identify_sequence: ToolDef = {
  name: "timeline_identify_sequence",
  description: "Identify known attack sequences from observed binary/technique patterns (e.g. macro dropper chain, AWL bypass to beacon)",
  schema: {
    binaries: z.array(z.string()).describe("List of binary names observed in order (e.g. ['winword.exe', 'cmd.exe', 'powershell.exe', 'reg.exe'])"),
    include_partial: z.boolean().optional().describe("Include partial sequence matches (default: true)"),
  },
  async execute(args: { binaries: string[]; include_partial?: boolean }, ctx: ToolContext): Promise<ToolResult> {
    const includePartial = args.include_partial !== false;
    const inputBinaries = args.binaries.map(normalizeBinaryName);
    const inputSet = new Set(inputBinaries);

    const matches: Array<{
      sequence: string;
      description: string;
      matchType: "full" | "partial";
      matchedPhases: Array<{ phase: string; matchedBinaries: string[] }>;
      missingPhases: string[];
      attckIds: string[];
      commonActors: string[];
      coveragePercent: number;
    }> = [];

    for (const seq of ATTACK_SEQUENCES) {
      const matchedPhases: Array<{ phase: string; matchedBinaries: string[] }> = [];
      const missingPhases: string[] = [];

      for (const phase of seq.phases) {
        const phaseBinaries = phase.typicalBinaries.map(normalizeBinaryName);
        const matched = phaseBinaries.filter(b => inputSet.has(b));

        if (matched.length > 0) {
          matchedPhases.push({ phase: phase.name, matchedBinaries: matched });
        } else {
          missingPhases.push(phase.name);
        }
      }

      const coveragePercent = Math.round((matchedPhases.length / seq.phases.length) * 100);
      const isFullMatch = matchedPhases.length === seq.phases.length;

      if (isFullMatch || (includePartial && matchedPhases.length >= 2)) {
        matches.push({
          sequence: seq.name,
          description: seq.description,
          matchType: isFullMatch ? "full" : "partial",
          matchedPhases,
          missingPhases,
          attckIds: seq.attckIds,
          commonActors: seq.commonActors,
          coveragePercent,
        });
      }
    }

    // Sort by coverage
    matches.sort((a, b) => b.coveragePercent - a.coveragePercent);

    // Get KB entries for input binaries
    const kbSummary: Record<string, number> = {};
    for (const binary of inputBinaries) {
      const entries = ctx.knowledgeBase.lookupBinary(binary);
      kbSummary[binary] = entries.length;
    }

    return json({
      inputBinaries: args.binaries,
      totalMatches: matches.length,
      matches,
      kbCoverage: kbSummary,
    });
  },
};

const timeline_reconstruct_chain: ToolDef = {
  name: "timeline_reconstruct_chain",
  description: "Reconstruct a full attack chain from partial evidence (observed binaries, commands, or ATT&CK IDs)",
  schema: {
    evidence: z.array(z.object({
      type: z.enum(["binary", "command", "attck_id", "event_log"]).describe("Type of evidence"),
      value: z.string().describe("Evidence value (binary name, command line, ATT&CK ID, or event description)"),
      timestamp: z.string().optional().describe("Timestamp if available"),
    })).describe("Partial evidence collected during investigation"),
    platform: z.string().optional().describe("Target platform for KB enrichment"),
  },
  async execute(args: {
    evidence: Array<{ type: string; value: string; timestamp?: string }>;
    platform?: string;
  }, ctx: ToolContext): Promise<ToolResult> {
    // Extract unique binaries and ATT&CK IDs from evidence
    const observedBinaries = new Set<string>();
    const observedAttckIds = new Set<string>();
    const observedCommands: string[] = [];

    for (const e of args.evidence) {
      switch (e.type) {
        case "binary":
          observedBinaries.add(normalizeBinaryName(e.value));
          break;
        case "command":
          observedCommands.push(e.value);
          // Extract binary from command
          const parts = e.value.trim().split(/\s+/);
          if (parts[0]) observedBinaries.add(normalizeBinaryName(parts[0]));
          break;
        case "attck_id":
          observedAttckIds.add(e.value.toUpperCase());
          break;
        case "event_log":
          // Try to extract binary from event description
          const knownBins = ["certutil", "powershell", "mshta", "regsvr32", "rundll32", "bitsadmin", "cmd", "wmic", "wscript", "cscript", "reg", "schtasks"];
          for (const bin of knownBins) {
            if (e.value.toLowerCase().includes(bin)) observedBinaries.add(bin);
          }
          break;
      }
    }

    // Classify each observed binary into phases
    const phaseMapping: Array<{
      binary: string;
      phases: Array<{ phase: string; tactic: string; confidence: string }>;
    }> = [];

    for (const binary of observedBinaries) {
      const classification = PHASE_CLASSIFICATIONS.get(binary);
      if (classification) {
        phaseMapping.push({
          binary,
          phases: classification.possiblePhases.map(p => ({
            phase: p.phase,
            tactic: p.tactic,
            confidence: p.confidence,
          })),
        });
      }
    }

    // Match against known attack sequences
    const matchedSequences = ATTACK_SEQUENCES.filter(seq => {
      const seqBinaries = new Set(seq.phases.flatMap(p => p.typicalBinaries.map(normalizeBinaryName)));
      const binaryOverlap = Array.from(observedBinaries).filter(b => seqBinaries.has(b));
      const attckOverlap = seq.attckIds.filter(id => observedAttckIds.has(id));
      return binaryOverlap.length >= 2 || attckOverlap.length >= 2;
    });

    // Reconstruct likely attack chain
    const reconstructedChain: Array<{
      phase: string;
      tactic: string;
      observedBinaries: string[];
      missingBinaries: string[];
      confidence: string;
      evidenceSupport: string[];
    }> = [];

    // Use the best matching sequence as template
    if (matchedSequences.length > 0) {
      const bestMatch = matchedSequences[0];
      for (const phase of bestMatch.phases) {
        const phaseBinaries = phase.typicalBinaries.map(normalizeBinaryName);
        const observed = phaseBinaries.filter(b => observedBinaries.has(b));
        const missing = phaseBinaries.filter(b => !observedBinaries.has(b));

        const evidenceSupport: string[] = [];
        for (const e of args.evidence) {
          const eLower = e.value.toLowerCase();
          if (phaseBinaries.some(b => eLower.includes(b))) {
            evidenceSupport.push(`${e.type}: ${e.value}`);
          }
        }

        reconstructedChain.push({
          phase: phase.name,
          tactic: phase.attckTactic,
          observedBinaries: observed,
          missingBinaries: missing,
          confidence: observed.length > 0 ? "confirmed" : "inferred",
          evidenceSupport,
        });
      }
    }

    // Get KB entries for observed binaries
    const kbEntries: Record<string, Record<string, unknown>[]> = {};
    for (const binary of observedBinaries) {
      const entries = ctx.knowledgeBase.lookupBinary(binary, args.platform as Platform);
      if (entries.length > 0) {
        kbEntries[binary] = deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry);
      }
    }

    // Get KB entries for observed ATT&CK IDs
    const attckEntries: Record<string, number> = {};
    for (const attckId of observedAttckIds) {
      const entries = ctx.knowledgeBase.searchByAttck(attckId, args.platform as Platform);
      attckEntries[attckId] = entries.length;
    }

    return json({
      evidenceCount: args.evidence.length,
      observedBinaries: Array.from(observedBinaries),
      observedAttckIds: Array.from(observedAttckIds),
      phaseClassification: phaseMapping,
      matchedSequences: matchedSequences.map(s => ({
        name: s.name,
        description: s.description,
        commonActors: s.commonActors,
        attckIds: s.attckIds,
      })),
      reconstructedChain,
      kbEntries,
      attckCoverage: attckEntries,
      recommendations: [
        reconstructedChain.some(c => c.confidence === "inferred")
          ? `Look for evidence of: ${reconstructedChain.filter(c => c.confidence === "inferred").map(c => `${c.phase} (${c.missingBinaries.join(", ")})`).join("; ")}`
          : null,
        observedBinaries.size > 0 ? `Review process trees for: ${Array.from(observedBinaries).join(", ")}` : null,
        "Check for additional IOCs in Sysmon, Security, and PowerShell event logs",
        "Correlate network connections from identified binaries with C2 infrastructure",
        matchedSequences.length > 0 ? `Attack pattern matches: ${matchedSequences.map(s => s.name).join(", ")} - investigate associated TTPs` : null,
      ].filter(Boolean),
    });
  },
};

export const incidentTimelineTools: ToolDef[] = [
  timeline_map_events,
  timeline_identify_sequence,
  timeline_reconstruct_chain,
];
