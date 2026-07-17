import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

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
  };
}

interface OpsecResult {
  command: string;
  platform: string;
  noise_level: number;
  log_sources: string[];
  edr_detections: string[];
  risk_score: number;
  alternatives: string[];
  recommendations: string[];
}

// ── opsec_noise_level ───────────────────────────────────────────────────────

const opsec_noise_level: ToolDef = {
  name: "opsec_noise_level",
  description: "Analyze the noise level of a command — process creation, network activity, file operations, and registry changes",
  schema: {
    command: z.string().describe("The command to analyze for noise"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform } = args;

    const hasNetwork = /curl|wget|nc|ncat|socat|Invoke-WebRequest|iwr|Net\.WebClient|fetch/i.test(command);
    const hasFileWrite = />>|>\s|tee|Out-File|Set-Content|cp\s|copy\s|move\s|mv\s/i.test(command);
    const hasProcessSpawn = /exec|spawn|fork|Start-Process|cmd\s|bash\s|sh\s|powershell/i.test(command);
    const hasPrivEsc = /sudo|runas|doas|pkexec|su\s/i.test(command);
    const hasPipe = /\|/.test(command);

    let noiseLevel = 1;
    const signals: string[] = [];

    if (hasNetwork) { noiseLevel += 2; signals.push("network_activity"); }
    if (hasFileWrite) { noiseLevel += 1; signals.push("file_write_operation"); }
    if (hasProcessSpawn) { noiseLevel += 1; signals.push("child_process_creation"); }
    if (hasPrivEsc) { noiseLevel += 1; signals.push("privilege_escalation_attempt"); }
    if (hasPipe) { signals.push("pipe_chain"); }
    noiseLevel = Math.min(5, noiseLevel);

    const logSources = platform === "windows"
      ? ["Security EventLog 4688", "Sysmon Event ID 1", "PowerShell ScriptBlock 4104"]
      : platform === "macos"
        ? ["Unified Log", "Endpoint Security Framework", "OpenBSM audit"]
        : ["auditd", "syslog", "journald", "/proc monitoring"];

    const result: OpsecResult = {
      command,
      platform,
      noise_level: noiseLevel,
      log_sources: logSources,
      edr_detections: signals,
      risk_score: noiseLevel,
      alternatives: [],
      recommendations: noiseLevel >= 3
        ? ["Break command into smaller operations", "Add time delays between stages", "Use less-monitored binaries"]
        : ["Current noise level is acceptable for most environments"],
    };

    return json(result);
  },
};

// ── opsec_log_footprint ─────────────────────────────────────────────────────

const opsec_log_footprint: ToolDef = {
  name: "opsec_log_footprint",
  description: "Analyze what logs a command generates — syslog, security eventlog, sysmon, auditd, and more",
  schema: {
    command: z.string().describe("The command to analyze for log footprint"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform } = args;

    const windowsLogs: { source: string; event_id: string; description: string }[] = [
      { source: "Security", event_id: "4688", description: "Process creation with command line" },
      { source: "Sysmon", event_id: "1", description: "Process creation with full details" },
      { source: "Sysmon", event_id: "3", description: "Network connection" },
      { source: "Sysmon", event_id: "11", description: "File creation" },
      { source: "PowerShell", event_id: "4104", description: "Script block logging" },
      { source: "Security", event_id: "4663", description: "Object access attempt" },
    ];

    const linuxLogs: { source: string; event_id: string; description: string }[] = [
      { source: "auditd", event_id: "SYSCALL_EXECVE", description: "Process execution audit" },
      { source: "syslog", event_id: "process", description: "Process creation syslog entry" },
      { source: "journald", event_id: "unit_start", description: "Systemd unit activity" },
      { source: "auth.log", event_id: "sudo", description: "Privilege escalation via sudo" },
      { source: "auditd", event_id: "SYSCALL_OPEN", description: "File access audit" },
    ];

    const macosLogs: { source: string; event_id: string; description: string }[] = [
      { source: "Unified Log", event_id: "process_exec", description: "Process execution via ES framework" },
      { source: "OpenBSM", event_id: "AUE_EXECVE", description: "Process execution audit event" },
      { source: "Unified Log", event_id: "network", description: "Network connection events" },
      { source: "install.log", event_id: "install", description: "Software installation events" },
      { source: "TCC.db", event_id: "access", description: "TCC permission access events" },
    ];

    const logMap: Record<string, typeof windowsLogs> = {
      windows: windowsLogs, linux: linuxLogs, macos: macosLogs,
    };

    const relevantLogs = logMap[platform] || linuxLogs;
    const hasPowerShell = /powershell|pwsh/i.test(command);
    const hasNetwork = /curl|wget|nc|Invoke-WebRequest/i.test(command);
    const hasSudo = /sudo|runas|doas/i.test(command);

    const triggered = relevantLogs.filter(log => {
      if (log.event_id === "4104" && !hasPowerShell) return false;
      if (log.event_id === "3" && !hasNetwork) return false;
      if (log.event_id === "network" && !hasNetwork) return false;
      if (log.event_id === "sudo" && !hasSudo) return false;
      return true;
    });

    const result: OpsecResult = {
      command,
      platform,
      noise_level: triggered.length,
      log_sources: triggered.map(l => `${l.source}:${l.event_id}`),
      edr_detections: triggered.map(l => l.description),
      risk_score: Math.min(5, Math.ceil(triggered.length / 2)),
      alternatives: [],
      recommendations: [
        `Command will generate entries in ${triggered.length} log sources`,
        triggered.length >= 4 ? "High log footprint — consider log-aware alternatives" : "Moderate log footprint",
      ],
    };

    return json({ ...result, log_detail: triggered });
  },
};

// ── opsec_edr_trigger ───────────────────────────────────────────────────────

const opsec_edr_trigger: ToolDef = {
  name: "opsec_edr_trigger",
  description: "Analyze EDR trigger probability — which detections would fire for a given command and EDR product",
  schema: {
    command: z.string().describe("The command to analyze for EDR triggers"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
    edr_product: z.string().optional().describe("Optional EDR product name (e.g., CrowdStrike, SentinelOne, Defender)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform, edr_product } = args;

    const detectionPatterns: { pattern: RegExp; rule: string; severity: string }[] = [
      { pattern: /certutil.*-encode|certutil.*-decode/i, rule: "Certutil encode/decode activity", severity: "high" },
      { pattern: /powershell.*-enc|-EncodedCommand/i, rule: "PowerShell encoded command", severity: "high" },
      { pattern: /base64.*-d|base64.*-D/i, rule: "Base64 decode execution", severity: "medium" },
      { pattern: /curl.*\|.*sh|wget.*\|.*bash/i, rule: "Remote script download and execute", severity: "critical" },
      { pattern: /whoami|hostname|ipconfig|ifconfig/i, rule: "Discovery command execution", severity: "low" },
      { pattern: /net\s+user|net\s+group|net\s+localgroup/i, rule: "User/group enumeration", severity: "medium" },
      { pattern: /reg\s+save|reg\s+export/i, rule: "Registry hive export", severity: "high" },
      { pattern: /mimikatz|sekurlsa|kerberos/i, rule: "Credential dumping tool", severity: "critical" },
      { pattern: /schtasks.*\/create|crontab/i, rule: "Scheduled task creation", severity: "medium" },
      { pattern: /nc\s+-l|ncat.*-l|socat.*listen/i, rule: "Reverse/bind shell listener", severity: "critical" },
    ];

    const triggered = detectionPatterns.filter(dp => dp.pattern.test(command));

    const edrStrength: Record<string, number> = {
      crowdstrike: 5, sentinelone: 5, defender: 3, carbonblack: 4, elastic: 3,
    };
    const edrKey = (edr_product || "generic").toLowerCase().replace(/[\s-]/g, "");
    const strength = edrStrength[edrKey] || 3;

    const triggerProbability = Math.min(100, triggered.reduce((sum, t) => {
      const base = t.severity === "critical" ? 40 : t.severity === "high" ? 25 : t.severity === "medium" ? 15 : 5;
      return sum + Math.ceil(base * (strength / 3));
    }, 0));

    const result: OpsecResult = {
      command,
      platform,
      noise_level: triggered.length,
      log_sources: [],
      edr_detections: triggered.map(t => `[${t.severity.toUpperCase()}] ${t.rule}`),
      risk_score: Math.min(5, Math.ceil(triggerProbability / 20)),
      alternatives: [],
      recommendations: triggerProbability >= 60
        ? ["High detection probability — use alternative binaries", "Break into smaller operations", "Add obfuscation layers"]
        : triggerProbability >= 30
          ? ["Moderate detection risk — consider timing and context"]
          : ["Low detection probability for this command"],
    };

    return json({
      ...result,
      edr_product: edr_product || "generic",
      edr_strength: strength,
      trigger_probability: `${triggerProbability}%`,
      matched_rules: triggered.map(t => ({ rule: t.rule, severity: t.severity })),
    });
  },
};

// ── opsec_safe_alternatives ─────────────────────────────────────────────────

const opsec_safe_alternatives: ToolDef = {
  name: "opsec_safe_alternatives",
  description: "Find safer LOL binary alternatives with lower detection probability for a given command",
  schema: {
    command: z.string().describe("The command to find safer alternatives for"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform } = args;

    const binaryMatch = command.match(/^(\S+)/);
    const primaryBinary = binaryMatch ? binaryMatch[1].replace(/\.exe$/i, "").toLowerCase() : "";

    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(primaryBinary, platform));

    const alternatives: { binary: string; stealth_score: number; reason: string }[] = [];

    for (const entry of kbEntries) {
      if (entry.binary.toLowerCase() !== primaryBinary && entry.stealthScore <= 3) {
        alternatives.push({
          binary: entry.binary,
          stealth_score: entry.stealthScore,
          reason: `${entry.binary} provides similar functions (${entry.functions?.join(", ") || "N/A"}) with stealth score ${entry.stealthScore}`,
        });
      }
    }

    const functionKeywords = ["download", "execute", "encode", "shell", "copy", "read"];
    for (const keyword of functionKeywords) {
      if (command.toLowerCase().includes(keyword)) {
        const extra = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(keyword, platform));
        for (const entry of extra) {
          if (entry.binary.toLowerCase() !== primaryBinary && entry.stealthScore <= 2) {
            const already = alternatives.some(a => a.binary === entry.binary);
            if (!already) {
              alternatives.push({
                binary: entry.binary,
                stealth_score: entry.stealthScore,
                reason: `Lower-profile alternative for ${keyword} operation`,
              });
            }
          }
        }
      }
    }

    alternatives.sort((a, b) => a.stealth_score - b.stealth_score);

    const result: OpsecResult = {
      command,
      platform,
      noise_level: 0,
      log_sources: [],
      edr_detections: [],
      risk_score: alternatives.length > 0 ? 2 : 4,
      alternatives: alternatives.slice(0, 8).map(a => a.binary),
      recommendations: alternatives.length > 0
        ? [`Found ${alternatives.length} alternatives with lower detection profiles`]
        : ["No lower-profile alternatives found in knowledge base — consider obfuscation instead"],
    };

    return json({
      ...result,
      original_binary: primaryBinary,
      alternative_details: alternatives.slice(0, 8),
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const opsecRiskTools: ToolDef[] = [
  opsec_noise_level,
  opsec_log_footprint,
  opsec_edr_trigger,
  opsec_safe_alternatives,
];
