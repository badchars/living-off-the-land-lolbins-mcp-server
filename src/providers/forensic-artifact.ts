import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Event Log Indicators ━━━

interface EventLogIndicator {
  logSource: string;
  eventId: number;
  eventName: string;
  indicatorFields: Record<string, string>;
  technique: string;
  binary: string;
  attckId: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  falsePositiveRate: "low" | "medium" | "high";
}

const EVENT_LOG_INDICATORS: EventLogIndicator[] = [
  // Security Log
  { logSource: "Security", eventId: 4688, eventName: "Process Creation", indicatorFields: { NewProcessName: "certutil", ProcessCommandLine: "-urlcache" }, technique: "certutil Download", binary: "certutil", attckId: "T1105", description: "certutil process created with download arguments", severity: "high", falsePositiveRate: "low" },
  { logSource: "Security", eventId: 4688, eventName: "Process Creation", indicatorFields: { NewProcessName: "powershell", ProcessCommandLine: "-enc" }, technique: "Encoded PowerShell", binary: "powershell", attckId: "T1059.001", description: "PowerShell launched with encoded command", severity: "high", falsePositiveRate: "medium" },
  { logSource: "Security", eventId: 4688, eventName: "Process Creation", indicatorFields: { NewProcessName: "mshta" }, technique: "mshta Execution", binary: "mshta", attckId: "T1218.005", description: "mshta.exe process created (potential LOL abuse)", severity: "medium", falsePositiveRate: "medium" },
  { logSource: "Security", eventId: 4688, eventName: "Process Creation", indicatorFields: { NewProcessName: "regsvr32", ProcessCommandLine: "scrobj" }, technique: "Squiblydoo", binary: "regsvr32", attckId: "T1218.010", description: "regsvr32 loading COM scriptlet", severity: "critical", falsePositiveRate: "low" },
  { logSource: "Security", eventId: 4688, eventName: "Process Creation", indicatorFields: { NewProcessName: "bitsadmin", ProcessCommandLine: "/transfer" }, technique: "BITS Download", binary: "bitsadmin", attckId: "T1197", description: "bitsadmin transfer job created", severity: "high", falsePositiveRate: "medium" },

  // Sysmon
  { logSource: "Sysmon", eventId: 1, eventName: "Process Create", indicatorFields: { Image: "rundll32", CommandLine: "javascript:" }, technique: "rundll32 JS Execution", binary: "rundll32", attckId: "T1218.011", description: "rundll32 executing inline JavaScript", severity: "critical", falsePositiveRate: "low" },
  { logSource: "Sysmon", eventId: 1, eventName: "Process Create", indicatorFields: { ParentImage: "wmiprvse", Image: "cmd" }, technique: "WMI Remote Exec", binary: "wmic", attckId: "T1047", description: "WMI provider spawning cmd (remote execution indicator)", severity: "critical", falsePositiveRate: "low" },
  { logSource: "Sysmon", eventId: 3, eventName: "Network Connection", indicatorFields: { Image: "certutil" }, technique: "certutil Network", binary: "certutil", attckId: "T1105", description: "certutil making outbound connection", severity: "high", falsePositiveRate: "low" },
  { logSource: "Sysmon", eventId: 3, eventName: "Network Connection", indicatorFields: { Image: "mshta" }, technique: "mshta Network", binary: "mshta", attckId: "T1218.005", description: "mshta making outbound connection (remote HTA)", severity: "critical", falsePositiveRate: "low" },
  { logSource: "Sysmon", eventId: 7, eventName: "Image Loaded", indicatorFields: { Image: "rundll32" }, technique: "rundll32 DLL Load", binary: "rundll32", attckId: "T1218.011", description: "rundll32 loading DLL (check path for anomalies)", severity: "medium", falsePositiveRate: "high" },
  { logSource: "Sysmon", eventId: 11, eventName: "File Create", indicatorFields: { Image: "certutil" }, technique: "certutil File Drop", binary: "certutil", attckId: "T1105", description: "certutil writing file to disk", severity: "high", falsePositiveRate: "low" },
  { logSource: "Sysmon", eventId: 13, eventName: "Registry Value Set", indicatorFields: { TargetObject: "CurrentVersion\\Run" }, technique: "Registry Run Persistence", binary: "reg", attckId: "T1547.001", description: "Run key registry value modified", severity: "high", falsePositiveRate: "medium" },

  // PowerShell
  { logSource: "PowerShell", eventId: 4104, eventName: "Script Block Logging", indicatorFields: { ScriptBlockText: "DownloadString" }, technique: "Download Cradle", binary: "powershell", attckId: "T1105", description: "PowerShell download cradle detected in script block", severity: "critical", falsePositiveRate: "low" },
  { logSource: "PowerShell", eventId: 4104, eventName: "Script Block Logging", indicatorFields: { ScriptBlockText: "Invoke-Expression" }, technique: "Dynamic Execution", binary: "powershell", attckId: "T1059.001", description: "PowerShell IEX detected in script block", severity: "high", falsePositiveRate: "medium" },
  { logSource: "PowerShell", eventId: 4104, eventName: "Script Block Logging", indicatorFields: { ScriptBlockText: "Net.WebClient" }, technique: "Web Download", binary: "powershell", attckId: "T1105", description: "PowerShell Net.WebClient usage for download", severity: "high", falsePositiveRate: "low" },

  // BITS
  { logSource: "BITS-Client", eventId: 59, eventName: "BITS Transfer", indicatorFields: { url: "http" }, technique: "BITS Transfer", binary: "bitsadmin", attckId: "T1197", description: "BITS job transferring file from HTTP source", severity: "high", falsePositiveRate: "medium" },
];

// ━━━ Process Monitor Patterns ━━━

interface ProcMonPattern {
  operation: string;
  processName: string;
  pathPattern: string;
  technique: string;
  binary: string;
  attckId: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

const PROCMON_PATTERNS: ProcMonPattern[] = [
  // File operations
  { operation: "CreateFile", processName: "certutil.exe", pathPattern: "*.exe", technique: "certutil File Drop", binary: "certutil", attckId: "T1105", description: "certutil writing executable to disk", severity: "critical" },
  { operation: "CreateFile", processName: "certutil.exe", pathPattern: "*.dll", technique: "certutil DLL Drop", binary: "certutil", attckId: "T1105", description: "certutil writing DLL to disk", severity: "critical" },
  { operation: "CreateFile", processName: "powershell.exe", pathPattern: "\\Temp\\*", technique: "PS Temp File", binary: "powershell", attckId: "T1059.001", description: "PowerShell writing to temp directory", severity: "medium" },
  { operation: "CreateFile", processName: "mshta.exe", pathPattern: "*", technique: "mshta File Write", binary: "mshta", attckId: "T1218.005", description: "mshta creating file on disk", severity: "high" },

  // Registry operations
  { operation: "RegSetValue", processName: "reg.exe", pathPattern: "\\Run\\*", technique: "Registry Persistence", binary: "reg", attckId: "T1547.001", description: "reg.exe modifying Run key", severity: "high" },
  { operation: "RegSetValue", processName: "powershell.exe", pathPattern: "\\Run\\*", technique: "PS Registry Persist", binary: "powershell", attckId: "T1547.001", description: "PowerShell modifying Run key for persistence", severity: "high" },

  // Network operations
  { operation: "TCP Connect", processName: "certutil.exe", pathPattern: "*:80", technique: "certutil HTTP", binary: "certutil", attckId: "T1105", description: "certutil making HTTP connection", severity: "high" },
  { operation: "TCP Connect", processName: "certutil.exe", pathPattern: "*:443", technique: "certutil HTTPS", binary: "certutil", attckId: "T1105", description: "certutil making HTTPS connection", severity: "high" },
  { operation: "TCP Connect", processName: "mshta.exe", pathPattern: "*:80", technique: "mshta HTTP", binary: "mshta", attckId: "T1218.005", description: "mshta making HTTP connection", severity: "critical" },
  { operation: "TCP Connect", processName: "regsvr32.exe", pathPattern: "*:80", technique: "regsvr32 HTTP", binary: "regsvr32", attckId: "T1218.010", description: "regsvr32 making HTTP connection (Squiblydoo)", severity: "critical" },
  { operation: "TCP Connect", processName: "regsvr32.exe", pathPattern: "*:443", technique: "regsvr32 HTTPS", binary: "regsvr32", attckId: "T1218.010", description: "regsvr32 making HTTPS connection", severity: "critical" },

  // Process operations
  { operation: "Process Create", processName: "mshta.exe", pathPattern: "powershell.exe", technique: "HTA to PS", binary: "mshta", attckId: "T1218.005", description: "mshta spawning PowerShell process", severity: "critical" },
  { operation: "Process Create", processName: "wscript.exe", pathPattern: "powershell.exe", technique: "VBS to PS", binary: "wscript", attckId: "T1059.005", description: "wscript spawning PowerShell process", severity: "high" },
  { operation: "Process Create", processName: "rundll32.exe", pathPattern: "cmd.exe", technique: "rundll32 to CMD", binary: "rundll32", attckId: "T1218.011", description: "rundll32 spawning cmd process", severity: "high" },
];

// ━━━ Network Indicators ━━━

interface NetworkIndicator {
  protocol: string;
  pattern: string;
  binary: string;
  technique: string;
  attckId: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

const NETWORK_INDICATORS: NetworkIndicator[] = [
  { protocol: "HTTP", pattern: "User-Agent containing 'CertUtil'", binary: "certutil", technique: "certutil Download", attckId: "T1105", description: "certutil HTTP download identified by User-Agent string", severity: "high" },
  { protocol: "HTTP", pattern: "User-Agent containing 'Microsoft BITS'", binary: "bitsadmin", technique: "BITS Download", attckId: "T1197", description: "BITS job HTTP transfer identified by User-Agent", severity: "high" },
  { protocol: "HTTP", pattern: "User-Agent containing 'PowerShell'", binary: "powershell", technique: "PS Web Request", attckId: "T1105", description: "PowerShell web request identified by User-Agent", severity: "medium" },
  { protocol: "HTTP", pattern: "URL path ending in .hta", binary: "mshta", technique: "Remote HTA", attckId: "T1218.005", description: "HTA file download (likely mshta payload)", severity: "critical" },
  { protocol: "HTTP", pattern: "URL path ending in .sct", binary: "regsvr32", technique: "Remote SCT", attckId: "T1218.010", description: "SCT scriptlet download (Squiblydoo payload)", severity: "critical" },
  { protocol: "HTTP", pattern: "URL path ending in .xsl", binary: "wmic", technique: "Remote XSL", attckId: "T1220", description: "XSL stylesheet download (WMIC XSL execution)", severity: "critical" },
  { protocol: "DNS", pattern: "Long subdomain labels (>30 chars)", binary: "dns", technique: "DNS Tunnel", attckId: "T1071.004", description: "Potentially encoded data in DNS subdomain labels", severity: "high" },
  { protocol: "DNS", pattern: "High frequency TXT queries to single domain", binary: "dns", technique: "DNS C2", attckId: "T1071.004", description: "DNS TXT record queries suggesting C2 communication", severity: "high" },
  { protocol: "HTTP", pattern: "POST to known paste sites (pastebin, paste.ee)", binary: "curl", technique: "Data Exfil", attckId: "T1567.001", description: "Data upload to paste service for exfiltration", severity: "high" },
  { protocol: "HTTP", pattern: "POST to Discord/Slack webhooks", binary: "curl", technique: "Webhook C2", attckId: "T1102.002", description: "Data sent to messaging platform webhook (C2 or exfil)", severity: "high" },
  { protocol: "ICMP", pattern: "Large ICMP payload size (>64 bytes)", binary: "ping", technique: "ICMP Tunnel", attckId: "T1095", description: "Oversized ICMP packets suggesting data tunneling", severity: "medium" },
  { protocol: "HTTP", pattern: "Base64 encoded data in URL parameters", binary: "curl", technique: "Encoded Exfil", attckId: "T1048.001", description: "Base64-encoded data in HTTP request (exfiltration)", severity: "medium" },
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
    detection: {
      edrCoverage: e.detection.edrCoverage,
      sigmaRules: e.detection.sigmaRules.length,
      sysmonEvents: e.detection.sysmonEvents,
      logSources: e.detection.logSources,
    },
  };
}

// ━━━ Tools ━━━

const forensic_event_log: ToolDef = {
  name: "forensic_event_log",
  description: "Analyze Windows Event Log entries for LOL technique indicators. Provide event source, ID, and field values to identify LOL binary abuse.",
  schema: {
    log_source: z.string().describe("Event log source (e.g. Security, Sysmon, PowerShell, BITS-Client)"),
    event_id: z.number().describe("Windows Event ID number"),
    fields: z.record(z.string()).optional().describe("Event field values to match against (e.g. {NewProcessName: 'certutil', ProcessCommandLine: '-urlcache'})"),
    platform: z.string().optional().describe("Target platform for KB filtering"),
  },
  async execute(args: { log_source: string; event_id: number; fields?: Record<string, string>; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const sourceLower = args.log_source.toLowerCase();
    const matches: Array<EventLogIndicator & { fieldMatches: Record<string, string> }> = [];

    for (const indicator of EVENT_LOG_INDICATORS) {
      if (indicator.logSource.toLowerCase() !== sourceLower) continue;
      if (indicator.eventId !== args.event_id) continue;

      if (!args.fields) {
        // No fields provided, return all matching indicators for this source+eventID
        matches.push({ ...indicator, fieldMatches: {} });
        continue;
      }

      // Match provided fields against indicator fields
      const fieldMatches: Record<string, string> = {};
      let allMatch = true;

      for (const [indicatorField, indicatorValue] of Object.entries(indicator.indicatorFields)) {
        const providedValue = args.fields[indicatorField];
        if (providedValue && providedValue.toLowerCase().includes(indicatorValue.toLowerCase())) {
          fieldMatches[indicatorField] = indicatorValue;
        } else if (!providedValue) {
          // Field not provided, don't fail the match
          continue;
        } else {
          allMatch = false;
          break;
        }
      }

      if (allMatch && Object.keys(fieldMatches).length > 0) {
        matches.push({ ...indicator, fieldMatches });
      }
    }

    // Get KB entries for matched binaries
    const matchedBinaries = new Set(matches.map(m => m.binary));
    const kbEntries: Record<string, Record<string, unknown>[]> = {};
    for (const binary of matchedBinaries) {
      const entries = ctx.knowledgeBase.lookupBinary(binary, args.platform as Platform);
      if (entries.length > 0) {
        kbEntries[binary] = deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry);
      }
    }

    return json({
      logSource: args.log_source,
      eventId: args.event_id,
      providedFields: args.fields || {},
      totalMatches: matches.length,
      matches: matches.map(m => ({
        technique: m.technique,
        binary: m.binary,
        attckId: m.attckId,
        description: m.description,
        severity: m.severity,
        falsePositiveRate: m.falsePositiveRate,
        indicatorFields: m.indicatorFields,
        fieldMatches: m.fieldMatches,
      })),
      kbEntries,
    });
  },
};

const forensic_procmon: ToolDef = {
  name: "forensic_procmon",
  description: "Analyze Process Monitor (ProcMon) trace entries for LOL binary abuse patterns. Match operation, process, and path.",
  schema: {
    operation: z.string().describe("ProcMon operation type (e.g. CreateFile, RegSetValue, TCP Connect, Process Create)"),
    process_name: z.string().describe("Process name from ProcMon trace (e.g. certutil.exe, powershell.exe)"),
    path: z.string().optional().describe("Path or target from ProcMon entry (file path, registry key, network endpoint)"),
  },
  async execute(args: { operation: string; process_name: string; path?: string }, ctx: ToolContext): Promise<ToolResult> {
    const opLower = args.operation.toLowerCase();
    const procLower = args.process_name.toLowerCase();
    const pathLower = args.path?.toLowerCase() || "";

    const matches: Array<ProcMonPattern & { matchConfidence: "high" | "medium" | "low" }> = [];

    for (const pattern of PROCMON_PATTERNS) {
      const opMatch = pattern.operation.toLowerCase() === opLower;
      const procMatch = procLower.includes(pattern.processName.toLowerCase().replace(".exe", "")) ||
                        pattern.processName.toLowerCase().includes(procLower.replace(".exe", ""));

      if (opMatch && procMatch) {
        let confidence: "high" | "medium" | "low" = "medium";

        // Check path pattern match if provided
        if (args.path && pattern.pathPattern !== "*") {
          const pathPatLower = pattern.pathPattern.toLowerCase().replace("*", "");
          if (pathLower.includes(pathPatLower) || pathPatLower.includes(pathLower.replace(/\\/g, "/"))) {
            confidence = "high";
          }
        } else if (!args.path) {
          confidence = "low";
        }

        matches.push({ ...pattern, matchConfidence: confidence });
      }
    }

    // Sort by confidence
    matches.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return order[a.matchConfidence] - order[b.matchConfidence];
    });

    // Get KB entries
    const binaryName = args.process_name.replace(/\.exe$/i, "");
    const kbEntries = ctx.knowledgeBase.lookupBinary(binaryName);

    return json({
      operation: args.operation,
      processName: args.process_name,
      path: args.path,
      totalMatches: matches.length,
      matches: matches.map(m => ({
        technique: m.technique,
        binary: m.binary,
        attckId: m.attckId,
        description: m.description,
        severity: m.severity,
        expectedPathPattern: m.pathPattern,
        matchConfidence: m.matchConfidence,
      })),
      kbEntries: deduplicateByBinary(kbEntries).slice(0, 5).map(summarizeKbEntry),
    });
  },
};

const forensic_edr_alert: ToolDef = {
  name: "forensic_edr_alert",
  description: "Analyze EDR alerts and map them to specific LOL techniques with KB enrichment for forensic investigation",
  schema: {
    alert_title: z.string().describe("EDR alert title or name"),
    alert_description: z.string().optional().describe("EDR alert description text"),
    process_name: z.string().optional().describe("Process name from the EDR alert"),
    command_line: z.string().optional().describe("Command line from the EDR alert"),
    parent_process: z.string().optional().describe("Parent process from the EDR alert"),
  },
  async execute(args: {
    alert_title: string;
    alert_description?: string;
    process_name?: string;
    command_line?: string;
    parent_process?: string;
  }, ctx: ToolContext): Promise<ToolResult> {
    const combinedText = [
      args.alert_title,
      args.alert_description || "",
      args.process_name || "",
      args.command_line || "",
    ].join(" ").toLowerCase();

    // Match against known LOL binaries in the alert
    const knownBinaries = [
      "certutil", "powershell", "mshta", "regsvr32", "rundll32",
      "bitsadmin", "cmstp", "wmic", "wscript", "cscript",
      "msiexec", "cmd", "schtasks", "reg",
    ];

    const detectedBinaries = knownBinaries.filter(b => combinedText.includes(b));

    // Check for technique-specific keywords
    const techniqueKeywords: Array<{ keywords: string[]; technique: string; attckId: string; severity: string }> = [
      { keywords: ["download", "urlcache", "transfer"], technique: "File Download", attckId: "T1105", severity: "high" },
      { keywords: ["encode", "decode", "base64", "obfuscat"], technique: "Obfuscation", attckId: "T1140", severity: "medium" },
      { keywords: ["persistence", "run key", "startup", "scheduled task"], technique: "Persistence", attckId: "T1547", severity: "high" },
      { keywords: ["lateral", "remote", "wmi", "psexec"], technique: "Lateral Movement", attckId: "T1047", severity: "critical" },
      { keywords: ["bypass", "whitelist", "applocker", "awl"], technique: "AWL Bypass", attckId: "T1218", severity: "critical" },
      { keywords: ["injection", "hollowing", "dll"], technique: "Process Injection", attckId: "T1055", severity: "critical" },
      { keywords: ["exfil", "upload", "staging"], technique: "Exfiltration", attckId: "T1567", severity: "high" },
      { keywords: ["c2", "command and control", "beacon", "callback"], technique: "C2 Communication", attckId: "T1071", severity: "critical" },
      { keywords: ["credential", "dump", "mimikatz", "lsass"], technique: "Credential Access", attckId: "T1003", severity: "critical" },
      { keywords: ["privilege", "escalat", "uac"], technique: "Privilege Escalation", attckId: "T1548", severity: "high" },
    ];

    const matchedTechniques = techniqueKeywords
      .filter(tk => tk.keywords.some(kw => combinedText.includes(kw)))
      .map(tk => ({
        technique: tk.technique,
        attckId: tk.attckId,
        severity: tk.severity,
        matchedKeywords: tk.keywords.filter(kw => combinedText.includes(kw)),
      }));

    // Get KB entries for detected binaries
    const kbEntries: Record<string, Record<string, unknown>[]> = {};
    for (const binary of detectedBinaries) {
      const entries = ctx.knowledgeBase.lookupBinary(binary);
      if (entries.length > 0) {
        kbEntries[binary] = deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry);
      }
    }

    // Determine overall threat level
    const severities = matchedTechniques.map(m => m.severity);
    const threatLevel = severities.includes("critical") ? "critical"
      : severities.includes("high") ? "high"
      : severities.includes("medium") ? "medium"
      : "low";

    return json({
      alertTitle: args.alert_title,
      alertDescription: args.alert_description,
      threatLevel,
      detectedBinaries,
      matchedTechniques,
      forensicContext: {
        processName: args.process_name,
        commandLine: args.command_line,
        parentProcess: args.parent_process,
      },
      kbEntries,
      recommendations: [
        detectedBinaries.length > 0 ? `Investigate ${detectedBinaries.join(", ")} execution context and parent process` : null,
        args.command_line ? "Analyze full command line for encoded/obfuscated content" : null,
        args.parent_process ? `Verify parent process (${args.parent_process}) legitimacy` : null,
        "Check for lateral movement indicators on adjacent systems",
        "Review file system changes in Temp and ProgramData directories",
      ].filter(Boolean),
    });
  },
};

const forensic_network_capture: ToolDef = {
  name: "forensic_network_capture",
  description: "Analyze network traffic patterns for LOL-based C2, exfiltration, and payload delivery indicators",
  schema: {
    protocol: z.string().describe("Network protocol observed (HTTP, HTTPS, DNS, ICMP, TCP)"),
    destination: z.string().optional().describe("Destination host, IP, or domain"),
    user_agent: z.string().optional().describe("HTTP User-Agent string if available"),
    url_path: z.string().optional().describe("URL path from HTTP request"),
    payload_size: z.number().optional().describe("Payload/packet size in bytes"),
    frequency: z.string().optional().describe("Traffic frequency pattern (e.g. 'periodic-30s', 'burst', 'continuous')"),
  },
  async execute(args: {
    protocol: string;
    destination?: string;
    user_agent?: string;
    url_path?: string;
    payload_size?: number;
    frequency?: string;
  }, ctx: ToolContext): Promise<ToolResult> {
    const protocolUpper = args.protocol.toUpperCase();
    const matches: Array<NetworkIndicator & { matchConfidence: "high" | "medium" | "low" }> = [];

    for (const indicator of NETWORK_INDICATORS) {
      if (indicator.protocol.toUpperCase() !== protocolUpper) continue;

      let confidence: "high" | "medium" | "low" = "low";

      // Check User-Agent match
      if (args.user_agent && indicator.pattern.toLowerCase().includes("user-agent")) {
        const patternValue = indicator.pattern.match(/containing '(.+?)'/)?.[1]?.toLowerCase();
        if (patternValue && args.user_agent.toLowerCase().includes(patternValue)) {
          confidence = "high";
          matches.push({ ...indicator, matchConfidence: confidence });
          continue;
        }
      }

      // Check URL path match
      if (args.url_path && indicator.pattern.toLowerCase().includes("url path")) {
        const extension = indicator.pattern.match(/ending in (\.\w+)/)?.[1];
        if (extension && args.url_path.toLowerCase().endsWith(extension)) {
          confidence = "high";
          matches.push({ ...indicator, matchConfidence: confidence });
          continue;
        }
      }

      // Check destination match
      if (args.destination && indicator.pattern.toLowerCase().includes(args.destination.toLowerCase())) {
        confidence = "high";
        matches.push({ ...indicator, matchConfidence: confidence });
        continue;
      }

      // Check generic patterns
      if (args.payload_size && indicator.pattern.toLowerCase().includes("large") && args.payload_size > 64) {
        confidence = "medium";
        matches.push({ ...indicator, matchConfidence: confidence });
        continue;
      }

      if (args.frequency && indicator.pattern.toLowerCase().includes("frequency") && args.frequency.includes("periodic")) {
        confidence = "medium";
        matches.push({ ...indicator, matchConfidence: confidence });
        continue;
      }

      // Add with low confidence if protocol matches but no specific field match
      if (indicator.protocol.toUpperCase() === protocolUpper) {
        matches.push({ ...indicator, matchConfidence: "low" });
      }
    }

    // Sort by confidence
    matches.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return order[a.matchConfidence] - order[b.matchConfidence];
    });

    // Only return high/medium confidence if there are any
    const highMedMatches = matches.filter(m => m.matchConfidence !== "low");
    const finalMatches = highMedMatches.length > 0 ? highMedMatches : matches.slice(0, 5);

    // Get KB entries for identified binaries
    const identifiedBinaries = new Set(finalMatches.map(m => m.binary));
    const kbEntries: Record<string, Record<string, unknown>[]> = {};
    for (const binary of identifiedBinaries) {
      if (binary === "dns") continue; // Not a binary
      const entries = ctx.knowledgeBase.lookupBinary(binary);
      if (entries.length > 0) {
        kbEntries[binary] = deduplicateByBinary(entries).slice(0, 3).map(summarizeKbEntry);
      }
    }

    return json({
      protocol: args.protocol,
      destination: args.destination,
      analysisInput: {
        userAgent: args.user_agent,
        urlPath: args.url_path,
        payloadSize: args.payload_size,
        frequency: args.frequency,
      },
      totalIndicators: finalMatches.length,
      indicators: finalMatches.map(m => ({
        technique: m.technique,
        binary: m.binary,
        attckId: m.attckId,
        description: m.description,
        severity: m.severity,
        matchPattern: m.pattern,
        matchConfidence: m.matchConfidence,
      })),
      kbEntries,
    });
  },
};

export const forensicArtifactTools: ToolDef[] = [
  forensic_event_log,
  forensic_procmon,
  forensic_edr_alert,
  forensic_network_capture,
];
