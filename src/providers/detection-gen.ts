import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

function deduplicateByBinary(entries: UnifiedLOLEntry[]): UnifiedLOLEntry[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    const key = `${e.binary}-${e.platform}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function generateSigmaYaml(entry: UnifiedLOLEntry, technique?: string): string {
  const title = technique
    ? `LOL ${entry.binary} - ${technique}`
    : `Suspicious ${entry.binary} Execution`;
  const contexts = entry.executionContexts.slice(0, 3);
  const cmdPatterns = contexts.map(c => c.command.split(" ").slice(1).join(" ")).filter(Boolean);

  let yaml = `title: ${title}\n`;
  yaml += `id: generated-${entry.id}-${Date.now()}\n`;
  yaml += `status: experimental\n`;
  yaml += `description: Detects suspicious usage of ${entry.binary} for ${entry.functions.join(", ")}\n`;
  yaml += `references:\n`;
  for (const r of entry.resources.slice(0, 3)) {
    yaml += `  - ${r}\n`;
  }
  yaml += `author: LOL-MCP Detection Generator\n`;
  yaml += `date: ${new Date().toISOString().split("T")[0]}\n`;
  yaml += `tags:\n`;
  for (const t of entry.attckTechniques) {
    yaml += `  - attack.${t.toLowerCase()}\n`;
  }
  yaml += `logsource:\n`;
  yaml += `  category: process_creation\n`;
  yaml += `  product: windows\n`;
  yaml += `detection:\n`;
  yaml += `  selection:\n`;
  yaml += `    Image|endswith: '\\\\${entry.binary}.exe'\n`;
  if (cmdPatterns.length > 0) {
    yaml += `  condition_args:\n`;
    yaml += `    CommandLine|contains:\n`;
    for (const p of cmdPatterns.slice(0, 5)) {
      yaml += `      - '${p.replace(/'/g, "''")}'\n`;
    }
    yaml += `  condition: selection and condition_args\n`;
  } else {
    yaml += `  condition: selection\n`;
  }
  yaml += `falsepositives:\n`;
  yaml += `  - Legitimate administrative usage of ${entry.binary}\n`;
  yaml += `level: ${entry.stealthScore >= 4 ? "high" : entry.stealthScore >= 3 ? "medium" : "low"}\n`;

  return yaml;
}

function generateYaraRule(entry: UnifiedLOLEntry): string {
  const ruleName = `LOL_${entry.binary.replace(/[^a-zA-Z0-9]/g, "_")}_artifact`;
  const contexts = entry.executionContexts.slice(0, 5);
  const strings = contexts.map((c, i) => {
    const pattern = c.command.length > 10 ? c.command.substring(0, 50) : c.command;
    return `    $cmd${i} = "${pattern.replace(/"/g, '\\"')}" ascii nocase`;
  });

  let rule = `rule ${ruleName} {\n`;
  rule += `  meta:\n`;
  rule += `    description = "Detects ${entry.binary} LOL technique artifacts"\n`;
  rule += `    author = "LOL-MCP Detection Generator"\n`;
  rule += `    date = "${new Date().toISOString().split("T")[0]}"\n`;
  for (const t of entry.attckTechniques.slice(0, 3)) {
    rule += `    mitre_att_ck = "${t}"\n`;
  }
  rule += `    severity = "${entry.stealthScore >= 4 ? "high" : "medium"}"\n`;
  rule += `  strings:\n`;
  rule += strings.join("\n") + "\n";
  rule += `  condition:\n`;
  rule += `    any of ($cmd*)\n`;
  rule += `}\n`;

  return rule;
}

// ━━━ Tools ━━━

const gen_sigma_rule: ToolDef = {
  name: "gen_sigma_rule",
  description: "Generate Sigma detection rule YAML for a given binary/technique. Produces deployable rule based on KB execution contexts.",
  schema: {
    binary: z.string().describe("Binary name to generate Sigma rule for"),
    technique: z.string().optional().describe("Specific technique name to focus detection on"),
    platform: z.string().optional().describe("Target platform (windows, linux, macos)"),
  },
  async execute(args: { binary: string; technique?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, args.platform as Platform);
    if (entries.length === 0) return text(`No KB entries found for binary: ${args.binary}`);

    const entry = entries[0];
    const sigmaYaml = generateSigmaYaml(entry, args.technique);

    return json({
      binary: entry.binary,
      platform: entry.platform,
      technique: args.technique || entry.functions.join(", "),
      attckTechniques: entry.attckTechniques,
      sigmaRule: sigmaYaml,
      existingRules: entry.detection.sigmaRules,
    });
  },
};

const gen_yara_rule: ToolDef = {
  name: "gen_yara_rule",
  description: "Generate YARA rule for detecting file-based LOL technique artifacts. Creates rule from KB execution context patterns.",
  schema: {
    binary: z.string().describe("Binary name to generate YARA rule for"),
    platform: z.string().optional().describe("Target platform"),
  },
  async execute(args: { binary: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, args.platform as Platform);
    if (entries.length === 0) return text(`No KB entries found for binary: ${args.binary}`);

    const entry = entries[0];
    const yaraRule = generateYaraRule(entry);

    return json({
      binary: entry.binary,
      platform: entry.platform,
      functions: entry.functions,
      yaraRule,
      existingYaraRules: entry.detection.yaraRules,
    });
  },
};

const gen_sysmon_config: ToolDef = {
  name: "gen_sysmon_config",
  description: "Generate Sysmon config XML snippet to detect specific LOL techniques. Produces event filtering rules for the binary.",
  schema: {
    binary: z.string().describe("Binary name to generate Sysmon config for"),
    event_ids: z.array(z.number()).optional().describe("Specific Sysmon event IDs to configure (default: auto-detect)"),
  },
  async execute(args: { binary: string; event_ids?: number[] }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, "windows" as Platform);
    if (entries.length === 0) return text(`No KB entries found for binary: ${args.binary}`);

    const entry = entries[0];
    const eventIds = args.event_ids || entry.detection.sysmonEvents;
    const effectiveEvents = eventIds.length > 0 ? eventIds : [1, 3, 11];

    let xml = `<!-- Sysmon Config for ${entry.binary} LOL Detection -->\n`;
    xml += `<RuleGroup groupRelation="or">\n`;

    for (const eventId of effectiveEvents) {
      switch (eventId) {
        case 1:
          xml += `  <!-- Event ID 1: Process Create -->\n`;
          xml += `  <ProcessCreate onmatch="include">\n`;
          xml += `    <Image condition="end with">${entry.binary}.exe</Image>\n`;
          for (const ctx2 of entry.executionContexts.slice(0, 3)) {
            const cmdPart = ctx2.command.split(" ").slice(1, 3).join(" ");
            if (cmdPart) {
              xml += `    <CommandLine condition="contains">${cmdPart.replace(/[<>&]/g, "")}</CommandLine>\n`;
            }
          }
          xml += `  </ProcessCreate>\n`;
          break;
        case 3:
          xml += `  <!-- Event ID 3: Network Connection -->\n`;
          xml += `  <NetworkConnect onmatch="include">\n`;
          xml += `    <Image condition="end with">${entry.binary}.exe</Image>\n`;
          xml += `  </NetworkConnect>\n`;
          break;
        case 7:
          xml += `  <!-- Event ID 7: Image Loaded -->\n`;
          xml += `  <ImageLoad onmatch="include">\n`;
          xml += `    <Image condition="end with">${entry.binary}.exe</Image>\n`;
          xml += `  </ImageLoad>\n`;
          break;
        case 11:
          xml += `  <!-- Event ID 11: File Create -->\n`;
          xml += `  <FileCreate onmatch="include">\n`;
          xml += `    <Image condition="end with">${entry.binary}.exe</Image>\n`;
          xml += `  </FileCreate>\n`;
          break;
        default:
          xml += `  <!-- Event ID ${eventId} -->\n`;
      }
    }

    xml += `</RuleGroup>\n`;

    return json({
      binary: entry.binary,
      sysmonEvents: effectiveEvents,
      configXml: xml,
      notes: `Deploy this config snippet in your Sysmon configuration to monitor ${entry.binary} activity`,
    });
  },
};

const gen_edr_query: ToolDef = {
  name: "gen_edr_query",
  description: "Generate EDR query in KQL/SPL/Lucene for a given LOL technique. Produces ready-to-deploy search query for your SIEM/EDR.",
  schema: {
    binary: z.string().describe("Binary name to generate query for"),
    edr_product: z.enum(["kql", "spl", "lucene"]).describe("Query language: kql (Microsoft Defender/Sentinel), spl (Splunk), lucene (Elastic)"),
    technique: z.string().optional().describe("Specific technique to focus on"),
  },
  async execute(args: { binary: string; edr_product: string; technique?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary);
    if (entries.length === 0) return text(`No KB entries found for binary: ${args.binary}`);

    const entry = entries[0];
    const cmdParts = entry.executionContexts
      .slice(0, 5)
      .map(c => c.command.split(" ").slice(1).join(" "))
      .filter(Boolean);

    let query = "";

    switch (args.edr_product) {
      case "kql":
        query = `DeviceProcessEvents\n| where FileName =~ "${entry.binary}.exe"\n`;
        if (cmdParts.length > 0) {
          query += `| where ProcessCommandLine has_any (${cmdParts.slice(0, 5).map(p => `"${p.substring(0, 40)}"`).join(", ")})\n`;
        }
        query += `| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName\n`;
        query += `| sort by Timestamp desc`;
        break;
      case "spl":
        query = `index=* sourcetype=* process_name="${entry.binary}.exe"\n`;
        if (cmdParts.length > 0) {
          const orClauses = cmdParts.slice(0, 5).map(p => `"${p.substring(0, 40)}"`).join(" OR ");
          query += `| search command_line=(${orClauses})\n`;
        }
        query += `| table _time, host, user, command_line, parent_process\n`;
        query += `| sort - _time`;
        break;
      case "lucene":
        query = `process.name:"${entry.binary}.exe"`;
        if (cmdParts.length > 0) {
          const parts = cmdParts.slice(0, 3).map(p => `"${p.substring(0, 40)}"`).join(" OR ");
          query += ` AND process.command_line:(${parts})`;
        }
        break;
    }

    return json({
      binary: entry.binary,
      queryLanguage: args.edr_product,
      technique: args.technique || entry.functions.join(", "),
      query,
      attckTechniques: entry.attckTechniques,
      notes: `Query targets ${entry.binary} with suspicious arguments. Tune thresholds based on environment baseline.`,
    });
  },
};

const gen_hunt_query: ToolDef = {
  name: "gen_hunt_query",
  description: "Generate threat hunting query for a specific binary/technique. Produces proactive hunting hypothesis and detection logic.",
  schema: {
    binary: z.string().describe("Binary name to hunt for"),
    hypothesis: z.string().optional().describe("Hunting hypothesis (e.g. 'attacker using certutil for download')"),
    platform: z.string().optional().describe("Target platform"),
  },
  async execute(args: { binary: string; hypothesis?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, args.platform as Platform);
    if (entries.length === 0) return text(`No KB entries found for binary: ${args.binary}`);

    const entry = entries[0];
    const hypothesis = args.hypothesis || `Adversary using ${entry.binary} for ${entry.functions.join(" or ")}`;

    const huntQueries = {
      kql: `// Hypothesis: ${hypothesis}\nDeviceProcessEvents\n| where FileName =~ "${entry.binary}.exe"\n| where Timestamp > ago(30d)\n| summarize ExecutionCount=count(), UniqueHosts=dcount(DeviceName) by ProcessCommandLine\n| where ExecutionCount < 5\n| sort by ExecutionCount asc`,
      spl: `// Hypothesis: ${hypothesis}\nindex=* sourcetype=* process_name="${entry.binary}.exe" earliest=-30d\n| stats count dc(host) as unique_hosts by command_line\n| where count < 5\n| sort count`,
    };

    return json({
      binary: entry.binary,
      platform: entry.platform,
      hypothesis,
      attckTechniques: entry.attckTechniques,
      functions: entry.functions,
      huntQueries,
      dataSourcesRequired: entry.detection.logSources,
      sysmonEventsNeeded: entry.detection.sysmonEvents,
      expectedFalsePositives: [
        `Legitimate admin usage of ${entry.binary}`,
        "Automated system maintenance scripts",
        "Software deployment tools",
      ],
      successCriteria: `Identify anomalous ${entry.binary} executions not matching known-good baselines`,
    });
  },
};

const gen_atomic_test: ToolDef = {
  name: "gen_atomic_test",
  description: "Generate Atomic Red Team test YAML for validation of detection rules against a LOL technique.",
  schema: {
    binary: z.string().describe("Binary name to generate atomic test for"),
    technique_id: z.string().optional().describe("ATT&CK technique ID (e.g. T1105)"),
    platform: z.string().optional().describe("Target platform"),
  },
  async execute(args: { binary: string; technique_id?: string; platform?: string }, ctx: ToolContext): Promise<ToolResult> {
    const entries = ctx.knowledgeBase.lookupBinary(args.binary, args.platform as Platform);
    if (entries.length === 0) return text(`No KB entries found for binary: ${args.binary}`);

    const entry = entries[0];
    const techniqueId = args.technique_id || entry.attckTechniques[0] || "T1000";
    const contexts = entry.executionContexts.slice(0, 3);

    let yaml = `attack_technique: ${techniqueId}\n`;
    yaml += `display_name: "LOL ${entry.binary} - ${entry.functions.join(", ")}"\n`;
    yaml += `atomic_tests:\n`;

    for (let i = 0; i < contexts.length; i++) {
      const ctx2 = contexts[i];
      yaml += `  - name: "${entry.binary} ${ctx2.result}"\n`;
      yaml += `    auto_generated_guid: gen-${Date.now()}-${i}\n`;
      yaml += `    description: |\n`;
      yaml += `      Test ${entry.binary} execution for ${ctx2.result}.\n`;
      yaml += `      Prerequisites: ${ctx2.prerequisite || "none"}\n`;
      yaml += `    supported_platforms:\n`;
      yaml += `      - ${entry.platform}\n`;
      yaml += `    executor:\n`;
      yaml += `      name: ${entry.platform === "windows" ? "command_prompt" : "sh"}\n`;
      yaml += `      command: |\n`;
      yaml += `        ${ctx2.command}\n`;
      if (ctx2.prerequisite) {
        yaml += `    dependency_executor_name: ${entry.platform === "windows" ? "powershell" : "sh"}\n`;
        yaml += `    dependencies:\n`;
        yaml += `      - description: "${ctx2.prerequisite}"\n`;
        yaml += `        prereq_command: |\n`;
        yaml += `          where ${entry.binary}\n`;
        yaml += `        get_prereq_command: |\n`;
        yaml += `          echo "Install ${entry.binary} manually"\n`;
      }
    }

    return json({
      binary: entry.binary,
      platform: entry.platform,
      techniqueId,
      attckTechniques: entry.attckTechniques,
      atomicTestYaml: yaml,
      existingAtomicTests: entry.detection.atomicTests,
    });
  },
};

export const detectionGenTools: ToolDef[] = [
  gen_sigma_rule,
  gen_yara_rule,
  gen_sysmon_config,
  gen_edr_query,
  gen_hunt_query,
  gen_atomic_test,
];
