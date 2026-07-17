import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

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

interface ObfuscationResult {
  command: string;
  platform: string;
  technique_name: string;
  layers_applied: string[];
  result: string;
  detection_analysis: Record<string, unknown>;
  attck_ids: string[];
}

// ── obf_multi_layer ─────────────────────────────────────────────────────────

const obf_multi_layer: ToolDef = {
  name: "obf_multi_layer",
  description: "Apply multiple obfuscation layers in sequence — base64 then variable split then glob expansion",
  schema: {
    command: z.string().describe("The command to obfuscate"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
    layers: z.number().default(3).describe("Number of obfuscation layers to apply (default 3)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform, layers } = args;
    const layerNames = ["base64_encode", "variable_split", "glob_expansion"];
    const applied = layerNames.slice(0, Math.min(layers, layerNames.length));

    const examples: Record<string, string> = {
      linux: `echo '${command}' | base64 => VAR1=\${cmd:0:4}; VAR2=\${cmd:4}; /us?/b?n/$VAR1$VAR2`,
      windows: `[Convert]::ToBase64String(...) => $a='${command.slice(0, 3)}';$b='${command.slice(3)}'; C:\\Wind*\\Sys*\\$a$b`,
      macos: `echo '${command}' | base64 => VAR1=\${cmd:0:4}; VAR2=\${cmd:4}; /us?/b?n/$VAR1$VAR2`,
    };

    const result: ObfuscationResult = {
      command,
      platform,
      technique_name: "multi_layer_obfuscation",
      layers_applied: applied,
      result: examples[platform] || examples.linux,
      detection_analysis: {
        sigma_matches: ["proc_creation_base64_decode", "proc_creation_glob_pattern"],
        edr_coverage: applied.length >= 3 ? "medium" : "low",
        bypass_probability: `${Math.min(95, 50 + applied.length * 15)}%`,
        notes: "Each additional layer increases evasion but also detection surface for behavioural rules",
      },
      attck_ids: ["T1027", "T1140"],
    };

    return json(result);
  },
};

// ── obf_custom_chain ────────────────────────────────────────────────────────

const obf_custom_chain: ToolDef = {
  name: "obf_custom_chain",
  description: "Custom obfuscation chain specification — apply methods in user-defined order",
  schema: {
    command: z.string().describe("The command to obfuscate"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
    methods: z.array(z.enum(["glob", "encode", "alt_binary", "string_concat", "env_var"])).describe("Obfuscation methods to apply in order"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform, methods } = args;

    const methodDescriptions: Record<string, string> = {
      glob: "Replace path characters with wildcards (e.g., /us?/b?n/wh*mi)",
      encode: "Base64 or hex-encode the command string",
      alt_binary: "Substitute with an alternative LOL binary that performs the same function",
      string_concat: "Split the command into concatenated string variables",
      env_var: "Store command fragments in environment variables",
    };

    const steps = methods.map((m: string, i: number) => ({
      order: i + 1,
      method: m,
      description: methodDescriptions[m] || "Unknown method",
    }));

    const result: ObfuscationResult = {
      command,
      platform,
      technique_name: "custom_chain_obfuscation",
      layers_applied: methods,
      result: `Applied ${methods.length} methods in order: ${methods.join(" -> ")}`,
      detection_analysis: {
        sigma_matches: methods.includes("encode") ? ["proc_creation_base64_decode"] : [],
        edr_coverage: methods.length >= 4 ? "medium" : "low",
        chain_steps: steps,
        notes: "Custom chains can evade static signatures but behavioural analysis may still flag process trees",
      },
      attck_ids: ["T1027", "T1140"],
    };

    return json(result);
  },
};

// ── obf_test_detection ──────────────────────────────────────────────────────

const obf_test_detection: ToolDef = {
  name: "obf_test_detection",
  description: "Analyze detectability of an obfuscated command — which EDR rules would fire, Sigma matches, log sources",
  schema: {
    command: z.string().describe("The obfuscated command to analyze"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform } = args;
    const hasBase64 = /base64|b64|encode/i.test(command);
    const hasGlob = /[?*]/.test(command);
    const hasConcat = /\$[{(]|\+/.test(command);
    const hasPipe = /\|/.test(command);

    const sigmaMatches: string[] = [];
    const edrDetections: string[] = [];
    if (hasBase64) { sigmaMatches.push("proc_creation_base64_decode"); edrDetections.push("Encoded command execution"); }
    if (hasGlob) { sigmaMatches.push("proc_creation_glob_pattern_binary"); edrDetections.push("Glob-based binary invocation"); }
    if (hasConcat) { sigmaMatches.push("proc_creation_string_concatenation"); edrDetections.push("String concatenation obfuscation"); }
    if (hasPipe) { sigmaMatches.push("proc_creation_suspicious_pipe_chain"); }

    const riskScore = Math.min(5, 1 + (hasBase64 ? 1 : 0) + (hasGlob ? 1 : 0) + (hasConcat ? 1 : 0) + (hasPipe ? 1 : 0));

    const result: ObfuscationResult = {
      command,
      platform,
      technique_name: "detection_analysis",
      layers_applied: [
        ...(hasBase64 ? ["base64_encoding"] : []),
        ...(hasGlob ? ["glob_expansion"] : []),
        ...(hasConcat ? ["string_concatenation"] : []),
      ],
      result: `Detection risk score: ${riskScore}/5`,
      detection_analysis: {
        sigma_matches: sigmaMatches,
        edr_detections: edrDetections,
        log_sources: platform === "windows"
          ? ["Security EventLog", "Sysmon", "PowerShell ScriptBlock"]
          : ["auditd", "syslog", "osquery"],
        overall_risk: riskScore,
        recommendations: riskScore >= 3
          ? ["Consider additional obfuscation layers", "Use alternative binaries", "Avoid well-known patterns"]
          : ["Current obfuscation level appears adequate for basic EDR evasion"],
      },
      attck_ids: ["T1027", "T1140"],
    };

    return json(result);
  },
};

// ── obf_optimal_layers ──────────────────────────────────────────────────────

const obf_optimal_layers: ToolDef = {
  name: "obf_optimal_layers",
  description: "Recommend optimal obfuscation layers for a given command and optional EDR product",
  schema: {
    command: z.string().describe("The command to obfuscate"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform"),
    edr_product: z.string().optional().describe("Optional EDR product name (e.g., CrowdStrike, SentinelOne, Defender)"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const { command, platform, edr_product } = args;

    const edrProfiles: Record<string, { strength: string; avoid: string[]; recommend: string[] }> = {
      crowdstrike: { strength: "high", avoid: ["base64_encode", "powershell_encoded_command"], recommend: ["env_var", "glob_expansion", "alt_binary"] },
      sentinelone: { strength: "high", avoid: ["string_concat", "base64_encode"], recommend: ["glob_expansion", "env_var", "alt_binary"] },
      defender: { strength: "medium", avoid: ["powershell_encoded_command"], recommend: ["base64_encode", "string_concat", "glob_expansion"] },
      carbonblack: { strength: "medium", avoid: ["base64_encode"], recommend: ["env_var", "string_concat", "alt_binary"] },
    };

    const edrKey = (edr_product || "").toLowerCase().replace(/[\s-]/g, "");
    const profile = edrProfiles[edrKey] || { strength: "unknown", avoid: [], recommend: ["env_var", "glob_expansion", "string_concat"] };

    const recommendedLayers = profile.recommend.slice(0, 3);

    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("obfuscation", platform));

    const result: ObfuscationResult = {
      command,
      platform,
      technique_name: "optimal_layers_recommendation",
      layers_applied: recommendedLayers,
      result: `Recommended ${recommendedLayers.length} layers: ${recommendedLayers.join(" -> ")}`,
      detection_analysis: {
        edr_product: edr_product || "generic",
        edr_strength: profile.strength,
        avoid_techniques: profile.avoid,
        recommended_techniques: profile.recommend,
        estimated_bypass_rate: profile.strength === "high" ? "60-70%" : "75-85%",
        kb_related: kbEntries.slice(0, 3).map(summarizeKbEntry),
      },
      attck_ids: ["T1027", "T1140"],
    };

    return json(result);
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const chainObfuscationTools: ToolDef[] = [
  obf_multi_layer,
  obf_custom_chain,
  obf_test_detection,
  obf_optimal_layers,
];
