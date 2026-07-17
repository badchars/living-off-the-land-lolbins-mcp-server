import { parse as parseYAML } from "yaml";
import type { UnifiedLOLEntry, LOLFunction, Platform } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";

// ━━━ LOFLCAB function → LOLFunction ━━━
const FUNCTION_MAP: Record<string, LOLFunction> = {
  "shell": "shell",
  "command": "command",
  "reverse-shell": "reverse_shell",
  "reverse_shell": "reverse_shell",
  "bind-shell": "bind_shell",
  "bind_shell": "bind_shell",
  "file-write": "file_write",
  "file_write": "file_write",
  "file-read": "file_read",
  "file_read": "file_read",
  "upload": "upload",
  "download": "download",
  "library-load": "library_load",
  "library_load": "library_load",
  "privilege-escalation": "privilege_escalation",
  "privilege_escalation": "privilege_escalation",
  "persistence": "persistence",
  "lateral-movement": "lateral_movement",
  "lateral_movement": "lateral_movement",
  "defense-evasion": "defense_evasion",
  "defense_evasion": "defense_evasion",
  "credential-access": "credential_access",
  "credential_access": "credential_access",
  "execute": "command_execution",
  "execution": "command_execution",
  "command_execution": "command_execution",
  "reconnaissance": "reconnaissance",
  "c2": "c2",
};

// ━━━ Function → ATT&CK mapping ━━━
const ATTCK_MAP: Record<string, string> = {
  "shell": "T1059",
  "command": "T1059",
  "reverse_shell": "T1059",
  "bind_shell": "T1059",
  "file_write": "T1565",
  "file_read": "T1005",
  "upload": "T1041",
  "download": "T1105",
  "library_load": "T1574",
  "privilege_escalation": "T1548",
  "command_execution": "T1059",
};

function detectPlatform(entry: any, filename: string): Platform {
  const os = (entry.os || entry.platform || "").toLowerCase();
  if (os.includes("windows") || os.includes("win")) return "windows";
  if (os.includes("macos") || os.includes("darwin") || os.includes("mac")) return "macos";
  if (os.includes("esxi")) return "esxi";
  if (os.includes("linux")) return "linux";
  // Heuristic: .exe = windows
  if (filename.endsWith(".exe") || filename.endsWith(".dll")) return "windows";
  return "linux";
}

export function parseLOFLCABEntry(filename: string, content: string): UnifiedLOLEntry | null {
  // Extract YAML — either frontmatter (---..---) or raw YAML
  let yamlContent: string;
  const fmMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (fmMatch) {
    yamlContent = fmMatch[1];
  } else {
    yamlContent = content;
  }

  let yaml: any;
  try {
    yaml = parseYAML(yamlContent);
  } catch {
    return null;
  }

  if (!yaml) return null;

  const binaryName = yaml.name || yaml.Name || filename.replace(/\.(yml|yaml)$/i, "");
  if (!binaryName) return null;

  const functionsAvailable: LOLFunction[] = [];
  const attckSet = new Set<string>();
  const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];

  // Parse functions (may be object keyed by function name, or array)
  const funcs = yaml.functions || yaml.Functions || {};
  if (typeof funcs === "object" && !Array.isArray(funcs)) {
    for (const funcName of Object.keys(funcs)) {
      const lolFunc = FUNCTION_MAP[funcName.toLowerCase()];
      if (lolFunc) {
        functionsAvailable.push(lolFunc);
        const attck = ATTCK_MAP[lolFunc];
        if (attck) attckSet.add(attck);
      }

      const variants = funcs[funcName];
      if (!Array.isArray(variants)) continue;
      for (const variant of variants) {
        const code = variant.code || variant.command || "";
        if (!code) continue;
        contexts.push({
          context: "unprivileged",
          prerequisite: "",
          command: code,
          result: variant.description || funcName,
          oneLiner: !code.includes("\n"),
        });
      }
    }
  } else if (Array.isArray(funcs)) {
    for (const f of funcs) {
      const funcName = typeof f === "string" ? f : (f.name || f.type || "");
      const lolFunc = FUNCTION_MAP[funcName.toLowerCase()];
      if (lolFunc) {
        functionsAvailable.push(lolFunc);
        const attck = ATTCK_MAP[lolFunc];
        if (attck) attckSet.add(attck);
      }
    }
  }

  // Parse examples / commands
  const examples = yaml.examples || yaml.Examples || [];
  if (Array.isArray(examples)) {
    for (const ex of examples) {
      const code = typeof ex === "string" ? ex : (ex.code || ex.command || "");
      if (!code) continue;
      contexts.push({
        context: "unprivileged",
        prerequisite: "",
        command: code,
        result: typeof ex === "object" ? (ex.description || "") : "",
        oneLiner: !code.includes("\n"),
      });
    }
  }

  if (functionsAvailable.length === 0) return null;

  const platform = detectPlatform(yaml, filename);
  const description = yaml.description || yaml.Description || "";

  return {
    id: `loflcab-${binaryName.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
    binary: binaryName,
    aliases: [],
    platform,
    catalogSource: "loflcab",
    category: "binary",
    description,
    functions: Array.from(new Set(functionsAvailable)),
    executionContexts: contexts,
    attckTechniques: Array.from(attckSet),
    detection: emptyDetection(),
    stealthScore: 2,
    stealthNotes: `LOFLCAB ${platform} binary`,
    fullPaths: [],
    resources: [`https://lofl-project.github.io/LOFLCAB/binaries/${binaryName}/`],
    relatedEntries: [],
    chainPotential: [],
  };
}

export function parseLOFLCABEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const item of data) {
    if (!item) continue;
    const name = item.name || item.Name;
    if (!name) continue;

    const functionsRaw = item.functions || item.Functions || {};
    const funcsSet = new Set<LOLFunction>();
    const attckSet = new Set<string>();
    const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];

    if (typeof functionsRaw === "object" && !Array.isArray(functionsRaw)) {
      for (const funcName of Object.keys(functionsRaw)) {
        const lolFunc = FUNCTION_MAP[funcName.toLowerCase()];
        if (lolFunc) {
          funcsSet.add(lolFunc);
          const attck = ATTCK_MAP[lolFunc];
          if (attck) attckSet.add(attck);
        }
        const variants = functionsRaw[funcName];
        if (Array.isArray(variants)) {
          for (const v of variants) {
            const code = v.code || v.command || "";
            if (code) {
              contexts.push({
                context: "unprivileged",
                prerequisite: "",
                command: code,
                result: v.description || funcName,
                oneLiner: !code.includes("\n"),
              });
            }
          }
        }
      }
    }

    if (funcsSet.size === 0) continue;

    const platform = detectPlatform(item, name);

    entries.push({
      id: `loflcab-${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
      binary: name,
      aliases: [],
      platform,
      catalogSource: "loflcab",
      category: "binary",
      description: item.description || item.Description || "",
      functions: Array.from(funcsSet),
      executionContexts: contexts,
      attckTechniques: Array.from(attckSet),
      detection: emptyDetection(),
      stealthScore: 2,
      stealthNotes: `LOFLCAB ${platform} binary`,
      fullPaths: [],
      resources: [`https://lofl-project.github.io/LOFLCAB/binaries/${name}/`],
      relatedEntries: [],
      chainPotential: [],
    });
  }

  return entries;
}
