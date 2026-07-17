import { parse as parseYAML } from "yaml";
import type {
  UnifiedLOLEntry, LOLFunction, ContextType, ExecutionContext,
} from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";
import { normalizeBinaryName, getAliases } from "../utils/normalize.js";

// ━━━ GTFOBins function → LOLFunction mapping ━━━
const FUNCTION_MAP: Record<string, LOLFunction> = {
  "shell": "shell",
  "command": "command",
  "reverse-shell": "reverse_shell",
  "bind-shell": "bind_shell",
  "file-write": "file_write",
  "file-read": "file_read",
  "upload": "upload",
  "download": "download",
  "library-load": "library_load",
  "privilege-escalation": "privilege_escalation",
  "inherit": "inherit",
};

// ━━━ MITRE ATT&CK per function ━━━
const ATTCK_MAP: Record<string, string[]> = {
  "shell": ["T1059"],
  "command": ["T1059"],
  "reverse-shell": ["T1059", "T1071"],
  "bind-shell": ["T1059", "T1071"],
  "file-write": ["T1565"],
  "file-read": ["T1005"],
  "upload": ["T1041"],
  "download": ["T1105"],
  "library-load": ["T1574"],
  "privilege-escalation": ["T1548"],
  "inherit": [],
};

// ━━━ Context → additional ATT&CK ━━━
const CONTEXT_ATTCK: Record<string, string[]> = {
  "sudo": ["T1548.003"],
  "suid": ["T1548.001"],
  "capabilities": ["T1548.001"],
  "unprivileged": [],
};

// ━━━ Prerequisite descriptions ━━━
const PREREQUISITE_MAP: Record<string, string> = {
  "sudo": "sudo privileges for this binary",
  "suid": "SUID bit set on binary",
  "capabilities": "Linux capabilities assigned to binary",
  "unprivileged": "",
};

// ━━━ Stealth score heuristics ━━━
const VERY_COMMON = new Set([
  "bash", "sh", "env", "find", "less", "more", "vim", "nano", "cat", "cp", "mv",
  "tar", "gzip", "awk", "sed", "sort", "head", "tail", "tee", "xargs",
]);
const COMMON_SCRIPTING = new Set([
  "python", "perl", "ruby", "php", "node", "lua", "julia", "tclsh", "wish",
]);
const NETWORK_TOOLS = new Set([
  "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "sftp", "ftp", "rsync", "openssl",
]);
const KNOWN_SUSPICIOUS = new Set([
  "nmap", "gtester", "busybox",
]);

function computeStealthScore(binary: string, functions: string[]): number {
  const norm = normalizeBinaryName(binary);
  if (VERY_COMMON.has(norm)) return 2;
  if (COMMON_SCRIPTING.has(norm)) return 3;
  if (NETWORK_TOOLS.has(norm)) {
    return functions.includes("reverse-shell") ? 4 : 3;
  }
  if (KNOWN_SUSPICIOUS.has(norm)) return 4;
  return 2; // rare/unusual binaries are often unmonitored
}

export function parseGTFOBinsEntry(filename: string, content: string): UnifiedLOLEntry | null {
  // Extract YAML between --- delimiters
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return null;

  let yaml: any;
  try {
    yaml = parseYAML(match[1]);
  } catch {
    return null;
  }

  if (!yaml || !yaml.functions) return null;

  const binaryName = filename;
  const functionsAvailable: LOLFunction[] = [];
  const executionContexts: ExecutionContext[] = [];
  const attckSet = new Set<string>();
  const functionNames = Object.keys(yaml.functions);

  for (const funcName of functionNames) {
    const lolFunc = FUNCTION_MAP[funcName];
    if (!lolFunc) continue;
    functionsAvailable.push(lolFunc);

    const attcks = ATTCK_MAP[funcName] || [];
    for (const a of attcks) attckSet.add(a);

    const variants = yaml.functions[funcName];
    if (!Array.isArray(variants)) continue;

    for (const variant of variants) {
      const defaultCode = variant.code || "";

      // Check if there are explicit context overrides
      if (variant.sudo || variant.suid || variant.capabilities) {
        // Process each context
        const contexts: [string, any][] = [];
        if (variant.sudo) contexts.push(["sudo", variant.sudo]);
        if (variant.suid) contexts.push(["suid", variant.suid]);
        if (variant.capabilities) contexts.push(["capabilities", variant.capabilities]);

        for (const [ctxName, ctxValue] of contexts) {
          const ctxAttcks = CONTEXT_ATTCK[ctxName] || [];
          for (const a of ctxAttcks) attckSet.add(a);

          let command: string;
          if (typeof ctxValue === "string") {
            command = ctxValue;
          } else if (ctxValue && typeof ctxValue === "object" && ctxValue.code) {
            command = ctxValue.code;
          } else if (ctxName === "sudo") {
            command = `sudo ${binaryName} ${defaultCode}`.trim();
          } else {
            command = defaultCode;
          }

          const result = getResult(funcName, ctxName);

          executionContexts.push({
            context: ctxName as ContextType,
            prerequisite: PREREQUISITE_MAP[ctxName] || "",
            command,
            result,
            oneLiner: !command.includes("\n"),
            requiredCapabilities: ctxValue?.list,
            binaryPreservesPriv: ctxValue?.shell === false ? true : undefined,
          });
        }
      }

      // Always add unprivileged context with the default code
      if (defaultCode) {
        executionContexts.push({
          context: "unprivileged",
          prerequisite: "",
          command: defaultCode,
          result: getResult(funcName, "unprivileged"),
          oneLiner: !defaultCode.includes("\n"),
        });
      }
    }
  }

  if (functionsAvailable.length === 0) return null;

  const aliases = getAliases(binaryName);
  const stealthScore = computeStealthScore(binaryName, functionNames);

  return {
    id: `gtfobins-${binaryName}`,
    binary: binaryName,
    aliases,
    platform: "linux",
    catalogSource: "gtfobins",
    category: "binary",
    description: yaml.description || "",
    functions: [...new Set(functionsAvailable)],
    executionContexts,
    attckTechniques: [...attckSet],
    detection: emptyDetection(),
    stealthScore,
    stealthNotes: `Base stealth for ${binaryName} on Linux`,
    fullPaths: [`/usr/bin/${binaryName}`, `/usr/local/bin/${binaryName}`],
    resources: [`https://gtfobins.github.io/gtfobins/${binaryName}/`],
    relatedEntries: [],
    chainPotential: buildChainPotential(binaryName, functionsAvailable),
    inheritsFrom: yaml.functions?.inherit ? extractInheritParent(yaml.functions.inherit) : undefined,
  };
}

function getResult(funcName: string, context: string): string {
  const escalationContexts = ["sudo", "suid", "capabilities"];
  const isEscalation = escalationContexts.includes(context);

  switch (funcName) {
    case "shell": return isEscalation ? "root shell" : "interactive shell";
    case "command": return isEscalation ? "command as root" : "command execution";
    case "reverse-shell": return isEscalation ? "root reverse shell" : "reverse shell";
    case "bind-shell": return isEscalation ? "root bind shell" : "bind shell";
    case "file-read": return isEscalation ? "read any file as root" : "file read";
    case "file-write": return isEscalation ? "write any file as root" : "file write";
    case "upload": return "data exfiltration";
    case "download": return "file download";
    case "library-load": return "shared library execution";
    case "privilege-escalation": return "privilege escalation";
    default: return funcName;
  }
}

function buildChainPotential(binary: string, functions: LOLFunction[]): string[] {
  const chains: string[] = [];
  if (functions.includes("file_write")) {
    chains.push(`${binary} can write to cron for persistence`);
    chains.push(`${binary} can write SSH keys for lateral movement`);
  }
  if (functions.includes("download")) {
    chains.push(`${binary} can download additional tools`);
  }
  if (functions.includes("shell") && functions.includes("file_write")) {
    chains.push(`${binary} can escalate then persist via file write`);
  }
  return chains;
}

function extractInheritParent(inheritData: any[]): string | undefined {
  if (!Array.isArray(inheritData) || inheritData.length === 0) return undefined;
  const first = inheritData[0];
  if (first && first.binary) return first.binary;
  return undefined;
}
