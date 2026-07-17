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

interface CryptoTechnique {
  technique: string;
  description: string;
  platform: Platform | "multi";
  binary: string;
  encode_command: string;
  decode_command: string;
  stealth_score: number;
  attck_ids: string[];
  detection_notes: string;
}

// ── crypto_certutil ───────────────────────────────────────────────────────────

const crypto_certutil: ToolDef = {
  name: "crypto_certutil",
  description: "Find certutil-based encoding/decoding techniques for data obfuscation and payload staging on Windows",
  schema: {
    operation: z.enum(["encode", "decode", "hash"]).default("encode").describe("Crypto operation type"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("certutil", "windows"));

    const techniques: CryptoTechnique[] = [
      {
        technique: "certutil Base64 encode",
        description: "Use certutil to Base64-encode files for obfuscation or staging",
        platform: "windows", binary: "certutil.exe",
        encode_command: "certutil -encode payload.exe encoded.txt",
        decode_command: "certutil -decode encoded.txt payload.exe",
        stealth_score: 4, attck_ids: ["T1140", "T1027"],
        detection_notes: "Sigma rules for certutil -encode/-decode. Well-known LOL technique.",
      },
      {
        technique: "certutil hex encode",
        description: "Use certutil to hex-encode data",
        platform: "windows", binary: "certutil.exe",
        encode_command: "certutil -encodehex payload.exe encoded.hex 4",
        decode_command: "certutil -decodehex encoded.hex payload.exe 4",
        stealth_score: 4, attck_ids: ["T1140", "T1027"],
        detection_notes: "Monitor certutil with -encodehex/-decodehex flags.",
      },
    ];

    return json({
      binary: "certutil", total_techniques: techniques.length, techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── crypto_openssl ────────────────────────────────────────────────────────────

const crypto_openssl: ToolDef = {
  name: "crypto_openssl",
  description: "Find openssl-based encryption and encoding techniques for data obfuscation on Linux/macOS",
  schema: {
    operation: z.enum(["encode", "decode", "encrypt", "decrypt"]).default("encode").describe("Crypto operation"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("openssl"));

    const techniques: CryptoTechnique[] = [
      {
        technique: "openssl Base64 encode",
        description: "Use openssl for Base64 encoding of files and data",
        platform: "linux", binary: "openssl",
        encode_command: "openssl base64 -in payload.bin -out encoded.txt",
        decode_command: "openssl base64 -d -in encoded.txt -out payload.bin",
        stealth_score: 2, attck_ids: ["T1140", "T1027"],
        detection_notes: "Monitor openssl base64 usage.",
      },
      {
        technique: "openssl AES encryption",
        description: "Use openssl to encrypt files with AES for secure staging",
        platform: "linux", binary: "openssl",
        encode_command: "openssl enc -aes-256-cbc -salt -in secret.txt -out secret.enc -pass pass:<KEY>",
        decode_command: "openssl enc -aes-256-cbc -d -in secret.enc -out secret.txt -pass pass:<KEY>",
        stealth_score: 1, attck_ids: ["T1027", "T1573.001"],
        detection_notes: "Monitor openssl enc usage.",
      },
    ];

    return json({
      binary: "openssl", total_techniques: techniques.length, techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── crypto_gpg ────────────────────────────────────────────────────────────────

const crypto_gpg: ToolDef = {
  name: "crypto_gpg",
  description: "Find GPG-based encryption techniques for data protection and secure exfiltration",
  schema: {
    operation: z.enum(["encrypt", "decrypt", "sign"]).default("encrypt").describe("GPG operation"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("gpg"));

    const techniques: CryptoTechnique[] = [
      {
        technique: "GPG symmetric encryption",
        description: "Use GPG symmetric encryption to protect exfiltration data",
        platform: "linux", binary: "gpg",
        encode_command: "gpg --symmetric --cipher-algo AES256 -o secret.gpg secret.txt",
        decode_command: "gpg -d -o secret.txt secret.gpg",
        stealth_score: 2, attck_ids: ["T1027", "T1573.001"],
        detection_notes: "Monitor gpg process creation with symmetric encryption flags.",
      },
      {
        technique: "GPG asymmetric encryption",
        description: "Use GPG public key encryption for secure data exfiltration",
        platform: "linux", binary: "gpg",
        encode_command: "gpg --encrypt --recipient attacker@evil.com -o secret.gpg secret.txt",
        decode_command: "gpg --decrypt -o secret.txt secret.gpg",
        stealth_score: 1, attck_ids: ["T1027", "T1573.002"],
        detection_notes: "Monitor GPG key import and encryption operations.",
      },
    ];

    return json({
      binary: "gpg", total_techniques: techniques.length, techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── crypto_base64_variants ────────────────────────────────────────────────────

const crypto_base64_variants: ToolDef = {
  name: "crypto_base64_variants",
  description: "Find Base64 encoding variants across platforms — Linux base64, macOS base64, Python, Perl",
  schema: {
    platform: z.enum(["linux", "windows", "macos", "all"]).default("all").describe("Target platform"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const techniques: CryptoTechnique[] = [
      {
        technique: "Linux base64 command",
        description: "Use the native base64 command for encoding/decoding",
        platform: "linux", binary: "base64",
        encode_command: "base64 < payload.bin > encoded.txt",
        decode_command: "base64 -d < encoded.txt > payload.bin",
        stealth_score: 2, attck_ids: ["T1140"],
        detection_notes: "Monitor base64 process creation.",
      },
      {
        technique: "macOS base64 command",
        description: "Use macOS base64 with -D flag for decoding",
        platform: "macos", binary: "base64",
        encode_command: "base64 -i payload.bin -o encoded.txt",
        decode_command: "base64 -D -i encoded.txt -o payload.bin",
        stealth_score: 2, attck_ids: ["T1140"],
        detection_notes: "Monitor base64 process. macOS uses -D instead of -d.",
      },
      {
        technique: "Python base64 encoding",
        description: "Use Python for cross-platform base64 encoding",
        platform: "multi", binary: "python3",
        encode_command: "python3 -c \"import base64,sys; sys.stdout.buffer.write(base64.b64encode(open('payload.bin','rb').read()))\"",
        decode_command: "python3 -c \"import base64,sys; sys.stdout.buffer.write(base64.b64decode(open('encoded.txt','r').read()))\"",
        stealth_score: 2, attck_ids: ["T1140", "T1059.006"],
        detection_notes: "Monitor python3 with base64 import.",
      },
    ];

    const filtered = args.platform === "all" ? techniques : techniques.filter(t => t.platform === args.platform || t.platform === "multi");

    return json({ category: "base64_variants", total_techniques: filtered.length, techniques: filtered });
  },
};

// ── crypto_powershell ─────────────────────────────────────────────────────────

const crypto_powershell: ToolDef = {
  name: "crypto_powershell",
  description: "Find PowerShell-based encoding and encryption techniques for data obfuscation on Windows",
  schema: {
    operation: z.enum(["encode", "decode", "encrypt", "decrypt"]).default("encode").describe("Crypto operation"),
  },
  async execute(args: any, ctx: ToolContext): Promise<ToolResult> {
    const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword("powershell", "windows"));

    const techniques: CryptoTechnique[] = [
      {
        technique: "PowerShell Base64 encoding",
        description: "Use [Convert]::ToBase64String for Base64 encoding in PowerShell",
        platform: "windows", binary: "powershell.exe",
        encode_command: '[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\\payload.bin")) | Out-File encoded.txt',
        decode_command: '[IO.File]::WriteAllBytes("C:\\payload.bin", [Convert]::FromBase64String((Get-Content encoded.txt)))',
        stealth_score: 3, attck_ids: ["T1140", "T1059.001"],
        detection_notes: "PowerShell script block logging. Monitor ToBase64String/FromBase64String.",
      },
      {
        technique: "PowerShell -EncodedCommand",
        description: "Use PowerShell -EncodedCommand parameter for command obfuscation",
        platform: "windows", binary: "powershell.exe",
        encode_command: '[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("whoami"))',
        decode_command: "powershell.exe -EncodedCommand <BASE64>",
        stealth_score: 4, attck_ids: ["T1027", "T1059.001"],
        detection_notes: "Monitor -enc/-EncodedCommand flag. Well-known obfuscation technique.",
      },
    ];

    return json({
      binary: "powershell", total_techniques: techniques.length, techniques,
      kb_entries: kbEntries.slice(0, 5).map(summarizeKbEntry),
    });
  },
};

// ── Export ─────────────────────────────────────────────────────────────────────

export const nativeCryptoTools: ToolDef[] = [
  crypto_certutil,
  crypto_openssl,
  crypto_gpg,
  crypto_base64_variants,
  crypto_powershell,
];
