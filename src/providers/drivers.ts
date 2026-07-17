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
    driver_category: e.driverCategory ?? null,
    cves: e.cves ?? [],
    driver_samples: (e.driverSamples ?? []).slice(0, 3),
  };
}

// ━━━ Hardcoded BYOVD Technique Data ━━━

interface ByovdEntry {
  driver: string;
  description: string;
  cves: string[];
  vendor: string;
  abusePrimitive: string;
  attck: string[];
  detectionNotes: string;
}

const BYOVD_CANDIDATES: ByovdEntry[] = [
  {
    driver: "RTCore64.sys",
    description: "Micro-Star MSI Afterburner driver with arbitrary kernel memory R/W",
    cves: ["CVE-2019-16098"],
    vendor: "MSI",
    abusePrimitive: "Arbitrary kernel memory read/write via IOCTL",
    attck: ["T1068", "T1562.001"],
    detectionNotes: "Monitor for RTCore64.sys load. Check driver signature and hash against LOLDrivers.",
  },
  {
    driver: "dbutil_2_3.sys",
    description: "Dell BIOS utility driver with arbitrary kernel memory R/W",
    cves: ["CVE-2021-21551"],
    vendor: "Dell",
    abusePrimitive: "Arbitrary kernel memory read/write, privilege escalation",
    attck: ["T1068", "T1562.001"],
    detectionNotes: "Monitor for dbutil_2_3.sys load. Known EDR killer driver.",
  },
  {
    driver: "gdrv.sys",
    description: "GIGABYTE driver with arbitrary kernel memory R/W for EDR bypass",
    cves: ["CVE-2018-19320"],
    vendor: "GIGABYTE",
    abusePrimitive: "Arbitrary physical memory read/write via IOCTL",
    attck: ["T1068", "T1562.001"],
    detectionNotes: "Monitor for gdrv.sys load. Revoked certificate.",
  },
  {
    driver: "ene.sys",
    description: "ENE Technology driver used by multiple threat actors for EDR kills",
    cves: [],
    vendor: "ENE Technology",
    abusePrimitive: "Arbitrary kernel memory read/write",
    attck: ["T1068", "T1562.001"],
    detectionNotes: "Monitor for ene.sys. Frequently used in ransomware campaigns.",
  },
  {
    driver: "AsIO3.sys",
    description: "ASUS driver with physical memory access for kernel manipulation",
    cves: ["CVE-2023-1292"],
    vendor: "ASUS",
    abusePrimitive: "Physical memory read/write via IOCTL",
    attck: ["T1068", "T1562.001"],
    detectionNotes: "Monitor for AsIO3.sys load. Check certificate validity.",
  },
  {
    driver: "procexp152.sys",
    description: "Process Explorer driver that can terminate protected processes",
    cves: [],
    vendor: "Microsoft (Sysinternals)",
    abusePrimitive: "Terminate any process including AV/EDR via kernel handle",
    attck: ["T1562.001"],
    detectionNotes: "Monitor for procexp152.sys. Legitimate but abused for EDR kill.",
  },
];

// ━━━ Tools ━━━

const driver_hash_lookup: ToolDef = {
  name: "driver_hash_lookup",
  description: "Find a vulnerable or malicious driver in the LOLDrivers catalog by SHA256 hash",
  schema: {
    sha256: z.string().describe("SHA256 hash of the driver file to look up"),
  },
  async execute(args: { sha256: string }, ctx: ToolContext): Promise<ToolResult> {
    const hash = args.sha256.toLowerCase().trim();
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return text("Invalid SHA256 hash format. Must be 64 hex characters.");
    }

    const driverEntries = ctx.knowledgeBase.searchByCatalog("loldrivers");
    const matches = driverEntries.filter(e =>
      (e.driverSamples ?? []).some(s => s.sha256.toLowerCase() === hash),
    );

    if (matches.length === 0) {
      return json({ found: false, hash, message: "No matching driver found in LOLDrivers catalog." });
    }

    return json({
      found: true,
      hash,
      total_matches: matches.length,
      drivers: matches.map(summarizeKbEntry),
    });
  },
};

const driver_name_lookup: ToolDef = {
  name: "driver_name_lookup",
  description: "Find a driver in the LOLDrivers catalog by filename (e.g. RTCore64.sys, dbutil_2_3.sys)",
  schema: {
    filename: z.string().describe("Driver filename to search for (e.g. 'RTCore64.sys')"),
  },
  async execute(args: { filename: string }, ctx: ToolContext): Promise<ToolResult> {
    const name = args.filename.toLowerCase().trim();

    // Search LOLDrivers catalog
    const driverEntries = ctx.knowledgeBase.searchByCatalog("loldrivers");
    const byBinary = driverEntries.filter(e => e.binary.toLowerCase().includes(name));
    const bySample = driverEntries.filter(e =>
      (e.driverSamples ?? []).some(s => s.filename.toLowerCase().includes(name)),
    );

    const seen = new Set<string>();
    const combined: any[] = [];
    for (const e of [...byBinary, ...bySample]) {
      if (!seen.has(e.id)) { seen.add(e.id); combined.push(e); }
    }

    // Also keyword search
    const kwResults = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(name, "windows"));
    const driverKw = kwResults.filter(e => e.category === "driver");

    for (const e of driverKw) {
      if (!seen.has(e.id)) { seen.add(e.id); combined.push(e); }
    }

    if (combined.length === 0) {
      return json({ found: false, filename: args.filename, message: "No matching driver found." });
    }

    return json({
      found: true,
      filename: args.filename,
      total_matches: combined.length,
      drivers: combined.map(summarizeKbEntry),
    });
  },
};

const driver_byovd_candidates: ToolDef = {
  name: "driver_byovd_candidates",
  description: "Find Bring Your Own Vulnerable Driver (BYOVD) candidates for EDR bypass scenarios",
  schema: {
    vendor: z.string().optional().describe("Filter by driver vendor (e.g. 'MSI', 'Dell', 'ASUS')"),
    primitive: z.string().optional().describe("Filter by abuse primitive keyword (e.g. 'memory', 'terminate')"),
  },
  async execute(args: { vendor?: string; primitive?: string }, ctx: ToolContext): Promise<ToolResult> {
    let candidates = [...BYOVD_CANDIDATES];

    if (args.vendor) {
      const v = args.vendor.toLowerCase();
      candidates = candidates.filter(c => c.vendor.toLowerCase().includes(v));
    }
    if (args.primitive) {
      const p = args.primitive.toLowerCase();
      candidates = candidates.filter(c => c.abusePrimitive.toLowerCase().includes(p));
    }

    // Enrich from KB
    const driverEntries = ctx.knowledgeBase.searchByCatalog("loldrivers")
      .filter(e => e.driverCategory === "vulnerable");

    return json({
      total_hardcoded: candidates.length,
      candidates: candidates.map(c => ({
        driver: c.driver,
        description: c.description,
        cves: c.cves,
        vendor: c.vendor,
        abuse_primitive: c.abusePrimitive,
        attck: c.attck,
        detection_notes: c.detectionNotes,
      })),
      kb_vulnerable_drivers: driverEntries.slice(0, 15).map(summarizeKbEntry),
      total_kb_vulnerable: driverEntries.length,
    });
  },
};

const driver_cert_check: ToolDef = {
  name: "driver_cert_check",
  description: "Check driver certificate and signer information from the LOLDrivers catalog",
  schema: {
    driver_name: z.string().describe("Driver filename to check certificate info for"),
  },
  async execute(args: { driver_name: string }, ctx: ToolContext): Promise<ToolResult> {
    const name = args.driver_name.toLowerCase().trim();

    const driverEntries = ctx.knowledgeBase.searchByCatalog("loldrivers");
    const matches = driverEntries.filter(e =>
      e.binary.toLowerCase().includes(name) ||
      (e.driverSamples ?? []).some(s => s.filename.toLowerCase().includes(name)),
    );

    if (matches.length === 0) {
      return json({ found: false, driver_name: args.driver_name, message: "No matching driver found." });
    }

    return json({
      found: true,
      driver_name: args.driver_name,
      total_matches: matches.length,
      drivers: matches.map(e => ({
        binary: e.binary,
        category: e.driverCategory ?? "unknown",
        samples: (e.driverSamples ?? []).map(s => ({
          filename: s.filename,
          sha256: s.sha256,
          signature: s.signature,
          machine_type: s.machineType,
          imphash: s.imphash ?? null,
        })),
        cves: e.cves ?? [],
        description: e.description,
        detection: {
          edr_coverage: e.detection.edrCoverage,
          sigma_rules: e.detection.sigmaRules.length,
          iocs: e.detection.iocs,
        },
      })),
    });
  },
};

const driver_vulnerable_match: ToolDef = {
  name: "driver_vulnerable_match",
  description: "Match a list of loaded driver names against the LOLDrivers database to find vulnerable ones",
  schema: {
    driver_list: z.array(z.string()).describe("Array of loaded driver filenames to check (e.g. ['ntfs.sys','RTCore64.sys'])"),
  },
  async execute(args: { driver_list: string[] }, ctx: ToolContext): Promise<ToolResult> {
    if (!args.driver_list || args.driver_list.length === 0) {
      return text("Please provide a non-empty list of driver filenames.");
    }

    const driverEntries = ctx.knowledgeBase.searchByCatalog("loldrivers");
    const driverMap = new Map<string, any[]>();
    for (const e of driverEntries) {
      const key = e.binary.toLowerCase();
      if (!driverMap.has(key)) driverMap.set(key, []);
      driverMap.get(key)!.push(e);
      for (const s of e.driverSamples ?? []) {
        const sKey = s.filename.toLowerCase();
        if (!driverMap.has(sKey)) driverMap.set(sKey, []);
        driverMap.get(sKey)!.push(e);
      }
    }

    const results: any[] = [];
    const notFound: string[] = [];

    for (const driverName of args.driver_list) {
      const lower = driverName.toLowerCase().trim();
      const matches = driverMap.get(lower);
      if (matches && matches.length > 0) {
        const seen = new Set<string>();
        const unique = matches.filter(e => {
          if (seen.has(e.id)) return false;
          seen.add(e.id);
          return true;
        });
        results.push({
          input_name: driverName,
          status: "FOUND_IN_LOLDRIVERS",
          matches: unique.map(summarizeKbEntry),
        });
      } else {
        notFound.push(driverName);
      }
    }

    return json({
      total_checked: args.driver_list.length,
      total_found: results.length,
      total_clean: notFound.length,
      vulnerable_matches: results,
      not_found: notFound,
    });
  },
};

export const driversTools: ToolDef[] = [
  driver_hash_lookup,
  driver_name_lookup,
  driver_byovd_candidates,
  driver_cert_check,
  driver_vulnerable_match,
];
