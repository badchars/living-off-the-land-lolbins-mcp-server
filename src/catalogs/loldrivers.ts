import type { UnifiedLOLEntry, LOLFunction, DriverSample } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";
import type { DetectionInfo } from "../schema/unified-entry.js";
import { normalizeBinaryName } from "../utils/normalize.js";

function parseDriverDetection(detections: any[]): DetectionInfo {
  const det = emptyDetection();
  if (!Array.isArray(detections)) return det;

  for (const d of detections) {
    if (!d || typeof d !== "object") continue;
    const type = (d.type || "").toLowerCase();
    const value = d.value || "";
    if (!value) continue;

    switch (type) {
      case "yara_signature":
        det.yaraRules.push(value);
        break;
      case "sigma_hash":
      case "sigma_names":
      case "sysmon_hash_detect":
      case "sigma":
        det.sigmaRules.push(value);
        break;
      case "sysmon_hash_block":
      case "blockrule":
        det.blockRules.push(value);
        break;
      case "ioc":
        det.iocs.push(value);
        break;
    }
  }

  const totalRules = det.sigmaRules.length + det.yaraRules.length;
  if (totalRules >= 3) det.edrCoverage = "high";
  else if (totalRules >= 1) det.edrCoverage = "medium";
  else det.edrCoverage = "none";

  return det;
}

function determineDriverFunctions(entry: any): LOLFunction[] {
  const funcs: LOLFunction[] = ["privilege_escalation"];
  const tags = ((entry.Tags || []).join(" ") + " " + (entry.Category || "")).toLowerCase();
  const desc = ((entry.Commands?.Description || "") + " " + (entry.Commands?.Usecase || "")).toLowerCase();

  if (tags.includes("edr") || desc.includes("edr") || desc.includes("disable") || desc.includes("kill")) {
    funcs.push("edr_disable");
  }
  if (tags.includes("byovd") || desc.includes("byovd")) {
    funcs.push("defense_evasion");
  }
  if (tags.includes("process killer") || desc.includes("process") || desc.includes("terminate")) {
    funcs.push("command_execution");
  }

  return [...new Set(funcs)];
}

export function parseLOLDriversEntries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const driverEntry of data) {
    if (!driverEntry || !driverEntry.Id) continue;

    const samples: DriverSample[] = (driverEntry.KnownVulnerableSamples || []).map((s: any) => ({
      filename: s.Filename || s.OriginalFilename || "",
      md5: s.MD5 || "",
      sha1: s.SHA1 || "",
      sha256: s.SHA256 || "",
      machineType: s.MachineType || s.Machine || "",
      signature: s.Company || s.CompanyName || "",
      imphash: s.Imphash || "",
    }));

    // Binary name from Tags or first sample
    const tags = driverEntry.Tags || [];
    const binaryName = tags[0] || samples[0]?.filename || driverEntry.Id;
    const commands = driverEntry.Commands || {};

    const detection = parseDriverDetection(driverEntry.Detection || []);
    const functions = determineDriverFunctions(driverEntry);

    // Parse MITRE IDs
    const attckTechniques: string[] = [];
    const mitreId = driverEntry.MitreID || "";
    if (mitreId) {
      const ids = mitreId.split(",").map((s: string) => s.trim()).filter(Boolean);
      attckTechniques.push(...ids);
    }

    // Parse CVEs
    const cves: string[] = [];
    if (Array.isArray(driverEntry.CVE)) {
      cves.push(...driverEntry.CVE.filter(Boolean));
    } else if (Array.isArray(driverEntry.CVEs)) {
      cves.push(...driverEntry.CVEs.filter(Boolean));
    }

    const entry: UnifiedLOLEntry = {
      id: `loldrivers-${driverEntry.Id}`,
      binary: binaryName,
      aliases: [],
      platform: "windows",
      catalogSource: "loldrivers",
      category: "driver",
      description: commands.Description || "",
      functions,
      executionContexts: [{
        context: "kernel",
        prerequisite: "Kernel-level access or admin to load driver",
        command: commands.Command || `sc create ${normalizeBinaryName(binaryName)} binPath= "${binaryName}" type= kernel && sc start ${normalizeBinaryName(binaryName)}`,
        result: commands.Usecase || "Elevate privileges",
        oneLiner: true,
      }],
      attckTechniques,
      detection,
      stealthScore: detection.blockRules.length > 0 ? 5 : (detection.yaraRules.length > 0 ? 4 : 3),
      stealthNotes: "Kernel-level driver — high detection if known",
      fullPaths: [],
      resources: Array.isArray(driverEntry.Resources) ? driverEntry.Resources.filter(Boolean) : [],
      relatedEntries: [],
      chainPotential: functions.includes("edr_disable")
        ? [`${binaryName} can disable EDR → enables further attack chain`]
        : [],
      driverCategory: (driverEntry.Category || "").toLowerCase() === "malicious" ? "malicious" : "vulnerable",
      driverSamples: samples,
      cves,
    };

    entries.push(entry);
  }

  return entries;
}
