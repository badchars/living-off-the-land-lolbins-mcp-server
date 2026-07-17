import type { UnifiedLOLEntry, LOLFunction, EntryCategory } from "../schema/unified-entry.js";
import { emptyDetection } from "../schema/unified-entry.js";

// ━━━ C2 Category → EntryCategory ━━━
function determineCategory(entry: any): EntryCategory {
  const name = (entry.name || entry.Name || "").toLowerCase();
  const desc = (entry.description || entry.Description || "").toLowerCase();
  if (desc.includes("website") || desc.includes("web service") || desc.includes("saas") || desc.includes("cloud")) {
    return "site";
  }
  if (desc.includes("api") || desc.includes("endpoint")) {
    return "service";
  }
  return "service";
}

function extractFunctions(entry: any): LOLFunction[] {
  const funcs = new Set<LOLFunction>();
  funcs.add("c2");

  const desc = (entry.description || entry.Description || "").toLowerCase();
  if (desc.includes("download") || desc.includes("fetch") || desc.includes("retrieve")) {
    funcs.add("download");
  }
  if (desc.includes("upload") || desc.includes("exfil") || desc.includes("send")) {
    funcs.add("upload");
  }
  if (desc.includes("tunnel") || desc.includes("proxy") || desc.includes("redirect")) {
    funcs.add("lateral_movement");
  }
  if (desc.includes("execute") || desc.includes("command") || desc.includes("shell")) {
    funcs.add("command_execution");
  }

  return Array.from(funcs);
}

export function parseLOLC2Entries(data: any[]): UnifiedLOLEntry[] {
  const entries: UnifiedLOLEntry[] = [];

  for (const c2Entry of data) {
    if (!c2Entry) continue;
    const name = c2Entry.name || c2Entry.Name;
    if (!name) continue;

    const description = c2Entry.description || c2Entry.Description || "";
    const functions = extractFunctions(c2Entry);
    const category = determineCategory(c2Entry);
    const website = c2Entry.website || c2Entry.Website || c2Entry.url || c2Entry.URL || "";

    const detection = emptyDetection();
    // C2 services often have network-based detection
    if (website) {
      detection.iocs.push(website);
    }

    const contexts: import("../schema/unified-entry.js").ExecutionContext[] = [];
    const commands = c2Entry.commands || c2Entry.Commands || [];

    if (Array.isArray(commands) && commands.length > 0) {
      for (const cmd of commands) {
        if (!cmd) continue;
        const command = typeof cmd === "string" ? cmd : (cmd.command || cmd.Command || "");
        if (!command) continue;
        contexts.push({
          context: "unprivileged",
          prerequisite: `Access to ${name} service`,
          command,
          result: "C2 communication channel",
          oneLiner: !command.includes("\n"),
        });
      }
    }

    if (contexts.length === 0) {
      contexts.push({
        context: "unprivileged",
        prerequisite: `Access to ${name} service`,
        command: "",
        result: "C2 communication channel via legitimate service",
        oneLiner: true,
      });
    }

    const entry: UnifiedLOLEntry = {
      id: `lolc2-${name.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`,
      binary: name,
      aliases: [],
      platform: "multi",
      catalogSource: "lolc2",
      category,
      description: description || `${name} — legitimate service abusable for C2`,
      functions,
      executionContexts: contexts,
      attckTechniques: ["T1071", "T1102"],
      detection,
      stealthScore: 2,
      stealthNotes: "Legitimate service — C2 traffic blends with normal usage",
      fullPaths: [],
      resources: website ? [website] : [],
      relatedEntries: [],
      chainPotential: [
        `${name} can be used as covert C2 channel`,
        `${name} traffic blends with legitimate usage`,
      ],
    };

    entries.push(entry);
  }

  return entries;
}
