import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { UnifiedLOLEntry } from "../schema/unified-entry.js";
import { parseGTFOBinsEntry } from "../catalogs/gtfobins.js";
import { parseLOLBASEntries } from "../catalogs/lolbas.js";
import { parseLOOBinsEntries } from "../catalogs/loobins.js";
import { parseLOLDriversEntries } from "../catalogs/loldrivers.js";
import { parseLOLRMMEntries } from "../catalogs/lolrmm.js";
import { parseLOLESXiEntries } from "../catalogs/lolesxi.js";
import { parseLOTPEntries } from "../catalogs/lotp.js";
import { parseLOLC2Entries } from "../catalogs/lolc2.js";
import { parseLOFLCABEntry } from "../catalogs/loflcab.js";
import { parseWADComsEntry } from "../catalogs/wadcoms.js";

export async function loadFromDataDir(dataDir: string): Promise<UnifiedLOLEntry[]> {
  const entries: UnifiedLOLEntry[] = [];

  // 1. GTFOBins (per-file YAML)
  const gtfDir = join(dataDir, "gtfobins");
  try {
    const files = await readdir(gtfDir);
    for (const filename of files) {
      if (filename.startsWith(".")) continue;
      const content = await readFile(join(gtfDir, filename), "utf-8");
      const entry = parseGTFOBinsEntry(filename, content);
      if (entry) entries.push(entry);
    }
  } catch {
    // gtfobins directory may not exist yet
  }

  // 2. LOLBAS (single JSON)
  try {
    const lolbasData = JSON.parse(await readFile(join(dataDir, "lolbas.json"), "utf-8"));
    entries.push(...parseLOLBASEntries(lolbasData));
  } catch {
    // file may not exist
  }

  // 3. LOOBins (single JSON)
  try {
    const loobinsData = JSON.parse(await readFile(join(dataDir, "loobins.json"), "utf-8"));
    entries.push(...parseLOOBinsEntries(loobinsData));
  } catch {
    // file may not exist
  }

  // 4. LOLDrivers (single JSON)
  try {
    const driversData = JSON.parse(await readFile(join(dataDir, "loldrivers.json"), "utf-8"));
    entries.push(...parseLOLDriversEntries(driversData));
  } catch {
    // file may not exist
  }

  // 5. LOLRMM (single JSON)
  try {
    const rmmData = JSON.parse(await readFile(join(dataDir, "lolrmm.json"), "utf-8"));
    entries.push(...parseLOLRMMEntries(rmmData));
  } catch {
    // file may not exist
  }

  // 6. LOLESXi (single JSON)
  try {
    const esxiData = JSON.parse(await readFile(join(dataDir, "lolesxi.json"), "utf-8"));
    entries.push(...parseLOLESXiEntries(esxiData));
  } catch {
    // file may not exist
  }

  // 7. LOTP (single JSON)
  try {
    const lotpData = JSON.parse(await readFile(join(dataDir, "lotp.json"), "utf-8"));
    entries.push(...parseLOTPEntries(lotpData));
  } catch {
    // file may not exist
  }

  // 8. LOLC2 (single JSON)
  try {
    const c2Data = JSON.parse(await readFile(join(dataDir, "lolc2.json"), "utf-8"));
    entries.push(...parseLOLC2Entries(c2Data));
  } catch {
    // file may not exist
  }

  // 9. LOFLCAB (per-file YAML)
  const loflcabDir = join(dataDir, "loflcab");
  try {
    const files = await readdir(loflcabDir);
    for (const filename of files) {
      if (filename.startsWith(".")) continue;
      const content = await readFile(join(loflcabDir, filename), "utf-8");
      const entry = parseLOFLCABEntry(filename, content);
      if (entry) entries.push(entry);
    }
  } catch {
    // loflcab directory may not exist yet
  }

  // 10. WADComs (per-file YAML/MD)
  const wadcomsDir = join(dataDir, "wadcoms");
  try {
    const files = await readdir(wadcomsDir);
    for (const filename of files) {
      if (filename.startsWith(".")) continue;
      const content = await readFile(join(wadcomsDir, filename), "utf-8");
      const entry = parseWADComsEntry(filename, content);
      if (entry) entries.push(entry);
    }
  } catch {
    // wadcoms directory may not exist yet
  }

  return entries;
}
