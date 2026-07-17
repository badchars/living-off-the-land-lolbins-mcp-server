import type { UnifiedLOLEntry, CatalogSource } from "../schema/unified-entry.js";

export interface CatalogParser {
  source: CatalogSource;
  platform: string;
  parseEntries: (data: any) => UnifiedLOLEntry[];
}

import { parseLOLBASEntries } from "./lolbas.js";
import { parseLOOBinsEntries } from "./loobins.js";
import { parseLOLDriversEntries } from "./loldrivers.js";
import { parseLOLRMMEntries } from "./lolrmm.js";
import { parseLOLESXiEntries } from "./lolesxi.js";
import { parseLOTPEntries } from "./lotp.js";
import { parseLOLC2Entries } from "./lolc2.js";
import { parseLOFLCABEntries } from "./loflcab.js";
import { parseWADComsEntries } from "./wadcoms.js";

export const catalogParsers: CatalogParser[] = [
  {
    source: "lolbas",
    platform: "windows",
    parseEntries: parseLOLBASEntries,
  },
  {
    source: "loobins",
    platform: "macos",
    parseEntries: parseLOOBinsEntries,
  },
  {
    source: "loldrivers",
    platform: "windows",
    parseEntries: parseLOLDriversEntries,
  },
  {
    source: "lolrmm",
    platform: "windows",
    parseEntries: parseLOLRMMEntries,
  },
  {
    source: "lolesxi",
    platform: "esxi",
    parseEntries: parseLOLESXiEntries,
  },
  {
    source: "lotp",
    platform: "cicd",
    parseEntries: parseLOTPEntries,
  },
  {
    source: "lolc2",
    platform: "multi",
    parseEntries: parseLOLC2Entries,
  },
  {
    source: "loflcab",
    platform: "linux",
    parseEntries: parseLOFLCABEntries,
  },
  {
    source: "wadcoms",
    platform: "windows",
    parseEntries: parseWADComsEntries,
  },
];

// GTFOBins is handled separately (per-file YAML parsing)
export { parseGTFOBinsEntry } from "./gtfobins.js";
export { parseLOLBASEntries } from "./lolbas.js";
export { parseLOOBinsEntries } from "./loobins.js";
export { parseLOLDriversEntries } from "./loldrivers.js";
export { parseLOLRMMEntries } from "./lolrmm.js";
export { parseLOLESXiEntries } from "./lolesxi.js";
export { parseLOTPEntries } from "./lotp.js";
export { parseLOLC2Entries } from "./lolc2.js";
export { parseLOFLCABEntry, parseLOFLCABEntries } from "./loflcab.js";
export { parseWADComsEntry, parseWADComsEntries } from "./wadcoms.js";
