#!/usr/bin/env bun
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { updateAll } from "../knowledge-base/updater.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const dataDir = resolve(__dirname, "../../data");

console.log("Living off the Land — Knowledge Base Snapshot");
console.log(`Target: ${dataDir}\n`);

const results = await updateAll(dataDir);

for (const r of results) {
  const status = r.success ? `✓ ${r.entriesFetched} entries` : `✗ ${r.error}`;
  console.log(`  ${r.catalog.padEnd(12)} ${status}`);
}

const total = results.reduce((sum, r) => sum + r.entriesFetched, 0);
console.log(`\nTotal: ${total} entries across ${results.filter(r => r.success).length} catalogs`);
