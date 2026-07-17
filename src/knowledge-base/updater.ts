import { mkdir, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { apiFetch, apiFetchText } from "../utils/http.js";
import { TTLCache } from "../utils/cache.js";
import { RateLimiter } from "../utils/rate-limiter.js";

const updateCache = new TTLCache<string>(60);
const updateLimiter = new RateLimiter(5, 60);

export interface UpdateResult {
  catalog: string;
  entriesFetched: number;
  success: boolean;
  error?: string;
}

export async function updateCatalog(dataDir: string, catalog: string): Promise<UpdateResult> {
  const opts = { cache: updateCache, limiter: updateLimiter, timeout: 60000 };

  try {
    switch (catalog) {
      case "lolbas": {
        const data = await apiFetchText("https://lolbas-project.github.io/api/lolbas.json", opts);
        await writeFile(join(dataDir, "lolbas.json"), data);
        const parsed = JSON.parse(data);
        return { catalog, entriesFetched: Array.isArray(parsed) ? parsed.length : 0, success: true };
      }

      case "loobins": {
        const data = await apiFetchText("https://loobins.io/loobins.json", opts);
        await writeFile(join(dataDir, "loobins.json"), data);
        const parsed = JSON.parse(data);
        return { catalog, entriesFetched: Array.isArray(parsed) ? parsed.length : 0, success: true };
      }

      case "loldrivers": {
        const data = await apiFetchText("https://www.loldrivers.io/api/drivers.json", opts);
        await writeFile(join(dataDir, "loldrivers.json"), data);
        const parsed = JSON.parse(data);
        return { catalog, entriesFetched: Array.isArray(parsed) ? parsed.length : 0, success: true };
      }

      case "gtfobins": {
        const gtfDir = join(dataDir, "gtfobins");
        await mkdir(gtfDir, { recursive: true });

        const contentsUrl = "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins";
        const listing: any[] = await apiFetch(contentsUrl, opts);

        let count = 0;
        for (const file of listing) {
          if (!file.download_url) continue;
          try {
            const content = await apiFetchText(file.download_url, {
              ...opts,
              limiter: new RateLimiter(20, 60),
            });
            await writeFile(join(gtfDir, file.name), content);
            count++;
          } catch {
            // skip individual file failures
          }
        }
        return { catalog, entriesFetched: count, success: true };
      }

      case "lolrmm": {
        const data = await apiFetchText("https://lolrmm.io/api/rmm_tools.json", opts);
        await writeFile(join(dataDir, "lolrmm.json"), data);
        const parsed = JSON.parse(data);
        return { catalog, entriesFetched: Array.isArray(parsed) ? parsed.length : 0, success: true };
      }

      case "lolesxi": {
        const data = await apiFetchText("https://lolesxi-project.github.io/LOLESXi/api/lolesxi.json", opts);
        await writeFile(join(dataDir, "lolesxi.json"), data);
        const parsed = JSON.parse(data);
        return { catalog, entriesFetched: Array.isArray(parsed) ? parsed.length : 0, success: true };
      }

      case "lotp": {
        const data = await apiFetchText("https://boostsecurityio.github.io/lotp/api.json", opts);
        await writeFile(join(dataDir, "lotp.json"), data);
        const parsed = JSON.parse(data);
        return { catalog, entriesFetched: Array.isArray(parsed) ? parsed.length : 0, success: true };
      }

      case "lolc2": {
        const data = await apiFetchText("https://raw.githubusercontent.com/lolc2/lolc2.github.io/main/c2_data.json", opts);
        await writeFile(join(dataDir, "lolc2.json"), data);
        const parsed = JSON.parse(data);
        return { catalog, entriesFetched: Array.isArray(parsed) ? parsed.length : 0, success: true };
      }

      case "loflcab": {
        const loflcabDir = join(dataDir, "loflcab");
        await mkdir(loflcabDir, { recursive: true });

        const contentsUrl = "https://api.github.com/repos/LOFL-Project/LOFLCAB/contents/yml";
        const listing: any[] = await apiFetch(contentsUrl, opts);

        let count = 0;
        for (const file of listing) {
          if (!file.download_url) continue;
          try {
            const content = await apiFetchText(file.download_url, {
              ...opts,
              limiter: new RateLimiter(20, 60),
            });
            await writeFile(join(loflcabDir, file.name), content);
            count++;
          } catch {
            // skip individual file failures
          }
        }
        return { catalog, entriesFetched: count, success: true };
      }

      case "wadcoms": {
        const wadcomsDir = join(dataDir, "wadcoms");
        await mkdir(wadcomsDir, { recursive: true });

        const contentsUrl = "https://api.github.com/repos/WADComs/WADComs.github.io/contents/_wadcoms";
        const listing: any[] = await apiFetch(contentsUrl, opts);

        let count = 0;
        for (const file of listing) {
          if (!file.download_url) continue;
          try {
            const content = await apiFetchText(file.download_url, {
              ...opts,
              limiter: new RateLimiter(20, 60),
            });
            await writeFile(join(wadcomsDir, file.name), content);
            count++;
          } catch {
            // skip individual file failures
          }
        }
        return { catalog, entriesFetched: count, success: true };
      }

      default:
        return { catalog, entriesFetched: 0, success: false, error: `Unknown catalog: ${catalog}` };
    }
  } catch (err: any) {
    return { catalog, entriesFetched: 0, success: false, error: err.message || String(err) };
  }
}

export async function updateAll(dataDir: string): Promise<UpdateResult[]> {
  await mkdir(dataDir, { recursive: true });
  const catalogs = [
    "lolbas", "loobins", "loldrivers", "gtfobins",
    "lolrmm", "lolesxi", "lotp", "lolc2", "loflcab", "wadcoms",
  ];
  const results: UpdateResult[] = [];

  for (const catalog of catalogs) {
    const result = await updateCatalog(dataDir, catalog);
    results.push(result);
  }

  // Write manifest
  const manifest = {
    generated: new Date().toISOString(),
    catalogs: Object.fromEntries(results.map(r => [r.catalog, { entries: r.entriesFetched, success: r.success }])),
  };
  await writeFile(join(dataDir, "manifest.json"), JSON.stringify(manifest, null, 2));

  return results;
}
