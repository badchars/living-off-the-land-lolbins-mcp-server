import type {
  UnifiedLOLEntry, Platform, CatalogSource, LOLFunction,
} from "../schema/unified-entry.js";
import type { EnvironmentState, MatchedEntry } from "../schema/environment.js";
import { normalizeBinaryName, addToIndex, deduplicateById, getAliases } from "../utils/normalize.js";
import { basename } from "node:path";

export class KnowledgeBase {
  private entries: UnifiedLOLEntry[] = [];
  private byBinary = new Map<string, UnifiedLOLEntry[]>();
  private byAlias = new Map<string, UnifiedLOLEntry[]>();
  private byPlatform = new Map<Platform, UnifiedLOLEntry[]>();
  private byCatalog = new Map<CatalogSource, UnifiedLOLEntry[]>();
  private byFunction = new Map<LOLFunction, UnifiedLOLEntry[]>();
  private byAttck = new Map<string, UnifiedLOLEntry[]>();
  private byId = new Map<string, UnifiedLOLEntry>();

  load(entries: UnifiedLOLEntry[]): void {
    this.entries = entries;
    this.byBinary.clear();
    this.byAlias.clear();
    this.byPlatform.clear();
    this.byCatalog.clear();
    this.byFunction.clear();
    this.byAttck.clear();
    this.byId.clear();

    for (const e of entries) {
      this.byId.set(e.id, e);
      addToIndex(this.byBinary, normalizeBinaryName(e.binary), e);
      for (const alias of e.aliases) {
        addToIndex(this.byAlias, normalizeBinaryName(alias), e);
      }
      addToIndex(this.byPlatform, e.platform, e);
      addToIndex(this.byCatalog, e.catalogSource, e);
      for (const f of e.functions) addToIndex(this.byFunction, f, e);
      for (const t of e.attckTechniques) addToIndex(this.byAttck, t, e);
    }

    this.linkRelatedEntries();
  }

  getById(id: string): UnifiedLOLEntry | undefined {
    return this.byId.get(id);
  }

  lookupBinary(name: string, platform?: Platform): UnifiedLOLEntry[] {
    const norm = normalizeBinaryName(name);
    const direct = this.byBinary.get(norm) || [];
    const aliased = this.byAlias.get(norm) || [];
    const all = deduplicateById([...direct, ...aliased]);
    if (platform && platform !== ("all" as any)) {
      return all.filter(e => e.platform === platform);
    }
    return all;
  }

  searchByFunction(func: LOLFunction, platform?: Platform): UnifiedLOLEntry[] {
    const results = this.byFunction.get(func) || [];
    if (platform) return results.filter(e => e.platform === platform);
    return results;
  }

  searchByAttck(techniqueId: string, platform?: Platform): UnifiedLOLEntry[] {
    const results = this.byAttck.get(techniqueId) || [];
    if (platform) return results.filter(e => e.platform === platform);
    return results;
  }

  searchByPlatform(platform: Platform): UnifiedLOLEntry[] {
    return this.byPlatform.get(platform) || [];
  }

  searchByCatalog(catalog: CatalogSource): UnifiedLOLEntry[] {
    return this.byCatalog.get(catalog) || [];
  }

  searchByStealth(maxStealth: number, platform?: Platform): UnifiedLOLEntry[] {
    let results = this.entries.filter(e => e.stealthScore <= maxStealth);
    if (platform) results = results.filter(e => e.platform === platform);
    return results;
  }

  searchByKeyword(keyword: string, platform?: Platform): UnifiedLOLEntry[] {
    const lower = keyword.toLowerCase();
    let results = this.entries.filter(e =>
      e.binary.toLowerCase().includes(lower) ||
      e.description.toLowerCase().includes(lower) ||
      e.executionContexts.some(c => c.command.toLowerCase().includes(lower)) ||
      e.aliases.some(a => a.toLowerCase().includes(lower))
    );
    if (platform) results = results.filter(e => e.platform === platform);
    return results;
  }

  searchByDetectionCoverage(hasDetection: boolean): UnifiedLOLEntry[] {
    return this.entries.filter(e => {
      const hasDet = e.detection.sigmaRules.length > 0 ||
        e.detection.yaraRules.length > 0 ||
        e.detection.elasticRules.length > 0 ||
        e.detection.splunkRules.length > 0;
      return hasDetection ? hasDet : !hasDet;
    });
  }

  searchCombined(filters: {
    platform?: Platform;
    function?: LOLFunction;
    maxStealth?: number;
    catalog?: CatalogSource;
    hasDetection?: boolean;
    category?: string;
  }): UnifiedLOLEntry[] {
    let results = this.entries;

    if (filters.platform) results = results.filter(e => e.platform === filters.platform);
    if (filters.function) results = results.filter(e => e.functions.includes(filters.function!));
    if (filters.maxStealth !== undefined) results = results.filter(e => e.stealthScore <= filters.maxStealth!);
    if (filters.catalog) results = results.filter(e => e.catalogSource === filters.catalog);
    if (filters.category) results = results.filter(e => e.category === filters.category);
    if (filters.hasDetection !== undefined) {
      results = results.filter(e => {
        const hasDet = e.detection.sigmaRules.length > 0 ||
          e.detection.yaraRules.length > 0 ||
          e.detection.elasticRules.length > 0;
        return filters.hasDetection ? hasDet : !hasDet;
      });
    }

    return results;
  }

  matchEnvironment(state: EnvironmentState): MatchedEntry[] {
    const matched: MatchedEntry[] = [];
    const platformEntries = this.byPlatform.get(state.platform) || [];

    // 1. SUID binaries (Linux)
    for (const suidPath of state.suidBinaries) {
      const binName = basename(suidPath);
      const entries = this.lookupBinary(binName, state.platform);
      for (const entry of entries) {
        const suidContexts = entry.executionContexts.filter(c => c.context === "suid");
        if (suidContexts.length > 0) {
          matched.push({
            entry,
            matchReason: `SUID bit set on ${suidPath}`,
            applicableContexts: suidContexts,
            effectiveStealthScore: this.adjustStealth(entry.stealthScore, state),
          });
        }
      }
    }

    // 2. Sudo entries (Linux)
    for (const sudo of state.sudoEntries) {
      const entries = this.lookupBinary(sudo.binaryNormalized, state.platform);
      for (const entry of entries) {
        const sudoContexts = entry.executionContexts.filter(c => c.context === "sudo");
        if (sudoContexts.length > 0) {
          matched.push({
            entry,
            matchReason: `sudo ${sudo.nopasswd ? "NOPASSWD" : ""}: ${sudo.constraints}`,
            applicableContexts: sudoContexts,
            effectiveStealthScore: this.adjustStealth(entry.stealthScore, state),
          });
        }
      }
    }

    // 3. Capabilities (Linux)
    for (const cap of state.capabilities) {
      const entries = this.lookupBinary(cap.binaryNormalized, state.platform);
      for (const entry of entries) {
        const capContexts = entry.executionContexts.filter(c =>
          c.context === "capabilities" &&
          (!c.requiredCapabilities || c.requiredCapabilities.some(rc =>
            cap.capabilities.some(ec => ec.toLowerCase().includes(rc.toLowerCase().replace("cap_", "")))
          ))
        );
        if (capContexts.length > 0) {
          matched.push({
            entry,
            matchReason: `Capability ${cap.capabilities.join(",")} on ${cap.binary}`,
            applicableContexts: capContexts,
            effectiveStealthScore: this.adjustStealth(entry.stealthScore, state),
          });
        }
      }
    }

    // 4. Installed binaries (unprivileged contexts)
    for (const binName of state.installedBinaries) {
      const entries = this.lookupBinary(binName, state.platform);
      for (const entry of entries) {
        const unprivContexts = entry.executionContexts.filter(c =>
          c.context === "unprivileged" || c.context === "user"
        );
        if (unprivContexts.length > 0) {
          matched.push({
            entry,
            matchReason: `Installed binary: ${binName}`,
            applicableContexts: unprivContexts,
            effectiveStealthScore: this.adjustStealth(entry.stealthScore, state),
          });
        }
      }
    }

    // 5. Loaded drivers (Windows)
    for (const driver of state.loadedDrivers) {
      const driverEntries = platformEntries.filter(e =>
        e.category === "driver" && e.driverSamples?.some(s =>
          (driver.hash && s.sha256.toLowerCase() === driver.hash.toLowerCase()) ||
          normalizeBinaryName(s.filename) === normalizeBinaryName(driver.filename)
        )
      );
      for (const entry of driverEntries) {
        matched.push({
          entry,
          matchReason: `Loaded driver matches LOLDrivers: ${driver.filename}`,
          applicableContexts: entry.executionContexts,
          effectiveStealthScore: this.adjustStealth(entry.stealthScore, state),
        });
      }
    }

    // 6. Token privileges (Windows)
    if (state.tokenPrivileges.length > 0) {
      const tokenEntries = platformEntries.filter(e =>
        e.functions.includes("privilege_escalation") &&
        e.executionContexts.some(c => c.context === "admin" || c.context === "system")
      );
      for (const entry of tokenEntries) {
        const adminContexts = entry.executionContexts.filter(c =>
          c.context === "admin" || c.context === "system"
        );
        if (adminContexts.length > 0) {
          matched.push({
            entry,
            matchReason: `Token privileges: ${state.tokenPrivileges.slice(0, 3).join(", ")}`,
            applicableContexts: adminContexts,
            effectiveStealthScore: this.adjustStealth(entry.stealthScore, state),
          });
        }
      }
    }

    return this.deduplicateMatched(matched);
  }

  private adjustStealth(baseScore: number, state: EnvironmentState): number {
    let score = baseScore;
    if (state.edrDetected !== "none") score += 1;
    return Math.min(score, 5);
  }

  private deduplicateMatched(matched: MatchedEntry[]): MatchedEntry[] {
    const seen = new Map<string, MatchedEntry>();
    for (const m of matched) {
      const existing = seen.get(m.entry.id);
      if (!existing || m.applicableContexts.length > existing.applicableContexts.length) {
        seen.set(m.entry.id, m);
      }
    }
    return [...seen.values()];
  }

  private linkRelatedEntries(): void {
    const byNorm = new Map<string, UnifiedLOLEntry[]>();
    for (const e of this.entries) {
      const norm = normalizeBinaryName(e.binary);
      addToIndex(byNorm, norm, e);
    }
    for (const [, group] of byNorm) {
      if (group.length > 1) {
        for (const e of group) {
          e.relatedEntries = group.filter(o => o.id !== e.id).map(o => o.id);
        }
      }
    }
  }

  stats(): {
    total: number;
    byCatalog: Record<string, number>;
    byPlatform: Record<string, number>;
    byFunction: Record<string, number>;
  } {
    const byCat: Record<string, number> = {};
    for (const [k, v] of this.byCatalog) byCat[k] = v.length;
    const byPlat: Record<string, number> = {};
    for (const [k, v] of this.byPlatform) byPlat[k] = v.length;
    const byFunc: Record<string, number> = {};
    for (const [k, v] of this.byFunction) byFunc[k] = v.length;

    return { total: this.entries.length, byCatalog: byCat, byPlatform: byPlat, byFunction: byFunc };
  }

  get allEntries(): UnifiedLOLEntry[] {
    return this.entries;
  }

  get totalEntries(): number {
    return this.entries.length;
  }
}
