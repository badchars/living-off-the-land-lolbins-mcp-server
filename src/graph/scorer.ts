import type { AttackPath } from "../schema/graph.js";
import type { EnvironmentState } from "../schema/environment.js";

export interface ScoringWeights {
  certainty: number; // default 0.4
  brevity: number; // default 0.1
  stealth: number; // default 0.3
  impact: number; // default 0.2
}

const DEFAULT_WEIGHTS: ScoringWeights = {
  certainty: 0.4,
  brevity: 0.1,
  stealth: 0.3,
  impact: 0.2,
};

/**
 * Compute brevity score: shorter paths get higher scores.
 * 1 step = 1.0, 2 steps = 0.8, 3 steps = 0.6, 4+ steps = max(0.2, 1 - steps * 0.2)
 */
function computeBrevity(path: AttackPath): number {
  const steps = path.steps.length;
  if (steps === 0) return 0;
  return Math.max(0.2, 1 - (steps - 1) * 0.2);
}

/**
 * Compute impact score based on what the path achieves.
 * root/SYSTEM = 1.0, admin/Administrator = 0.8, else 0.5
 * +0.2 if persistence is established (capped at 1.0)
 * +0.3 if lateral movement is achieved (capped at 1.0)
 */
export function computeImpact(path: AttackPath): number {
  let base = 0.5;

  // Check last step result for privilege target
  const lastResult = path.steps[path.steps.length - 1]?.result?.toLowerCase() ?? "";
  if (lastResult === "root" || lastResult === "system") {
    base = 1.0;
  } else if (lastResult === "administrator") {
    base = 0.8;
  } else {
    // Check all step results (might reach target mid-chain)
    for (const step of path.steps) {
      const r = step.result.toLowerCase();
      if (r === "root" || r === "system") {
        base = Math.max(base, 1.0);
      } else if (r === "administrator") {
        base = Math.max(base, 0.8);
      }
    }
  }

  // Check for persistence
  const hasPersistence = path.steps.some(
    (s) => s.action === "EnablesPersistence",
  );
  if (hasPersistence) {
    base = Math.min(1.0, base + 0.2);
  }

  // Check for lateral movement
  const hasLateral = path.steps.some((s) => s.action === "CanReach");
  if (hasLateral) {
    base = Math.min(1.0, base + 0.3);
  }

  return Math.round(base * 100) / 100;
}

/**
 * Adjust stealth score when EDR is detected.
 * If EDR is present, stealth matters more — paths that avoid detection get +0.1 bonus,
 * paths that trigger known detections get -0.1 penalty.
 * The adjustment is reflected in the path's totalStealth.
 */
export function adjustStealth(path: AttackPath, state: EnvironmentState): number {
  let stealth = path.totalStealth;

  if (state.edrDetected && state.edrDetected !== "none") {
    // EDR is active — check detection coverage of steps
    const highDetectionSteps = path.steps.filter(
      (s) => s.detection.edrCoverage === "high",
    ).length;
    const lowDetectionSteps = path.steps.filter(
      (s) => s.detection.edrCoverage === "none" || s.detection.edrCoverage === "low",
    ).length;

    // Penalty for high-detection steps
    stealth -= highDetectionSteps * 0.1;
    // Bonus for low-detection steps
    stealth += lowDetectionSteps * 0.05;

    // Overall penalty: EDR presence makes everything harder
    stealth -= 0.1;
  }

  return Math.round(Math.max(0, Math.min(1, stealth)) * 100) / 100;
}

/**
 * Multi-objective scoring of an attack path.
 * Score = w_certainty * certainty + w_brevity * brevity + w_stealth * stealth + w_impact * impact
 */
export function scorePath(
  path: AttackPath,
  weights?: Partial<ScoringWeights>,
  state?: EnvironmentState,
): number {
  const w: ScoringWeights = { ...DEFAULT_WEIGHTS, ...weights };

  const certainty = path.certainty;
  const brevity = computeBrevity(path);
  const stealth = state ? adjustStealth(path, state) : path.totalStealth;
  const impact = computeImpact(path);

  // Update path fields
  path.impact = impact;

  const score =
    w.certainty * certainty +
    w.brevity * brevity +
    w.stealth * stealth +
    w.impact * impact;

  // Normalize to [0, 1]
  const totalWeight = w.certainty + w.brevity + w.stealth + w.impact;
  const normalized = totalWeight > 0 ? score / totalWeight : 0;

  path.score = Math.round(normalized * 100) / 100;
  return path.score;
}

/**
 * Rank paths by score descending.
 * Assigns rank (1-based) to each path.
 */
export function rankPaths(
  paths: AttackPath[],
  weights?: Partial<ScoringWeights>,
  state?: EnvironmentState,
): AttackPath[] {
  const w: ScoringWeights = { ...DEFAULT_WEIGHTS, ...weights };

  // Score all paths
  for (const path of paths) {
    scorePath(path, w, state);
  }

  // Sort by score descending
  const sorted = [...paths].sort((a, b) => b.score - a.score);

  // Assign ranks
  for (let i = 0; i < sorted.length; i++) {
    sorted[i].rank = i + 1;
  }

  return sorted;
}
