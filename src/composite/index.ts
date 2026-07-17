import type { ToolDef } from "../types/index.js";
import { lookupBinaryComposite } from "./lookup-binary.js";
import { searchTechniquesComposite } from "./search-techniques.js";
import { updateKbComposite } from "./update-kb.js";
import { enumerateHostComposite } from "./enumerate-host.js";
import { findEscalationComposite } from "./find-escalation.js";
import { discoverChainsComposite } from "./discover-chains.js";
import { findTokenAbuseComposite } from "./find-token-abuse.js";
import { analyzeBinaryComposite } from "./analyze-binary.js";
import { analyzeEnvironmentComposite } from "./analyze-environment.js";
import { comparePlatformsComposite } from "./compare-platforms.js";
import { findPersistenceComposite } from "./find-persistence.js";
import { findComAbuseComposite } from "./find-com-abuse.js";
import { findLateralComposite } from "./find-lateral.js";
import { findNamedPipeComposite } from "./find-named-pipe.js";
import { findCredentialComposite } from "./find-credential.js";
import { findWmiAbuseComposite } from "./find-wmi-abuse.js";
import { findExecutionComposite } from "./find-execution.js";
import { findInitialAccessComposite } from "./find-initial-access.js";
import { findPackageManagerComposite } from "./find-package-manager.js";
import { findDiscoveryComposite } from "./find-discovery.js";
import { findCollectionComposite } from "./find-collection.js";
import { findExfiltrationComposite } from "./find-exfiltration.js";
import { findC2Composite } from "./find-c2.js";
import { findNativeCryptoComposite } from "./find-native-crypto.js";
import { findEvasionComposite } from "./find-evasion.js";
import { findProcessManipulationComposite } from "./find-process-manipulation.js";
import { findEnvvarAbuseComposite } from "./find-envvar-abuse.js";
import { findAntiforensicsComposite } from "./find-antiforensics.js";
import { findDllHijackComposite } from "./find-dll-hijack.js";
import { generatePayloadComposite } from "./generate-payload.js";
import { obfuscatePayloadComposite } from "./obfuscate-payload.js";
import { chainObfuscationComposite } from "./chain-obfuscation.js";
import { generateStagedComposite } from "./generate-staged.js";
import { analyzeOpsecComposite } from "./analyze-opsec.js";
import { buildPlanComposite } from "./build-plan.js";
import { scanDriversComposite } from "./scan-drivers.js";
import { findRmmComposite } from "./find-rmm.js";
import { findCicdComposite } from "./find-cicd.js";
import { findCloudAbuseComposite } from "./find-cloud-abuse.js";
import { findContainerEscapeComposite } from "./find-container-escape.js";
import { findMacosTccComposite } from "./find-macos-tcc.js";
import { queryWadcomsComposite } from "./query-wadcoms.js";
import { mapThreatActorComposite } from "./map-threat-actor.js";
import { simulateAdversaryComposite } from "./simulate-adversary.js";
import { trackEvolutionComposite } from "./track-evolution.js";
import { identifyTechniqueComposite } from "./identify-technique.js";
import { analyzeForensicComposite } from "./analyze-forensic.js";
import { correlateTimelineComposite } from "./correlate-timeline.js";
import { assessDetectionComposite } from "./assess-detection.js";
import { generateDetectionComposite } from "./generate-detection.js";
import { analyzeDetectionComposite } from "./analyze-detection.js";
import { findBlindSpotsComposite } from "./find-blind-spots.js";
import { scoreRedVsBlueComposite } from "./score-red-vs-blue.js";
import { mapAttckComposite } from "./map-attck.js";
import { compareOsVersionsComposite } from "./compare-os-versions.js";
import { exportReportComposite } from "./export-report.js";
import { visualizeAttackComposite } from "./visualize-attack.js";
import { generatePurpleTeamComposite } from "./generate-purple-team.js";
import { exportCalderaComposite } from "./export-caldera.js";

export const compositeTools: ToolDef[] = [
  lookupBinaryComposite,
  searchTechniquesComposite,
  updateKbComposite,
  enumerateHostComposite,
  findEscalationComposite,
  discoverChainsComposite,
  findTokenAbuseComposite,
  analyzeBinaryComposite,
  analyzeEnvironmentComposite,
  comparePlatformsComposite,
  findPersistenceComposite,
  findComAbuseComposite,
  findLateralComposite,
  findNamedPipeComposite,
  findCredentialComposite,
  findWmiAbuseComposite,
  findExecutionComposite,
  findInitialAccessComposite,
  findPackageManagerComposite,
  findDiscoveryComposite,
  findCollectionComposite,
  findExfiltrationComposite,
  findC2Composite,
  findNativeCryptoComposite,
  findEvasionComposite,
  findProcessManipulationComposite,
  findEnvvarAbuseComposite,
  findAntiforensicsComposite,
  findDllHijackComposite,
  generatePayloadComposite,
  obfuscatePayloadComposite,
  chainObfuscationComposite,
  generateStagedComposite,
  analyzeOpsecComposite,
  buildPlanComposite,
  scanDriversComposite,
  findRmmComposite,
  findCicdComposite,
  findCloudAbuseComposite,
  findContainerEscapeComposite,
  findMacosTccComposite,
  queryWadcomsComposite,
  mapThreatActorComposite,
  simulateAdversaryComposite,
  trackEvolutionComposite,
  identifyTechniqueComposite,
  analyzeForensicComposite,
  correlateTimelineComposite,
  assessDetectionComposite,
  generateDetectionComposite,
  analyzeDetectionComposite,
  findBlindSpotsComposite,
  scoreRedVsBlueComposite,
  mapAttckComposite,
  compareOsVersionsComposite,
  exportReportComposite,
  visualizeAttackComposite,
  generatePurpleTeamComposite,
  exportCalderaComposite,
];
