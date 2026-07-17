import type { ToolDef } from "../types/index.js";
import { compositeTools } from "../composite/index.js";
// Phase 1 providers
import { lookupTools } from "../providers/lookup.js";
import { searchTools } from "../providers/search.js";
import { updateTools } from "../providers/update.js";
// Phase 2 providers
import { enumerateTools } from "../providers/enumerate.js";
import { escalationTools } from "../providers/escalation.js";
import { chainTools } from "../providers/chains.js";
// Phase 3 providers
import { persistenceTools } from "../providers/persistence.js";
import { lateralTools } from "../providers/lateral.js";
import { credentialTools } from "../providers/credential.js";
import { executionTools } from "../providers/execution.js";
import { exfiltrationTools } from "../providers/exfiltration.js";
import { c2Tools } from "../providers/c2.js";
import { initialAccessTools } from "../providers/initial-access.js";
import { discoveryTools } from "../providers/discovery.js";
import { collectionTools } from "../providers/collection.js";
import { comAbuseTools } from "../providers/com-abuse.js";
import { namedPipeTools } from "../providers/named-pipe.js";
import { wmiAbuseTools } from "../providers/wmi-abuse.js";
import { packageManagerTools } from "../providers/package-manager.js";
import { nativeCryptoTools } from "../providers/native-crypto.js";
// Phase 4 providers
import { evasionTools } from "../providers/evasion.js";
import { processManipulationTools } from "../providers/process-manipulation.js";
import { envvarAbuseTools } from "../providers/envvar-abuse.js";
import { antiforensicsTools } from "../providers/antiforensics.js";
import { dllHijackTools } from "../providers/dll-hijack.js";
import { payloadTools } from "../providers/payload.js";
import { obfuscateTools } from "../providers/obfuscate.js";
import { chainObfuscationTools } from "../providers/chain-obfuscation.js";
import { stagedPayloadTools } from "../providers/staged-payload.js";
import { opsecRiskTools } from "../providers/opsec-risk.js";
import { planTools } from "../providers/plan.js";
// Phase 5 providers
import { driversTools } from "../providers/drivers.js";
import { rmmTools } from "../providers/rmm.js";
import { cicdTools } from "../providers/cicd.js";
import { cloudAbuseTools } from "../providers/cloud-abuse.js";
import { containerEscapeTools } from "../providers/container-escape.js";
import { macosTccTools } from "../providers/macos-tcc.js";
import { wadcomsTools } from "../providers/wadcoms.js";
// Phase 6 providers
import { threatActorTools } from "../providers/threat-actor.js";
import { adversarySimTools } from "../providers/adversary-sim.js";
import { techniqueEvolutionTools } from "../providers/technique-evolution.js";
import { identifyTechniqueTools } from "../providers/identify-technique.js";
import { forensicArtifactTools } from "../providers/forensic-artifact.js";
import { incidentTimelineTools } from "../providers/incident-timeline.js";
// Phase 7 providers
import { detectionGenTools } from "../providers/detection-gen.js";
import { detectionEffectivenessTools } from "../providers/detection-effectiveness.js";
import { detectionBlindSpotsTools } from "../providers/detection-blind-spots.js";
import { redVsBlueTools } from "../providers/red-vs-blue.js";
import { attckTools } from "../providers/attck.js";
import { osVersionsTools } from "../providers/os-versions.js";
// Phase 8 providers
import { reportTools } from "../providers/report.js";
import { visualizeTools } from "../providers/visualize.js";
import { purpleTeamTools } from "../providers/purple-team.js";
import { calderaTools } from "../providers/caldera.js";

// Composite tools are exposed to MCP clients
export const allTools: ToolDef[] = compositeTools;

// Individual tools are used internally by composites and available via --tool CLI
export const individualTools: ToolDef[] = [
  // Phase 1
  ...lookupTools,
  ...searchTools,
  ...updateTools,
  // Phase 2
  ...enumerateTools,
  ...escalationTools,
  ...chainTools,
  // Phase 3
  ...persistenceTools,
  ...lateralTools,
  ...credentialTools,
  ...executionTools,
  ...exfiltrationTools,
  ...c2Tools,
  ...initialAccessTools,
  ...discoveryTools,
  ...collectionTools,
  ...comAbuseTools,
  ...namedPipeTools,
  ...wmiAbuseTools,
  ...packageManagerTools,
  ...nativeCryptoTools,
  // Phase 4
  ...evasionTools,
  ...processManipulationTools,
  ...envvarAbuseTools,
  ...antiforensicsTools,
  ...dllHijackTools,
  ...payloadTools,
  ...obfuscateTools,
  ...chainObfuscationTools,
  ...stagedPayloadTools,
  ...opsecRiskTools,
  ...planTools,
  // Phase 5
  ...driversTools,
  ...rmmTools,
  ...cicdTools,
  ...cloudAbuseTools,
  ...containerEscapeTools,
  ...macosTccTools,
  ...wadcomsTools,
  // Phase 6
  ...threatActorTools,
  ...adversarySimTools,
  ...techniqueEvolutionTools,
  ...identifyTechniqueTools,
  ...forensicArtifactTools,
  ...incidentTimelineTools,
  // Phase 7
  ...detectionGenTools,
  ...detectionEffectivenessTools,
  ...detectionBlindSpotsTools,
  ...redVsBlueTools,
  ...attckTools,
  ...osVersionsTools,
  // Phase 8
  ...reportTools,
  ...visualizeTools,
  ...purpleTeamTools,
  ...calderaTools,
];

// All tools combined (for --list-all and --tool CLI dispatch)
export const allToolsCombined: ToolDef[] = [
  ...allTools,
  ...individualTools,
];
