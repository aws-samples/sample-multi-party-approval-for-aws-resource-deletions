import * as fs from 'fs';
import * as path from 'path';

export interface ApprovalLevelConfig {
  /** IAM Identity Center permission set names whose provisioned roles may approve. */
  readonly permissionSets: string[];
  /**
   * Explicit approver principal ARNs (IAM roles or users). The token `{account}` is
   * replaced with the member account ID, e.g. arn:aws:iam::{account}:role/SecurityApprover.
   */
  readonly principalArns: string[];
  /** Number of distinct humans that must approve this level. */
  readonly minApprovals: number;
  /** Optional e-mail addresses notified when a request waits for THIS level. */
  readonly notificationEmails?: string[];
}

export interface GuardConfig {
  /** OUs that receive the member stack (StackSet) and the SCPs. */
  readonly organizationalUnitIds: string[];
  /** Attach the SCPs to the OUs. Set to false for a dry run of the member stack first. */
  readonly attachScps: boolean;
  /** SELF when deploying from the management account, DELEGATED_ADMIN otherwise. */
  readonly stackSetCallAs: 'SELF' | 'DELEGATED_ADMIN';
  /** Regions where approved deletions may target resources. */
  readonly allowedTargetRegions: string[];
  readonly approvals: {
    readonly level1: ApprovalLevelConfig;
    readonly level2: ApprovalLevelConfig;
  };
  /**
   * Format of resolved IAM Identity Center role ARNs in the aws:approve Approvers list.
   * true (default): full ARN with the /aws-reserved/sso.amazonaws.com/... path.
   * false: arn:aws:iam::<account>:role/<RoleName>. Switch if approvers do not get the
   * Approve option in the console (see README, "Validate in a sandbox").
   */
  readonly approverRoleArnWithPath?: boolean;
  /** How long a request can wait for each approval level (1-720 hours). */
  readonly approvalTimeoutHours: number;
  /**
   * Optional e-mail addresses notified of request outcomes (validated, executed, rejected,
   * refused invocations), for example requesters and the security team.
   */
  readonly notificationEmails: string[];
  readonly terraform: {
    /** Terraform CLI version the build image must provide (checked at build time). */
    readonly version: string;
    /**
     * ECR image URI (tag or digest) with Terraform, the AWS CLI, jq and unzip preinstalled,
     * e.g. 111122223333.dkr.ecr.eu-west-1.amazonaws.com/terraform-build@sha256:<digest>.
     * Empty: the Terraform approval path (runbook and CodeBuild projects) is not deployed.
     */
    readonly buildImage?: string;
    /** Managed policies attached to the role that applies approved Terraform plans. */
    readonly applyManagedPolicyArns: string[];
  };
  /**
   * Extra principals exempted from the destructive-actions SCP, for example
   * a Karpenter controller role that legitimately terminates EC2 instances.
   * Wildcards are allowed (ArnLike semantics). Keep this list short.
   */
  readonly additionalExemptPrincipalArns: string[];
  /**
   * Principals allowed to modify the guard's own resources in member accounts
   * (in addition to the StackSets execution role). Usually empty.
   */
  readonly platformAdminPrincipalArns: string[];
  /** Optional EventBridge bus ARN (central security account) to forward guard events to. */
  readonly centralEventBusArn: string;
}

const ROOT = path.resolve(__dirname, '..', '..', '..');

/** Load guard-config.json (or the example file when the real one is missing). */
export function loadConfig(configPath?: string): GuardConfig {
  const candidates = configPath
    ? [path.resolve(configPath)]
    : [path.join(ROOT, 'guard-config.json'), path.join(ROOT, 'guard-config.example.json')];
  const file = candidates.find((c) => fs.existsSync(c));
  if (!file) {
    throw new Error(`No configuration file found. Looked for: ${candidates.join(', ')}`);
  }
  const cfg = JSON.parse(fs.readFileSync(file, 'utf8')) as GuardConfig;
  validateConfig(cfg);
  return cfg;
}

export function validateConfig(cfg: GuardConfig): void {
  const errors: string[] = [];
  if (!cfg.allowedTargetRegions?.length) errors.push('allowedTargetRegions must contain at least one region');
  for (const [name, lvl] of Object.entries(cfg.approvals ?? {})) {
    const sources = (lvl.permissionSets?.length ?? 0) + (lvl.principalArns?.length ?? 0);
    if (sources === 0) errors.push(`approvals.${name} needs at least one permission set or principal ARN`);
    if (!Number.isInteger(lvl.minApprovals) || lvl.minApprovals < 1 || lvl.minApprovals > 10) {
      errors.push(`approvals.${name}.minApprovals must be an integer between 1 and 10`);
    }
  }
  if (!cfg.approvals?.level1 || !cfg.approvals?.level2) errors.push('approvals.level1 and approvals.level2 are required');
  if (!(cfg.approvalTimeoutHours >= 1 && cfg.approvalTimeoutHours <= 720)) {
    errors.push('approvalTimeoutHours must be between 1 and 720 (aws:approve maximum is 30 days)');
  }
  if (!/^\d+\.\d+\.\d+$/.test(cfg.terraform?.version ?? '')) errors.push('terraform.version must look like 1.2.3');
  const image = cfg.terraform?.buildImage ?? '';
  if (image && !/^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(\.cn)?\/[a-z0-9._/-]+(:[\w.-]{1,128}|@sha256:[a-f0-9]{64})$/.test(image)) {
    errors.push('terraform.buildImage must be an ECR image URI with a tag or @sha256 digest');
  }
  if (!['SELF', 'DELEGATED_ADMIN'].includes(cfg.stackSetCallAs)) errors.push('stackSetCallAs must be SELF or DELEGATED_ADMIN');
  // Exemptions must be roles: the guard-protection SCP then stops administrators from
  // creating a role with an exempt name or rewriting its trust policy.
  for (const arn of cfg.additionalExemptPrincipalArns ?? []) {
    if (!/^arn:aws[a-z-]*:iam::(\*|\d{12}):role\/[\w+=,.@\/*-]+$/.test(arn)) {
      errors.push(`additionalExemptPrincipalArns: ${arn} must be an IAM role ARN (wildcards allowed)`);
    }
  }
  if (errors.length) {
    throw new Error(`Invalid guard configuration:\n - ${errors.join('\n - ')}`);
  }
}
