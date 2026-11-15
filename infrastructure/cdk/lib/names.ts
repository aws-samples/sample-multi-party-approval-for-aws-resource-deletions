/**
 * Fixed physical names shared by the member-account stack and the SCPs.
 *
 * The SCPs exempt and protect resources BY NAME, so these names must be identical
 * in every account and must never be derived from CDK-generated hashes.
 */
export const PREFIX = 'DeletionGuard';

export const NAMES = {
  /** Lambda that verifies approvals and performs the deletion. Exempt from the destructive SCP. */
  gateFunction: `${PREFIX}-Gate`,
  gateRole: `${PREFIX}-GateRole`,
  /** Role assumed by SSM Automation while running the runbooks (no delete permissions). */
  runbookRole: `${PREFIX}-RunbookRole`,
  /** Custom-resource Lambda that resolves IAM Identity Center approver roles. */
  resolverFunction: `${PREFIX}-ApproverResolver`,
  resolverRole: `${PREFIX}-ApproverResolverRole`,
  terraformPlanProject: `${PREFIX}-TerraformPlan`,
  terraformPlanRole: `${PREFIX}-TerraformPlanRole`,
  terraformApplyProject: `${PREFIX}-TerraformApply`,
  /** Role that applies approved Terraform plans. Exempt from the destructive SCP. */
  terraformApplyRole: `${PREFIX}-TerraformApplyRole`,
  eventForwarderRole: `${PREFIX}-EventForwarderRole`,
  ledgerTable: `${PREFIX}-Ledger`,
  resourceRunbook: `${PREFIX}-DeleteResource`,
  terraformRunbook: `${PREFIX}-TerraformChange`,
  /**
   * One topic per approval level, so that approvers are only notified when a request
   * waits for THEIR level. aws:approve requires the topic name to start with "Automation".
   */
  level1Topic: `Automation${PREFIX}Level1`,
  level2Topic: `Automation${PREFIX}Level2`,
  /** Outcomes published by the gate (validated, executed, rejected, refused). */
  notificationsTopic: `${PREFIX}-Notifications`,
  /** Bucket name is suffixed with account and region in the member stack. */
  plansBucketPrefix: 'deletion-guard-plans',
  /** Server access logs destination in each member account (suffixed with account and region). */
  accessLogsBucketPrefix: 'deletion-guard-access-logs',
  eventRulePrefix: `${PREFIX}-`,
  kmsAlias: 'alias/deletion-guard',
  /** Name of the StackSet, and therefore prefix of the stacks it creates. */
  stackSet: `${PREFIX}-Member`,
} as const;

/** Service-managed StackSets execution role created in every member account. */
export const STACKSETS_EXEC_ROLE_PATTERN = 'arn:aws:iam::*:role/stacksets-exec-*';
