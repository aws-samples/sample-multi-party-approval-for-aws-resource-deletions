import { GuardConfig } from './config';
import { NAMES, PREFIX, STACKSETS_EXEC_ROLE_PATTERN } from './names';
import { deniedDestructiveActions } from './protected-resources';

/** AWS Organizations limit for a single SCP document (characters, minified JSON). */
export const SCP_MAX_SIZE = 5120;

type Statement = Record<string, unknown>;
export interface PolicyDocument {
  Version: '2012-10-17';
  Statement: Statement[];
}

const roleArn = (name: string) => `arn:aws:iam::*:role/${name}`;

/** Principals allowed to perform protected deletions (the approved execution path). */
export function deletionExemptPrincipals(cfg: GuardConfig): string[] {
  return [
    roleArn(NAMES.gateRole),
    roleArn(NAMES.terraformApplyRole),
    // Lets StackSets update/remove the guard's own resources.
    STACKSETS_EXEC_ROLE_PATTERN,
    ...cfg.additionalExemptPrincipalArns,
  ];
}

/** Principals allowed to change the guard's own resources. */
export function platformPrincipals(cfg: GuardConfig): string[] {
  return [STACKSETS_EXEC_ROLE_PATTERN, ...cfg.platformAdminPrincipalArns];
}

const exceptFor = (principals: string[]) => ({ ArnNotLike: { 'aws:PrincipalArn': principals } });

/** IAM actions that create a role or change who can use it and what it can do. */
const ROLE_WRITE_ACTIONS = [
  'iam:AttachRolePolicy',
  'iam:CreateRole',
  'iam:DeleteRole',
  'iam:DeleteRolePermissionsBoundary',
  'iam:DeleteRolePolicy',
  'iam:DetachRolePolicy',
  'iam:PutRolePermissionsBoundary',
  'iam:PutRolePolicy',
  'iam:TagRole',
  'iam:UntagRole',
  'iam:UpdateAssumeRolePolicy',
  'iam:UpdateRole',
  'iam:UpdateRoleDescription',
];

/**
 * SCP 1 - deny destructive control-plane actions organization-wide, for every
 * identity (including the member account root user, CI/CD roles, Terraform and
 * CloudFormation service roles), except the guard's executor roles.
 */
export function buildDestructiveActionsScp(cfg: GuardConfig): PolicyDocument {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyDestructiveActionsOutsideApprovedPath',
        Effect: 'Deny',
        Action: deniedDestructiveActions(),
        Resource: '*',
        Condition: exceptFor(deletionExemptPrincipals(cfg)),
      },
    ],
  };
}

/**
 * SCP 2 - protect the guard itself. Without this, an administrator in a member
 * account could edit the gate Lambda, widen the runbook approvers, pass the exempt
 * roles to their own compute, or tamper with the ledger and plan artifacts.
 */
export function buildGuardProtectionScp(cfg: GuardConfig): PolicyDocument {
  const platform = platformPrincipals(cfg);
  const platformAndGate = [...platform, roleArn(NAMES.gateRole)];
  const guardRoles = `arn:aws:iam::*:role/${PREFIX}-*`;

  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ProtectGuardRoles',
        Effect: 'Deny',
        Action: ROLE_WRITE_ACTIONS,
        Resource: guardRoles,
        Condition: exceptFor(platform),
      },
      // Additional exempt roles (e.g. AWSControlTowerExecution, a Karpenter controller) are
      // exempted BY NAME. Without this statement an administrator could create a role with
      // that name, or rewrite its trust policy, assume it and delete anything.
      ...(cfg.additionalExemptPrincipalArns.length
        ? [
            {
              Sid: 'ProtectAdditionalExemptRoles',
              Effect: 'Deny',
              Action: [...ROLE_WRITE_ACTIONS, 'iam:PassRole', 'sts:AssumeRole'],
              Resource: cfg.additionalExemptPrincipalArns,
              // Cross-account callers (e.g. Control Tower from the management account) are not
              // subject to member-account SCPs, so they keep working.
              Condition: exceptFor([...platform, ...cfg.additionalExemptPrincipalArns]),
            },
          ]
        : []),
      {
        // Nobody may hand the exempt roles to their own Lambda, CodeBuild project or EC2.
        // The gate may pass its own role to CloudFormation when it deletes a stack.
        Sid: 'ProtectExemptRolesFromPassAndAssume',
        Effect: 'Deny',
        Action: ['iam:PassRole', 'sts:AssumeRole'],
        Resource: [roleArn(NAMES.gateRole), roleArn(NAMES.terraformApplyRole)],
        Condition: exceptFor(platformAndGate),
      },
      {
        Sid: 'ProtectGuardFunctions',
        Effect: 'Deny',
        NotAction: ['lambda:Get*', 'lambda:List*', 'lambda:InvokeFunction'],
        Resource: `arn:aws:lambda:*:*:function:${PREFIX}-*`,
        Condition: exceptFor(platform),
      },
      {
        // Only the runbooks invoke the gate. The gate would reject forged calls anyway,
        // this removes the noise (and a denial-of-service vector) of direct invocations.
        Sid: 'OnlyRunbooksInvokeGate',
        Effect: 'Deny',
        Action: 'lambda:InvokeFunction',
        Resource: `arn:aws:lambda:*:*:function:${NAMES.gateFunction}`,
        Condition: exceptFor([...platform, roleArn(NAMES.runbookRole)]),
      },
      {
        Sid: 'ProtectGuardRunbooks',
        Effect: 'Deny',
        NotAction: ['ssm:Describe*', 'ssm:Get*', 'ssm:List*', 'ssm:StartAutomationExecution'],
        Resource: [`arn:aws:ssm:*:*:document/${PREFIX}-*`],
        Condition: exceptFor(platform),
      },
      {
        // StartBuild must be gated too: it accepts buildspec and environment overrides.
        Sid: 'ProtectGuardBuildProjects',
        Effect: 'Deny',
        NotAction: ['codebuild:BatchGet*', 'codebuild:List*'],
        Resource: `arn:aws:codebuild:*:*:project/${PREFIX}-*`,
        Condition: exceptFor(platformAndGate),
      },
      {
        Sid: 'ProtectGuardLedger',
        Effect: 'Deny',
        // Reads stay allowed (including Scan, used by the console "Explore items" view) so that
        // auditors can browse the ledger; every write is denied.
        NotAction: ['dynamodb:Describe*', 'dynamodb:Get*', 'dynamodb:List*', 'dynamodb:Query', 'dynamodb:Scan', 'dynamodb:BatchGetItem'],
        Resource: [`arn:aws:dynamodb:*:*:table/${NAMES.ledgerTable}`, `arn:aws:dynamodb:*:*:table/${NAMES.ledgerTable}/*`],
        Condition: exceptFor(platformAndGate),
      },
      {
        Sid: 'ProtectGuardPlanArtifacts',
        Effect: 'Deny',
        NotAction: ['s3:Get*', 's3:List*'],
        Resource: [
          `arn:aws:s3:::${NAMES.plansBucketPrefix}-*`,
          `arn:aws:s3:::${NAMES.plansBucketPrefix}-*/*`,
          `arn:aws:s3:::${NAMES.accessLogsBucketPrefix}-*`,
          `arn:aws:s3:::${NAMES.accessLogsBucketPrefix}-*/*`,
        ],
        Condition: exceptFor([...platformAndGate, roleArn(NAMES.terraformPlanRole)]),
      },
      {
        Sid: 'ProtectGuardNotifications',
        Effect: 'Deny',
        NotAction: ['sns:Get*', 'sns:List*', 'sns:Publish', 'sns:Subscribe', 'sns:ConfirmSubscription', 'events:Describe*', 'events:List*'],
        Resource: [
          `arn:aws:sns:*:*:Automation${PREFIX}*`,
          `arn:aws:sns:*:*:${NAMES.notificationsTopic}`,
          `arn:aws:events:*:*:rule/${PREFIX}-*`,
        ],
        Condition: exceptFor(platform),
      },
      {
        Sid: 'ProtectGuardStack',
        Effect: 'Deny',
        NotAction: ['cloudformation:Describe*', 'cloudformation:Get*', 'cloudformation:List*', 'cloudformation:Detect*'],
        Resource: `arn:aws:cloudformation:*:*:stack/StackSet-${NAMES.stackSet}-*/*`,
        Condition: exceptFor(platform),
      },
      {
        // Leaving the organization would remove every SCP from the account.
        Sid: 'DenyLeavingOrganization',
        Effect: 'Deny',
        Action: 'organizations:LeaveOrganization',
        Resource: '*',
      },
    ],
  };
}

/** Minified size, as counted by AWS Organizations. */
export function scpSize(doc: PolicyDocument): number {
  return JSON.stringify(doc).length;
}
