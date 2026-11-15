/**
 * SSM Automation runbook definitions.
 *
 * The runbooks orchestrate the human workflow (request -> level 1 -> level 2 ->
 * execute). They are NOT the security boundary: the gate Lambda re-reads the
 * execution from the SSM API and independently verifies document name, current
 * step, approvers, quorum and requester before it deletes anything.
 *
 * Step names are part of the contract with the gate (src/deletion_gate/gate.py).
 */
export const STEP = {
  validate: 'ValidateRequest',
  approve1: 'ApproveLevel1',
  approve2: 'ApproveLevel2',
  execute: 'ExecuteDeletion',
  plan: 'PlanChange',
  apply: 'ApplyChange',
} as const;

export interface RunbookProps {
  readonly runbookRoleArn: string;
  readonly gateFunctionArn: string;
  /** Per-level approval topics: approvers are only notified for their own level. */
  readonly level1TopicArn: string;
  readonly level2TopicArn: string;
  /** Token or list resolving to the approver principal ARNs for each level. */
  readonly level1Approvers: string[];
  readonly level2Approvers: string[];
  readonly level1MinApprovals: number;
  readonly level2MinApprovals: number;
  readonly approvalTimeoutSeconds: number;
  readonly allowedTargetRegions: string[];
  readonly resourceTypes: string[];
}

const invokeGate = (name: string, action: string, timeoutSeconds: number, gateFunctionArn: string) => ({
  name,
  action: 'aws:invokeLambdaFunction',
  onFailure: 'Abort',
  isCritical: true,
  timeoutSeconds,
  inputs: {
    FunctionName: gateFunctionArn,
    InvocationType: 'RequestResponse',
    // The gate trusts nothing in this payload except the execution ID, which it
    // uses to fetch the authoritative execution record from the SSM API.
    Payload: JSON.stringify({ action, executionId: '{{automation:EXECUTION_ID}}' }),
  },
});

const approval = (
  name: string,
  level: number,
  approvers: string[],
  minApprovals: number,
  props: RunbookProps,
  details: string,
) => ({
  name,
  action: 'aws:approve',
  onFailure: 'Abort',
  timeoutSeconds: props.approvalTimeoutSeconds,
  inputs: {
    NotificationArn: level === 1 ? props.level1TopicArn : props.level2TopicArn,
    // aws:approve validates Message against .{1,4096}: a single line, no line breaks.
    Message: [
      `[DeletionGuard] Level ${level} approval required for execution {{automation:EXECUTION_ID}}.`,
      details,
      'Justification: {{Justification}}',
      'Approve or reject in the Systems Manager console (Automation > Executions) or with:',
      'aws ssm send-automation-signal --automation-execution-id {{automation:EXECUTION_ID}} --signal-type Approve (or Reject)',
      'The requester cannot approve their own request and each approver counts only once across all levels.',
    ].join(' | '),
    MinRequiredApprovals: minApprovals,
    Approvers: approvers,
  },
});

export function resourceDeletionRunbook(props: RunbookProps): Record<string, unknown> {
  const details = [
    'Request: DELETE {{ResourceType}} "{{ResourceIdentifier}}" in {{TargetRegion}}.',
    'Disable deletion protection: {{DisableDeletionProtection}}.',
    'Gate validation: {{ValidateRequest.Payload}}',
  ].join(' | ');

  return {
    schemaVersion: '0.3',
    description:
      'DeletionGuard: delete one protected AWS resource after multi-party approval. ' +
      'The deletion is performed by the DeletionGuard gate, which verifies the approvals independently.',
    assumeRole: props.runbookRoleArn,
    parameters: {
      ResourceType: {
        type: 'String',
        description: 'CloudFormation resource type of the resource to delete.',
        allowedValues: props.resourceTypes,
      },
      ResourceIdentifier: {
        type: 'String',
        description: 'Cloud Control API primary identifier (for example the DB instance identifier, table name, bucket name or stack name).',
        // Printable ASCII without spaces. No backslash escapes anywhere in allowedPattern: the
        // Systems Manager console escapes them again (\s would forbid the letter s).
        allowedPattern: '^[!-~]{1,1024}$',
      },
      TargetRegion: {
        type: 'String',
        description: 'Region where the resource lives.',
        allowedValues: props.allowedTargetRegions,
      },
      Justification: {
        type: 'String',
        description: 'Why this resource must be deleted (ticket reference, context). Single line, minimum 20 characters.',
        // Single line: the justification is embedded in the approval Message.
        allowedPattern: '^.{20,1000}$',
      },
      // String, not Boolean: SSM does not allow Boolean parameters inside text such as
      // the approval Message, and approvers must see this flag.
      DisableDeletionProtection: {
        type: 'String',
        description: 'If true, the gate switches off resource-level deletion protection right before deleting.',
        allowedValues: ['false', 'true'],
        default: 'false',
      },
    },
    mainSteps: [
      invokeGate(STEP.validate, 'validate', 120, props.gateFunctionArn),
      approval(STEP.approve1, 1, props.level1Approvers, props.level1MinApprovals, props, details),
      approval(STEP.approve2, 2, props.level2Approvers, props.level2MinApprovals, props, details),
      invokeGate(STEP.execute, 'execute', 900, props.gateFunctionArn),
    ],
    outputs: [`${STEP.execute}.Payload`],
  };
}

export function terraformChangeRunbook(props: RunbookProps): Record<string, unknown> {
  const details = [
    'Request: terraform {{Operation}} of s3://{{SourceBucket}}/{{SourceKey}} (working directory "{{WorkingDirectory}}").',
    'Plan summary from the gate: {{PlanChange.Payload}}',
    'Review the full plan (plan.txt) in the plans bucket under plans/{{automation:EXECUTION_ID}}/ before approving.',
  ].join(' | ');

  return {
    schemaVersion: '0.3',
    description:
      'DeletionGuard: run a destructive Terraform change (destroy, or an apply that deletes/replaces resources) ' +
      'after multi-party approval. Approvers approve a saved plan; exactly that plan is applied.',
    assumeRole: props.runbookRoleArn,
    parameters: {
      SourceBucket: {
        type: 'String',
        description: 'S3 bucket that holds the zipped Terraform configuration (versioning recommended).',
        allowedPattern: '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$',
      },
      SourceKey: {
        type: 'String',
        description: 'S3 key of the zipped Terraform configuration.',
        allowedPattern: '^[A-Za-z0-9!_.*\'()/-]{1,1020}[.]zip$',
      },
      WorkingDirectory: {
        type: 'String',
        description: 'Directory inside the zip that contains the root module.',
        default: '.',
        allowedPattern: '^[A-Za-z0-9_./-]{1,256}$',
      },
      Operation: {
        type: 'String',
        description: 'destroy runs "terraform plan -destroy"; apply runs "terraform plan" (for changes that delete or replace resources).',
        allowedValues: ['destroy', 'apply'],
      },
      Justification: {
        type: 'String',
        description: 'Why this change is needed (ticket reference, context). Single line, minimum 20 characters.',
        // Single line: the justification is embedded in the approval Message.
        allowedPattern: '^.{20,1000}$',
      },
    },
    mainSteps: [
      invokeGate(STEP.plan, 'tf-plan', 900, props.gateFunctionArn),
      approval(STEP.approve1, 1, props.level1Approvers, props.level1MinApprovals, props, details),
      approval(STEP.approve2, 2, props.level2Approvers, props.level2MinApprovals, props, details),
      invokeGate(STEP.apply, 'tf-apply', 900, props.gateFunctionArn),
    ],
    outputs: [`${STEP.apply}.Payload`],
  };
}
