import * as cdk from 'aws-cdk-lib';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { GuardConfig } from './config';
import { NAMES } from './names';
import { gateExecutionActions, PROTECTED_RESOURCE_TYPES } from './protected-resources';
import { resourceDeletionRunbook, terraformChangeRunbook } from './runbooks';
import { terraformApplyBuildSpec, terraformPlanBuildSpec } from './terraform-buildspecs';

export interface MemberAccountStackProps extends cdk.StackProps {
  readonly config: GuardConfig;
}

/**
 * Deployed into every member account (home region only) through a service-managed
 * StackSet. The template must be asset-free: Lambda code is read from the central
 * artifacts bucket passed in as parameters.
 */
export class MemberAccountStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: MemberAccountStackProps) {
    super(scope, id, props);
    const cfg = props.config;
    const account = cdk.Aws.ACCOUNT_ID;
    const region = cdk.Aws.REGION;

    // ------------------------------------------------------------------ parameters
    const artifactsBucketName = new cdk.CfnParameter(this, 'ArtifactsBucket', {
      type: 'String',
      description: 'Central artifacts bucket (same region) that holds the gate Lambda package.',
    });
    const gateCodeKey = new cdk.CfnParameter(this, 'GateCodeKey', {
      type: 'String',
      description: 'S3 key of the gate Lambda zip package.',
    });
    const approverRefreshToken = new cdk.CfnParameter(this, 'ApproverRefreshToken', {
      type: 'String',
      default: '1',
      description: 'Change this value to force re-resolution of the IAM Identity Center approver roles.',
    });

    const artifacts = s3.Bucket.fromBucketName(this, 'ArtifactsBucketRef', artifactsBucketName.valueAsString);

    // ------------------------------------------------------------------ approver resolution
    // IAM Identity Center role names carry a random suffix that differs per account,
    // so approvers are resolved in each account at deploy time.
    const resolverRole = new iam.Role(this, 'ApproverResolverRole', {
      roleName: NAMES.resolverRole,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'DeletionGuard: resolves IAM Identity Center approver roles',
    });
    // ListRoles: find Identity Center roles. GetRole: check that every approver role can only
    // be assumed through SAML federation (otherwise its session name does not identify a person).
    resolverRole.addToPolicy(new iam.PolicyStatement({ actions: ['iam:ListRoles', 'iam:GetRole'], resources: ['*'] }));
    const resolverLogs = new logs.LogGroup(this, 'ApproverResolverLogs', {
      logGroupName: `/aws/lambda/${NAMES.resolverFunction}`,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    resolverLogs.grantWrite(resolverRole);

    const resolverFn = new lambda.Function(this, 'ApproverResolver', {
      functionName: NAMES.resolverFunction,
      runtime: lambda.Runtime.PYTHON_3_13,
      // Same package as the gate (lambda/gate-<hash>.zip contains both modules).
      handler: 'approver_resolver.index.handler',
      code: lambda.Code.fromBucket(artifacts, gateCodeKey.valueAsString),
      role: resolverRole,
      timeout: cdk.Duration.seconds(60),
      logGroup: resolverLogs,
      description: 'DeletionGuard: resolves approver principals for the approval runbooks',
    });

    const approvers = new cdk.CustomResource(this, 'Approvers', {
      serviceToken: resolverFn.functionArn,
      resourceType: 'Custom::DeletionGuardApprovers',
      properties: {
        Level1PermissionSets: cfg.approvals.level1.permissionSets,
        Level1PrincipalArns: cfg.approvals.level1.principalArns,
        Level1MinApprovals: String(cfg.approvals.level1.minApprovals),
        Level2PermissionSets: cfg.approvals.level2.permissionSets,
        Level2PrincipalArns: cfg.approvals.level2.principalArns,
        Level2MinApprovals: String(cfg.approvals.level2.minApprovals),
        RoleArnWithPath: String(cfg.approverRoleArnWithPath ?? true),
        RefreshToken: approverRefreshToken.valueAsString,
      },
    });
    approvers.node.addDependency(resolverLogs);
    const level1Approvers = approvers.getAttString('Level1');
    const level2Approvers = approvers.getAttString('Level2');

    // ------------------------------------------------------------------ audit ledger
    const ledger = new dynamodb.Table(this, 'Ledger', {
      tableName: NAMES.ledgerTable,
      partitionKey: { name: 'executionId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      // No table-level deletion protection: it would block CloudFormation from cleaning up
      // after a failed first deployment. The ledger is protected by both SCPs instead
      // (dynamodb:DeleteTable and every write are denied outside the guard).
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });

    // ------------------------------------------------------------------ S3 server access logs
    // Destination for server access logs of the plans bucket. Protected by the
    // guard-protection SCP; S3 log delivery uses a service principal, which SCPs do not affect.
    const accessLogsBucket = new s3.Bucket(this, 'AccessLogsBucket', {
      bucketName: `${NAMES.accessLogsBucketPrefix}-${account}-${region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      lifecycleRules: [{ expiration: cdk.Duration.days(365), noncurrentVersionExpiration: cdk.Duration.days(30) }],
      removalPolicy: cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });

    // ------------------------------------------------------------------ Terraform plan artifacts
    const plansBucket = new s3.Bucket(this, 'PlansBucket', {
      bucketName: `${NAMES.plansBucketPrefix}-${account}-${region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'plans-bucket/',
      lifecycleRules: [{ expiration: cdk.Duration.days(365), noncurrentVersionExpiration: cdk.Duration.days(30) }],
      removalPolicy: cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });

    // ------------------------------------------------------------------ notifications
    // AWS managed key: SSM (through the runbook role) and the gate publish as IAM principals.
    const snsKey = kms.Alias.fromAliasName(this, 'SnsManagedKey', 'alias/aws/sns');
    const newTopic = (id: string, topicName: string, displayName: string, emails: string[]) => {
      const t = new sns.Topic(this, id, { topicName, displayName, masterKey: snsKey, enforceSSL: true });
      emails.forEach((endpoint, i) => {
        new sns.Subscription(this, `${id}Email${i}`, { topic: t, protocol: sns.SubscriptionProtocol.EMAIL, endpoint });
      });
      return t;
    };
    // One topic per approval level (aws:approve requires names starting with "Automation"),
    // so that level 2 approvers are not asked to act while a request still waits for level 1.
    const level1Topic = newTopic('Level1Topic', NAMES.level1Topic, 'DeletionGuard - level 1 approval needed',
      cfg.approvals.level1.notificationEmails ?? []);
    const level2Topic = newTopic('Level2Topic', NAMES.level2Topic, 'DeletionGuard - level 2 approval needed',
      cfg.approvals.level2.notificationEmails ?? []);
    const topic = newTopic('NotificationsTopic', NAMES.notificationsTopic, 'DeletionGuard - request outcomes',
      cfg.notificationEmails);

    // ------------------------------------------------------------------ roles
    const sourceAccountCondition = { StringEquals: { 'aws:SourceAccount': account } };

    // Role assumed by SSM Automation. It can only invoke the gate and publish notifications.
    const runbookRole = new iam.Role(this, 'RunbookRole', {
      roleName: NAMES.runbookRole,
      assumedBy: new iam.ServicePrincipal('ssm.amazonaws.com', { conditions: sourceAccountCondition }),
      description: 'DeletionGuard: SSM Automation role for the approval runbooks (no delete permissions)',
    });
    level1Topic.grantPublish(runbookRole);
    level2Topic.grantPublish(runbookRole);

    // The gate role is the ONLY identity (besides the Terraform apply role) exempted
    // from the destructive-actions SCP.
    const gateRole = new iam.Role(this, 'GateRole', {
      roleName: NAMES.gateRole,
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com', { conditions: sourceAccountCondition }),
        // CloudFormation assumes this role when the gate deletes a stack, so that
        // the stack's resources are deleted by an SCP-exempt principal.
        new iam.ServicePrincipal('cloudformation.amazonaws.com', { conditions: sourceAccountCondition }),
      ),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess')],
      description: 'DeletionGuard: verifies approvals and performs approved deletions',
    });
    gateRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ApprovedDeletions',
        actions: [
          ...gateExecutionActions(),
          'cloudformation:DeleteResource',
          'cloudformation:GetResource',
          'cloudformation:GetResourceRequestStatus',
        ],
        resources: ['*'],
      }),
    );
    gateRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadAndStopOwnExecutions',
        actions: ['ssm:GetAutomationExecution', 'ssm:DescribeAutomationStepExecutions', 'ssm:StopAutomationExecution'],
        resources: [`arn:${cdk.Aws.PARTITION}:ssm:${region}:${account}:automation-execution/*`],
      }),
    );
    gateRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'PassSelfToCloudFormationForStackDeletion',
        actions: ['iam:PassRole'],
        resources: [`arn:${cdk.Aws.PARTITION}:iam::${account}:role/${NAMES.gateRole}`],
        conditions: { StringEquals: { 'iam:PassedToService': 'cloudformation.amazonaws.com' } },
      }),
    );
    gateRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'PublishGuardEvents',
        actions: ['events:PutEvents'],
        resources: [`arn:${cdk.Aws.PARTITION}:events:${region}:${account}:event-bus/default`],
      }),
    );
    gateRole.addToPolicy(
      new iam.PolicyStatement({
        // Identifies the person behind each approval (SSM only records the permission set role).
        sid: 'ReadApprovalSignalsFromCloudTrail',
        actions: ['cloudtrail:LookupEvents'],
        resources: ['*'],
      }),
    );
    ledger.grantReadWriteData(gateRole);
    plansBucket.grantRead(gateRole);
    topic.grantPublish(gateRole);

    // ------------------------------------------------------------------ Terraform CodeBuild (optional)
    // Deployed only when terraform.buildImage is configured: an image in the customer's
    // ECR with the Terraform CLI preinstalled. Nothing is downloaded at build time.
    const tf = cfg.terraform.buildImage ? this.terraformBuilds(cfg, plansBucket, sourceAccountCondition) : undefined;
    if (tf) {
      gateRole.addToPolicy(
        new iam.PolicyStatement({
          sid: 'RunTerraformBuilds',
          actions: ['codebuild:StartBuild', 'codebuild:BatchGetBuilds', 'codebuild:StopBuild'],
          resources: [tf.planProject.projectArn, tf.applyProject.projectArn],
        }),
      );
    }
    // ------------------------------------------------------------------ gate Lambda
    const gateLogs = new logs.LogGroup(this, 'GateLogs', {
      logGroupName: `/aws/lambda/${NAMES.gateFunction}`,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    gateLogs.grantWrite(gateRole);
    const gateFn = new lambda.Function(this, 'Gate', {
      functionName: NAMES.gateFunction,
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'deletion_gate.handler.lambda_handler',
      code: lambda.Code.fromBucket(artifacts, gateCodeKey.valueAsString),
      role: gateRole,
      timeout: cdk.Duration.minutes(15),
      memorySize: 256,
      reservedConcurrentExecutions: 10,
      logGroup: gateLogs,
      description: 'DeletionGuard: verifies multi-party approvals and performs approved deletions',
      environment: {
        RESOURCE_RUNBOOK: NAMES.resourceRunbook,
        TERRAFORM_RUNBOOK: NAMES.terraformRunbook,
        LEDGER_TABLE: ledger.tableName,
        APPROVERS_L1: level1Approvers,
        APPROVERS_L2: level2Approvers,
        MIN_APPROVALS_L1: String(cfg.approvals.level1.minApprovals),
        MIN_APPROVALS_L2: String(cfg.approvals.level2.minApprovals),
        ALLOWED_REGIONS: cfg.allowedTargetRegions.join(','),
        ALLOWED_RESOURCE_TYPES: PROTECTED_RESOURCE_TYPES.map((r) => r.type).join(','),
        PLAN_PROJECT: tf?.planProject.projectName ?? '',
        APPLY_PROJECT: tf?.applyProject.projectName ?? '',
        PLANS_BUCKET: plansBucket.bucketName,
        TOPIC_ARN: topic.topicArn,
        GATE_ROLE_ARN: gateRole.roleArn,
      },
    });
    gateFn.grantInvoke(runbookRole);
    // The deployment scripts upload the package under a content-addressed key
    // (lambda/gate-<sha256>.zip), so every code change is a new key and a new deployment.
    cdk.Annotations.of(this).acknowledgeWarning(
      '@aws-cdk/aws-lambda:codeFromBucketObjectVersionNotSpecified',
      'Gate package key is content-addressed',
    );

    // ------------------------------------------------------------------ runbooks
    const runbookProps = {
      runbookRoleArn: runbookRole.roleArn,
      gateFunctionArn: gateFn.functionArn,
      level1TopicArn: level1Topic.topicArn,
      level2TopicArn: level2Topic.topicArn,
      level1Approvers: cdk.Fn.split(',', level1Approvers),
      level2Approvers: cdk.Fn.split(',', level2Approvers),
      level1MinApprovals: cfg.approvals.level1.minApprovals,
      level2MinApprovals: cfg.approvals.level2.minApprovals,
      approvalTimeoutSeconds: cfg.approvalTimeoutHours * 3600,
      allowedTargetRegions: cfg.allowedTargetRegions,
      resourceTypes: PROTECTED_RESOURCE_TYPES.map((r) => r.type),
    };

    new ssm.CfnDocument(this, 'DeleteResourceRunbook', {
      name: NAMES.resourceRunbook,
      documentType: 'Automation',
      documentFormat: 'JSON',
      updateMethod: 'NewVersion',
      content: resourceDeletionRunbook(runbookProps),
    });
    if (tf) {
      new ssm.CfnDocument(this, 'TerraformChangeRunbook', {
        name: NAMES.terraformRunbook,
        documentType: 'Automation',
        documentFormat: 'JSON',
        updateMethod: 'NewVersion',
        content: terraformChangeRunbook(runbookProps),
      });
    }

    // ------------------------------------------------------------------ central event forwarding (optional)
    if (cfg.centralEventBusArn) {
      const forwarderRole = new iam.Role(this, 'EventForwarderRole', {
        roleName: NAMES.eventForwarderRole,
        assumedBy: new iam.ServicePrincipal('events.amazonaws.com', { conditions: sourceAccountCondition }),
        description: 'DeletionGuard: forwards guard events to the central security event bus',
      });
      forwarderRole.addToPolicy(new iam.PolicyStatement({ actions: ['events:PutEvents'], resources: [cfg.centralEventBusArn] }));

      const forward = (id: string, ruleName: string, description: string, eventPattern: Record<string, unknown>) =>
        new events.CfnRule(this, id, {
          name: `${NAMES.eventRulePrefix}${ruleName}`,
          description,
          eventPattern,
          state: 'ENABLED',
          targets: [{ id: 'CentralBus', arn: cfg.centralEventBusArn, roleArn: forwarderRole.roleArn }],
        });

      forward('ForwardRunbookEvents', 'ForwardRunbookEvents', 'Forward DeletionGuard runbook execution and step events', {
        source: ['aws.ssm'],
        'detail-type': ['EC2 Automation Execution Status-change Notification', 'EC2 Automation Step Status-change Notification'],
        detail: { Definition: [NAMES.resourceRunbook, NAMES.terraformRunbook] },
      });
      forward('ForwardApplyBuildEvents', 'ForwardApplyBuildEvents', 'Forward Terraform apply build state changes', {
        source: ['aws.codebuild'],
        'detail-type': ['CodeBuild Build State Change'],
        detail: { 'project-name': [NAMES.terraformApplyProject] },
      });
      forward('ForwardGateEvents', 'ForwardGateEvents', 'Forward decisions taken by the DeletionGuard gate', {
        source: ['deletion-guard'],
      });
    }

    // ------------------------------------------------------------------ outputs
    new cdk.CfnOutput(this, 'ResourceRunbookName', { value: NAMES.resourceRunbook });
    new cdk.CfnOutput(this, 'TerraformRunbookName', { value: tf ? NAMES.terraformRunbook : 'disabled (terraform.buildImage not set)' });
    new cdk.CfnOutput(this, 'RunbookRoleArn', { value: runbookRole.roleArn });
    new cdk.CfnOutput(this, 'PlansBucketName', { value: plansBucket.bucketName });
    new cdk.CfnOutput(this, 'Level1Approvers', { value: level1Approvers });
    new cdk.CfnOutput(this, 'Level2Approvers', { value: level2Approvers });
  }

  /** Terraform plan (read-only) and apply (SCP-exempt) CodeBuild projects on the customer's image. */
  private terraformBuilds(
    cfg: GuardConfig,
    plansBucket: s3.IBucket,
    sourceAccountCondition: Record<string, Record<string, string>>,
  ): { planProject: codebuild.Project; applyProject: codebuild.Project } {
    const image = parseEcrImage(cfg.terraform.buildImage!);

    const tfPlanRole = new iam.Role(this, 'TerraformPlanRole', {
      roleName: NAMES.terraformPlanRole,
      assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com', { conditions: sourceAccountCondition }),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess')],
      description: 'DeletionGuard: read-only role that produces Terraform plans for approval',
    });
    plansBucket.grantReadWrite(tfPlanRole, 'plans/*');

    const tfApplyRole = new iam.Role(this, 'TerraformApplyRole', {
      roleName: NAMES.terraformApplyRole,
      assumedBy: new iam.ServicePrincipal('codebuild.amazonaws.com', { conditions: sourceAccountCondition }),
      managedPolicies: cfg.terraform.applyManagedPolicyArns.map((arn, i) =>
        iam.ManagedPolicy.fromManagedPolicyArn(this, `ApplyPolicy${i}`, arn),
      ),
      description: 'DeletionGuard: applies approved Terraform plans (exempt from the destructive SCP)',
    });
    plansBucket.grantRead(tfApplyRole, 'plans/*');

    // Image pulled with the project's service role, so cross-account ECR repositories
    // only need a repository policy that trusts the organization.
    const repository = ecr.Repository.fromRepositoryAttributes(this, 'TerraformImageRepo', {
      repositoryArn: `arn:${cdk.Aws.PARTITION}:ecr:${image.region}:${image.account}:repository/${image.repository}`,
      repositoryName: image.repository,
    });
    const tfEnv: codebuild.BuildEnvironment = {
      buildImage: codebuild.LinuxBuildImage.fromEcrRepository(repository, image.tagOrDigest),
      computeType: codebuild.ComputeType.SMALL,
      environmentVariables: { TF_VERSION: { value: cfg.terraform.version } },
    };

    const planLogs = new logs.LogGroup(this, 'TerraformPlanLogs', {
      logGroupName: `/aws/codebuild/${NAMES.terraformPlanProject}`,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const planProject = new codebuild.Project(this, 'TerraformPlanProject', {
      projectName: NAMES.terraformPlanProject,
      description: 'DeletionGuard: produce a Terraform plan to be approved (read-only)',
      role: tfPlanRole,
      environment: tfEnv,
      buildSpec: codebuild.BuildSpec.fromObject(terraformPlanBuildSpec()),
      timeout: cdk.Duration.minutes(30),
      logging: { cloudWatch: { logGroup: planLogs } },
    });

    const applyLogs = new logs.LogGroup(this, 'TerraformApplyLogs', {
      logGroupName: `/aws/codebuild/${NAMES.terraformApplyProject}`,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const applyProject = new codebuild.Project(this, 'TerraformApplyProject', {
      projectName: NAMES.terraformApplyProject,
      description: 'DeletionGuard: apply an approved Terraform plan (only the gate can start it)',
      role: tfApplyRole,
      environment: tfEnv,
      buildSpec: codebuild.BuildSpec.fromObject(terraformApplyBuildSpec()),
      timeout: cdk.Duration.minutes(60),
      logging: { cloudWatch: { logGroup: applyLogs } },
    });

    return { planProject, applyProject };
  }
}

/** Parse <account>.dkr.ecr.<region>.amazonaws.com/<repository>(:<tag>|@sha256:<digest>). */
export function parseEcrImage(uri: string): { account: string; region: string; repository: string; tagOrDigest: string } {
  const m = /^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?\/([a-z0-9._/-]+?)(?::([\w.-]{1,128})|@(sha256:[a-f0-9]{64}))$/.exec(uri);
  if (!m) {
    throw new Error(`terraform.buildImage must be an ECR image URI with a tag or digest, got "${uri}"`);
  }
  return { account: m[1], region: m[2], repository: m[3], tagOrDigest: m[4] ?? m[5] };
}
