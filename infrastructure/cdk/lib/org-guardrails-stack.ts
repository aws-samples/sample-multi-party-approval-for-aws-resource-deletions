import * as cdk from 'aws-cdk-lib';
import * as organizations from 'aws-cdk-lib/aws-organizations';
import { Construct } from 'constructs';
import { GuardConfig } from './config';
import { NAMES } from './names';
import { buildDestructiveActionsScp, buildGuardProtectionScp } from './scp-policies';

export interface OrgGuardrailsStackProps extends cdk.StackProps {
  readonly config: GuardConfig;
  readonly artifactsBucketName: string;
  readonly gateCodeKey: string;
  readonly memberTemplateKey: string;
}

/**
 * Deployed in the management account (or an Organizations/StackSets delegated
 * administrator). Rolls out the member stack to every account in the target OUs
 * and attaches the two SCPs.
 */
export class OrgGuardrailsStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: OrgGuardrailsStackProps) {
    super(scope, id, props);
    const cfg = props.config;
    const region = cdk.Stack.of(this).region;

    const stackSet = new cdk.CfnStackSet(this, 'MemberStackSet', {
      stackSetName: NAMES.stackSet,
      description: 'DeletionGuard member-account components (gate, runbooks, Terraform builds, ledger)',
      permissionModel: 'SERVICE_MANAGED',
      callAs: cfg.stackSetCallAs,
      autoDeployment: { enabled: true, retainStacksOnAccountRemoval: false },
      managedExecution: { Active: true },
      capabilities: ['CAPABILITY_NAMED_IAM'],
      templateUrl: `https://${props.artifactsBucketName}.s3.${region}.${cdk.Aws.URL_SUFFIX}/${props.memberTemplateKey}`,
      parameters: [
        { parameterKey: 'ArtifactsBucket', parameterValue: props.artifactsBucketName },
        { parameterKey: 'GateCodeKey', parameterValue: props.gateCodeKey },
      ],
      operationPreferences: {
        regionConcurrencyType: 'PARALLEL',
        maxConcurrentPercentage: 25,
        failureTolerancePercentage: 0,
      },
      stackInstancesGroup: [
        {
          // One home region per account: the SCPs are global and the runbooks
          // accept a TargetRegion parameter.
          regions: [region],
          deploymentTargets: { organizationalUnitIds: cfg.organizationalUnitIds },
        },
      ],
    });

    if (cfg.attachScps) {
      const destructive = new organizations.CfnPolicy(this, 'DestructiveActionsScp', {
        name: 'DeletionGuard-DenyDestructiveActions',
        description: 'Deny destructive control-plane actions except through the DeletionGuard approval workflow',
        type: 'SERVICE_CONTROL_POLICY',
        content: buildDestructiveActionsScp(cfg),
        targetIds: cfg.organizationalUnitIds,
      });
      const protection = new organizations.CfnPolicy(this, 'GuardProtectionScp', {
        name: 'DeletionGuard-ProtectGuard',
        description: 'Protect the DeletionGuard components from tampering in member accounts',
        type: 'SERVICE_CONTROL_POLICY',
        content: buildGuardProtectionScp(cfg),
        targetIds: cfg.organizationalUnitIds,
      });
      // Roll out the gate before the deny takes effect.
      destructive.addResourceDependency(stackSet);
      protection.addResourceDependency(stackSet);
    }

    new cdk.CfnOutput(this, 'StackSetName', { value: NAMES.stackSet });
    new cdk.CfnOutput(this, 'ScpsAttached', { value: String(cfg.attachScps) });
  }
}
