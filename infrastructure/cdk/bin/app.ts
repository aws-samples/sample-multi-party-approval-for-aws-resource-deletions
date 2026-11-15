#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { ArtifactsStack } from '../lib/artifacts-stack';
import { getRegion } from '../lib/aws-env';
import { loadConfig } from '../lib/config';
import { MemberAccountStack } from '../lib/member-account-stack';
import { OrgGuardrailsStack } from '../lib/org-guardrails-stack';

const app = new cdk.App();
const config = loadConfig(app.node.tryGetContext('configPath'));
const region = getRegion();
const env = { account: process.env.CDK_DEFAULT_ACCOUNT, region };

// Values produced by the deployment scripts (see deploy-all.ps1 / deploy-all.sh).
const organizationId: string | undefined = app.node.tryGetContext('organizationId');
const artifactsBucketName: string | undefined = app.node.tryGetContext('artifactsBucket');
const gateCodeKey: string | undefined = app.node.tryGetContext('gateCodeKey');
const memberTemplateKey: string | undefined = app.node.tryGetContext('memberTemplateKey');

// Member-account template. Never deployed with `cdk deploy`: the scripts upload the
// synthesized template and roll it out with a service-managed StackSet. It is
// synthesized without bootstrap dependencies so it works in any account.
new MemberAccountStack(app, 'DeletionGuardMember', {
  config,
  synthesizer: new cdk.BootstraplessSynthesizer(),
  analyticsReporting: false,
  description: 'DeletionGuard member-account components: approval runbooks, verification gate, Terraform plan/apply',
});

if (organizationId) {
  new ArtifactsStack(app, `DeletionGuardArtifacts-${region}`, {
    env,
    organizationId,
    description: 'DeletionGuard artifacts bucket (gate package and member template)',
  });
}

if (artifactsBucketName && gateCodeKey && memberTemplateKey) {
  new OrgGuardrailsStack(app, `DeletionGuardOrg-${region}`, {
    env,
    config,
    artifactsBucketName,
    gateCodeKey,
    memberTemplateKey,
    description: 'Multi-party approval guard for AWS resource deletions: SCPs and member StackSet',
  });
}
