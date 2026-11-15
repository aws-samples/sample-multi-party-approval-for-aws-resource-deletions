import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { loadConfig, validateConfig } from '../lib/config';
import { MemberAccountStack } from '../lib/member-account-stack';
import { NAMES } from '../lib/names';
import { OrgGuardrailsStack } from '../lib/org-guardrails-stack';
import { deniedDestructiveActions, PROTECTED_RESOURCE_TYPES } from '../lib/protected-resources';
import { buildDestructiveActionsScp, buildGuardProtectionScp, SCP_MAX_SIZE, scpSize } from '../lib/scp-policies';

const config = loadConfig(path.join(__dirname, '..', '..', '..', 'guard-config.example.json'));
// Same feature flags as cdk.json: S3 access logs are granted with a bucket policy, not ACLs.
const appContext = { '@aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy': true };

// Fake 12-digit account ID built at runtime.
const FAKE_ACCOUNT = '1'.repeat(4) + '2'.repeat(4) + '3'.repeat(4);
const TF_IMAGE = `${FAKE_ACCOUNT}.dkr.ecr.eu-west-1.amazonaws.com/terraform-build:1.17.2`;
const withTerraform = { ...config, terraform: { ...config.terraform, buildImage: TF_IMAGE } };

function memberTemplate(cfg = config): Template {
  const app = new cdk.App({ context: appContext });
  const stack = new MemberAccountStack(app, 'DeletionGuardMember', {
    config: cfg,
    synthesizer: new cdk.BootstraplessSynthesizer(),
    analyticsReporting: false,
  });
  return Template.fromStack(stack);
}

describe('SCPs', () => {
  test('fit within the AWS Organizations size limit', () => {
    expect(scpSize(buildDestructiveActionsScp(config))).toBeLessThanOrEqual(SCP_MAX_SIZE);
    expect(scpSize(buildGuardProtectionScp(config))).toBeLessThanOrEqual(SCP_MAX_SIZE);
  });

  test('deny every catalog delete action and exempt only the guard executors', () => {
    const scp = buildDestructiveActionsScp(config);
    const stmt = scp.Statement[0] as any;
    for (const r of PROTECTED_RESOURCE_TYPES) {
      r.deleteActions.forEach((a) => expect(stmt.Action).toContain(a));
    }
    expect(stmt.Effect).toBe('Deny');
    expect(stmt.Condition.ArnNotLike['aws:PrincipalArn']).toEqual([
      `arn:aws:iam::*:role/${NAMES.gateRole}`,
      `arn:aws:iam::*:role/${NAMES.terraformApplyRole}`,
      'arn:aws:iam::*:role/stacksets-exec-*',
    ]);
  });

  test('never deny data-plane delete actions', () => {
    const dataPlane = ['s3:DeleteObject', 's3:DeleteObjectVersion', 'dynamodb:DeleteItem', 'sqs:DeleteMessage'];
    dataPlane.forEach((a) => expect(deniedDestructiveActions()).not.toContain(a));
    expect(deniedDestructiveActions().some((a) => a.includes('*'))).toBe(false);
  });

  test('additional exempt roles cannot be created, rewritten, passed or assumed by admins', () => {
    const ct = 'arn:aws:iam::*:role/AWSControlTowerExecution';
    const cfg = { ...config, additionalExemptPrincipalArns: [ct] };
    const scp = buildGuardProtectionScp(cfg);
    const stmt = (scp.Statement as any[]).find((s) => s.Sid === 'ProtectAdditionalExemptRoles');
    expect(stmt.Resource).toEqual([ct]);
    ['iam:CreateRole', 'iam:UpdateAssumeRolePolicy', 'iam:AttachRolePolicy', 'iam:PassRole', 'sts:AssumeRole'].forEach((a) =>
      expect(stmt.Action).toContain(a),
    );
    expect(scpSize(scp)).toBeLessThanOrEqual(SCP_MAX_SIZE);
    // Without additional exemptions the statement is omitted.
    expect((buildGuardProtectionScp(config).Statement as any[]).some((s) => s.Sid === 'ProtectAdditionalExemptRoles')).toBe(false);
    // Exemptions must be roles.
    expect(() => validateConfig({ ...config, additionalExemptPrincipalArns: ['arn:aws:iam::*:user/alice'] })).toThrow(/IAM role ARN/);
  });

  test('protect the exempt roles from PassRole and the gate from direct invocation', () => {
    const stmts = buildGuardProtectionScp(config).Statement as any[];
    const pass = stmts.find((s) => s.Sid === 'ProtectExemptRolesFromPassAndAssume');
    expect(pass.Action).toEqual(['iam:PassRole', 'sts:AssumeRole']);
    const invoke = stmts.find((s) => s.Sid === 'OnlyRunbooksInvokeGate');
    expect(invoke.Condition.ArnNotLike['aws:PrincipalArn']).toContain(`arn:aws:iam::*:role/${NAMES.runbookRole}`);
    expect(stmts.find((s) => s.Sid === 'DenyLeavingOrganization')).toBeDefined();
  });
});

describe('Member account stack', () => {
  test('is asset free so it can be deployed by StackSets', () => {
    const json = memberTemplate().toJSON();
    expect(JSON.stringify(json)).not.toContain('cdk-hnb659fds');
    expect(json.Parameters?.BootstrapVersion).toBeUndefined();
  });

  test('uses fixed names that the SCPs rely on', () => {
    const t = memberTemplate(withTerraform);
    t.hasResourceProperties('AWS::Lambda::Function', { FunctionName: NAMES.gateFunction });
    t.hasResourceProperties('AWS::IAM::Role', { RoleName: NAMES.gateRole });
    t.hasResourceProperties('AWS::IAM::Role', { RoleName: NAMES.terraformApplyRole });
    t.hasResourceProperties('AWS::IAM::Role', { RoleName: NAMES.runbookRole });
    t.hasResourceProperties('AWS::CodeBuild::Project', { Name: NAMES.terraformApplyProject });
    t.hasResourceProperties('AWS::DynamoDB::Table', { TableName: NAMES.ledgerTable });
    t.hasResourceProperties('AWS::SNS::Topic', { TopicName: Match.stringLikeRegexp('^Automation') });
  });

  test('audit resources are retained on delete but cleaned up if the first deployment fails', () => {
    // Fixed names: a resource left behind by a failed create would block every later deployment.
    const t = memberTemplate(withTerraform).toJSON();
    const stateful = Object.values(t.Resources as Record<string, any>).filter((r) =>
      ['AWS::DynamoDB::Table', 'AWS::S3::Bucket'].includes(r.Type),
    );
    expect(stateful.length).toBeGreaterThanOrEqual(3);
    stateful.forEach((r) => {
      expect(r.DeletionPolicy).toBe('RetainExceptOnCreate');
      expect(r.Properties.DeletionProtectionEnabled).toBeUndefined();
    });
  });

  test('plans bucket writes server access logs', () => {
    memberTemplate().hasResourceProperties('AWS::S3::Bucket', {
      LoggingConfiguration: { DestinationBucketName: Match.anyValue(), LogFilePrefix: 'plans-bucket/' },
    });
  });

  test('runbooks contain two approval levels before the gated action', () => {
    const docs = memberTemplate(withTerraform).findResources('AWS::SSM::Document');
    const contents = Object.values(docs).map((d: any) => d.Properties.Content);
    expect(contents).toHaveLength(2);
    for (const c of contents) {
      const steps = c.mainSteps.map((s: any) => `${s.name}:${s.action}`);
      expect(steps[1]).toBe('ApproveLevel1:aws:approve');
      expect(steps[2]).toBe('ApproveLevel2:aws:approve');
      expect(steps[3]).toMatch(/:aws:invokeLambdaFunction$/);
      expect(c.mainSteps[1].inputs.MinRequiredApprovals).toBe(1);
    }
  });

  test('approval messages satisfy the aws:approve Message constraint', () => {
    // SSM validates Message against .{1,4096}: one line, at most 4,096 characters.
    const docs = memberTemplate(withTerraform).findResources('AWS::SSM::Document');
    for (const d of Object.values(docs) as any[]) {
      const content = d.Properties.Content;
      for (const step of content.mainSteps.filter((s: any) => s.action === 'aws:approve')) {
        expect(step.inputs.Message).toMatch(/^.{1,4096}$/);
      }
      // Free text that ends up inside the Message must be single line too.
      // '.' does not match line breaks, in SSM (Java) and in the console (JavaScript).
      expect(content.parameters.Justification.allowedPattern).toBe('^.{20,1000}$');
      // The console re-escapes backslashes, so patterns must not contain any.
      for (const p of Object.values(content.parameters) as any[]) {
        if (p.allowedPattern) expect(p.allowedPattern).not.toContain('\\');
      }
    }
  });

  test('each approval level notifies its own topic', () => {
    const t = memberTemplate(withTerraform);
    const topics = Object.entries(t.findResources('AWS::SNS::Topic')) as [string, any][];
    const idOf = (name: string) => topics.find(([, r]) => r.Properties.TopicName === name)![0];
    const l1 = idOf(NAMES.level1Topic);
    const l2 = idOf(NAMES.level2Topic);
    expect(idOf(NAMES.notificationsTopic)).toBeDefined();
    for (const d of Object.values(t.findResources('AWS::SSM::Document')) as any[]) {
      const steps = d.Properties.Content.mainSteps;
      expect(steps[1].inputs.NotificationArn).toEqual({ Ref: l1 });
      expect(steps[2].inputs.NotificationArn).toEqual({ Ref: l2 });
    }
  });

  test('only String parameters are interpolated into runbook text', () => {
    // SSM rejects non-String parameters used as a substring (e.g. inside an approval Message).
    const docs = memberTemplate(withTerraform).findResources('AWS::SSM::Document');
    for (const d of Object.values(docs) as any[]) {
      const content = d.Properties.Content;
      const nonString = Object.entries(content.parameters).filter(([, p]: any) => p.type !== 'String').map(([n]) => n);
      const strings: string[] = [];
      const collect = (v: unknown): void => {
        if (typeof v === 'string') strings.push(v);
        else if (Array.isArray(v)) v.forEach(collect);
        else if (v && typeof v === 'object') Object.values(v).forEach(collect);
      };
      collect(content.mainSteps);
      for (const name of nonString) {
        strings.forEach((s) => expect(s).not.toContain(`{{${name}}}`));
      }
    }
  });

  test('the gate can write its logs and read approval signals from CloudTrail', () => {
    const policies = Object.values(memberTemplate().findResources('AWS::IAM::Policy')).filter((p: any) =>
      JSON.stringify(p.Properties.Roles).includes('GateRole'),
    );
    const actions = JSON.stringify(policies);
    expect(actions).toContain('logs:PutLogEvents');
    expect(actions).toContain('cloudtrail:LookupEvents');
  });

  test('the runbook role cannot delete anything', () => {
    const roles = memberTemplate(withTerraform).findResources('AWS::IAM::Policy');
    const runbookPolicies = Object.values(roles).filter((p: any) =>
      JSON.stringify(p.Properties.Roles).includes('RunbookRole'),
    );
    const actions = JSON.stringify(runbookPolicies);
    deniedDestructiveActions().forEach((a) => expect(actions).not.toContain(`"${a}"`));
  });

  test('Terraform path is deployed only with a customer build image, and never downloads Terraform', () => {
    const without = memberTemplate();
    expect(Object.keys(without.findResources('AWS::CodeBuild::Project'))).toHaveLength(0);
    expect(Object.keys(without.findResources('AWS::SSM::Document'))).toHaveLength(1);

    const t = memberTemplate(withTerraform);
    const projects = Object.values(t.findResources('AWS::CodeBuild::Project')) as any[];
    expect(projects).toHaveLength(2);
    for (const p of projects) {
      expect(JSON.stringify(p.Properties.Environment.Image)).toContain('terraform-build');
      expect(p.Properties.Environment.ImagePullCredentialsType).toBe('SERVICE_ROLE');
      expect(p.Properties.Source.BuildSpec).not.toMatch(/https?:\/\//);
    }
  });

  test('rejects an invalid build image URI', () => {
    expect(() => validateConfig({ ...config, terraform: { ...config.terraform, buildImage: 'hashicorp/terraform:latest' } }))
      .toThrow(/terraform.buildImage/);
  });

  test('forwards events only when a central bus is configured', () => {    expect(Object.keys(memberTemplate().findResources('AWS::Events::Rule'))).toHaveLength(0);
    const withBus = memberTemplate({ ...config, centralEventBusArn: 'arn:aws:events:eu-west-1:999988887777:event-bus/security' });
    expect(Object.keys(withBus.findResources('AWS::Events::Rule'))).toHaveLength(3);
  });
});

describe('Org stack', () => {
  test('rolls out the StackSet before attaching the SCPs', () => {
    const app = new cdk.App();
    const stack = new OrgGuardrailsStack(app, 'Org', {
      env: { account: '123456789012', region: 'eu-west-1' },
      config: { ...config, attachScps: true },
      artifactsBucketName: 'deletion-guard-artifacts-123456789012-eu-west-1',
      gateCodeKey: 'lambda/gate.zip',
      memberTemplateKey: 'templates/member.json',
    });
    const t = Template.fromStack(stack);
    t.hasResourceProperties('AWS::CloudFormation::StackSet', {
      PermissionModel: 'SERVICE_MANAGED',
      AutoDeployment: { Enabled: true, RetainStacksOnAccountRemoval: false },
    });
    const policies = t.findResources('AWS::Organizations::Policy');
    expect(Object.keys(policies)).toHaveLength(2);
    Object.values(policies).forEach((p: any) => expect(p.DependsOn).toEqual(['MemberStackSet']));
  });
});
