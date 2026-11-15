# DeletionGuard: multi-party approval for AWS resource deletions

*Prevent malicious or accidental deletion of AWS resources from the console, CLI, SDKs and any infrastructure as code tool (CloudFormation, CDK, Terraform, Pulumi, Ansible, ...) using AWS Organizations SCPs and AWS Systems Manager Automation approvals.*

## Overview

An approval step enforced inside a tool only protects that tool. If an identity has
`rds:DeleteDBInstance`, it can delete the database from any tool: the console, the
CLI, an SDK script or an infrastructure as code pipeline. DeletionGuard moves the
approval gate into the **permission layer**, so that it applies to all of them:

1. An SCP denies destructive control-plane actions to **every** identity in the target
   OUs: administrators, CI/CD roles, CloudFormation service roles and the root user.
2. The only identities allowed to delete are two DeletionGuard roles. They act only
   after an SSM Automation request has been approved by two approval levels.
3. A gate Lambda independently verifies the approvals before deleting. It checks that
   approvers are authorized and distinct, that nobody approved their own request, and
   that each approval is used only once.
4. For Terraform, approvers approve a **saved plan**, and exactly that plan is applied.
5. A second SCP protects the mechanism itself from tampering.

The guard works across all accounts in the target OUs (deployed by a service-managed
StackSet) and across all regions (SCPs are global, and the target region is a request
parameter).

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design, the verification logic and the threat model.

## At a glance

| | |
|---|---|
| **Scope** | Multi-account (AWS Organizations), multi-region |
| **Covers** | Console, AWS CLI, SDKs, and any IaC tool that calls AWS APIs: CloudFormation, CDK, Terraform (`aws` and `awscc` providers), Pulumi, Ansible, Crossplane, Cloud Control API |
| **Approved paths** | Single resource (any tool), whole CloudFormation/CDK stack, Terraform plan-and-apply |
| **Key services** | AWS Organizations (SCPs), CloudFormation StackSets, Systems Manager Automation, AWS Lambda, Cloud Control API, CodeBuild, DynamoDB, SNS, EventBridge |
| **IaC** | AWS CDK (TypeScript) |
| **Gate runtime** | Python 3.13, boto3 only |
| **Estimated cost** | Low single-digit USD per account per month for typical request volumes (see [Cost](#cost)) |

## How a deletion works

```text
Requester              Level 1 approver      Level 2 approver      DeletionGuard gate
    |  start runbook          |                     |                      |
    |------------------------------------------------------------------>   | validate resource, ledger VALIDATED
    |                         |<-- SNS -------------|                      |
    |                         |  Approve            |                      |
    |                         |                     |<-- SNS               |
    |                         |                     |  Approve             |
    |                         |                     |                      | verify approvals, ledger EXECUTING
    |                         |                     |                      | Cloud Control DeleteResource
    |<------------------------------------------------- notification ------| ledger COMPLETED
```

Any other attempt fails with an explicit deny. For example, an administrator running
`aws dynamodb delete-table` or a pipeline running `terraform destroy`:

```text
An error occurred (AccessDeniedException) when calling the DeleteTable operation:
User: arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_AdministratorAccess_.../alice
is not authorized to perform: dynamodb:DeleteTable on resource: ...
with an explicit deny in a service control policy
```

## What is protected

The catalog lives in [`infrastructure/cdk/lib/protected-resources.ts`](infrastructure/cdk/lib/protected-resources.ts).
The SCP deny list, the runbook's allowed resource types and the gate's IAM permissions
are all generated from it.

| Resource type (runbook `ResourceType`) | Denied action | `ResourceIdentifier` (Cloud Control primary identifier) | Deletion protection handled |
|---|---|---|---|
| `AWS::EC2::Instance` | `ec2:TerminateInstances` | Instance ID | Yes (`DisableApiTermination`) |
| `AWS::EC2::VPC` | `ec2:DeleteVpc` | VPC ID | |
| `AWS::RDS::DBInstance` | `rds:DeleteDBInstance` | DB instance identifier | Yes |
| `AWS::RDS::DBCluster` | `rds:DeleteDBCluster` | DB cluster identifier | Yes |
| `AWS::DynamoDB::Table` | `dynamodb:DeleteTable` | Table name | Yes |
| `AWS::S3::Bucket` | `s3:DeleteBucket` | Bucket name (bucket must be empty) | |
| `AWS::Lambda::Function` | `lambda:DeleteFunction` | Function name | |
| `AWS::ECS::Cluster` / `AWS::ECS::Service` | `ecs:DeleteCluster` / `ecs:DeleteService` | Cluster name / `ServiceArn\|ClusterName` | |
| `AWS::EKS::Cluster` | `eks:DeleteCluster` | Cluster name | |
| `AWS::ElasticLoadBalancingV2::LoadBalancer` | `elasticloadbalancing:DeleteLoadBalancer` | Load balancer ARN | Yes |
| `AWS::EFS::FileSystem` | `elasticfilesystem:DeleteFileSystem` | File system ID | |
| `AWS::OpenSearchService::Domain` | `es:DeleteDomain` | Domain name | |
| `AWS::Redshift::Cluster` | `redshift:DeleteCluster` | Cluster identifier | |
| `AWS::KMS::Key` | `kms:ScheduleKeyDeletion` | Key ID | |
| `AWS::SecretsManager::Secret` | `secretsmanager:DeleteSecret` | Secret ARN | |
| `AWS::Backup::BackupVault` | `backup:DeleteBackupVault` | Vault name | |
| `AWS::Logs::LogGroup` | `logs:DeleteLogGroup` | Log group name | |
| `AWS::SQS::Queue` | `sqs:DeleteQueue` | Queue URL | |
| `AWS::SNS::Topic` | `sns:DeleteTopic` | Topic ARN | |
| `AWS::Kinesis::Stream` | `kinesis:DeleteStream` | Stream name | |
| `AWS::ECR::Repository` | `ecr:DeleteRepository` | Repository name | |
| `AWS::Route53::HostedZone` | `route53:DeleteHostedZone` | Hosted zone ID | |
| `AWS::CloudFormation::Stack` | `cloudformation:DeleteStack` | Stack name or ID | Yes (termination protection) |

The SCP also denies `cloudformation:DeleteResource` (Cloud Control API, Terraform `awscc`), `cloudformation:DeleteStackSet`, `rds:DeleteGlobalCluster`, `dynamodb:DeleteBackup`, `elasticache:DeleteCacheCluster`, `elasticache:DeleteReplicationGroup`, `fsx:DeleteFileSystem`, `glacier:DeleteVault`, `cognito-idp:DeleteUserPool`, `eks:DeleteNodegroup` and `ec2:DeleteTransitGateway`. Use the Terraform runbook for those, or add a catalog entry.

To verify Cloud Control support for a type before adding it, run `aws cloudformation describe-type --type RESOURCE --type-name <type> --query ProvisioningType`. The value must be `FULLY_MUTABLE` or `IMMUTABLE`.

## Prerequisites

- An AWS Organization with all features enabled, and SCPs enabled.
- Trusted access for CloudFormation StackSets with AWS Organizations
  (`aws organizations enable-aws-service-access --service-principal member.org.stacksets.cloudformation.amazonaws.com`,
  or enable it from the StackSets console).
- Credentials in the **management account**, or in a delegated administrator for both
  StackSets and Organizations policies (set `stackSetCallAs` to `DELEGATED_ADMIN`).
- AWS CLI v2, Node.js 20+ and npm. Python 3.9+ is needed by the Bash scripts and the tests.
- IAM Identity Center (recommended) with two approver permission sets provisioned to
  every target account, for example `DeletionApproverTeamLead` and `DeletionApproverSecurity`.
  A SAML IdP federated directly with IAM (AD FS, Okta, Entra ID) also works, see
  [Identity providers](#identity-providers-iam-identity-center-ad-fs-okta-microsoft-entra-id).
  Attach [`examples/iam/approver-permission-set-policy.json`](examples/iam/approver-permission-set-policy.json)
  to them, and [`examples/iam/requester-permission-set-policy.json`](examples/iam/requester-permission-set-policy.json)
  to the permission sets of people who may request deletions.

## Configuration

Copy `guard-config.example.json` to `guard-config.json` (it is git-ignored) and edit it:

| Key | Description |
|---|---|
| `organizationalUnitIds` | OUs that receive the guard and the SCPs. Start with a sandbox OU |
| `attachScps` | `false` deploys the guard without enforcing it, `true` attaches both SCPs |
| `stackSetCallAs` | `SELF` (management account) or `DELEGATED_ADMIN` |
| `allowedTargetRegions` | Regions where approved deletions may target resources |
| `approvals.level1` / `level2` | `permissionSets` (IAM Identity Center permission set names) and/or `principalArns` (IAM role or user ARNs, `{account}` is replaced by the member account ID), plus `minApprovals` (distinct humans required) |
| `approverRoleArnWithPath` | Optional, default `true`. Format of resolved Identity Center role ARNs in `aws:approve` (see the validation checklist) |
| `approvalTimeoutHours` | Time each approval level can wait (1-720) |
| `approvals.levelN.notificationEmails` | Optional. E-mail addresses notified when a request waits for **that** level (topics `AutomationDeletionGuardLevel1` / `Level2`). Levels are approved in order: level 2 approvers are notified only after level 1 approved |
| `notificationEmails` | Optional. E-mail addresses notified of request outcomes (validated, executed, rejected, refused invocations) through `DeletionGuard-Notifications`, for example requesters and the security team |
| `terraform.buildImage` | ECR image URI (tag or `@sha256:` digest) used by the Terraform plan and apply builds. Leave empty to deploy without the Terraform approval path. See [Terraform build image](#terraform-build-image) |
| `terraform.version` | Terraform CLI version the build image must provide. The build fails if the image ships a different version |
| `terraform.applyManagedPolicyArns` | Policies of the role that applies approved plans. Use AWS managed policies or policies you protect: this role is exempt from the deny |
| `additionalExemptPrincipalArns` | IAM **role** ARNs (wildcards allowed) of automation that must keep deleting, for example a Karpenter controller role. With AWS Control Tower add `arn:aws:iam::*:role/AWSControlTowerExecution`, so that Control Tower can still update or remove its own resources. The protection SCP prevents member-account administrators from creating a role with an exempt name, changing its trust or permissions, passing it, or assuming it. Keep the list short |
| `platformAdminPrincipalArns` | Additional principals allowed to modify the guard itself (break-glass) |
| `centralEventBusArn` | Optional EventBridge bus in a security account that receives all guard events |

`minApprovals` cannot exceed the number of approver principals for that level. This
is an `aws:approve` constraint. Each IAM Identity Center permission set counts as one
principal. A typical setup is one approval from the team-lead permission set and one
from the security permission set: two distinct people, neither of them the requester.

## Identity providers: IAM Identity Center, AD FS, Okta, Microsoft Entra ID

The gate identifies the people behind a request and its approvals by **role session
name** (or IAM user name). That name is only trustworthy when the identity provider
sets it, so requester and approver roles must be assumable **only through SAML
federation**. DeletionGuard enforces this in two places:

- at deployment, the approver resolver fails if a configured approver role can be
  assumed in any other way (`sts:AssumeRole`, an AWS service, web identity);
- at runtime, the gate rejects a request whose requester or approvers use such a role,
  or the root user. IAM users are accepted and identified by user name.

### IAM Identity Center (with any external IdP, including AD FS)

Nothing to change. Permission set roles trust only the Identity Center SAML provider,
and the session name is the Identity Center user name. Use `permissionSets` in the
configuration, as in the example file. This is the setup that was tested live.

### SAML federation directly with IAM (AD FS, Okta, Entra ID)

1. **Roles.** Create the same roles in every target account, for example
   `ADFS-DeletionRequester`, `ADFS-DeletionApproverTeamLead` and
   `ADFS-DeletionApproverSecurity`, with the policies in [`examples/iam/`](examples/iam/)
   and a trust policy that allows **only** your SAML provider:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "Federated": "arn:aws:iam::<account>:saml-provider/ADFS" },
       "Action": "sts:AssumeRoleWithSAML",
       "Condition": { "StringEquals": { "SAML:aud": "https://signin.aws.amazon.com/saml" } }
     }]
   }
   ```

2. **Session name.** Map the SAML attribute
   `https://aws.amazon.com/SAML/Attributes/RoleSessionName` to a unique identifier that
   users cannot change, such as the UPN or the e-mail address. Use the same value for
   every role, so that the same person is recognized across the requester role and the
   approver roles. Comparison is case-insensitive.

3. **Configuration.** Use `principalArns` instead of `permissionSets`; `{account}` is
   replaced with each member account ID:

   ```json
   "approvals": {
     "level1": { "permissionSets": [], "principalArns": ["arn:aws:iam::{account}:role/ADFS-DeletionApproverTeamLead"], "minApprovals": 1 },
     "level2": { "permissionSets": [], "principalArns": ["arn:aws:iam::{account}:role/ADFS-DeletionApproverSecurity"], "minApprovals": 1 }
   }
   ```

   If the roles have a path, include it in the ARN.

Not tested live: the direct SAML setup relies on the same mechanism as Identity
Center (the session name in CloudTrail) and is covered by unit tests.

## Terraform build image

The Terraform approval path runs `terraform plan` and `terraform apply` in CodeBuild.
The builds download nothing at runtime: they use a container image that **you**
build, scan and publish in Amazon ECR, with Terraform pinned to a version you control.

Requirements for the image:

- Linux x86_64, with `bash`, `terraform` (the version in `terraform.version`), the AWS CLI v2, `jq`, `unzip` and `sha256sum` on the `PATH`.
- Any Terraform providers your configurations need are downloaded by `terraform init`
  from your configured registry or mirror. To avoid public downloads entirely,
  configure a [provider network mirror](https://developer.hashicorp.com/terraform/cli/config/config-file#provider_installation)
  in the image.
- Reference the image by digest (`...@sha256:<digest>`) so that a pushed tag cannot change what approved plans run with.

Where to store it:

- **Same account:** push the image to an ECR repository in each member account and home Region.
- **Central account (recommended):** push it once to a shared tooling account and add a
  repository policy that lets the organization's CodeBuild projects pull:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "OrgCodeBuildPull",
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
    "Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-xxxxxxxxxx" } }
  }]
}
```

The build projects pull the image with their own service role, and the stack grants
those roles the ECR pull permissions. If `terraform.buildImage` is empty, the
`DeletionGuard-TerraformChange` runbook and the CodeBuild projects are not deployed.
Terraform-driven deletions are still blocked by the SCP, but there is no approved
path to run them.

## Deploy

From the management (or delegated administrator) account, in the home region:

```powershell
# PowerShell
Copy-Item guard-config.example.json guard-config.json   # then edit it
.\deploy-all.ps1
```

```bash
# Bash
cp guard-config.example.json guard-config.json          # then edit it
./deploy-all.sh
```

The script:

1. Checks prerequisites and shows the account, region, organization, OUs and whether SCPs will be attached.
2. Deploys `DeletionGuardArtifacts-<region>`: an S3 bucket readable by your organization.
3. Packages the gate (`src/deletion_gate`) and synthesizes the asset-free member template, then uploads both under content-addressed keys.
4. Deploys `DeletionGuardOrg-<region>`. This creates the `DeletionGuard-Member` StackSet and, if `attachScps` is `true`, the two SCPs, which are attached only after the StackSet is in place.
5. Prints the StackSet instances and the next commands.

**Recommended rollout**

1. Deploy with `attachScps: false` to a sandbox OU.
2. Test an approved deletion and a Terraform destroy.
3. Set `attachScps: true` and redeploy.
4. Run the [validation checklist](#validate-in-a-sandbox-before-production).
5. Extend `organizationalUnitIds`.

## Usage

Requests are opened, approved and audited in the account that owns the resource, in
the guard's **home Region**. The resource itself can be in any allowed target Region.
Everything can be done from the console or from the CLI, and the two can be mixed:
for example, request from a script and approve in the console.

### Delete one resource from the console

Sign in as the requester (for example through the IAM Identity Center access portal),
then:

1. Open **Systems Manager** in the home Region and choose **Automation** >
   **Execute automation**.
2. On the **Owned by me** tab, choose `DeletionGuard-DeleteResource`, then **Next**.
3. Keep **Simple execution** and fill in the parameters:

   | Parameter | Value |
   |---|---|
   | `ResourceType` | Select from the list, for example `AWS::DynamoDB::Table` |
   | `ResourceIdentifier` | The Cloud Control primary identifier (see [What is protected](#what-is-protected)), for example the table name |
   | `TargetRegion` | Region of the resource (select from the list) |
   | `Justification` | One line, at least 20 characters, for example `Decommission legacy orders service - CHG-1234` |
   | `DisableDeletionProtection` | `true` to let the gate switch off resource-level deletion protection right before deleting |

4. Choose **Execute**. On the execution page, `ValidateRequest` succeeds and
   `ApproveLevel1` shows **Waiting**. Level 1 approvers are notified.

### Delete one resource from the CLI

```powershell
.\scripts\request-resource-deletion.ps1 -ResourceType AWS::DynamoDB::Table -ResourceIdentifier orders `
    -TargetRegion eu-west-1 -Justification 'Decommission legacy orders service - CHG-1234'
```

```bash
./scripts/request-resource-deletion.sh -t AWS::DynamoDB::Table -i orders -r eu-west-1 \
    -j 'Decommission legacy orders service - CHG-1234'
```

Add `-DisableDeletionProtection` / `-p` to let the gate switch off resource-level
deletion protection right before deleting. Approvers see this flag in the approval
request.

### Terraform destroy, or an apply that deletes or replaces resources

This path requires `terraform.buildImage` (see [Terraform build image](#terraform-build-image)).
The Terraform configuration must use a remote backend (see
[`examples/terraform-sample/backend.tf.example`](examples/terraform-sample/backend.tf.example)).
Upload it as a zip to a versioned S3 bucket (the script can do this for you):

```powershell
.\scripts\request-terraform-change.ps1 -SourceDirectory .\examples\terraform-sample -SourceBucket my-tf-sources `
    -Operation destroy -Justification 'Remove the sample stack after the PoC - CHG-1235'
```

```bash
./scripts/request-terraform-change.sh -d ./examples/terraform-sample -b my-tf-sources -o destroy \
    -j 'Remove the sample stack after the PoC - CHG-1235'
```

The `PlanChange` step produces `plan.txt` and `plan.json` under
`s3://deletion-guard-plans-<account>-<region>/plans/<execution-id>/`. Approvers review
the plan, the approval message includes the create, update and delete counts and the
plan SHA-256, and after both levels approve, exactly that plan is applied.

Use `-Operation apply` for regular changes that Terraform cannot perform without
deleting, such as replacements. With the SCP in place, those fail in your normal
pipeline.

### Approve or reject from the console

Levels are approved **in order**. Level 1 approvers are notified when the request is
opened, level 2 approvers only after level 1 has approved. Each approver signs in with
their own identity (for example the approver permission set in the access portal),
then:

1. Open **Systems Manager** in the home Region and choose **Automation**. The
   **Executions** list shows the waiting request with status **Waiting**.
2. Select the execution and choose **Approve/Deny**, or open the **Approve** or
   **Reject** link in the notification e-mail, which points to the same page.
3. Read the request: resource, target Region, deletion protection flag, justification
   and, for Terraform, the plan summary and the location of `plan.txt`.
4. Choose **Approve** or **Deny**, add a comment (it is recorded with the decision) and
   choose **Submit**.

After the last approval, the `ExecuteDeletion` (or `ApplyChange`) step stays
**In progress** for 2 to 3 minutes while the gate reads the approvals from CloudTrail.
Then it completes and the outcome is notified through `DeletionGuard-Notifications`.

### Approve or reject from the CLI

```bash
aws ssm send-automation-signal --automation-execution-id <id> --signal-type Approve --payload Comment="Reviewed plan, OK"
aws ssm send-automation-signal --automation-execution-id <id> --signal-type Reject  --payload Comment="Wrong table"
```

Run these commands with the approver's own credentials, in the home Region.

### Audit

- `DeletionGuard-Ledger` (DynamoDB) holds one item per request: requester,
  justification, resource or plan, approvers per level, status and outcome.
- CloudTrail records `StartAutomationExecution`, every `SendAutomationSignal` and the
  delete call made by `DeletionGuard-GateRole` or `DeletionGuard-TerraformApplyRole`.
- Gate decisions are published to the default event bus (`source: deletion-guard`)
  and, if configured, forwarded to `centralEventBusArn`.

## Monitoring blocked attempts

Denied attempts are the most useful signal: someone, or some pipeline, tried to delete
outside the approved path. With an organization trail delivered to CloudWatch Logs, use
this Logs Insights query:

```text
fields eventTime, recipientAccountId, awsRegion, userIdentity.arn, eventSource, eventName
| filter errorCode like /AccessDenied/ and errorMessage like /explicit deny in a service control policy/
| sort eventTime desc
```

Create a metric filter and alarm on the same pattern to be notified in near real time.

## Tested on a live organization

The sample was validated end to end on an AWS Organization with AWS Control Tower and
IAM Identity Center, one member account in the target OU, home Region `eu-west-1`
and target Region `eu-central-1`, using three Identity Center users (requester, level 1
approver, level 2 approver) from the CLI and from the console.

| Scenario | Result |
|---|---|
| Approved deletion of a DynamoDB table in another Region, with deletion protection on | Deleted after both approvals. Deletion protection switched off by the gate. Approvers identified by person through CloudTrail |
| Approved deletion of a CloudFormation stack | `DELETE_COMPLETE`, executed by CloudFormation with `DeletionGuard-GateRole` |
| The same deletions with the SCPs attached | Work. The approved path is unaffected by the deny |
| Requester approves with an approver permission set they also hold | Rejected by the gate (`the requester cannot approve their own request`) |
| Level 2 approver approves level 1, non-approver approves | Rejected by SSM (`not in the approver list`) |
| Rejection, Interactive mode, replay of a finished request, look-alike runbook without approvals | Refused. Nothing deleted |
| Request nobody approves | Times out after `approvalTimeoutHours`. Nothing deleted |
| As a member-account **administrator**: `delete-table`, Cloud Control `delete-resource`, `delete-stack`, `delete-queue` | Explicit deny in a service control policy |
| As an administrator: change the gate, the runbook or the gate role, assume or pass the exempt role, write the ledger, invoke the gate, create a role with an exempt name | Denied |
| Approval notifications | Level 1 approvers notified first, level 2 approvers only after level 1 approved, outcome notifications to the requester |

Time from the last approval to the deletion: about 2 to 3 minutes, mostly CloudTrail
delivery. Not tested live: `organizations:LeaveOrganization` (covered by the SCP
content tests only, because a failing test would remove the account from the
organization) and the Terraform plan-and-apply path, which needs your own build image.

## Validate in a sandbox before production

Confirm these behaviors in your own environment:

1. **An end-to-end approved deletion** with your IAM Identity Center setup: requester,
   level 1 and level 2 approvers as three different users, in separate browser profiles.
   If an approval is refused with an authorization error, set
   `"approverRoleArnWithPath": false` and redeploy (the gate works with both formats).
2. **CloudTrail delivery time** in your Regions. The gate waits up to 10 minutes for
   the `SendAutomationSignal` events before rejecting.
3. **Cloud Control coverage and permissions** for the resource types you care about.
   If a Cloud Control handler needs an extra permission, add it to the catalog entry.
4. **Legitimate automation that deletes.** Examples are Karpenter, cleanup jobs, blue/green
   deployments that delete ECS services, and CloudFormation updates that replace
   resources. Also include AWS services that act through a customer-managed service
   role rather than a service-linked role, such as Amazon EMR or EC2 Spot Fleet
   terminating instances. Those calls are denied. Exempt the specific roles, use the Terraform
   runbook with `-Operation apply`, or keep those workloads in OUs without the SCP.
5. **Break-glass.** Agree on how to detach `DeletionGuard-DenyDestructiveActions` from
   the management account in an emergency, and alert on `DetachPolicy`.

## FAQ and troubleshooting

### Requesting

**I can't find `DeletionGuard-DeleteResource` in Execute automation.**
Check that the console is in the guard's **home Region** and look on the **Owned by me**
tab. The runbook only exists in member accounts of the target OUs (not in the
management account).

**The console says *Input does not match the expected pattern* for `Justification`.**
The justification must be a single line of 20 to 1,000 characters. It is embedded in
the approval message, which `aws:approve` requires to be a single line.

**`ValidateRequest` fails.**
Read the step output, or the gate log `/aws/lambda/DeletionGuard-Gate`. Common causes:

- the resource does not exist, or `ResourceIdentifier` is not the Cloud Control primary
  identifier (for example a load balancer needs its ARN, a queue its URL);
- the target Region is not in `allowedTargetRegions`;
- *The requester ... is not a verifiable person*: the requester signed in with a role
  that can be assumed without SAML federation, or as the root user (see
  [Identity providers](#identity-providers-iam-identity-center-ad-fs-okta-microsoft-entra-id)).

**A deletion I used to run in my pipeline now fails with *explicit deny in a service control policy*.**
That is the guard working. Open a request instead, or, for automation that must keep
deleting, add its role to `additionalExemptPrincipalArns`.

### Approving

**Approve/Deny says *is not in the approver list of step ApproveLevel1*.**
The request is still waiting for level 1 and you are a level 2 approver. Wait for the
level 1 approval (you will get your own notification), refresh, then approve.

**Approve/Deny says *is not in the approver list* although I am an approver.**
You are signed in with the wrong role. In the access portal, choose the approver
permission set for that level. If no approver is ever accepted, set
`"approverRoleArnWithPath": false` and redeploy.

**The approval was accepted, but the request was then cancelled.**
The gate rejected it after reading CloudTrail. The reason is in the
`DeletionGuard Request Rejected` notification and in the gate log, for example
*the requester cannot approve their own request* (an approver permission set used by
the requester) or *distinct new approver(s)* (the same person approved both levels).

**`ExecuteDeletion` stays *In progress* for minutes after the last approval.**
Expected: the gate waits until CloudTrail shows who sent each approval, usually 2 to 3
minutes. If the events don't appear within 10 minutes, the request is rejected.

**An approver didn't receive the notification.**
Check that the subscription to `AutomationDeletionGuardLevel1` (or `Level2`) is
confirmed (SNS console, subscription status). Notifications for a level are only sent
when the request reaches that level. In shared mailboxes or plus-addressed aliases,
look for the subject *DeletionGuard - level N approval needed*.

**Approve says *automation ... is in TimedOut status*.**
Nobody approved within `approvalTimeoutHours`. The request expired and nothing was
deleted; open a new one.

### Operating

**How do I see who requested and approved a deletion?**
In the `DeletionGuard-Ledger` table (DynamoDB console, **Explore items**), in CloudTrail
(`StartAutomationExecution`, `SendAutomationSignal`, and the delete call made by
`DeletionGuard-GateRole`), and in the `DeletionGuard` events on EventBridge.

**How do I delete a resource urgently, during an incident?**
The approved path still needs two approvers. For a true emergency, detach
`DeletionGuard-DenyDestructiveActions` from the management account (an audited
action), delete, and attach it again. Agree on this break-glass procedure beforehand.

**Can I change approvers, Regions or the catalog?**
Edit `guard-config.json` (or `protected-resources.ts` for the catalog) and run the
deployment script again. The StackSet updates every member account, and a change of
the `approvals` block resolves the approver roles again. New accounts that join a
target OU get the guard and resolve their approvers automatically.

**Does it work with AD FS, Okta or Entra ID?**
Yes, through IAM Identity Center or SAML federated directly with IAM. See
[Identity providers](#identity-providers-iam-identity-center-ad-fs-okta-microsoft-entra-id).

**Does it work with Pulumi, Ansible or other IaC tools?**
Their deletions are denied like any other API call. Run approved deletions through the
single-resource runbook, then refresh the tool's state.

### Deploying

**The approver resolver fails with *permission set ... is not provisioned in account ...*.**
Provision the approver permission sets to every account of the target OUs, then redeploy.

**The approver resolver fails with *can be assumed without SAML federation*.**
An approver role in `principalArns` trusts something other than a SAML provider (an
AWS account, a service, web identity). Restrict its trust policy, or use another role.

**The StackSet fails and the deployment rolls back.**
Read the stack events of the failed stack instance in the member account
(`StackSet-DeletionGuard-Member-*`, CloudFormation console), or
`aws cloudformation list-stack-set-operation-results` in the management account.

## Limitations

- **Management account.** SCPs do not apply to the management account. Do not run
  workloads there.
- **Data-plane destruction is out of scope.** Examples are `s3:DeleteObject`, S3
  lifecycle rules that expire objects, `dynamodb:DeleteItem`, and reducing backup
  retention. Protect data with S3 Versioning and Object Lock, DynamoDB PITR, and AWS
  Backup vault lock. AWS Backup can also be combined with Multi-party approval for
  logically air-gapped vaults.
- **IaC state after a single-resource deletion.** The SCP blocks deletions from every
  IaC tool (CloudFormation, CDK, Terraform, Pulumi, Ansible, ...). After an approved
  single-resource deletion, update the tool that manages the resource (`pulumi refresh`,
  `terraform state rm`, remove it from the template or playbook). Otherwise the next run
  recreates it. For whole CloudFormation/CDK stacks use `ResourceType
  AWS::CloudFormation::Stack`, and for Terraform the plan-and-apply runbook, which keep
  the state consistent.
- **CloudFormation replacements.** When an update replaces a protected resource,
  CloudFormation's cleanup delete is denied and the old resource is left in place.
  The stack update itself completes.
- **One home region per account.** `aws:approve` does not support multi-account or
  multi-Region automations. The target region is a parameter.
- **Approvers.** `aws:approve` allows up to 10 approver principals per level, and
  `minApprovals` cannot exceed that number.
- **Long operations.** The gate waits up to about 14 minutes. Longer deletions and
  applies continue in the background: the ledger records `IN_PROGRESS`, and the
  Terraform build state is forwarded to the central bus.
- **Broad read access.** The gate and Terraform plan roles use `ReadOnlyAccess` so that
  Cloud Control handlers and `terraform plan` work for any resource type. Narrow it if
  your catalog is small.

## Why not Systems Manager Change Manager?

Change Manager provides change templates with multi-level approvals. However, it is
[closed to new customers since November 7, 2025](https://docs.aws.amazon.com/systems-manager/latest/userguide/change-manager-availability-change.html).
DeletionGuard uses the `aws:approve` action of SSM Automation, which is part of
Automation and remains available.

## Cost

Everything is pay-per-use and idle most of the time. Per member account (home region):

| Item | Driver | Typical monthly cost |
|---|---|---|
| Lambda (gate, resolver) | A few invocations per request | Negligible |
| SSM Automation | 4 steps per request | Within or near the free tier ([pricing](https://aws.amazon.com/systems-manager/pricing/)) |
| CodeBuild `general1.small` | About 2 to 5 minutes per Terraform request (plan and apply) | Cents per Terraform request ([pricing](https://aws.amazon.com/codebuild/pricing/)) |
| DynamoDB on-demand + PITR | One small item per request | Cents |
| S3 plans bucket + server access logs bucket | KB to MB per Terraform request, 365-day expiry | Cents |
| CloudWatch Logs | Gate and build logs, 1-year retention | Cents |
| SNS, EventBridge | Notifications and optional cross-account events | Free tier or cents |
| SCPs, StackSets | | No charge |

For dozens of requests per month, expect a low single-digit USD per account. Use the
[AWS Pricing Calculator](https://calculator.aws/) for your volumes. To reduce cost,
shorten log retention and the plan expiry, and skip `centralEventBusArn` if you
already aggregate CloudTrail centrally.

## Cleanup

1. Detach and delete the SCPs: set `attachScps: false` and run the deploy script again.
2. Delete the `DeletionGuardOrg-<region>` stack. This removes the StackSet instances
   from member accounts.
3. The ledger table, the plans bucket and the access logs
   bucket in each account are retained on purpose. Delete them manually if you no
   longer need the audit trail.
4. Delete `DeletionGuardArtifacts-<region>`, then empty and delete the retained
   artifacts bucket and its access logs bucket.

## Development

```bash
# CDK: compile, unit tests (SCP size limits, template shape, dependencies), synth
cd infrastructure/cdk && npm ci && npx tsc --noEmit && npx jest && npx cdk synth DeletionGuardMember

# Gate: unit tests (approval verification, replay, self-approval, Terraform plan pinning)
python -m venv .venv && .venv/bin/pip install -r src/requirements-dev.txt   # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest src/tests -q
```

## Repository structure

```text
deletion-approval-guard/
├── README.md, ARCHITECTURE.md
├── deploy-all.ps1, deploy-all.sh          # Organization deployment
├── guard-config.example.json              # Configuration template
├── infrastructure/cdk/
│   ├── bin/app.ts                         # CDK app (artifacts, org, member stacks)
│   ├── lib/protected-resources.ts         # Catalog: SCP deny list + runbook types
│   ├── lib/scp-policies.ts                # The two SCPs
│   ├── lib/org-guardrails-stack.ts        # StackSet + SCP attachment
│   ├── lib/member-account-stack.ts        # Gate, runbooks, roles, CodeBuild, ledger
│   ├── lib/runbooks.ts                    # SSM Automation documents (aws:approve x2)
│   ├── lib/terraform-buildspecs.ts        # Plan / apply buildspecs
│   └── test/                              # Jest tests
├── src/
│   ├── deletion_gate/                     # Gate Lambda (verification + execution)
│   ├── approver_resolver/                 # Custom resource (Identity Center roles)
│   └── tests/                             # pytest
├── scripts/                               # request-resource-deletion, request-terraform-change
└── examples/
    ├── terraform-sample/                  # Workload to try the Terraform path
    └── iam/                               # Requester / approver permission set policies
```

## Contributing

We welcome community contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
