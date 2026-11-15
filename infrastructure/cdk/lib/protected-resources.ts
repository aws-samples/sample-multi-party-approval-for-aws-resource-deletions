/**
 * Single source of truth for what the guard protects.
 *
 * - Every `deleteActions` entry is denied organization-wide by the
 *   destructive-actions SCP for every principal except the guard's executor roles.
 * - Every `type` can be deleted through the DeletionGuard-DeleteResource runbook
 *   (via the AWS Cloud Control API, or a native handler for CloudFormation stacks).
 * - `protectionActions` are the API calls the gate uses to switch off resource-level
 *   deletion protection when the requester sets DisableDeletionProtection=true.
 *
 * Keep this list to control-plane actions that destroy long-lived, stateful or
 * foundational resources. Do NOT add data-plane actions (s3:DeleteObject,
 * dynamodb:DeleteItem, ...): they are part of normal application behaviour and are
 * better protected with S3 Versioning/Object Lock, PITR and AWS Backup.
 */
export interface ProtectedResourceType {
  /** CloudFormation / Cloud Control resource type name. */
  readonly type: string;
  /** IAM actions that destroy this resource type. Denied by the SCP. */
  readonly deleteActions: string[];
  /** IAM actions needed by the gate to disable deletion protection (optional). */
  readonly protectionActions?: string[];
}

export const PROTECTED_RESOURCE_TYPES: ProtectedResourceType[] = [
  { type: 'AWS::EC2::Instance', deleteActions: ['ec2:TerminateInstances'], protectionActions: ['ec2:ModifyInstanceAttribute'] },
  { type: 'AWS::EC2::VPC', deleteActions: ['ec2:DeleteVpc'] },
  { type: 'AWS::RDS::DBInstance', deleteActions: ['rds:DeleteDBInstance'], protectionActions: ['rds:ModifyDBInstance'] },
  { type: 'AWS::RDS::DBCluster', deleteActions: ['rds:DeleteDBCluster'], protectionActions: ['rds:ModifyDBCluster'] },
  { type: 'AWS::DynamoDB::Table', deleteActions: ['dynamodb:DeleteTable'], protectionActions: ['dynamodb:UpdateTable'] },
  { type: 'AWS::S3::Bucket', deleteActions: ['s3:DeleteBucket'] },
  { type: 'AWS::Lambda::Function', deleteActions: ['lambda:DeleteFunction'] },
  { type: 'AWS::ECS::Cluster', deleteActions: ['ecs:DeleteCluster'] },
  { type: 'AWS::ECS::Service', deleteActions: ['ecs:DeleteService'] },
  { type: 'AWS::EKS::Cluster', deleteActions: ['eks:DeleteCluster'] },
  {
    type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
    deleteActions: ['elasticloadbalancing:DeleteLoadBalancer'],
    protectionActions: ['elasticloadbalancing:ModifyLoadBalancerAttributes'],
  },
  { type: 'AWS::EFS::FileSystem', deleteActions: ['elasticfilesystem:DeleteFileSystem'] },
  { type: 'AWS::OpenSearchService::Domain', deleteActions: ['es:DeleteDomain'] },
  { type: 'AWS::Redshift::Cluster', deleteActions: ['redshift:DeleteCluster'] },
  { type: 'AWS::KMS::Key', deleteActions: ['kms:ScheduleKeyDeletion'] },
  { type: 'AWS::SecretsManager::Secret', deleteActions: ['secretsmanager:DeleteSecret'] },
  { type: 'AWS::Backup::BackupVault', deleteActions: ['backup:DeleteBackupVault'] },
  { type: 'AWS::Logs::LogGroup', deleteActions: ['logs:DeleteLogGroup'] },
  { type: 'AWS::SQS::Queue', deleteActions: ['sqs:DeleteQueue'] },
  { type: 'AWS::SNS::Topic', deleteActions: ['sns:DeleteTopic'] },
  { type: 'AWS::Kinesis::Stream', deleteActions: ['kinesis:DeleteStream'] },
  { type: 'AWS::ECR::Repository', deleteActions: ['ecr:DeleteRepository'] },
  { type: 'AWS::Route53::HostedZone', deleteActions: ['route53:DeleteHostedZone'] },
  {
    type: 'AWS::CloudFormation::Stack',
    deleteActions: ['cloudformation:DeleteStack'],
    protectionActions: ['cloudformation:UpdateTerminationProtection'],
  },
];

/**
 * Additional destructive actions denied by the SCP that have no dedicated runbook
 * resource type. They can still be performed through the approved Terraform runbook.
 *
 * cloudformation:DeleteResource is the Cloud Control API delete operation, used for
 * example by the Terraform `awscc` provider.
 */
export const ADDITIONAL_DENIED_ACTIONS: string[] = [
  'cloudformation:DeleteResource',
  'cloudformation:DeleteStackSet',
  'rds:DeleteGlobalCluster',
  'dynamodb:DeleteBackup',
  'elasticache:DeleteCacheCluster',
  'elasticache:DeleteReplicationGroup',
  'fsx:DeleteFileSystem',
  'glacier:DeleteVault',
  'cognito-idp:DeleteUserPool',
  'eks:DeleteNodegroup',
  'ec2:DeleteTransitGateway',
];

/** All actions denied by the destructive-actions SCP (deduplicated, sorted). */
export function deniedDestructiveActions(): string[] {
  const all = new Set<string>(ADDITIONAL_DENIED_ACTIONS);
  for (const r of PROTECTED_RESOURCE_TYPES) {
    r.deleteActions.forEach((a) => all.add(a));
  }
  return [...all].sort();
}

/** Actions granted to the gate role so it can perform approved deletions. */
export function gateExecutionActions(): string[] {
  const all = new Set<string>();
  for (const r of PROTECTED_RESOURCE_TYPES) {
    r.deleteActions.forEach((a) => all.add(a));
    (r.protectionActions ?? []).forEach((a) => all.add(a));
  }
  return [...all].sort();
}
