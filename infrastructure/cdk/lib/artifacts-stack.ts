import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

export interface ArtifactsStackProps extends cdk.StackProps {
  /** AWS Organizations ID (o-xxxxxxxxxx). Member accounts get read access. */
  readonly organizationId: string;
}

/**
 * Central bucket (management or delegated-admin account, home region) that holds
 * the gate Lambda package and the member-account template used by the StackSet.
 * Lambda requires the code bucket to be in the same region as the function, which
 * is why the guard runs in a single home region per account.
 */
export class ArtifactsStack extends cdk.Stack {
  public readonly bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: ArtifactsStackProps) {
    super(scope, id, props);

    const accessLogs = new s3.Bucket(this, 'AccessLogsBucket', {
      bucketName: `deletion-guard-artifacts-logs-${cdk.Aws.ACCOUNT_ID}-${cdk.Aws.REGION}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      lifecycleRules: [{ expiration: cdk.Duration.days(365), noncurrentVersionExpiration: cdk.Duration.days(30) }],
      removalPolicy: cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });

    this.bucket = new s3.Bucket(this, 'ArtifactsBucket', {
      bucketName: `deletion-guard-artifacts-${cdk.Aws.ACCOUNT_ID}-${cdk.Aws.REGION}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      serverAccessLogsBucket: accessLogs,
      serverAccessLogsPrefix: 'artifacts-bucket/',
      removalPolicy: cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });

    // Member accounts (StackSets execution role, Lambda service on its behalf) read the package.
    this.bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'OrganizationRead',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: ['s3:GetObject', 's3:GetObjectVersion'],
        resources: [this.bucket.arnForObjects('*')],
        conditions: { StringEquals: { 'aws:PrincipalOrgID': props.organizationId } },
      }),
    );

    new cdk.CfnOutput(this, 'ArtifactsBucketName', { value: this.bucket.bucketName });
  }
}
