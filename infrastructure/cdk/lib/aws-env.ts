import { execSync } from 'child_process';

/**
 * Region detection, in the same priority order as the AWS CLI:
 * 1. AWS_REGION / AWS_DEFAULT_REGION environment variables
 * 2. `aws configure get region`
 * 3. CDK_DEFAULT_REGION (set by the CDK CLI from the active profile)
 */
export function getRegion(): string {
  const fromEnv = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
  if (fromEnv) return fromEnv;
  try {
    const fromCli = execSync('aws configure get region', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    if (fromCli) return fromCli;
  } catch {
    // AWS CLI not installed or no region configured; fall through.
  }
  if (process.env.CDK_DEFAULT_REGION) return process.env.CDK_DEFAULT_REGION;
  throw new Error('No AWS region configured. Set AWS_REGION or run "aws configure set region <region>".');
}
