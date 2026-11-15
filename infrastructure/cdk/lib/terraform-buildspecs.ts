/**
 * CodeBuild buildspecs for the Terraform path.
 *
 * Plan (read-only role):  download the exact source object version -> terraform plan
 *                         -> upload tfplan / plan.txt / plan.json -> export counts + SHA-256.
 * Apply (exempt role):    download the same source version + the approved tfplan
 *                         -> verify SHA-256 -> terraform apply tfplan.
 *
 * Only the gate can start these builds (guard-protection SCP), and it always passes
 * the environment variables itself. Approvers approve a concrete plan file, and
 * Terraform refuses to apply a saved plan if the state changed since it was created.
 */

// The build image (terraform.buildImage, in the customer's ECR) ships the Terraform CLI,
// the AWS CLI, jq and unzip. Nothing is downloaded at build time; the build only checks
// that the image provides the Terraform version pinned in guard-config.json.
const installTerraform = [
  'set -euo pipefail',
  'for tool in terraform aws jq unzip sha256sum; do command -v "$tool" > /dev/null || { echo "Build image is missing $tool"; exit 1; }; done',
  'ACTUAL=$(terraform version -json | jq -r .terraform_version)',
  'if [ "$ACTUAL" != "$TF_VERSION" ]; then echo "Build image has Terraform $ACTUAL, expected $TF_VERSION"; exit 1; fi',
  'terraform version',
].join('\n');

const fetchSource = [
  'set -euo pipefail',
  'case "$WORKING_DIRECTORY" in *..*) echo "Invalid working directory"; exit 1;; esac',
  'rm -rf /tmp/src && mkdir -p /tmp/src',
  'if [ -n "${SOURCE_VERSION_ID:-}" ]; then',
  '  aws s3api get-object --bucket "$SOURCE_BUCKET" --key "$SOURCE_KEY" --version-id "$SOURCE_VERSION_ID" /tmp/src.zip > /dev/null',
  'else',
  '  aws s3api get-object --bucket "$SOURCE_BUCKET" --key "$SOURCE_KEY" --if-match "$SOURCE_ETAG" /tmp/src.zip > /dev/null',
  'fi',
  'unzip -q /tmp/src.zip -d /tmp/src',
].join('\n');

export function terraformPlanBuildSpec(): Record<string, unknown> {
  return {
    version: '0.2',
    env: {
      shell: 'bash',
      'exported-variables': ['PLAN_SHA256', 'PLAN_DELETE', 'PLAN_CREATE', 'PLAN_UPDATE'],
    },
    phases: {
      install: { commands: [installTerraform] },
      build: {
        commands: [
          fetchSource,
          [
            'set -euo pipefail',
            'cd "/tmp/src/$WORKING_DIRECTORY"',
            'terraform init -input=false -no-color',
            // -lock=false: the plan role is read-only and cannot take the state lock.
            'PLAN_ARGS="-input=false -no-color -lock=false -out=tfplan"',
            'if [ "$TF_OPERATION" = "destroy" ]; then PLAN_ARGS="$PLAN_ARGS -destroy"; fi',
            'terraform plan $PLAN_ARGS',
            'terraform show -no-color tfplan > plan.txt',
            'terraform show -json tfplan > plan.json',
            'export PLAN_DELETE=$(jq \'[.resource_changes[]? | select(.change.actions | index("delete"))] | length\' plan.json)',
            'export PLAN_CREATE=$(jq \'[.resource_changes[]? | select(.change.actions | index("create"))] | length\' plan.json)',
            'export PLAN_UPDATE=$(jq \'[.resource_changes[]? | select(.change.actions == ["update"])] | length\' plan.json)',
            'export PLAN_SHA256=$(sha256sum tfplan | cut -d" " -f1)',
            'DEST="s3://$PLANS_BUCKET/plans/$EXECUTION_ID"',
            'aws s3 cp tfplan "$DEST/tfplan" --only-show-errors',
            'aws s3 cp plan.txt "$DEST/plan.txt" --only-show-errors',
            'aws s3 cp plan.json "$DEST/plan.json" --only-show-errors',
            'if [ -f .terraform.lock.hcl ]; then aws s3 cp .terraform.lock.hcl "$DEST/terraform.lock.hcl" --only-show-errors; fi',
            'echo "Plan: create=$PLAN_CREATE update=$PLAN_UPDATE delete=$PLAN_DELETE sha256=$PLAN_SHA256"',
          ].join('\n'),
        ],
      },
    },
  };
}

export function terraformApplyBuildSpec(): Record<string, unknown> {
  return {
    version: '0.2',
    env: { shell: 'bash' },
    phases: {
      install: { commands: [installTerraform] },
      build: {
        commands: [
          fetchSource,
          [
            'set -euo pipefail',
            'cd "/tmp/src/$WORKING_DIRECTORY"',
            'SRC="s3://$PLANS_BUCKET/plans/$EXECUTION_ID"',
            'aws s3 cp "$SRC/tfplan" tfplan --only-show-errors',
            'if aws s3 ls "$SRC/terraform.lock.hcl" > /dev/null 2>&1; then aws s3 cp "$SRC/terraform.lock.hcl" .terraform.lock.hcl --only-show-errors; fi',
            // Refuse to apply anything other than the plan the approvers saw.
            'echo "$PLAN_SHA256  tfplan" | sha256sum -c -',
            'terraform init -input=false -no-color -lockfile=readonly',
            'terraform apply -input=false -no-color tfplan',
          ].join('\n'),
        ],
      },
    },
  };
}
