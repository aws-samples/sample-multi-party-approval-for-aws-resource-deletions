#!/usr/bin/env bash
# Deploys DeletionGuard to an AWS Organization.
#
# Run with credentials for the management account (or a delegated administrator for
# StackSets and Organizations policies), in the guard's home region.
#
# Usage: ./deploy-all.sh [-c|--config guard-config.json] [-y|--yes]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDK_DIR="$ROOT/infrastructure/cdk"
BUILD_DIR="$ROOT/build"
CONFIG_PATH="$ROOT/guard-config.json"
ASSUME_YES=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config) CONFIG_PATH="$2"; shift 2 ;;
    -y|--yes) ASSUME_YES=true; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

step() { printf '\n\033[36m==> %s\033[0m\n' "$1"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

# Content hash of files (relative path + bytes), first 16 hex chars.
content_hash() {
  python3 - "$ROOT" "$@" <<'PY'
import hashlib, os, sys
root, files = sys.argv[1], sorted(sys.argv[2:])
h = hashlib.sha256()
for f in files:
    h.update(os.path.relpath(f, root).replace(os.sep, "/").encode())
    h.update(open(f, "rb").read())
print(h.hexdigest()[:16])
PY
}

# ---------------------------------------------------------------------------- prerequisites
step "Checking prerequisites"
for cmd in aws node npm python3; do
  command -v "$cmd" > /dev/null || die "'$cmd' is required but was not found in PATH."
done
[[ -f "$CONFIG_PATH" ]] || die "Configuration not found: $CONFIG_PATH. Copy guard-config.example.json to guard-config.json and edit it."
CONFIG_PATH="$(cd "$(dirname "$CONFIG_PATH")" && pwd)/$(basename "$CONFIG_PATH")"

cfg() { python3 -c "import json,sys; v=json.load(open(sys.argv[1]))$1; print(','.join(v) if isinstance(v,list) else v)" "$CONFIG_PATH"; }
OUS="$(cfg "['organizationalUnitIds']")"
TARGET_REGIONS="$(cfg "['allowedTargetRegions']")"
ATTACH_SCPS="$(cfg "['attachScps']")"
CALL_AS="$(cfg "['stackSetCallAs']")"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text --no-cli-pager)" \
  || die "AWS credentials are not configured (aws sts get-caller-identity failed)."
CALLER="$(aws sts get-caller-identity --query Arn --output text --no-cli-pager)"

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region || true)}}"
[[ -n "$REGION" ]] || die "No AWS region configured. Set AWS_REGION or run: aws configure set region <region>"
export AWS_REGION="$REGION"

ORG_ID="$(aws organizations describe-organization --query Organization.Id --output text --no-cli-pager)" \
  || die "Could not read the AWS Organization. Run this from the management or a delegated administrator account."

echo
echo "  Account        : $ACCOUNT ($CALLER)"
echo "  Home region    : $REGION"
echo "  Organization   : $ORG_ID"
echo "  Target OUs     : $OUS"
echo "  Target regions : $TARGET_REGIONS"
echo "  Attach SCPs    : $ATTACH_SCPS"
if [[ "$ATTACH_SCPS" == "True" ]]; then
  echo
  printf '\033[33m  The SCPs will block destructive actions for EVERY identity in the target OUs\n'
  printf '  except the DeletionGuard executor roles. Test on a sandbox OU first.\033[0m\n'
fi
if [[ "$ASSUME_YES" != true ]]; then
  read -r -p $'\nProceed? (y/N) ' answer
  [[ "$answer" =~ ^(y|Y|yes)$ ]] || { echo "Aborted."; exit 1; }
fi

# ---------------------------------------------------------------------------- CDK dependencies & bootstrap
step "Installing CDK dependencies"
cd "$CDK_DIR"
npm ci --no-fund --no-audit

if ! aws cloudformation describe-stacks --stack-name CDKToolkit --region "$REGION" --no-cli-pager > /dev/null 2>&1; then
  step "Bootstrapping CDK in $ACCOUNT/$REGION"
  npx cdk bootstrap "aws://$ACCOUNT/$REGION"
fi

# ---------------------------------------------------------------------------- artifacts bucket
ARTIFACTS_STACK="DeletionGuardArtifacts-$REGION"
step "Deploying $ARTIFACTS_STACK"
npx cdk deploy "$ARTIFACTS_STACK" -c "organizationId=$ORG_ID" -c "configPath=$CONFIG_PATH" \
  --require-approval never
BUCKET="$(aws cloudformation describe-stacks --stack-name "$ARTIFACTS_STACK" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ArtifactsBucketName'].OutputValue" --output text --no-cli-pager)"

# ---------------------------------------------------------------------------- gate package
step "Packaging the gate Lambda"
GATE_FILES=("$ROOT"/src/deletion_gate/*.py)
RESOLVER_FILES=("$ROOT"/src/approver_resolver/*.py)
GATE_HASH="$(content_hash "${GATE_FILES[@]}" "${RESOLVER_FILES[@]}")"
rm -rf "$BUILD_DIR/gate" && mkdir -p "$BUILD_DIR/gate/deletion_gate" "$BUILD_DIR/gate/approver_resolver"
cp "${GATE_FILES[@]}" "$BUILD_DIR/gate/deletion_gate/"
cp "${RESOLVER_FILES[@]}" "$BUILD_DIR/gate/approver_resolver/"
ZIP="$BUILD_DIR/gate-$GATE_HASH.zip"
python3 -c "import shutil,sys; shutil.make_archive(sys.argv[1][:-4], 'zip', sys.argv[2])" "$ZIP" "$BUILD_DIR/gate"
GATE_KEY="lambda/gate-$GATE_HASH.zip"
aws s3 cp "$ZIP" "s3://$BUCKET/$GATE_KEY" --only-show-errors --no-cli-pager

# ---------------------------------------------------------------------------- member template
step "Synthesizing the member-account template"
npx cdk synth DeletionGuardMember -c "configPath=$CONFIG_PATH" --quiet
TEMPLATE="$CDK_DIR/cdk.out/DeletionGuardMember.template.json"
TEMPLATE_KEY="templates/member-$(content_hash "$TEMPLATE").json"
aws s3 cp "$TEMPLATE" "s3://$BUCKET/$TEMPLATE_KEY" --only-show-errors --no-cli-pager

# ---------------------------------------------------------------------------- org stack
ORG_STACK="DeletionGuardOrg-$REGION"
step "Deploying $ORG_STACK (StackSet rollout can take several minutes)"
npx cdk deploy "$ORG_STACK" \
  -c "organizationId=$ORG_ID" -c "configPath=$CONFIG_PATH" -c "artifactsBucket=$BUCKET" \
  -c "gateCodeKey=$GATE_KEY" -c "memberTemplateKey=$TEMPLATE_KEY" \
  --require-approval never
cd "$ROOT"

# ---------------------------------------------------------------------------- summary
INSTANCES="$(aws cloudformation list-stack-instances --stack-set-name DeletionGuard-Member --call-as "$CALL_AS" \
  --region "$REGION" --query 'Summaries[].[Account,StackInstanceStatus.DetailedStatus]' --output text --no-cli-pager || true)"

printf '\n\033[32m========================================\n  DeletionGuard deployment complete\n========================================\033[0m\n\n'
echo "  Home region       : $REGION"
echo "  Artifacts bucket  : $BUCKET"
echo "  StackSet          : DeletionGuard-Member"
echo "  SCPs attached     : $ATTACH_SCPS"
echo "  Stack instances   :"
if [[ -n "$INSTANCES" ]]; then echo "$INSTANCES" | sed 's/^/    /'; else echo "    (none yet)"; fi
echo
echo "  Request a deletion from a member account (home region):"
echo "    ./scripts/request-resource-deletion.sh -t AWS::DynamoDB::Table -i <table> -r <region> -j '<why>'"
TF_IMAGE="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('terraform',{}).get('buildImage',''))" "$CONFIG_PATH")"
if [[ -n "$TF_IMAGE" ]]; then
  echo "  Request a Terraform destroy:"
  echo "    ./scripts/request-terraform-change.sh -d ./examples/terraform-sample -b <bucket> -o destroy -j '<why>'"
else
  echo "  Terraform approval path: not deployed (set terraform.buildImage to enable it)"
fi
echo
