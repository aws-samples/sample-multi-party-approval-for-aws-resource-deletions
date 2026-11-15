#!/usr/bin/env bash
# Opens a multi-party approved Terraform change (destroy, or an apply that deletes/replaces resources).
#
# Usage: ./request-terraform-change.sh -b <SourceBucket> (-k <SourceKey> | -d <SourceDirectory>) \
#          -o destroy|apply -j "<Justification, 20+ chars>" [-w <WorkingDirectory>] [--home-region <region>]
set -euo pipefail

BUCKET="" KEY="" DIR="" WORKDIR="." OPERATION="" JUSTIFICATION=""
HOME_REGION="${AWS_REGION:-$(aws configure get region || true)}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--bucket) BUCKET="$2"; shift 2 ;;
    -k|--key) KEY="$2"; shift 2 ;;
    -d|--directory) DIR="$2"; shift 2 ;;
    -w|--working-directory) WORKDIR="$2"; shift 2 ;;
    -o|--operation) OPERATION="$2"; shift 2 ;;
    -j|--justification) JUSTIFICATION="$2"; shift 2 ;;
    --home-region) HOME_REGION="$2"; shift 2 ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done
[[ -n "$BUCKET" && -n "$OPERATION" && -n "$JUSTIFICATION" && ( -n "$KEY" || -n "$DIR" ) ]] || { sed -n '2,5p' "$0"; exit 1; }
[[ "$OPERATION" == "destroy" || "$OPERATION" == "apply" ]] || { echo "Operation must be destroy or apply"; exit 1; }
[[ ${#JUSTIFICATION} -ge 20 ]] || { echo "Justification must be at least 20 characters"; exit 1; }
[[ -n "$HOME_REGION" ]] || { echo "Specify --home-region or configure a default region"; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ -n "$DIR" ]]; then
  DIR="$(cd "$DIR" && pwd)"
  NAME="$(basename "$DIR")"
  KEY="deletion-guard-sources/$NAME-$(date +%Y%m%d%H%M%S).zip"
  # Exclude local state and provider caches.
  python3 - "$DIR" "$TMP_DIR/src.zip" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1:]
skip = {".terraform", "terraform.tfstate", "terraform.tfstate.backup", "tfplan"}
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for base, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            if f not in skip:
                p = os.path.join(base, f)
                z.write(p, os.path.relpath(p, src))
PY
  aws s3 cp "$TMP_DIR/src.zip" "s3://$BUCKET/$KEY" --only-show-errors --no-cli-pager
  echo "Uploaded $DIR to s3://$BUCKET/$KEY"
fi

python3 - "$TMP_DIR/req.json" "$BUCKET" "$KEY" "$WORKDIR" "$OPERATION" "$JUSTIFICATION" <<'PY'
import json, sys
out, bucket, key, workdir, op, why = sys.argv[1:]
json.dump({"DocumentName": "DeletionGuard-TerraformChange", "Parameters": {
    "SourceBucket": [bucket], "SourceKey": [key], "WorkingDirectory": [workdir],
    "Operation": [op], "Justification": [why]}}, open(out, "w"))
PY

EXECUTION_ID="$(aws ssm start-automation-execution --cli-input-json "file://$TMP_DIR/req.json" --region "$HOME_REGION" \
  --query AutomationExecutionId --output text --no-cli-pager)"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text --no-cli-pager)"

echo
echo "Terraform change request submitted"
echo "  Execution ID : $EXECUTION_ID"
echo "  Source       : s3://$BUCKET/$KEY ($OPERATION)"
echo "  Plan (after the plan step): s3://deletion-guard-plans-$ACCOUNT-$HOME_REGION/plans/$EXECUTION_ID/plan.txt"
echo "  Track it     : https://$HOME_REGION.console.aws.amazon.com/systems-manager/automation/execution/$EXECUTION_ID?region=$HOME_REGION"
