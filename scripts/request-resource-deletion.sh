#!/usr/bin/env bash
# Opens a multi-party approved deletion request for one protected resource.
#
# Usage: ./request-resource-deletion.sh -t <ResourceType> -i <ResourceIdentifier> -r <TargetRegion> \
#          -j "<Justification, 20+ chars>" [-p] [--home-region <region>]
#   -p   disable resource-level deletion protection before deleting
set -euo pipefail

TYPE="" IDENT="" TARGET_REGION="" JUSTIFICATION="" PROTECTION=false
HOME_REGION="${AWS_REGION:-$(aws configure get region || true)}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--type) TYPE="$2"; shift 2 ;;
    -i|--identifier) IDENT="$2"; shift 2 ;;
    -r|--target-region) TARGET_REGION="$2"; shift 2 ;;
    -j|--justification) JUSTIFICATION="$2"; shift 2 ;;
    -p|--disable-deletion-protection) PROTECTION=true; shift ;;
    --home-region) HOME_REGION="$2"; shift 2 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done
[[ -n "$TYPE" && -n "$IDENT" && -n "$TARGET_REGION" && -n "$JUSTIFICATION" ]] || { sed -n '2,6p' "$0"; exit 1; }
[[ ${#JUSTIFICATION} -ge 20 ]] || { echo "Justification must be at least 20 characters"; exit 1; }
[[ -n "$HOME_REGION" ]] || { echo "Specify --home-region or configure a default region"; exit 1; }

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
# Build the request as a JSON file to avoid quoting issues with free-text justifications.
python3 - "$TMP" "$TYPE" "$IDENT" "$TARGET_REGION" "$JUSTIFICATION" "$PROTECTION" <<'PY'
import json, sys
out, rtype, ident, region, why, prot = sys.argv[1:]
json.dump({"DocumentName": "DeletionGuard-DeleteResource", "Parameters": {
    "ResourceType": [rtype], "ResourceIdentifier": [ident], "TargetRegion": [region],
    "Justification": [why], "DisableDeletionProtection": [prot]}}, open(out, "w"))
PY

EXECUTION_ID="$(aws ssm start-automation-execution --cli-input-json "file://$TMP" --region "$HOME_REGION" \
  --query AutomationExecutionId --output text --no-cli-pager)"

echo
echo "Deletion request submitted"
echo "  Execution ID : $EXECUTION_ID"
echo "  Resource     : $TYPE $IDENT ($TARGET_REGION)"
echo "  Track it     : https://$HOME_REGION.console.aws.amazon.com/systems-manager/automation/execution/$EXECUTION_ID?region=$HOME_REGION"
echo
echo "Approvers can approve with:"
echo "  aws ssm send-automation-signal --automation-execution-id $EXECUTION_ID --signal-type Approve --payload Comment='<reason>' --region $HOME_REGION"
