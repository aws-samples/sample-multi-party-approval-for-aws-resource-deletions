# Resolves DeletionGuard approvers in a member account (CloudFormation custom resource).
# IAM Identity Center role names have a per-account random suffix, so they are looked
# up at deploy time. Packaged with the gate (lambda/gate-<hash>.zip).
import json
import re
import urllib.request

import boto3

MAX_APPROVERS = 10  # aws:approve limit
SAML = {"sts:assumerolewithsaml", "sts:tagsession", "sts:setsourceidentity"}


def _send(event, context, status, data=None, reason=""):
    body = json.dumps({
        "Status": status,
        "Reason": (reason or "See CloudWatch Logs")[:900],
        "PhysicalResourceId": "deletion-guard-approvers",
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": data or {},
    }).encode()
    url = event["ResponseURL"]
    if not url.startswith("https://"):
        raise ValueError("ResponseURL must be an https:// URL")
    req = urllib.request.Request(url, data=body, method="PUT",
                                 headers={"Content-Type": "", "Content-Length": str(len(body))})
    urllib.request.urlopen(req, timeout=30)  # nosec B310 - https scheme enforced above


def _sso_roles():
    roles = []
    pages = boto3.client("iam").get_paginator("list_roles")
    for page in pages.paginate(PathPrefix="/aws-reserved/sso.amazonaws.com/"):
        roles.extend(page["Roles"])
    return roles


def _arn(role, props):
    if props.get("RoleArnWithPath", "true") == "true":
        return role["Arn"]
    # arn:<partition>:iam::<account>:role/<name> without the /aws-reserved/... path
    return role["Arn"].split(":role/")[0] + ":role/" + role["RoleName"]


def _l(v):
    return v if isinstance(v, list) else [v]


def _saml_only(doc):
    # The gate identifies people by session name: only SAML federation sets it reliably.
    st = _l(doc.get("Statement", []))
    for s in st:
        if s.get("Effect") != "Allow":
            continue
        p = s.get("Principal")
        if not (isinstance(p, dict) and set(p) == {"Federated"}
                and all(":saml-provider/" in f for f in _l(p["Federated"]))):
            return False
        if {a.lower() for a in _l(s.get("Action", []))} - SAML:
            return False
    return bool(st)


def _resolve(props, level, account, roles, trust=None):
    arns = [a.replace("{account}", account) for a in props.get(level + "PrincipalArns", []) if a]
    for ps in props.get(level + "PermissionSets", []):
        pattern = re.compile("^AWSReservedSSO_" + re.escape(ps) + "_[0-9a-f]+$")
        found = [_arn(r, props) for r in roles if pattern.match(r["RoleName"])]
        if not found:
            raise ValueError(f"{level}: permission set '{ps}' is not provisioned in account {account}")
        arns.extend(found)
    arns = sorted(set(arns))
    for a in arns:
        if trust and ":role/" in a and a.split(":")[4] == account:
            name = a.rsplit("/", 1)[1]
            if not _saml_only(trust(name)):
                raise ValueError(f"{level}: role {name} can be assumed without SAML federation, "
                                 "its session name would not identify a person")
    minimum = int(props.get(level + "MinApprovals", "1"))
    if not arns:
        raise ValueError(f"{level}: no approvers resolved")
    if len(arns) > MAX_APPROVERS:
        raise ValueError(f"{level}: {len(arns)} approvers, aws:approve allows {MAX_APPROVERS}")
    if minimum > len(arns):
        # aws:approve rejects MinRequiredApprovals greater than the Approvers count.
        raise ValueError(f"{level}: minApprovals {minimum} exceeds {len(arns)} approver principals")
    return ",".join(arns)


def handler(event, context):
    print(json.dumps({k: v for k, v in event.items() if k != "ResponseURL"}))
    try:
        if event["RequestType"] == "Delete":
            _send(event, context, "SUCCESS")
            return
        props = event["ResourceProperties"]
        account = context.invoked_function_arn.split(":")[4]
        roles = _sso_roles()
        iam = boto3.client("iam")
        trust = lambda n: iam.get_role(RoleName=n)["Role"]["AssumeRolePolicyDocument"]  # noqa: E731
        data = {lvl: _resolve(props, lvl, account, roles, trust) for lvl in ("Level1", "Level2")}
        print(json.dumps(data))
        _send(event, context, "SUCCESS", data)
    except Exception as exc:  # noqa: BLE001 - always answer CloudFormation
        print(f"ERROR: {exc}")
        _send(event, context, "FAILED", reason=str(exc))
