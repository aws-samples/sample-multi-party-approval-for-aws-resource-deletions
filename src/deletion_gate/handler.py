"""Lambda entry point for the DeletionGuard gate."""
from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

import boto3
from botocore.config import Config

from .deleters import Deleter
from .gate import Gate, GateConfig
from .ledger import Ledger
from .signals import fetch_signals
from .terraform import TerraformRunner
from .trust import make_identity_checker

logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger(__name__)

_BOTO = Config(retries={"mode": "standard", "max_attempts": 5})


def _split(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(name, "").split(",") if x.strip())


@lru_cache(maxsize=None)
def _client(service: str, region: str | None = None):
    return boto3.client(service, region_name=region, config=_BOTO)


def _notifier(topic_arn: str):
    sns, events = _client("sns"), _client("events")

    def notify(kind: str, detail: dict) -> None:
        try:
            events.put_events(Entries=[{"Source": "deletion-guard", "DetailType": f"DeletionGuard {kind}",
                                        "Detail": json.dumps(detail, default=str)}])
            sns.publish(TopicArn=topic_arn, Subject=f"DeletionGuard: {kind}"[:100],
                        Message=json.dumps(detail, indent=2, default=str))
        except Exception:  # noqa: BLE001 - notifications must never change the decision
            log.exception("Notification failed")

    return notify


def build_gate(account: str) -> Gate:
    env = os.environ
    cfg = GateConfig(
        account=account,
        resource_runbook=env["RESOURCE_RUNBOOK"],
        terraform_runbook=env["TERRAFORM_RUNBOOK"],
        approvers_l1=_split("APPROVERS_L1"),
        approvers_l2=_split("APPROVERS_L2"),
        min_l1=int(env["MIN_APPROVALS_L1"]),
        min_l2=int(env["MIN_APPROVALS_L2"]),
        allowed_regions=frozenset(_split("ALLOWED_REGIONS")),
        allowed_types=frozenset(_split("ALLOWED_RESOURCE_TYPES")),
        plans_bucket=env["PLANS_BUCKET"],
        topic_arn=env["TOPIC_ARN"],
    )
    return Gate(
        cfg=cfg,
        ssm=_client("ssm"),
        ledger=Ledger(_client("dynamodb"), env["LEDGER_TABLE"]),
        deleter=Deleter(lambda svc, region: _client(svc, region), env["GATE_ROLE_ARN"]),
        terraform=TerraformRunner(_client("codebuild"), _client("s3"), env["PLAN_PROJECT"], env["APPLY_PROJECT"],
                                  env["PLANS_BUCKET"]),
        notify=_notifier(env["TOPIC_ARN"]),
        # CloudTrail event history of this account and home Region, where the approvals happen.
        signals=lambda execution_id, since: fetch_signals(_client("cloudtrail"), execution_id, since),
        # Requester and approvers must use SAML-federated roles (or IAM users).
        identity_check=make_identity_checker(_client("iam")),
    )


def lambda_handler(event, context):
    log.info("Gate invoked: %s", json.dumps({"action": event.get("action"), "executionId": event.get("executionId")}))
    account = context.invoked_function_arn.split(":")[4]
    result = build_gate(account).handle(event, context.get_remaining_time_in_millis())
    log.info("Gate result: %s", json.dumps(result, default=str))
    return result
