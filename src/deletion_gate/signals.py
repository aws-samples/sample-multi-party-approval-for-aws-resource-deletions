"""Approval signals as recorded by AWS CloudTrail.

SSM Automation records each aws:approve decision against the approver's IAM principal.
For IAM Identity Center that is the permission set role, without the role session, so
SSM alone cannot tell which person approved. CloudTrail records every
SendAutomationSignal call with the caller's full identity (assumed-role ARN including
the session name, which IAM Identity Center sets to the user name). The gate pairs each
SSM decision with its CloudTrail event to identify the person behind it.

CloudTrail event history cannot be modified by account administrators.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Signal:
    time: datetime
    caller: str  # assumed-role, IAM user or root ARN
    signal_type: str  # Approve | Reject | ...


def fetch_signals(cloudtrail, execution_id: str, since: datetime) -> list[Signal]:
    """Successful SendAutomationSignal calls for one execution, oldest first."""
    signals: list[Signal] = []
    paginator = cloudtrail.get_paginator("lookup_events")
    pages = paginator.paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "SendAutomationSignal"}],
        StartTime=since - timedelta(minutes=1),
    )
    for page in pages:
        for event in page.get("Events", []):
            detail = json.loads(event.get("CloudTrailEvent") or "{}")
            if detail.get("eventSource") != "ssm.amazonaws.com" or detail.get("errorCode"):
                continue  # rejected calls (e.g. not in the approver list) are not approvals
            params = detail.get("requestParameters") or {}
            if params.get("automationExecutionId") != execution_id:
                continue
            caller = (detail.get("userIdentity") or {}).get("arn")
            if caller:
                signals.append(Signal(time=event["EventTime"], caller=caller, signal_type=str(params.get("signalType", ""))))
    return sorted(signals, key=lambda s: s.time)
