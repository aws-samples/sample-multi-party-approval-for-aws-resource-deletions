import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

# Make `deletion_gate` importable when running `pytest src/tests` from the repo root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from deletion_gate.signals import Signal  # noqa: E402

# Fake 12-digit account ID built at runtime (AWS documentation example pattern).
ACCOUNT = "1" * 4 + "2" * 4 + "3" * 4
SSO = f"arn:aws:sts::{ACCOUNT}:assumed-role"
REQUESTER_ROLE = "AWSReservedSSO_DeletionRequester_0a1b2c3d4e5f6a7b"
LEAD_ROLE = "AWSReservedSSO_DeletionApproverTeamLead_1111aaaa2222bbbb"
SECURITY_ROLE = "AWSReservedSSO_DeletionApproverSecurity_3333cccc4444dddd"

REQUESTER = f"{SSO}/{REQUESTER_ROLE}/dave"
L1_ROLE = f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/eu-west-1/{LEAD_ROLE}"
L2_ROLE = f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/eu-west-1/{SECURITY_ROLE}"
ALICE_L1 = f"{SSO}/{LEAD_ROLE}/alice"
BOB_L2 = f"{SSO}/{SECURITY_ROLE}/bob"
CAROL_L2 = f"{SSO}/{SECURITY_ROLE}/carol"
EXEC_ID = "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"

T0 = datetime(2026, 11, 13, 21, 0, 0, tzinfo=timezone.utc)
STEP_WINDOWS = {  # step name -> (start, end) offsets in seconds from T0
    "ValidateRequest": (0, 5), "PlanChange": (0, 5),
    "ApproveLevel1": (5, 300), "ApproveLevel2": (300, 600),
    "ExecuteDeletion": (600, None), "ApplyChange": (600, None),
}


def role_arn_of(session_arn: str) -> str:
    """IAM Identity Center role ARN (with path) as recorded by SSM in ApproverDecisions."""
    role = session_arn.split(":assumed-role/")[1].split("/")[0]
    return f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/eu-west-1/{role}"


def make_execution(document="DeletionGuard-DeleteResource", current="ExecuteDeletion", l1=None, l2=None,
                   params=None, executed_by=REQUESTER, mode="Auto", with_signals=True):
    """Build an execution record and the matching CloudTrail signals.

    l1 / l2: list of (caller session ARN, "Approve"|"Reject"). SSM records the role ARN of each
    caller in ApproverDecisions (observed behaviour); CloudTrail records the session ARN.
    """
    order = (["ValidateRequest", "ApproveLevel1", "ApproveLevel2", "ExecuteDeletion"]
             if document.endswith("DeleteResource") else
             ["PlanChange", "ApproveLevel1", "ApproveLevel2", "ApplyChange"])
    steps, signals = [], []
    for name in order:
        start, end = STEP_WINDOWS[name]
        step = {"StepName": name, "ExecutionStartTime": T0 + timedelta(seconds=start)}
        callers = {"ApproveLevel1": l1, "ApproveLevel2": l2}.get(name)
        if callers is not None:
            decisions = []
            for i, (caller, decision) in enumerate(callers):
                when = T0 + timedelta(seconds=start + 30 + i * 10, milliseconds=450)
                decisions.append(json.dumps({"Approver": role_arn_of(caller), "Decision": decision,
                                             "ApprovalDecisionTime": when.isoformat().replace("+00:00", "000Z"),
                                             "Comment": "ok"}))
                # CloudTrail eventTime has second precision.
                signals.append(Signal(time=when.replace(microsecond=0), caller=caller, signal_type=decision))
            step.update(StepStatus="Success", ExecutionEndTime=T0 + timedelta(seconds=end),
                        Outputs={"ApprovalStatus": ["Approved"], "ApproverDecisions": decisions})
        elif name == current:
            step["StepStatus"] = "InProgress"
        elif order.index(name) < order.index(current):
            step.update(StepStatus="Success", ExecutionEndTime=T0 + timedelta(seconds=end))
        else:
            step = {"StepName": name, "StepStatus": "Pending"}
        steps.append(step)
    default_params = {
        "ResourceType": ["AWS::DynamoDB::Table"], "ResourceIdentifier": ["orders"], "TargetRegion": ["eu-west-1"],
        "Justification": ["Decommissioning the legacy orders service, ticket CHG-1234"],
        "DisableDeletionProtection": ["false"],
    }
    execution = {
        "AutomationExecutionId": EXEC_ID, "DocumentName": document, "AutomationExecutionStatus": "InProgress",
        "Mode": mode, "ExecutedBy": executed_by, "ExecutionStartTime": T0, "StepExecutions": steps,
        "Parameters": params or default_params,
    }
    return execution, (signals if with_signals else [])
