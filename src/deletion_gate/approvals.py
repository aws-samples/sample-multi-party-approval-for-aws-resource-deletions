"""Independent verification of the approvals recorded on an SSM Automation execution.

The gate never trusts the runbook flow. It re-reads the execution from the SSM API,
pairs every recorded aws:approve decision with the SendAutomationSignal event that
CloudTrail recorded for it, and checks for every approval level:

* the aws:approve step completed successfully with ApprovalStatus=Approved;
* nobody rejected;
* every decision comes from a configured approver principal of that level;
* every decision has a matching CloudTrail event (same principal, same time), which
  identifies the person who approved;
* the requester (ExecutedBy) never approves their own request, whatever permission
  set they use to do it;
* the number of distinct people meets the level's quorum, and a person counts only
  once across all levels.

Anything unexpected is a rejection (fail closed). A decision whose CloudTrail event is
not visible yet raises ApprovalPending so that the caller can wait and retry.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from .errors import ApprovalError, ApprovalPending
from .identity import Principal, parse_caller, principal_key
from .signals import Signal

_APPROVED = {"approve", "approved"}
_REJECTED = {"reject", "rejected", "deny", "denied"}
# CloudTrail eventTime has second precision; SSM decision times are sub-second.
MATCH_WINDOW = timedelta(seconds=5)


@dataclass(frozen=True)
class LevelPolicy:
    step_name: str
    approvers: tuple[str, ...]
    min_approvals: int


@dataclass(frozen=True)
class Decision:
    principal: str
    decision: str
    time: Optional[datetime]


@dataclass
class ApprovalResult:
    requester: str
    # Per level: the CloudTrail caller ARNs (with session name) of the people who approved.
    levels: dict[str, list[str]] = field(default_factory=dict)

    @property
    def approvers(self) -> list[str]:
        return [arn for arns in self.levels.values() for arn in arns]


# ------------------------------------------------------------------------- parsing
def as_datetime(value: Any) -> Optional[datetime]:
    """Accept datetime, epoch seconds or ISO 8601 (with up to nanosecond precision)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # Python accepts at most microseconds
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _decision_word(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("Decision", "decision", "ApprovalDecision", "approvalDecision", "Status", "status"):
            if key in value:
                return str(value[key]).strip().lower()
        return ""
    return str(value).strip().lower()


def _decision_time(value: Any) -> Optional[datetime]:
    if isinstance(value, dict):
        for key in ("ApprovalDecisionTime", "approvalDecisionTime", "DecisionTime", "Time"):
            if value.get(key):
                return as_datetime(value[key])
    return None


def _from_mapping(obj: dict) -> list[Decision]:
    # Observed format: {"Approver": "<arn>", "Decision": "Approve", "ApprovalDecisionTime": "...", "Comment": "..."}
    for key in ("Approver", "approver", "ApproverArn", "approverArn", "Principal", "principal"):
        if isinstance(obj.get(key), str):
            return [Decision(obj[key], _decision_word(obj), _decision_time(obj))]
    # Alternative format: {"<approver arn>": {"Decision": "Approve", ...}}
    if obj and all(isinstance(k, str) and k.startswith("arn:") for k in obj):
        return [Decision(k, _decision_word(v), _decision_time(v)) for k, v in obj.items()]
    return []


def parse_decisions(raw_values: Iterable[Any]) -> list[Decision]:
    """Normalise the ApproverDecisions step output."""
    decisions: list[Decision] = []
    for raw in raw_values or []:
        try:
            obj = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError as exc:
            raise ApprovalError(f"ApproverDecisions is not JSON: {str(raw)[:200]!r}") from exc
        for item in obj if isinstance(obj, list) else [obj]:
            if isinstance(item, str):
                decisions.extend(parse_decisions([item]))
                continue
            found = _from_mapping(item) if isinstance(item, dict) else []
            if not found:
                raise ApprovalError(f"Unrecognised ApproverDecisions entry: {json.dumps(item, default=str)[:200]}")
            decisions.extend(found)
    return decisions


# ------------------------------------------------------------------------- verification
def _step(execution: dict, name: str) -> dict:
    for step in execution.get("StepExecutions", []):
        if step.get("StepName") == name:
            return step
    raise ApprovalError(f"Approval step {name} not found in execution")


def _key(arn: str, account: str) -> tuple[str, str, str]:
    try:
        return principal_key(arn, account)
    except ValueError as exc:
        raise ApprovalError(str(exc)) from exc


def _caller(arn: str) -> Principal:
    try:
        return parse_caller(arn)
    except ValueError as exc:
        raise ApprovalError(str(exc)) from exc


def _match_signal(decision: Decision, key: tuple[str, str, str], step: dict, signals: list[Signal],
                  used: set[int], account: str) -> Optional[int]:
    """Index of the CloudTrail Approve event that produced this decision."""
    start = as_datetime(step.get("ExecutionStartTime"))
    end = as_datetime(step.get("ExecutionEndTime"))
    best: Optional[tuple[timedelta, int]] = None
    for i, sig in enumerate(signals):
        if i in used or sig.signal_type.strip().lower() != "approve" or _key(sig.caller, account) != key:
            continue
        sig_time = as_datetime(sig.time)
        if decision.time is not None:
            distance = abs(sig_time - decision.time)
            if distance > MATCH_WINDOW:
                continue
        else:
            if (start and sig_time < start - MATCH_WINDOW) or (end and sig_time > end + MATCH_WINDOW):
                continue
            distance = abs(sig_time - (end or sig_time))
        if best is None or distance < best[0]:
            best = (distance, i)
    return best[1] if best else None


def verify_approvals(execution: dict, policies: list[LevelPolicy], account: str,
                     signals: list[Signal]) -> ApprovalResult:
    requester = _caller(execution.get("ExecutedBy", ""))
    result = ApprovalResult(requester=requester.arn)
    counted: set[str] = set()
    used: set[int] = set()

    for policy in policies:
        step = _step(execution, policy.step_name)
        if step.get("StepStatus") != "Success":
            raise ApprovalError(f"{policy.step_name} status is {step.get('StepStatus')}, expected Success")
        outputs = step.get("Outputs") or {}
        status = [s.strip().lower() for s in outputs.get("ApprovalStatus", [])]
        if status and status != ["approved"]:
            raise ApprovalError(f"{policy.step_name} ApprovalStatus is {status}")

        decisions = parse_decisions(outputs.get("ApproverDecisions", []))
        if not decisions:
            raise ApprovalError(f"{policy.step_name} has no recorded approver decisions")

        allowed = {_key(a, account) for a in policy.approvers}
        people: list[Principal] = []
        for decision in decisions:
            if decision.decision in _REJECTED:
                raise ApprovalError(f"{policy.step_name}: {decision.principal} rejected the request")
            if decision.decision not in _APPROVED:
                raise ApprovalError(f"{policy.step_name}: unknown decision {decision.decision!r} from {decision.principal}")
            key = _key(decision.principal, account)
            if key not in allowed:
                raise ApprovalError(f"{policy.step_name}: {decision.principal} is not an authorised approver for this level")

            index = _match_signal(decision, key, step, signals, used, account)
            if index is None:
                raise ApprovalPending(
                    f"{policy.step_name}: no CloudTrail SendAutomationSignal event yet for the approval by {decision.principal}"
                )
            used.add(index)
            person = _caller(signals[index].caller)
            if person.human == requester.human:
                raise ApprovalError(f"{policy.step_name}: the requester cannot approve their own request ({person.arn})")
            if person.human in counted:
                continue  # already counted at a previous level
            counted.add(person.human)
            people.append(person)

        if len(people) < policy.min_approvals:
            raise ApprovalError(
                f"{policy.step_name}: {len(people)} distinct new approver(s), {policy.min_approvals} required"
            )
        result.levels[policy.step_name] = [p.arn for p in people]

    return result
