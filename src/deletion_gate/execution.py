"""Authoritative view of an SSM Automation execution, as read by the gate."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from .approvals import as_datetime
from .errors import GateError

_EXECUTION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass
class Execution:
    raw: dict

    @property
    def id(self) -> str:
        return self.raw["AutomationExecutionId"]

    @property
    def document(self) -> str:
        return self.raw.get("DocumentName", "")

    @property
    def requester(self) -> str:
        return self.raw.get("ExecutedBy", "")

    @property
    def start_time(self) -> datetime:
        start = as_datetime(self.raw.get("ExecutionStartTime"))
        if start is None:
            raise GateError(f"Execution {self.id} has no start time")
        return start

    @property
    def current_step(self) -> str | None:
        running = [s["StepName"] for s in self.raw.get("StepExecutions", []) if s.get("StepStatus") == "InProgress"]
        return running[0] if len(running) == 1 else None

    def param(self, name: str, default: str | None = None) -> str:
        values = (self.raw.get("Parameters") or {}).get(name)
        if not values:
            if default is not None:
                return default
            raise GateError(f"Missing runbook parameter {name}")
        return str(values[0])


def load_execution(ssm, execution_id: str) -> Execution:
    if not isinstance(execution_id, str) or not _EXECUTION_ID.match(execution_id):
        raise GateError("Invalid or missing executionId")
    return Execution(ssm.get_automation_execution(AutomationExecutionId=execution_id)["AutomationExecution"])


def assert_at_step(execution: Execution, document: str, step: str) -> None:
    """Accept the call only from the expected runbook, while it is running the expected step.

    This blocks replaying old executions, calls from look-alike documents with weaker
    approval steps, and calls that try to skip ahead of the approval steps.
    """
    if execution.document != document:
        raise GateError(f"Execution {execution.id} runs {execution.document!r}, expected {document!r}")
    if execution.raw.get("AutomationExecutionStatus") != "InProgress":
        raise GateError(f"Execution {execution.id} is {execution.raw.get('AutomationExecutionStatus')}, expected InProgress")
    if execution.raw.get("Mode", "Auto") != "Auto":
        raise GateError("Only Auto mode executions are accepted (Interactive mode can run steps out of order)")
    if execution.raw.get("Targets") or execution.raw.get("TargetParameterName"):
        raise GateError("Rate-controlled / multi-target executions are not accepted")
    if execution.current_step != step:
        raise GateError(f"Execution {execution.id} is at step {execution.current_step!r}, expected {step!r}")
