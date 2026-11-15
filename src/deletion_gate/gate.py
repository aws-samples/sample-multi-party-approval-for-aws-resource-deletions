"""Gate actions invoked by the DeletionGuard runbooks.

Every action starts from the execution ID only and reloads the execution from the
SSM API. Request parameters, requester identity and approvals are read from that
authoritative record, never from the Lambda payload. The person behind each approval
is read from CloudTrail (see approvals.py and signals.py).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .approvals import ApprovalResult, LevelPolicy, verify_approvals
from .deleters import Deleter
from .errors import ApprovalError, ApprovalPending, GateError
from .execution import Execution, assert_at_step, load_execution
from .ledger import Ledger
from .signals import Signal
from .terraform import TerraformRunner

log = logging.getLogger(__name__)

# Contract with infrastructure/cdk/lib/runbooks.ts
STEP_VALIDATE = "ValidateRequest"
STEP_APPROVE_1 = "ApproveLevel1"
STEP_APPROVE_2 = "ApproveLevel2"
STEP_EXECUTE = "ExecuteDeletion"
STEP_PLAN = "PlanChange"
STEP_APPLY = "ApplyChange"


@dataclass(frozen=True)
class GateConfig:
    account: str
    resource_runbook: str
    terraform_runbook: str
    approvers_l1: tuple[str, ...]
    approvers_l2: tuple[str, ...]
    min_l1: int
    min_l2: int
    allowed_regions: frozenset[str]
    allowed_types: frozenset[str]
    plans_bucket: str
    topic_arn: str
    # How long to wait for approval signals to become visible in CloudTrail.
    signal_wait_seconds: int = 600
    signal_poll_seconds: int = 20

    def policies(self) -> list[LevelPolicy]:
        return [
            LevelPolicy(STEP_APPROVE_1, self.approvers_l1, self.min_l1),
            LevelPolicy(STEP_APPROVE_2, self.approvers_l2, self.min_l2),
        ]


class Gate:
    def __init__(self, cfg: GateConfig, ssm, ledger: Ledger, deleter: Deleter, terraform: TerraformRunner,
                 notify: Callable[[str, dict], None], signals: Callable[[str, datetime], list[Signal]],
                 identity_check: Callable[[str], list[str]],
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        self.cfg = cfg
        self.ssm = ssm
        self.ledger = ledger
        self.deleter = deleter
        self.tf = terraform
        self.notify = notify
        self.signals = signals
        self.identity_check = identity_check
        self.clock = clock
        self.sleep = sleep

    # ------------------------------------------------------------------ entry point
    def handle(self, event: dict, remaining_ms: int) -> dict:
        action = event.get("action")
        handlers = {
            "validate": (self.cfg.resource_runbook, STEP_VALIDATE, self._validate),
            "execute": (self.cfg.resource_runbook, STEP_EXECUTE, self._execute),
            "tf-plan": (self.cfg.terraform_runbook, STEP_PLAN, self._tf_plan),
            "tf-apply": (self.cfg.terraform_runbook, STEP_APPLY, self._tf_apply),
        }
        if action not in handlers:
            raise GateError(f"Unknown action {action!r}")
        document, step, fn = handlers[action]
        execution = load_execution(self.ssm, event.get("executionId"))
        try:
            assert_at_step(execution, document, step)
        except GateError as exc:
            # Wrong runbook, wrong step, replay or Interactive mode: a bypass attempt or a
            # premature call. Refuse without stopping the execution (it may be a legitimate
            # request still waiting for approval), and make the attempt visible.
            log.warning("Refusing %s for %s: %s", action, execution.id, exc)
            self.notify("Invocation Refused", {"executionId": execution.id, "action": action, "reason": str(exc),
                                               "requester": execution.requester, "document": execution.document})
            raise

        deadline = self.clock() + max(remaining_ms / 1000 - 60, 30)
        try:
            result = fn(execution, deadline)
        except GateError as exc:
            self._reject(execution, action, str(exc))
            raise
        except Exception as exc:
            # Fail closed on anything unexpected, and say so explicitly.
            log.exception("Unexpected error in %s for %s", action, execution.id)
            self._reject(execution, action, f"Internal error ({exc.__class__.__name__}): {exc}")
            raise
        return result

    def _reject(self, execution: Execution, action: str, reason: str) -> None:
        log.warning("Rejecting %s for %s: %s", action, execution.id, reason)
        self.notify("Request Rejected", {"executionId": execution.id, "action": action, "reason": reason,
                                         "requester": execution.requester, "document": execution.document})
        try:
            # Stop the execution so it cannot linger in a waiting state.
            self.ssm.stop_automation_execution(AutomationExecutionId=execution.id, Type="Cancel")
        except Exception:  # noqa: BLE001 - best effort, the step fails anyway
            log.exception("Could not stop execution %s", execution.id)

    # ------------------------------------------------------------------ approvals
    def _verified_approvals(self, execution: Execution, deadline: float) -> ApprovalResult:
        """Verify the approvals, waiting for their CloudTrail events if needed."""
        give_up = min(self.clock() + self.cfg.signal_wait_seconds, deadline - 120)
        while True:
            signals = self.signals(execution.id, execution.start_time)
            try:
                result = verify_approvals(execution.raw, self.cfg.policies(), self.cfg.account, signals)
                self._require_people([result.requester], "requester")
                self._require_people(result.approvers, "approver")
                return result
            except ApprovalPending as exc:
                if self.clock() >= give_up:
                    raise ApprovalError(f"{exc} (waited {self.cfg.signal_wait_seconds}s for CloudTrail)") from exc
                log.info("Waiting for CloudTrail: %s", exc)
                self.sleep(self.cfg.signal_poll_seconds)

    def _require_people(self, arns: list[str], role: str) -> None:
        """Reject callers whose session name does not reliably identify a person (see trust.py)."""
        for arn in arns:
            problems = self.identity_check(arn)
            if problems:
                raise ApprovalError(f"The {role} {arn} is not a verifiable person: {problems[0]}")

    # ------------------------------------------------------------------ resource deletion
    def _resource_params(self, execution: Execution) -> tuple[str, str, str]:
        rtype = execution.param("ResourceType")
        ident = execution.param("ResourceIdentifier")
        region = execution.param("TargetRegion")
        if rtype not in self.cfg.allowed_types:
            raise GateError(f"Resource type {rtype} is not supported by DeletionGuard")
        if region not in self.cfg.allowed_regions:
            raise GateError(f"Region {region} is not an allowed target region")
        return rtype, ident, region

    def _validate(self, execution: Execution, _deadline: float) -> dict:
        self._require_people([execution.requester], "requester")
        rtype, ident, region = self._resource_params(execution)
        summary = self.deleter.describe(rtype, ident, region)
        self.ledger.create(execution.id, "VALIDATED", {
            "kind": "resource", "requester": execution.requester, "resourceType": rtype,
            "resourceIdentifier": ident, "region": region, "justification": execution.param("Justification"),
        })
        self.notify("Request Validated", {"executionId": execution.id, "resourceType": rtype,
                                          "resourceIdentifier": ident, "region": region,
                                          "requester": execution.requester})
        return {"resource": f"{rtype} {ident} ({region})", "current": summary}

    def _execute(self, execution: Execution, deadline: float) -> dict:
        rtype, ident, region = self._resource_params(execution)
        record = self.ledger.get(execution.id)
        if (record.get("resourceType"), record.get("resourceIdentifier"), record.get("region")) != (rtype, ident, region):
            raise GateError("Execution parameters do not match the validated request")

        approval = self._verified_approvals(execution, deadline)
        self.ledger.transition(execution.id, "VALIDATED", "EXECUTING", {"approvers": approval.approvers})

        protection = "unchanged"
        if execution.param("DisableDeletionProtection", "false").lower() == "true":
            protection = self.deleter.disable_protection(rtype, ident, region)
        try:
            outcome = self.deleter.delete(rtype, ident, region, deadline)
        except Exception as exc:
            self.ledger.transition(execution.id, "EXECUTING", "FAILED", {"error": str(exc)[:500]})
            raise
        final = "COMPLETED" if outcome["status"] == "SUCCESS" else "IN_PROGRESS"
        self.ledger.transition(execution.id, "EXECUTING", final, {"outcome": outcome})

        detail = {"executionId": execution.id, "resourceType": rtype, "resourceIdentifier": ident, "region": region,
                  "requester": execution.requester, "approvers": approval.levels, "deletionProtection": protection,
                  "outcome": outcome}
        self.notify("Deletion Executed", detail)
        return {"status": final, "deletionProtection": protection, "outcome": outcome, "approvers": approval.levels}

    # ------------------------------------------------------------------ Terraform
    def _tf_params(self, execution: Execution) -> dict[str, str]:
        workdir = execution.param("WorkingDirectory", ".")
        if ".." in workdir or workdir.startswith("/"):
            raise GateError("WorkingDirectory must be a relative path inside the source archive")
        operation = execution.param("Operation")
        if operation not in ("destroy", "apply"):
            raise GateError("Operation must be destroy or apply")
        return {"bucket": execution.param("SourceBucket"), "key": execution.param("SourceKey"),
                "workdir": workdir, "operation": operation}

    def _tf_env(self, execution_id: str, p: dict[str, str], source: dict[str, str]) -> dict[str, str]:
        return {
            "EXECUTION_ID": execution_id, "PLANS_BUCKET": self.cfg.plans_bucket,
            "SOURCE_BUCKET": p["bucket"], "SOURCE_KEY": p["key"], "SOURCE_VERSION_ID": source["versionId"],
            "SOURCE_ETAG": source["etag"], "WORKING_DIRECTORY": p["workdir"], "TF_OPERATION": p["operation"],
        }

    def _tf_plan(self, execution: Execution, deadline: float) -> dict:
        self._require_people([execution.requester], "requester")
        p = self._tf_params(execution)
        source = self.tf.source_version(p["bucket"], p["key"])
        build = self.tf.run("plan", self._tf_env(execution.id, p, source), deadline)
        exported = build["exported"]
        sha = exported.get("PLAN_SHA256", "")
        if not sha or self.tf.plan_sha256(execution.id) != sha:
            raise GateError("Uploaded plan file does not match the plan produced by the build")
        counts = {k: int(exported.get(f"PLAN_{k.upper()}", "0") or 0) for k in ("create", "update", "delete")}
        self.ledger.create(execution.id, "PLANNED", {
            "kind": "terraform", "requester": execution.requester, "source": p, "sourceVersion": source,
            "planSha256": sha, "planBuildId": build["buildId"], "counts": counts,
            "justification": execution.param("Justification"),
        })
        self.notify("Plan Ready", {"executionId": execution.id, "requester": execution.requester,
                                   "counts": counts, "planSha256": sha})
        return {"operation": p["operation"], "counts": counts, "planSha256": sha,
                "plan": f"s3://{self.cfg.plans_bucket}/plans/{execution.id}/plan.txt"}

    def _tf_apply(self, execution: Execution, deadline: float) -> dict:
        p = self._tf_params(execution)
        record = self.ledger.get(execution.id)
        if record.get("source") != p:
            raise GateError("Execution parameters do not match the planned request")
        approval = self._verified_approvals(execution, deadline)
        sha = record["planSha256"]
        if self.tf.plan_sha256(execution.id) != sha:
            raise GateError("Plan file changed after approval")
        self.ledger.transition(execution.id, "PLANNED", "APPLYING", {"approvers": approval.approvers})

        env = {**self._tf_env(execution.id, p, record["sourceVersion"]), "PLAN_SHA256": sha}
        try:
            build = self.tf.run("apply", env, deadline)
        except Exception as exc:
            self.ledger.transition(execution.id, "APPLYING", "FAILED", {"error": str(exc)[:500]})
            raise
        final = "COMPLETED" if build["status"] == "SUCCEEDED" else "IN_PROGRESS"
        self.ledger.transition(execution.id, "APPLYING", final, {"applyBuildId": build["buildId"]})
        self.notify("Terraform Change Applied", {"executionId": execution.id, "requester": execution.requester,
                                                 "approvers": approval.levels, "buildId": build["buildId"],
                                                 "status": final, "counts": record.get("counts")})
        return {"status": final, "buildId": build["buildId"], "approvers": approval.levels}
