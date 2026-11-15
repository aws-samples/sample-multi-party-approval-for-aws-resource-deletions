import copy

import pytest

from conftest import ACCOUNT, ALICE_L1, BOB_L2, EXEC_ID, L1_ROLE, L2_ROLE, LEAD_ROLE, SSO, T0, make_execution
from deletion_gate.errors import GateError
from deletion_gate.gate import Gate, GateConfig


class FakeSsm:
    def __init__(self, execution):
        self.execution = execution
        self.stopped = []

    def get_automation_execution(self, AutomationExecutionId):
        assert AutomationExecutionId == EXEC_ID
        return {"AutomationExecution": copy.deepcopy(self.execution)}

    def stop_automation_execution(self, AutomationExecutionId, Type):
        self.stopped.append(AutomationExecutionId)


class FakeLedger:
    def __init__(self):
        self.items = {}

    def create(self, eid, status, item):
        if eid in self.items:
            raise GateError("already recorded")
        self.items[eid] = {"status": status, **copy.deepcopy(item)}

    def get(self, eid):
        if eid not in self.items:
            raise GateError("no ledger record")
        return copy.deepcopy(self.items[eid])

    def transition(self, eid, expected, new, item=None):
        if self.items.get(eid, {}).get("status") != expected:
            raise GateError(f"not in state {expected}")
        self.items[eid].update({"status": new, **(item or {})})


class FakeDeleter:
    def __init__(self):
        self.deleted = []
        self.protection_disabled = []

    def describe(self, rtype, ident, region):
        if ident == "missing":
            raise GateError("not found")
        return '{"TableName":"orders"}'

    def disable_protection(self, rtype, ident, region):
        self.protection_disabled.append(ident)
        return "disabled"

    def delete(self, rtype, ident, region, deadline):
        self.deleted.append((rtype, ident, region))
        return {"status": "SUCCESS", "requestToken": "t-1"}


class FakeTerraform:
    def __init__(self, sha="abc123"):
        self.sha = sha
        self.runs = []

    def source_version(self, bucket, key):
        return {"versionId": "v1", "etag": '"e1"'}

    def plan_sha256(self, eid):
        return self.sha

    def run(self, kind, env, deadline):
        self.runs.append((kind, env))
        exported = {"PLAN_SHA256": "abc123", "PLAN_DELETE": "3", "PLAN_CREATE": "0", "PLAN_UPDATE": "0"}
        return {"buildId": f"{kind}:1", "status": "SUCCEEDED", "exported": exported if kind == "plan" else {}}


CFG = GateConfig(
    account=ACCOUNT, resource_runbook="DeletionGuard-DeleteResource", terraform_runbook="DeletionGuard-TerraformChange",
    approvers_l1=(L1_ROLE,), approvers_l2=(L2_ROLE,), min_l1=1, min_l2=1,
    allowed_regions=frozenset({"eu-west-1"}), allowed_types=frozenset({"AWS::DynamoDB::Table"}),
    plans_bucket=f"deletion-guard-plans-{ACCOUNT}-eu-west-1", topic_arn=f"arn:aws:sns:eu-west-1:{ACCOUNT}:t",
)


class FakeClock:
    """Time only moves when the gate sleeps (waiting for CloudTrail)."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = 0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps += 1
        self.now += seconds


def build(scenario, ledger=None, tf=None, signals_after_polls=0, unverifiable=()):
    """scenario: (execution, signals) from make_execution. Signals appear after N polls."""
    execution, signals = scenario
    notes, clock, polls = [], FakeClock(), []
    ssm, deleter = FakeSsm(execution), FakeDeleter()

    def lookup(execution_id, since):
        assert execution_id == EXEC_ID
        polls.append(since)
        return signals if len(polls) > signals_after_polls else []

    gate = Gate(CFG, ssm, ledger or FakeLedger(), deleter, tf or FakeTerraform(),
                notify=lambda kind, detail: notes.append(kind), signals=lookup,
                identity_check=lambda arn: ["session name chosen by the caller"] if arn in unverifiable else [],
                clock=clock.time, sleep=clock.sleep)
    gate.fake_clock, gate.polls = clock, polls
    return gate, ssm, deleter, notes


def approved_execution(**kw):
    return make_execution(l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")], **kw)


def test_full_resource_deletion_flow():
    ledger = FakeLedger()
    gate, _, _, notes = build(make_execution(current="ValidateRequest"), ledger)
    out = gate.handle({"action": "validate", "executionId": EXEC_ID}, 900_000)
    assert "orders" in out["resource"]
    assert ledger.items[EXEC_ID]["status"] == "VALIDATED"

    gate, ssm, deleter, notes = build(approved_execution(), ledger)
    out = gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert out["status"] == "COMPLETED"
    assert deleter.deleted == [("AWS::DynamoDB::Table", "orders", "eu-west-1")]
    assert ledger.items[EXEC_ID]["status"] == "COMPLETED"
    assert ledger.items[EXEC_ID]["approvers"] == [ALICE_L1, BOB_L2]
    assert "Deletion Executed" in notes
    assert ssm.stopped == []


def test_execute_is_single_use():
    ledger = FakeLedger()
    ledger.items[EXEC_ID] = {"status": "COMPLETED", "resourceType": "AWS::DynamoDB::Table",
                             "resourceIdentifier": "orders", "region": "eu-west-1"}
    gate, ssm, deleter, _ = build(approved_execution(), ledger)
    with pytest.raises(GateError, match="not in state"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == []


def test_execute_without_validation_record_is_rejected():
    gate, ssm, deleter, _ = build(approved_execution())
    with pytest.raises(GateError, match="no ledger record"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == [] and ssm.stopped == [EXEC_ID]


def test_premature_execute_call_is_rejected_without_stopping_the_request():
    # Someone invokes "execute" while the request still waits for level 1.
    gate, ssm, deleter, notes = build(make_execution(current="ApproveLevel1"))
    with pytest.raises(GateError, match="expected 'ExecuteDeletion'"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == [] and ssm.stopped == []
    assert "Invocation Refused" in notes


def test_lookalike_document_is_rejected():
    gate, _, deleter, _ = build(approved_execution(document="Attacker-DeleteResource"))
    with pytest.raises(GateError, match="expected 'DeletionGuard-DeleteResource'"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == []


def test_interactive_mode_is_rejected():
    gate, _, deleter, _ = build(approved_execution(mode="Interactive"))
    with pytest.raises(GateError, match="Auto mode"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)


def test_self_approval_is_rejected_and_request_stopped():
    ledger = FakeLedger()
    ledger.items[EXEC_ID] = {"status": "VALIDATED", "resourceType": "AWS::DynamoDB::Table",
                             "resourceIdentifier": "orders", "region": "eu-west-1"}
    dave_l1 = f"{SSO}/{LEAD_ROLE}/dave"  # requester using the team-lead permission set
    ex = make_execution(l1=[(dave_l1, "Approve")], l2=[(BOB_L2, "Approve")])
    gate, ssm, deleter, notes = build(ex, ledger)
    with pytest.raises(GateError, match="requester"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == []
    assert ssm.stopped == [EXEC_ID]
    assert ledger.items[EXEC_ID]["status"] == "VALIDATED"
    assert "Request Rejected" in notes


def test_disallowed_region_and_type():
    params = {"ResourceType": ["AWS::DynamoDB::Table"], "ResourceIdentifier": ["orders"],
              "TargetRegion": ["ap-south-1"], "Justification": ["x" * 30]}
    gate, *_ = build(make_execution(current="ValidateRequest", params=params))
    with pytest.raises(GateError, match="allowed target region"):
        gate.handle({"action": "validate", "executionId": EXEC_ID}, 900_000)


def test_invalid_execution_id():
    gate, *_ = build(make_execution())
    with pytest.raises(GateError, match="Invalid"):
        gate.handle({"action": "execute", "executionId": "../../etc"}, 900_000)


TF_PARAMS = {"SourceBucket": ["tf-src"], "SourceKey": ["stacks/app.zip"], "WorkingDirectory": ["."],
             "Operation": ["destroy"], "Justification": ["Decommissioning the sample application stack"]}


def test_terraform_plan_then_apply():
    ledger, tf = FakeLedger(), FakeTerraform()
    ex = make_execution(document="DeletionGuard-TerraformChange", current="PlanChange", params=TF_PARAMS)
    gate, *_ = build(ex, ledger, tf)
    out = gate.handle({"action": "tf-plan", "executionId": EXEC_ID}, 900_000)
    assert out["counts"]["delete"] == 3
    assert ledger.items[EXEC_ID]["status"] == "PLANNED"

    ex = make_execution(document="DeletionGuard-TerraformChange", current="ApplyChange", params=TF_PARAMS,
                        l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")])
    gate, *_ = build(ex, ledger, tf)
    out = gate.handle({"action": "tf-apply", "executionId": EXEC_ID}, 900_000)
    assert out["status"] == "COMPLETED"
    kind, env = tf.runs[-1]
    assert kind == "apply" and env["PLAN_SHA256"] == "abc123" and env["SOURCE_VERSION_ID"] == "v1"


def test_terraform_apply_refuses_modified_plan():
    ledger = FakeLedger()
    ledger.items[EXEC_ID] = {"status": "PLANNED", "planSha256": "abc123",
                             "source": {"bucket": "tf-src", "key": "stacks/app.zip", "workdir": ".", "operation": "destroy"},
                             "sourceVersion": {"versionId": "v1", "etag": '"e1"'}}
    tf = FakeTerraform(sha="tampered")
    ex = make_execution(document="DeletionGuard-TerraformChange", current="ApplyChange", params=TF_PARAMS,
                        l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")])
    gate, ssm, *_ = build(ex, ledger, tf)
    with pytest.raises(GateError, match="Plan file changed"):
        gate.handle({"action": "tf-apply", "executionId": EXEC_ID}, 900_000)
    assert tf.runs == [] and ssm.stopped == [EXEC_ID]


def test_terraform_rejects_path_traversal():
    params = {**TF_PARAMS, "WorkingDirectory": ["../../"]}
    ex = make_execution(document="DeletionGuard-TerraformChange", current="PlanChange", params=params)
    gate, *_ = build(ex)
    with pytest.raises(GateError, match="relative path"):
        gate.handle({"action": "tf-plan", "executionId": EXEC_ID}, 900_000)


def _validated_ledger():
    ledger = FakeLedger()
    ledger.items[EXEC_ID] = {"status": "VALIDATED", "resourceType": "AWS::DynamoDB::Table",
                             "resourceIdentifier": "orders", "region": "eu-west-1"}
    return ledger


def test_waits_for_cloudtrail_then_deletes():
    ledger = _validated_ledger()
    gate, ssm, deleter, _ = build(approved_execution(), ledger, signals_after_polls=2)
    out = gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert out["status"] == "COMPLETED" and deleter.deleted
    assert gate.fake_clock.sleeps == 2 and gate.polls[0] == T0
    assert ledger.items[EXEC_ID]["approvers"] == [ALICE_L1, BOB_L2]


def test_rejects_when_approvals_never_appear_in_cloudtrail():
    ledger = _validated_ledger()
    gate, ssm, deleter, notes = build(approved_execution(), ledger, signals_after_polls=10_000)
    with pytest.raises(GateError, match="waited 600s for CloudTrail"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == [] and ssm.stopped == [EXEC_ID] and "Request Rejected" in notes
    assert ledger.items[EXEC_ID]["status"] == "VALIDATED"


def test_unexpected_error_is_an_explicit_rejection():
    ledger = _validated_ledger()
    gate, ssm, deleter, notes = build(approved_execution(), ledger)

    def boom(*_args):
        raise RuntimeError("CloudTrail throttled")

    gate.signals = boom
    with pytest.raises(RuntimeError):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == [] and ssm.stopped == [EXEC_ID] and "Request Rejected" in notes

def test_requester_with_unverifiable_identity_is_rejected_at_validation():
    from conftest import REQUESTER
    ledger = FakeLedger()
    gate, ssm, _, notes = build(make_execution(current="ValidateRequest"), ledger, unverifiable={REQUESTER})
    with pytest.raises(GateError, match="requester .* is not a verifiable person"):
        gate.handle({"action": "validate", "executionId": EXEC_ID}, 900_000)
    assert ledger.items == {} and ssm.stopped == [EXEC_ID] and "Request Rejected" in notes


def test_approver_with_unverifiable_identity_is_rejected_before_deleting():
    ledger = _validated_ledger()
    gate, ssm, deleter, _ = build(approved_execution(), ledger, unverifiable={BOB_L2})
    with pytest.raises(GateError, match="approver .* is not a verifiable person"):
        gate.handle({"action": "execute", "executionId": EXEC_ID}, 900_000)
    assert deleter.deleted == [] and ssm.stopped == [EXEC_ID]