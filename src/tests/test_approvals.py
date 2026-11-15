import json
from datetime import timedelta

import pytest

from conftest import (ACCOUNT, ALICE_L1, BOB_L2, CAROL_L2, L1_ROLE, L2_ROLE, LEAD_ROLE, REQUESTER, SECURITY_ROLE,
                      SSO, make_execution)
from deletion_gate.approvals import LevelPolicy, as_datetime, parse_decisions, verify_approvals
from deletion_gate.errors import ApprovalError, ApprovalPending
from deletion_gate.identity import parse_caller, principal_key
from deletion_gate.signals import Signal

POLICIES = [LevelPolicy("ApproveLevel1", (L1_ROLE,), 1), LevelPolicy("ApproveLevel2", (L2_ROLE,), 1)]
ALICE_ON_L2_ROLE = f"{SSO}/{SECURITY_ROLE}/alice"
DAVE_ON_L1_ROLE = f"{SSO}/{LEAD_ROLE}/dave"  # the requester also holds the team-lead permission set

# Exact ApproverDecisions value observed on a live account (aws:approve, IAM Identity Center approver).
OBSERVED = ('{"Approver":"arn:aws:iam::' + ACCOUNT + ':role/aws-reserved/sso.amazonaws.com/eu-west-1/'
            + LEAD_ROLE + '","Decision":"Approve","ApprovalDecisionTime":"2026-11-13T21:29:42.454913102Z",'
            '"Comment":"phase2 level1 OK"}')


def test_parse_observed_decision_format():
    [d] = parse_decisions([OBSERVED])
    assert d.principal == L1_ROLE and d.decision == "approve"
    assert d.time == as_datetime("2026-11-13T21:29:42.454913Z")


def test_parse_alternative_shape_and_fail_closed():
    [d] = parse_decisions([json.dumps({L1_ROLE: {"Decision": "Approved"}})])
    assert d.principal == L1_ROLE and d.decision == "approved"
    with pytest.raises(ApprovalError):
        parse_decisions([json.dumps({"something": "else"})])
    with pytest.raises(ApprovalError):
        parse_decisions(["not json"])


def test_role_and_session_share_the_principal_key():
    assert principal_key(L1_ROLE, ACCOUNT) == principal_key(ALICE_L1, ACCOUNT) == ("role", ACCOUNT, LEAD_ROLE)
    assert principal_key(L1_ROLE, ACCOUNT) != principal_key(BOB_L2, ACCOUNT)
    assert parse_caller(ALICE_L1).human == parse_caller(ALICE_ON_L2_ROLE).human == "person:alice"


def test_two_distinct_people_pass_and_are_identified_from_cloudtrail():
    ex, signals = make_execution(l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")])
    result = verify_approvals(ex, POLICIES, ACCOUNT, signals)
    assert result.levels == {"ApproveLevel1": [ALICE_L1], "ApproveLevel2": [BOB_L2]}
    assert result.requester == REQUESTER


def test_requester_cannot_approve_with_another_permission_set():
    # SSM only records the team-lead role: the requester is detected through CloudTrail.
    ex, signals = make_execution(l1=[(DAVE_ON_L1_ROLE, "Approve")], l2=[(BOB_L2, "Approve")])
    with pytest.raises(ApprovalError, match="requester"):
        verify_approvals(ex, POLICIES, ACCOUNT, signals)


def test_same_person_cannot_satisfy_both_levels():
    ex, signals = make_execution(l1=[(ALICE_L1, "Approve")], l2=[(ALICE_ON_L2_ROLE, "Approve")])
    with pytest.raises(ApprovalError, match="distinct new approver"):
        verify_approvals(ex, POLICIES, ACCOUNT, signals)


def test_missing_cloudtrail_event_is_pending():
    ex, _ = make_execution(l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")], with_signals=False)
    with pytest.raises(ApprovalPending):
        verify_approvals(ex, POLICIES, ACCOUNT, [])


def test_cloudtrail_event_must_match_principal_and_time():
    ex, signals = make_execution(l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")])
    # Same time, different principal: does not prove the level 1 decision.
    wrong_role = [Signal(signals[0].time, BOB_L2.replace("/bob", "/eve"), "Approve"), signals[1]]
    with pytest.raises(ApprovalPending):
        verify_approvals(ex, POLICIES, ACCOUNT, wrong_role)
    # Right principal, ten minutes away from the decision: not the same approval.
    late = [Signal(signals[0].time + timedelta(minutes=10), ALICE_L1, "Approve"), signals[1]]
    with pytest.raises(ApprovalPending):
        verify_approvals(ex, POLICIES, ACCOUNT, late)


def test_approver_from_wrong_level_is_rejected():
    ex, signals = make_execution(l1=[(BOB_L2, "Approve")], l2=[(CAROL_L2, "Approve")])
    with pytest.raises(ApprovalError, match="not an authorised approver"):
        verify_approvals(ex, POLICIES, ACCOUNT, signals)


def test_any_rejection_blocks():
    ex, signals = make_execution(l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve"), (CAROL_L2, "Reject")])
    with pytest.raises(ApprovalError, match="rejected"):
        verify_approvals(ex, POLICIES, ACCOUNT, signals)


def test_quorum_counts_people_not_roles():
    policies = [LevelPolicy("ApproveLevel1", (L1_ROLE,), 1), LevelPolicy("ApproveLevel2", (L2_ROLE,), 2)]
    ex, signals = make_execution(l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")])
    with pytest.raises(ApprovalError, match="2 required"):
        verify_approvals(ex, policies, ACCOUNT, signals)


def test_approval_step_not_completed():
    ex, signals = make_execution(l1=[(ALICE_L1, "Approve")], l2=[(BOB_L2, "Approve")])
    ex["StepExecutions"][2]["StepStatus"] = "Skipped"
    with pytest.raises(ApprovalError, match="expected Success"):
        verify_approvals(ex, POLICIES, ACCOUNT, signals)


def test_adfs_sessions_identify_people_case_insensitively():
    # AD FS federated directly with IAM: roles without the Identity Center path, the
    # RoleSessionName SAML attribute set to the user's e-mail address.
    adfs_l1 = f"arn:aws:iam::{ACCOUNT}:role/ADFS-DeletionApproverTeamLead"
    adfs_l2 = f"arn:aws:iam::{ACCOUNT}:role/ADFS-DeletionApproverSecurity"
    policies = [LevelPolicy("ApproveLevel1", (adfs_l1,), 1), LevelPolicy("ApproveLevel2", (adfs_l2,), 1)]
    requester = f"{SSO}/ADFS-Requester/Dave@Corp.example"
    lead = f"{SSO}/ADFS-DeletionApproverTeamLead/alice@corp.example"
    sec = f"{SSO}/ADFS-DeletionApproverSecurity/bob@corp.example"
    ex, signals = make_execution(l1=[(lead, "Approve")], l2=[(sec, "Approve")], executed_by=requester)
    for step in ex["StepExecutions"]:  # SSM records ADFS roles without path
        for i, raw in enumerate((step.get("Outputs") or {}).get("ApproverDecisions", [])):
            step["Outputs"]["ApproverDecisions"][i] = raw.replace("role/aws-reserved/sso.amazonaws.com/eu-west-1/", "role/")
    assert verify_approvals(ex, policies, ACCOUNT, signals).approvers == [lead, sec]
    # The requester approving with the team-lead role, under a differently-cased e-mail.
    self_l1 = f"{SSO}/ADFS-DeletionApproverTeamLead/DAVE@corp.example"
    ex, signals = make_execution(l1=[(self_l1, "Approve")], l2=[(sec, "Approve")], executed_by=requester)
    for step in ex["StepExecutions"]:
        for i, raw in enumerate((step.get("Outputs") or {}).get("ApproverDecisions", [])):
            step["Outputs"]["ApproverDecisions"][i] = raw.replace("role/aws-reserved/sso.amazonaws.com/eu-west-1/", "role/")
    with pytest.raises(ApprovalError, match="requester"):
        verify_approvals(ex, policies, ACCOUNT, signals)