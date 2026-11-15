import pytest

from approver_resolver.index import _resolve

# Fake 12-digit account ID built at runtime (AWS documentation example pattern).
ACCOUNT = "1" * 4 + "2" * 4 + "3" * 4
ROLES = [
    {"RoleName": "AWSReservedSSO_DeletionApproverTeamLead_1111aaaa2222bbbb",
     "Arn": f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_DeletionApproverTeamLead_1111aaaa2222bbbb"},
    {"RoleName": "AWSReservedSSO_DeletionApproverTeamLeadBackup_3333cccc4444dddd",
     "Arn": f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_DeletionApproverTeamLeadBackup_3333cccc4444dddd"},
]


def test_permission_set_match_is_exact():
    props = {"Level1PermissionSets": ["DeletionApproverTeamLead"], "Level1MinApprovals": "1"}
    assert _resolve(props, "Level1", ACCOUNT, ROLES) == ROLES[0]["Arn"]


def test_arn_without_path():
    props = {"Level1PermissionSets": ["DeletionApproverTeamLead"], "Level1MinApprovals": "1", "RoleArnWithPath": "false"}
    assert _resolve(props, "Level1", ACCOUNT, ROLES) == \
        f"arn:aws:iam::{ACCOUNT}:role/AWSReservedSSO_DeletionApproverTeamLead_1111aaaa2222bbbb"


def test_explicit_arns_get_account_substituted():
    props = {"Level2PrincipalArns": ["arn:aws:iam::{account}:role/SecurityApprover"], "Level2MinApprovals": "1"}
    assert _resolve(props, "Level2", ACCOUNT, ROLES) == f"arn:aws:iam::{ACCOUNT}:role/SecurityApprover"


def test_missing_permission_set_fails_deployment():
    with pytest.raises(ValueError, match="not provisioned"):
        _resolve({"Level1PermissionSets": ["Nope"], "Level1MinApprovals": "1"}, "Level1", ACCOUNT, ROLES)


SAML_TRUST = {"Statement": [{"Effect": "Allow", "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/ADFS"},
                             "Action": "sts:AssumeRoleWithSAML"}]}
OPEN_TRUST = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                             "Action": "sts:AssumeRole"}]}


def test_adfs_approver_roles_with_saml_trust_are_accepted():
    props = {"Level2PrincipalArns": ["arn:aws:iam::{account}:role/ADFS-DeletionApproverSecurity"], "Level2MinApprovals": "1"}
    assert _resolve(props, "Level2", ACCOUNT, ROLES, trust=lambda name: SAML_TRUST) == \
        f"arn:aws:iam::{ACCOUNT}:role/ADFS-DeletionApproverSecurity"


def test_approver_role_assumable_without_saml_fails_deployment():
    props = {"Level2PrincipalArns": ["arn:aws:iam::{account}:role/SharedAdmin"], "Level2MinApprovals": "1"}
    with pytest.raises(ValueError, match="without SAML federation"):
        _resolve(props, "Level2", ACCOUNT, ROLES, trust=lambda name: OPEN_TRUST)


def test_quorum_cannot_exceed_principals():
    props = {"Level1PermissionSets": ["DeletionApproverTeamLead"], "Level1MinApprovals": "2"}
    with pytest.raises(ValueError, match="exceeds"):
        _resolve(props, "Level1", ACCOUNT, ROLES)
