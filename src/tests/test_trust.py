import pytest

from conftest import ACCOUNT
from deletion_gate.trust import make_identity_checker, trust_problems

# Trust policy of an IAM Identity Center permission set role (shape created by Identity Center).
IDENTITY_CENTER = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/AWSSSO_0123456789abcdef_DO_NOT_DELETE"},
    "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
    "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
}]}
# AD FS (or Okta, Entra ID) federated directly with IAM.
ADFS = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/ADFS"},
    "Action": "sts:AssumeRoleWithSAML",
    "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
}]}


def with_extra(statement):
    return {"Version": "2012-10-17", "Statement": ADFS["Statement"] + [statement]}


def test_saml_only_trust_is_accepted():
    assert trust_problems(IDENTITY_CENTER) == []
    assert trust_problems(ADFS) == []


@pytest.mark.parametrize("statement", [
    # Anyone in the account could assume the role and choose any session name.
    {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"},
    # A service would use generated session names (instance IDs, function names...).
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
    {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
    # Web identity: the session name is chosen by the caller.
    {"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"}, "Action": "sts:AssumeRoleWithWebIdentity"},
    # SAML provider, but an extra action that lets the caller pick the session name.
    {"Effect": "Allow", "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/ADFS"}, "Action": ["sts:AssumeRoleWithSAML", "sts:AssumeRole"]},
])
def test_non_saml_trust_is_rejected(statement):
    assert trust_problems(with_extra(statement))


def test_deny_statements_are_ignored_and_empty_policy_rejected():
    deny = {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
    assert trust_problems(with_extra(deny)) == []
    assert trust_problems({"Statement": []})


class FakeIam:
    def __init__(self, policies):
        self.policies, self.calls = policies, 0

    def get_role(self, RoleName):
        self.calls += 1
        return {"Role": {"AssumeRolePolicyDocument": self.policies[RoleName]}}


def test_identity_checker():
    iam = FakeIam({"ADFS-Approver": ADFS, "Shared-Admin": with_extra(
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"})})
    check = make_identity_checker(iam)
    assert check(f"arn:aws:sts::{ACCOUNT}:assumed-role/ADFS-Approver/alice@corp.example") == []
    assert check(f"arn:aws:sts::{ACCOUNT}:assumed-role/ADFS-Approver/bob@corp.example") == []
    assert iam.calls == 1  # cached per role
    assert check(f"arn:aws:sts::{ACCOUNT}:assumed-role/Shared-Admin/whoever")
    assert check(f"arn:aws:iam::{ACCOUNT}:user/alice") == []
    assert check(f"arn:aws:iam::{ACCOUNT}:root")
