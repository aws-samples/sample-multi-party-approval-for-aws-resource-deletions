"""Checks that a caller is a verifiable person.

The gate identifies people by role session name (see identity.py). That name is only
trustworthy when the role can be assumed exclusively through SAML federation, where the
identity provider sets it: IAM Identity Center, or a SAML IdP such as AD FS, Okta or
Microsoft Entra ID federated directly with IAM (RoleSessionName attribute). If a role
can also be assumed with sts:AssumeRole, or by an AWS service, the caller or the service
chooses the session name, and one person could appear as two.

IAM users are identified by their user name and are accepted. The root user is not a
person the gate can tell apart and is rejected.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any, Callable

from .identity import parse_caller

# Actions a SAML-only trust policy may allow.
_SAML_ACTIONS = {"sts:assumerolewithsaml", "sts:tagsession", "sts:setsourceidentity"}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def trust_problems(policy: dict) -> list[str]:
    """Problems that make the session name of this role untrustworthy (empty list = OK)."""
    problems: list[str] = []
    for i, stmt in enumerate(_as_list((policy or {}).get("Statement"))):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if not isinstance(principal, dict) or set(principal) != {"Federated"}:
            problems.append(f"statement {i} trusts {principal!r}, not only a SAML identity provider")
            continue
        federated = _as_list(principal["Federated"])
        if not federated or any(":saml-provider/" not in str(f) for f in federated):
            problems.append(f"statement {i} trusts a non-SAML federated principal {federated}")
        actions = {str(a).lower() for a in _as_list(stmt.get("Action"))}
        if not actions or actions - _SAML_ACTIONS:
            problems.append(f"statement {i} allows {sorted(actions - _SAML_ACTIONS) or 'no action'}")
    if not problems and not _as_list((policy or {}).get("Statement")):
        problems.append("empty trust policy")
    return problems


def make_identity_checker(iam) -> Callable[[str], list[str]]:
    """Return check(caller_arn) -> problems, reading role trust policies through IAM."""

    @lru_cache(maxsize=64)
    def role_problems(role_name: str) -> tuple[str, ...]:
        policy = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
        return tuple(trust_problems(policy))

    def check(arn: str) -> list[str]:
        caller = parse_caller(arn)
        if caller.kind == "user":
            return []
        if caller.kind == "root":
            return ["the root user cannot be tied to a person"]
        return [f"role {caller.name}: {p}" for p in role_problems(caller.name)]

    return check
