"""Parsing and matching of IAM principal ARNs.

Two notions are used:

* principal key - the IAM principal (role or user). SSM records approver decisions per
  principal, and the configured approver lists contain principals.
* human - the person behind a call. For an assumed-role session it is the role session
  name: IAM Identity Center sets it to the user name and users cannot choose it. For an
  IAM user it is the user name. The human is taken from CloudTrail (see signals.py).

The session name only identifies a person when a SAML identity provider sets it; roles
that can be assumed in any other way are rejected (see trust.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_ASSUMED_ROLE = re.compile(r"^arn:(?P<p>[\w-]+):sts::(?P<a>\d{12}):assumed-role/(?P<role>[^/]+)/(?P<session>.+)$")
_ROLE = re.compile(r"^arn:(?P<p>[\w-]+):iam::(?P<a>\d{12}):role/(?:.*/)?(?P<role>[^/]+)$")
_USER = re.compile(r"^arn:(?P<p>[\w-]+):iam::(?P<a>\d{12}):user/(?:.*/)?(?P<user>[^/]+)$")
_ROOT = re.compile(r"^arn:(?P<p>[\w-]+):iam::(?P<a>\d{12}):root$")


@dataclass(frozen=True)
class Principal:
    arn: str
    kind: str  # assumed-role | user | root
    account: str
    name: str  # role name, user name or "root"
    session: Optional[str] = None

    @property
    def human(self) -> str:
        """Stable, case-insensitive key that identifies the person behind the call."""
        if self.kind == "assumed-role":
            return f"person:{(self.session or '').lower()}"
        if self.kind == "user":
            return f"person:{self.name.lower()}"
        return f"root:{self.account}"


def parse_caller(arn: str) -> Principal:
    """Parse the ARN of a caller (ExecutedBy, CloudTrail userIdentity.arn)."""
    arn = (arn or "").strip()
    if m := _ASSUMED_ROLE.match(arn):
        return Principal(arn, "assumed-role", m["a"], m["role"], m["session"])
    if m := _USER.match(arn):
        return Principal(arn, "user", m["a"], m["user"])
    if m := _ROOT.match(arn):
        return Principal(arn, "root", m["a"], "root")
    raise ValueError(f"Unrecognised caller ARN: {arn!r}")


def principal_key(arn: str, default_account: str) -> tuple[str, str, str]:
    """Normalise a role, assumed-role, user, root ARN or bare user name to (kind, account, name)."""
    arn = (arn or "").strip()
    if m := _ASSUMED_ROLE.match(arn):
        return ("role", m["a"], m["role"])
    if m := _ROLE.match(arn):
        return ("role", m["a"], m["role"])
    if m := _USER.match(arn):
        return ("user", m["a"], m["user"])
    if m := _ROOT.match(arn):
        return ("root", m["a"], "root")
    if arn and ":" not in arn and "/" not in arn:
        # aws:approve also accepts a bare IAM user name in the same account.
        return ("user", default_account, arn)
    raise ValueError(f"Unrecognised principal: {arn!r}")
