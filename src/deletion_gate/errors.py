class GateError(Exception):
    """A request was rejected by the gate. The message is safe to show to users."""


class ApprovalError(GateError):
    """The approvals recorded on an execution do not satisfy the policy."""


class ApprovalPending(ApprovalError):
    """An SSM approval decision has no matching CloudTrail event yet (delivery delay)."""
