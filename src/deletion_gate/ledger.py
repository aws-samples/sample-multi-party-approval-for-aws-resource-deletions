"""Single-use ledger of requests. Conditional writes make every approval usable once."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from .errors import GateError


class Ledger:
    def __init__(self, dynamodb, table: str):
        self._ddb = dynamodb
        self._table = table

    def create(self, execution_id: str, status: str, item: dict[str, Any]) -> None:
        record = {"executionId": execution_id, "status": status, "createdAt": int(time.time()), **item}
        try:
            self._ddb.put_item(
                TableName=self._table,
                Item=_marshal(record),
                ConditionExpression="attribute_not_exists(executionId)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise GateError(f"Execution {execution_id} is already recorded in the ledger") from exc
            raise

    def get(self, execution_id: str) -> dict[str, Any]:
        resp = self._ddb.get_item(TableName=self._table, Key={"executionId": {"S": execution_id}}, ConsistentRead=True)
        if "Item" not in resp:
            raise GateError(f"Execution {execution_id} has no ledger record (was the validation/plan step skipped?)")
        return _unmarshal(resp["Item"])

    def transition(self, execution_id: str, expected: str, new: str, item: dict[str, Any] | None = None) -> None:
        values = {"updatedAt": int(time.time()), **(item or {})}
        names = {"#s": "status", **{f"#k{i}": k for i, k in enumerate(values)}}
        attrs = {":new": {"S": new}, ":expected": {"S": expected}}
        sets = ["#s = :new"]
        for i, (k, v) in enumerate(values.items()):
            attrs[f":v{i}"] = _marshal_value(v)
            sets.append(f"#k{i} = :v{i}")
        try:
            self._ddb.update_item(
                TableName=self._table,
                Key={"executionId": {"S": execution_id}},
                UpdateExpression="SET " + ", ".join(sets),
                ConditionExpression="#s = :expected",
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=attrs,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise GateError(f"Execution {execution_id} is not in state {expected}; refusing to run twice") from exc
            raise


def _marshal_value(v: Any) -> dict:
    if isinstance(v, bool):
        return {"BOOL": v}
    if isinstance(v, (int, float)):
        return {"N": str(v)}
    if isinstance(v, (list, tuple)):
        return {"L": [_marshal_value(x) for x in v]}
    if isinstance(v, dict):
        return {"M": {k: _marshal_value(x) for k, x in v.items()}}
    return {"S": str(v)}


def _marshal(record: dict[str, Any]) -> dict:
    return {k: _marshal_value(v) for k, v in record.items() if v is not None}


def _unmarshal_value(v: dict) -> Any:
    (kind, val), = v.items()
    if kind == "S":
        return val
    if kind == "N":
        return int(val) if val.lstrip("-").isdigit() else float(val)
    if kind == "BOOL":
        return val
    if kind == "L":
        return [_unmarshal_value(x) for x in val]
    if kind == "M":
        return {k: _unmarshal_value(x) for k, x in val.items()}
    if kind == "NULL":
        return None
    return val


def _unmarshal(item: dict) -> dict[str, Any]:
    return {k: _unmarshal_value(v) for k, v in item.items()}
