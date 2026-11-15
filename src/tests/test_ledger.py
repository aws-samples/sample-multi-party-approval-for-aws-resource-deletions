import boto3
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from botocore.stub import ANY, Stubber

from deletion_gate.errors import GateError
from deletion_gate.ledger import Ledger


@pytest.fixture
def ddb():
    # Unsigned client: the Stubber intercepts every call, so no credentials are needed.
    client = boto3.client("dynamodb", region_name="eu-west-1", config=Config(signature_version=UNSIGNED))
    with Stubber(client) as stub:
        yield client, stub


def test_create_is_conditional(ddb):
    client, stub = ddb
    stub.add_response("put_item", {}, {
        "TableName": "L", "Item": ANY, "ConditionExpression": "attribute_not_exists(executionId)",
    })
    Ledger(client, "L").create("e1", "VALIDATED", {"kind": "resource"})


def test_create_twice_is_rejected(ddb):
    client, stub = ddb
    stub.add_client_error("put_item", service_error_code="ConditionalCheckFailedException")
    with pytest.raises(GateError, match="already recorded"):
        Ledger(client, "L").create("e1", "VALIDATED", {})


def test_transition_requires_expected_state(ddb):
    client, stub = ddb
    stub.add_client_error("update_item", service_error_code="ConditionalCheckFailedException")
    with pytest.raises(GateError, match="refusing to run twice"):
        Ledger(client, "L").transition("e1", "VALIDATED", "EXECUTING", {"approvers": ["a"]})


def test_get_roundtrip(ddb):
    client, stub = ddb
    stub.add_response("get_item", {"Item": {
        "executionId": {"S": "e1"}, "status": {"S": "PLANNED"}, "counts": {"M": {"delete": {"N": "3"}}},
        "source": {"M": {"bucket": {"S": "b"}}}, "approvers": {"L": [{"S": "a"}]},
    }})
    item = Ledger(client, "L").get("e1")
    assert item["counts"] == {"delete": 3} and item["source"] == {"bucket": "b"} and item["approvers"] == ["a"]
