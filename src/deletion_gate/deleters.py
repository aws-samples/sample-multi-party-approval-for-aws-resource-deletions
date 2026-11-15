"""Resource lookups and deletions performed by the gate (the only SCP-exempt identity).

Generic path: AWS Cloud Control API (GetResource / DeleteResource), which covers
hundreds of resource types with one code path. CloudFormation stacks use a native
handler so that CloudFormation deletes the stack's resources with the gate role.
"""
from __future__ import annotations

import json
import time
from typing import Callable

from botocore.exceptions import ClientError

from .errors import GateError

CFN_STACK = "AWS::CloudFormation::Stack"
_SUMMARY_LIMIT = 700


class Deleter:
    def __init__(self, client_factory: Callable[[str, str], object], gate_role_arn: str):
        self._client = client_factory
        self._gate_role_arn = gate_role_arn

    # ---------------------------------------------------------------- describe
    def describe(self, resource_type: str, identifier: str, region: str) -> str:
        """Return a short, human-readable summary. Raises GateError if the resource does not exist."""
        if resource_type == CFN_STACK:
            cfn = self._client("cloudformation", region)
            try:
                stack = cfn.describe_stacks(StackName=identifier)["Stacks"][0]
            except ClientError as exc:
                raise GateError(f"Stack {identifier} not found in {region}: {exc.response['Error']['Message']}") from exc
            resources = cfn.list_stack_resources(StackName=identifier).get("StackResourceSummaries", [])
            summary = {
                "StackStatus": stack["StackStatus"],
                "TerminationProtection": stack.get("EnableTerminationProtection", False),
                "ResourceCount": len(resources),
                "Resources": sorted({r["ResourceType"] for r in resources}),
            }
            return json.dumps(summary)[:_SUMMARY_LIMIT]

        cc = self._client("cloudcontrol", region)
        try:
            desc = cc.get_resource(TypeName=resource_type, Identifier=identifier)["ResourceDescription"]
        except ClientError as exc:
            raise GateError(
                f"{resource_type} {identifier} not readable through Cloud Control in {region}: "
                f"{exc.response['Error']['Code']}: {exc.response['Error']['Message']}"
            ) from exc
        return desc.get("Properties", "{}")[:_SUMMARY_LIMIT]

    # ---------------------------------------------------------------- protection
    def disable_protection(self, resource_type: str, identifier: str, region: str) -> str:
        """Switch off resource-level deletion protection where the type supports it."""
        c = lambda svc: self._client(svc, region)  # noqa: E731
        if resource_type == "AWS::EC2::Instance":
            c("ec2").modify_instance_attribute(InstanceId=identifier, DisableApiTermination={"Value": False})
        elif resource_type == "AWS::RDS::DBInstance":
            c("rds").modify_db_instance(DBInstanceIdentifier=identifier, DeletionProtection=False, ApplyImmediately=True)
        elif resource_type == "AWS::RDS::DBCluster":
            c("rds").modify_db_cluster(DBClusterIdentifier=identifier, DeletionProtection=False, ApplyImmediately=True)
        elif resource_type == "AWS::DynamoDB::Table":
            ddb = c("dynamodb")
            ddb.update_table(TableName=identifier, DeletionProtectionEnabled=False)
            ddb.get_waiter("table_exists").wait(TableName=identifier)
        elif resource_type == "AWS::ElasticLoadBalancingV2::LoadBalancer":
            c("elbv2").modify_load_balancer_attributes(
                LoadBalancerArn=identifier, Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}]
            )
        elif resource_type == CFN_STACK:
            c("cloudformation").update_termination_protection(EnableTerminationProtection=False, StackName=identifier)
        else:
            return "not applicable"
        return "disabled"

    # ---------------------------------------------------------------- delete
    def delete(self, resource_type: str, identifier: str, region: str, deadline: float) -> dict:
        if resource_type == CFN_STACK:
            return self._delete_stack(identifier, region, deadline)
        cc = self._client("cloudcontrol", region)
        event = cc.delete_resource(TypeName=resource_type, Identifier=identifier)["ProgressEvent"]
        token = event["RequestToken"]
        while event["OperationStatus"] in ("PENDING", "IN_PROGRESS") and time.time() < deadline:
            time.sleep(10)
            event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] == "FAILED":
            raise GateError(f"Cloud Control delete failed: {event.get('ErrorCode')}: {event.get('StatusMessage')}")
        return {"status": event["OperationStatus"], "requestToken": token}

    def _delete_stack(self, stack: str, region: str, deadline: float) -> dict:
        cfn = self._client("cloudformation", region)
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
        # Override the stack's own service role: CloudFormation must delete the stack's
        # resources as the gate role, the only principal exempt from the SCP.
        cfn.delete_stack(StackName=stack_id, RoleARN=self._gate_role_arn)
        status = "DELETE_IN_PROGRESS"
        while status == "DELETE_IN_PROGRESS" and time.time() < deadline:
            time.sleep(10)
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_FAILED":
            raise GateError(f"Stack deletion failed for {stack}; see the stack events")
        return {"status": "SUCCESS" if status == "DELETE_COMPLETE" else "IN_PROGRESS", "stackId": stack_id}
