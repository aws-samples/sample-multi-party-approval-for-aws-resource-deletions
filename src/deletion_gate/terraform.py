"""Terraform plan/apply through CodeBuild. Approvers approve a concrete plan file."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from .errors import GateError


class TerraformRunner:
    def __init__(self, codebuild, s3, plan_project: str, apply_project: str, plans_bucket: str):
        self._cb = codebuild
        self._s3 = s3
        self._plan_project = plan_project
        self._apply_project = apply_project
        self._plans_bucket = plans_bucket

    def source_version(self, bucket: str, key: str) -> dict:
        """Pin the exact source object so plan and apply use the same configuration."""
        try:
            head = self._s3.head_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            raise GateError(f"Terraform source s3://{bucket}/{key} not readable: {exc.response['Error']['Code']}") from exc
        version = head.get("VersionId")
        return {"versionId": "" if version in (None, "null") else version, "etag": head["ETag"]}

    def plan_sha256(self, execution_id: str) -> str:
        key = f"plans/{execution_id}/tfplan"
        try:
            body = self._s3.get_object(Bucket=self._plans_bucket, Key=key)["Body"].read()
        except ClientError as exc:
            raise GateError(f"Plan file s3://{self._plans_bucket}/{key} not found") from exc
        return hashlib.sha256(body).hexdigest()

    def _env(self, values: dict[str, str]) -> list[dict]:
        return [{"name": k, "value": v, "type": "PLAINTEXT"} for k, v in values.items()]

    def run(self, kind: str, env: dict[str, str], deadline: float) -> dict:
        project = self._plan_project if kind == "plan" else self._apply_project
        build = self._cb.start_build(projectName=project, environmentVariablesOverride=self._env(env))["build"]
        build_id = build["id"]
        while not build.get("buildComplete") and time.time() < deadline:
            time.sleep(15)
            build = self._cb.batch_get_builds(ids=[build_id])["builds"][0]
        if not build.get("buildComplete"):
            if kind == "plan":
                self._cb.stop_build(id=build_id)
                raise GateError(f"Terraform plan build {build_id} did not finish in time")
            return {"buildId": build_id, "status": "IN_PROGRESS"}
        status = build.get("buildStatus")
        if status != "SUCCEEDED":
            raise GateError(f"Terraform {kind} build {build_id} finished with status {status}")
        exported = {v["name"]: v.get("value", "") for v in build.get("exportedEnvironmentVariables", [])}
        return {"buildId": build_id, "status": status, "exported": exported}
