#!/usr/bin/env python3
"""
Gate C: Validate IAM policies using IAM Access Analyzer policy validation.

Fails the build if any finding severity meets/exceeds the configured threshold.
Default: fail on ERROR.

Requires:
- IAM read permissions to fetch role policies
- access-analyzer:ValidatePolicy to validate documents
"""

import json
import logging
import os
import re
import sys
import urllib.parse

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
TASK_ROLE_NAME = os.environ.get("TASK_ROLE_NAME", "")
EXEC_ROLE_NAME = os.environ.get("EXEC_ROLE_NAME", "")

FAIL_ON = os.environ.get("IAM_VALIDATE_FAIL_ON", "ERROR").upper()
SEVERITY_ORDER = {"SUGGESTION": 0, "WARNING": 1, "SECURITY_WARNING": 2, "ERROR": 3}

ROLE_NAME_PATTERN = re.compile(r"^[\w+=,.@-]+$")

iam = boto3.client("iam", region_name=AWS_REGION)
accessanalyzer = boto3.client("accessanalyzer", region_name=AWS_REGION)


def fail(msg: str) -> None:
    logger.error(msg)
    raise SystemExit(1)


def validate_inputs() -> None:
    if not TASK_ROLE_NAME or not EXEC_ROLE_NAME:
        fail("TASK_ROLE_NAME and EXEC_ROLE_NAME must be set")

    for role in (TASK_ROLE_NAME, EXEC_ROLE_NAME):
        if not ROLE_NAME_PATTERN.match(role):
            fail(f"Invalid role name format: {role}")

    if FAIL_ON not in SEVERITY_ORDER:
        fail(f"IAM_VALIDATE_FAIL_ON must be one of {', '.join(SEVERITY_ORDER.keys())}")

    logger.info("IAM ValidatePolicy Gate starting (IAM Access Analyzer)")
    logger.info("Region: %s", AWS_REGION)
    logger.info("Fail threshold: %s", FAIL_ON)
    logger.info("Task role: %s", TASK_ROLE_NAME)
    logger.info("Execution role: %s", EXEC_ROLE_NAME)


def decode_policy_doc(doc):
    if isinstance(doc, str):
        decoded = urllib.parse.unquote(doc)
        return json.loads(decoded)
    return doc


def to_json_string(policy_doc) -> str:
    policy = decode_policy_doc(policy_doc)
    if not isinstance(policy, dict):
        fail("Policy document is not a JSON object")
    return json.dumps(policy)


def severity_meets_threshold(sev: str) -> bool:
    return SEVERITY_ORDER.get(sev, -1) >= SEVERITY_ORDER[FAIL_ON]


def validate_policy(policy_json_str: str, label: str) -> int:
    """
    Returns count of findings at/above threshold.
    """
    try:
        resp = accessanalyzer.validate_policy(
            policyDocument=policy_json_str,
            policyType="IDENTITY_POLICY",
        )
    except ClientError as e:
        fail(f"Access Analyzer ValidatePolicy API error for {label}: {e}")

    findings = resp.get("findings", [])
    if not findings:
        logger.info("  %s: no findings", label)
        return 0

    hit = 0
    for f in findings:
        # FIXED: Use findingType for severity (not findingDetails)
        sev = f.get("findingType", "UNKNOWN")
        issue = f.get("issueCode", "UNKNOWN_ISSUE")
        msg = f.get("findingDetails", "")  # This is just a string
        locs = f.get("locations", [])
        
        # Extract path from first location if available
        path = ""
        if locs and isinstance(locs[0].get("path"), list):
            path = ".".join(str(p) for p in locs[0]["path"])

        logger.warning("  %s [%s] %s%s", label, sev, issue, f" (path: {path})" if path else "")
        if msg:
            logger.warning("    %s", msg)

        if severity_meets_threshold(sev):
            hit += 1

    if hit:
        logger.error("  %s: %d finding(s) at/above threshold %s", label, hit, FAIL_ON)
    else:
        logger.info("  %s: findings exist but below threshold %s", label, FAIL_ON)

    return hit


def iter_role_policies(role_name: str):
    """
    Yields tuples: (label, policy_document)
    """
    try:
        inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code == "NoSuchEntity":
            fail(f"Role does not exist: {role_name}")
        if code in ("AccessDenied", "AccessDeniedException"):
            fail(f"No permission to read IAM role: {role_name}")
        raise
    
    if not inline:
        logger.info("  %s: no inline policies", role_name)
    for pname in inline:
        resp = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
        yield (f"{role_name} inline:{pname}", resp["PolicyDocument"])

    attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
    if not attached:
        logger.info("  %s: no attached managed policies", role_name)
    for ap in attached:
        arn = ap["PolicyArn"]
        pol = iam.get_policy(PolicyArn=arn)
        default_ver = pol["Policy"]["DefaultVersionId"]
        ver = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)
        yield (f"{role_name} managed:{arn}@{default_ver}", ver["PolicyVersion"]["Document"])


def main() -> None:
    validate_inputs()

    total_hits = 0
    for role in (TASK_ROLE_NAME, EXEC_ROLE_NAME):
        logger.info("Validating policies for role: %s", role)
        for label, doc in iter_role_policies(role):
            total_hits += validate_policy(to_json_string(doc), label)

    if total_hits:
        fail(f"FAIL: IAM ValidatePolicy Gate triggered ({total_hits} finding(s) >= {FAIL_ON})")

    logger.info("✅ PASS: IAM ValidatePolicy Gate satisfied.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        fail(f"Unhandled error in IAM ValidatePolicy Gate: {e}")