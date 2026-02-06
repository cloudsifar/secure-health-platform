#!/usr/bin/env python3
"""
IAM Wildcard Gate: Enforces least-privilege by detecting overly permissive IAM policies.

CI/CD fails if:
- Any policy has Action: "*"
- Any non-allowlisted policy has Resource: "*"

v1 scope:
- Evaluates Action/Resource only (does not interpret NotAction/NotResource).
- Allows Resource:* only for explicitly allowlisted managed policy ARNs
(e.g., AmazonECSTaskExecutionRolePolicy).
"""

import json
import logging
import os
import re
import sys
import urllib.parse

import boto3
from botocore.exceptions import ClientError

# -------- Logging --------
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

# -------- Env / config --------
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
TASK_ROLE_NAME = os.environ.get("TASK_ROLE_NAME", "")
EXEC_ROLE_NAME = os.environ.get("EXEC_ROLE_NAME", "")

ALLOWLIST_RAW = os.environ.get("IAM_WILDCARD_RESOURCE_ALLOWLIST", "")
ALLOWLIST = {x.strip() for x in ALLOWLIST_RAW.split(",") if x.strip()}

ROLE_NAME_PATTERN = re.compile(r"^[\w+=,.@-]+$")

iam = boto3.client("iam", region_name=AWS_REGION)


def fail(msg: str, exit_code: int = 1) -> None:
    logger.error(msg)
    raise SystemExit(exit_code)


def validate_inputs() -> None:
    if not TASK_ROLE_NAME or not EXEC_ROLE_NAME:
        fail("TASK_ROLE_NAME and EXEC_ROLE_NAME must be set in the environment")

    for role in (TASK_ROLE_NAME, EXEC_ROLE_NAME):
        if not ROLE_NAME_PATTERN.match(role):
            fail(f"Invalid role name format: {role}")

    if not isinstance(ALLOWLIST, set):
        fail("Internal error: allowlist not parsed as a set")

    logger.info("IAM Wildcard Gate starting")
    logger.info("Region: %s", AWS_REGION)
    logger.info("Task role: %s", TASK_ROLE_NAME)
    logger.info("Execution role: %s", EXEC_ROLE_NAME)
    if ALLOWLIST:
        logger.info("Allowlisted policy ARNs: %s", ", ".join(sorted(ALLOWLIST)))
    else:
        logger.warning("No allowlisted policies configured (IAM_WILDCARD_RESOURCE_ALLOWLIST is empty)")


def decode_policy_doc(doc):
    """
    IAM can return policy documents either as:
    - a dict (already parsed), or
    - a URL-encoded JSON string (commonly for inline policies)
    """
    if isinstance(doc, str):
        try:
            decoded = urllib.parse.unquote(doc)
            return json.loads(decoded)
        except json.JSONDecodeError as e:
            fail(f"Invalid JSON in policy document: {e}")
    return doc


def has_star(val) -> bool:
    if isinstance(val, str):
        return val.strip() == "*"
    if isinstance(val, list):
        return any(isinstance(v, str) and v.strip() == "*" for v in val)
    return False


def check_policy(policy_doc, *, allow_resource_star: bool):
    """
    Return set of violations, e.g. {"Action:*", "Resource:*"}.
    Fail-closed if policy is malformed.
    """
    policy = decode_policy_doc(policy_doc)

    if not isinstance(policy, dict):
        fail("Policy document is not a JSON object")

    if "Statement" not in policy:
        fail("Policy document missing 'Statement' key")

    stmts = policy["Statement"]
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        fail("Policy 'Statement' must be an object or list")

    bad = set()

    for st in stmts:
        if not isinstance(st, dict):
            fail("Policy statement is not a JSON object")

        if st.get("Effect") != "Allow":
            continue

        action = st.get("Action")
        resource = st.get("Resource")

        if has_star(action):
            bad.add("Action:*")

        if has_star(resource) and not allow_resource_star:
            bad.add("Resource:*")

    return bad


def check_role(role_name: str) -> None:
    logger.info("Checking role: %s", role_name)

    try:
        # ---- Inline policies (strict: no Action:* or Resource:* allowed) ----
        inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        if not inline:
            logger.info("  No inline policies found")
        for pname in inline:
            logger.info("  Inline policy: %s", pname)
            resp = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
            bad = check_policy(resp["PolicyDocument"], allow_resource_star=False)
            if bad:
                fail(f"{role_name} inline policy '{pname}' has {', '.join(sorted(bad))}")

        # ---- Attached managed policies ----
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        if not attached:
            logger.info("  No attached managed policies found")

        for ap in attached:
            arn = ap["PolicyArn"]
            logger.info("  Attached policy: %s", arn)

            pol = iam.get_policy(PolicyArn=arn)
            default_ver = pol["Policy"]["DefaultVersionId"]
            ver = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)
            doc = ver["PolicyVersion"]["Document"]

            allow_resource_star = arn in ALLOWLIST
            bad = check_policy(doc, allow_resource_star=allow_resource_star)

            if "Action:*" in bad:
                fail(f"{role_name} attached policy '{arn}' has Action:*")

            if allow_resource_star:
                # Log only if the strict check would have flagged Resource:*
                strict_bad = check_policy(doc, allow_resource_star=False)
                if "Resource:*" in strict_bad:
                    logger.info("  Allowlisted policy contains Resource:* (permitted): %s", arn)

            if "Resource:*" in bad and not allow_resource_star:
                fail(f"{role_name} attached policy '{arn}' has Resource:* (not allowlisted)")

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code == "NoSuchEntity":
            fail(f"Role does not exist: {role_name}")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            fail(f"No permission to read IAM role/policies for: {role_name}")
        fail(f"AWS error checking role '{role_name}': {e}")


def main() -> None:
    validate_inputs()
    check_role(TASK_ROLE_NAME)
    check_role(EXEC_ROLE_NAME)
    logger.info("✅ PASS: IAM wildcard gate satisfied.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        # Catch-all: CI should fail with a useful message rather than a traceback dump
        fail(f"Unhandled error in IAM wildcard gate: {e}")
