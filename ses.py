"""AWS SES email forwarding infrastructure and declarative resource builders."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import zipfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_lambda.client import LambdaClient
    from mypy_boto3_s3.client import S3Client
    from mypy_boto3_ses.client import SESClient
    from mypy_boto3_sesv2.client import SESV2Client

    from provider import ConfigTree, Path

logger = logging.getLogger(__name__)


class State:
    """Module-level mutable state for AWS service clients."""

    def __init__(self) -> None:
        """Initialize empty clients."""
        self.ses: SESClient | None = None
        self.sesv2: SESV2Client | None = None
        self.s3: S3Client | None = None
        self.iam: IAMClient | None = None
        self.lambda_client: LambdaClient | None = None
        self.region: str = ""
        self.account_id: str = ""


state = State()


def init(region: str) -> None:
    """Initialize AWS service clients for the given region."""
    import boto3
    state.region = region
    state.ses = boto3.client("ses", region_name=region)
    state.sesv2 = boto3.client("sesv2", region_name=region)
    state.s3 = boto3.client("s3", region_name=region)
    state.iam = boto3.client("iam")
    state.lambda_client = boto3.client("lambda", region_name=region)
    state.account_id = boto3.client("sts").get_caller_identity()["Account"]


def get_lambda_arn() -> str:
    """Compute the Lambda function ARN from account ID and region."""
    return f"arn:aws:lambda:{state.region}:{state.account_id}:function:ses-forwarder"


# Lambda code
FORWARDER_CODE = """\
import boto3
import json
import os

def handler(event, context):
    s3 = boto3.client("s3")
    ses = boto3.client("ses", region_name=os.environ["REGION"])
    record = event["Records"][0]["ses"]
    message_id = record["mail"]["messageId"]
    bucket = os.environ["BUCKET"]
    forward_map = json.loads(os.environ["FORWARD_MAP"])

    obj = s3.get_object(Bucket=bucket, Key=message_id)
    raw = obj["Body"].read()

    for recipient in record["receipt"]["recipients"]:
        domain = recipient.split("@")[1]
        forward_to = forward_map.get(recipient) or forward_map.get(domain)
        if not forward_to:
            continue
        ses.send_raw_email(
            Source=f"noreply@{domain}",
            Destinations=[forward_to],
            RawMessage={"Data": raw},
        )

    s3.delete_object(Bucket=bucket, Key=message_id)
"""

CODE_HASH = hashlib.sha256(FORWARDER_CODE.encode()).hexdigest()[:16]


def zip_code() -> bytes:
    """Create a ZIP archive containing the forwarder Lambda code."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", FORWARDER_CODE)
    return buf.getvalue()


# Infrastructure resource maker

def ensure_s3_bucket(bucket_name: str) -> None:
    """Ensure the S3 bucket exists with the correct policy."""
    from botocore.exceptions import ClientError
    s3 = state.s3
    if s3 is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)
    try:
        s3.head_bucket(Bucket=bucket_name)
    except ClientError:
        logger.info("    bucket %s: creating...", bucket_name)
        if state.region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": state.region},
            )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ses.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }],
        }),
    )


def ensure_iam_role(bucket_name: str) -> str:
    """Ensure the IAM role exists with the correct policy. Returns role ARN."""
    from botocore.exceptions import ClientError
    iam = state.iam
    if iam is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)
    role_name = "ses-forwarder-lambda"
    try:
        role = iam.get_role(RoleName=role_name)
    except ClientError:
        logger.info("    role %s: creating...", role_name)
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="ses-forwarder",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ses:SendRawEmail"],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:DeleteObject"],
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:aws:logs:*:*:*",
                },
            ],
        }),
    )
    return role["Role"]["Arn"]


def make_lambda_fn(
    tree: ConfigTree,
    bucket_name: str,
    forward_map: dict[str, str],
    *,
    cloudee: dict[str, object] | None = None,
) -> None:
    """Build a Lambda function node in the config tree."""
    from provider import set_tree
    func_name = "ses-forwarder"
    env_vars = {
        "BUCKET": bucket_name,
        "CODE_HASH": CODE_HASH,
        "FORWARD_MAP": json.dumps(forward_map, sort_keys=True),
        "REGION": state.region,
    }

    if cloudee:
        value: dict[str, object] = cloudee
    else:
        value = {"function_name": func_name, "env_vars": env_vars}

    def push() -> None:
        import time

        from botocore.exceptions import ClientError
        lam = state.lambda_client
        if lam is None:
            msg = "SES not initialized"
            raise RuntimeError(msg)

        ensure_s3_bucket(bucket_name)
        role_arn = ensure_iam_role(bucket_name)
        code_zip = zip_code()

        try:
            lam.get_function(FunctionName=func_name)
            logger.info("    lambda %s: updating...", func_name)
            lam.update_function_configuration(
                FunctionName=func_name,
                Environment={"Variables": env_vars},
            )
            lam.get_waiter("function_updated").wait(FunctionName=func_name)
            lam.update_function_code(
                FunctionName=func_name,
                ZipFile=code_zip,
            )
        except lam.exceptions.ResourceNotFoundException:
            logger.info("    lambda %s: creating...", func_name)
            for attempt in range(5):
                try:
                    lam.create_function(
                        FunctionName=func_name,
                        Runtime="python3.12",
                        Role=role_arn,
                        Handler="index.handler",
                        Code={"ZipFile": code_zip},
                        Environment={"Variables": env_vars},
                        Timeout=30,
                    )
                    break
                except ClientError as e:
                    max_retries = 4
                    if "cannot be assumed" in str(e) and attempt < max_retries:
                        time.sleep(2)
                    else:
                        raise

        try:
            lam.add_permission(
                FunctionName=func_name,
                StatementId="ses-invoke",
                Action="lambda:InvokeFunction",
                Principal="ses.amazonaws.com",
            )
        except ClientError as e:
            if "ResourceConflictException" in str(type(e)):
                pass
            else:
                raise

    def remove() -> None:
        lam = state.lambda_client
        if lam is None:
            msg = "SES not initialized"
            raise RuntimeError(msg)
        logger.info("    deleting lambda %s...", func_name)
        lam.delete_function(FunctionName=func_name)

    path: Path = ("infra", "lambda")
    set_tree(tree, path, value, push, remove)


# Resource makers

def make_identity(
    tree: ConfigTree,
    domain: str,
) -> None:
    """Build an SES identity node in the config tree."""
    from provider import set_tree
    value: dict[str, str] = {"identity": domain}

    def push() -> None:
        sesv2 = state.sesv2
        if sesv2 is None:
            msg = "SES not initialized"
            raise RuntimeError(msg)
        logger.info("    creating identity %s...", domain)
        result = sesv2.create_email_identity(
            EmailIdentity=domain,
            DkimSigningAttributes={"NextSigningKeyLength": "RSA_2048_BIT"},
        )
        tokens = result["DkimAttributes"]["Tokens"]
        if tokens:
            logger.info("    DKIM DNS records needed for %s:", domain)
            for token in tokens:
                logger.info(
                    "      CNAME %s._domainkey.%s -> %s.dkim.amazonses.com",
                    token, domain, token,
                )

    def remove() -> None:
        sesv2 = state.sesv2
        if sesv2 is None:
            msg = "SES not initialized"
            raise RuntimeError(msg)
        logger.info("    deleting identity %s...", domain)
        sesv2.delete_email_identity(EmailIdentity=domain)

    path: Path = ("identities", domain)
    set_tree(tree, path, value, push, remove)


def make_rule_set(
    tree: ConfigTree,
    name: str,
    *,
    active: bool = True,
    cloudee: dict[str, object] | None = None,
) -> None:
    """Build an SES receipt rule set node in the config tree."""
    from provider import set_tree
    ses_client = state.ses
    if ses_client is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)

    value: dict[str, object] = (
        {"name": name, "active": cloudee["active"]}
        if cloudee
        else {"name": name, "active": active}
    )

    def push() -> None:
        if ses_client is None:
            return
        logger.info("    creating rule set %s...", name)
        ses_client.create_receipt_rule_set(RuleSetName=name)
        if active:
            ses_client.set_active_receipt_rule_set(RuleSetName=name)

    def remove() -> None:
        if ses_client is None:
            return
        logger.info("    deleting rule set %s...", name)
        active_set = ses_client.describe_active_receipt_rule_set()
        if active_set["Metadata"]["Name"] == name:
            ses_client.set_active_receipt_rule_set()  # deactivate
        ses_client.delete_receipt_rule_set(RuleSetName=name)

    path: Path = ("rule_sets", name)
    set_tree(tree, path, value, push, remove)


def make_receipt_rule(
    tree: ConfigTree,
    rule_set_name: str,
    rule_name: str | None = None,
    recipients: list[str] | None = None,
    actions: list[dict[str, object]] | None = None,
    *,
    scan: bool = True,
    tls: str = "Optional",
    cloudee: dict[str, object] | None = None,
) -> None:
    """Build an SES receipt rule node in the config tree."""
    from provider import set_tree
    ses_client = state.ses
    if ses_client is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)

    if cloudee:
        rule_name = str(cloudee["Name"])
        value: dict[str, object] = {
            "name": cloudee["Name"],
            "enabled": cloudee["Enabled"],
            "recipients": sorted(cloudee["Recipients"]),            "actions": cloudee["Actions"],
            "scan": cloudee["ScanEnabled"],
            "tls": cloudee["TlsPolicy"],
        }
    else:
        if rule_name is None:
            msg = "rule_name is required"
            raise ValueError(msg)
        if recipients is None:
            msg = "recipients is required"
            raise ValueError(msg)
        if actions is None:
            msg = "actions is required"
            raise ValueError(msg)
        value = {
            "name": rule_name,
            "enabled": True,
            "recipients": sorted(recipients),
            "actions": actions,
            "scan": scan,
            "tls": tls,
        }

    def push() -> None:
        if ses_client is None:
            return
        logger.info("    creating receipt rule %s...", rule_name)
        ses_client.create_receipt_rule(
            RuleSetName=rule_set_name,
            Rule={
                "Name": value["name"],
                "Enabled": value["enabled"],
                "Recipients": value["recipients"],
                "Actions": value["actions"],
                "ScanEnabled": value["scan"],
                "TlsPolicy": value["tls"],
            },
        )

    def remove() -> None:
        if ses_client is None:
            return
        logger.info("    deleting receipt rule %s...", rule_name)
        ses_client.delete_receipt_rule(
            RuleSetName=rule_set_name,
            RuleName=rule_name,
        )

    path: Path = ("rules", rule_set_name, str(rule_name))
    set_tree(tree, path, value, push, remove)


# Fetch cloud state

def fetch_infra(cloud: ConfigTree, bucket_name: str) -> None:
    """Fetch Lambda state into cloud tree."""
    lam = state.lambda_client
    if lam is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)

    try:
        func = lam.get_function(FunctionName="ses-forwarder")
        env = func["Configuration"]["Environment"]["Variables"]
        make_lambda_fn(
            cloud, bucket_name, {},
            cloudee={"function_name": "ses-forwarder", "env_vars": env},
        )
    except lam.exceptions.ResourceNotFoundException:
        pass


def fetch_identities(
    cloud: ConfigTree,
    sesv2: SESV2Client,
    dkim_tokens: dict[str, list[str]],
) -> int:
    """Fetch all SES domain identities into the cloud tree. Returns count."""
    identity_count = 0
    next_token: str | None = None
    while True:
        kwargs: dict[str, str] = {}
        if next_token:
            kwargs["NextToken"] = next_token
        response = sesv2.list_email_identities(**kwargs)
        for identity in response["EmailIdentities"]:
            name = identity["IdentityName"]
            if identity["IdentityType"] == "DOMAIN":
                make_identity(cloud, name)
                details = sesv2.get_email_identity(EmailIdentity=name)
                tokens = details.get("DkimAttributes", {}).get("Tokens", [])
                if tokens:
                    dkim_tokens[name] = list(tokens)
                identity_count += 1
        if "NextToken" not in response:
            break
        next_token = response["NextToken"]
    return identity_count


def fetch_rule_sets(cloud: ConfigTree, ses_client: SESClient) -> int:
    """Fetch all SES receipt rule sets into the cloud tree. Returns count."""
    rule_set_count = 0
    active_set = ses_client.describe_active_receipt_rule_set()
    active_name: str | None = (
        active_set["Metadata"]["Name"]
        if "Metadata" in active_set
        else None
    )

    for rs in ses_client.list_receipt_rule_sets()["RuleSets"]:
        name = rs["Name"]
        rule_set = ses_client.describe_receipt_rule_set(RuleSetName=name)
        make_rule_set(cloud, name, cloudee={"name": name, "active": name == active_name})
        rule_set_count += 1

        for rule in rule_set["Rules"]:
            make_receipt_rule(cloud, name, cloudee=dict(rule))

    return rule_set_count


def fetch_all(bucket_name: str) -> tuple[ConfigTree, dict[str, list[str]]]:
    """Fetch everything from cloud. Returns (cloud tree, dkim_tokens)."""
    ses_client = state.ses
    sesv2 = state.sesv2
    if ses_client is None or sesv2 is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)

    cloud: ConfigTree = {}

    logger.info("  fetching infrastructure...")
    fetch_infra(cloud, bucket_name)

    logger.info("  fetching identities...")
    dkim_tokens: dict[str, list[str]] = {}
    identity_count = fetch_identities(cloud, sesv2, dkim_tokens)

    logger.info("  fetching receipt rule sets...")
    rule_set_count = fetch_rule_sets(cloud, ses_client)

    logger.info("  %d identities, %d rule sets", identity_count, rule_set_count)

    return cloud, dkim_tokens
