"""AWS SES outbound email infrastructure and declarative resource builders."""

from __future__ import annotations

import json
import logging
from pathlib import Path as FilePath
from typing import TYPE_CHECKING, Any, Final, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable

    from provider import ConfigTree, Path

logger = logging.getLogger(__name__)


class SmtpCredential(TypedDict):
    """SMTP credential stored on disk."""
    host: str
    port: int
    username: str
    password: str


class State:
    """Module-level mutable state for AWS service clients."""

    def __init__(self) -> None:
        """Initialize empty clients."""
        super().__init__()
        self.sesv2: Any = None
        self.iam: Any = None
        self.region: str = ""


state = State()


def init(region: str) -> None:
    """Initialize AWS service clients for the given region."""
    import boto3
    state.region = region
    state.sesv2 = boto3.client("sesv2", region_name=region)  # pyright: ignore[reportUnknownMemberType]
    state.iam = boto3.client("iam")  # pyright: ignore[reportUnknownMemberType]


CREDENTIALS_FILE: Final = FilePath(__file__).parent / "smtp_credentials.json"


def load_credentials() -> dict[str, SmtpCredential]:
    """Load stored SMTP credentials from disk."""
    if CREDENTIALS_FILE.exists():
        return json.loads(CREDENTIALS_FILE.read_text())
    return {}


def write_credentials(credentials: dict[str, SmtpCredential]) -> None:
    """Write all SMTP credentials to disk."""
    CREDENTIALS_FILE.write_text(json.dumps(credentials, indent=2) + "\n")


def save_credential(domain: str, credential: SmtpCredential) -> None:
    """Save an SMTP credential for a domain to disk."""
    credentials = load_credentials()
    credentials[domain] = credential
    write_credentials(credentials)


def remove_credential(domain: str) -> None:
    """Remove a stored SMTP credential for a domain."""
    credentials = load_credentials()
    if domain in credentials:
        del credentials[domain]
        write_credentials(credentials)


def log_credentials() -> None:
    """Log all stored SMTP credentials."""
    credentials = load_credentials()
    if not credentials:
        return
    for domain, cred in sorted(credentials.items()):
        logger.info("  %s: host=%s port=%s user=%s", domain, cred["host"], cred["port"], cred["username"])


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


# SMTP credentials

SMTP_SIGNING_VERSION: Final = b"\x04"


def derive_smtp_password(secret_access_key: str, region: str) -> str:
    """Derive an SES SMTP password from an IAM secret access key using AWS's documented algorithm."""
    import base64
    import hashlib
    import hmac

    def sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    signature = sign(("AWS4" + secret_access_key).encode("utf-8"), "11111111")
    signature = sign(signature, region)
    signature = sign(signature, "ses")
    signature = sign(signature, "aws4_request")
    signature = sign(signature, "SendRawEmail")
    return base64.b64encode(SMTP_SIGNING_VERSION + signature).decode("utf-8")


def make_smtp_user(
    tree: ConfigTree,
    domain: str,
    *,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build an IAM SMTP user node in the config tree."""
    from provider import set_tree

    iam = state.iam
    if iam is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)

    username = f"ses-smtp-{domain.replace('.', '-')}"
    smtp_host = f"email-smtp.{state.region}.amazonaws.com"
    smtp_port = 587

    if remote_data:
        value: dict[str, object] = remote_data
    else:
        value = {"username": username, "host": smtp_host, "port": smtp_port}

    def push() -> None:
        from botocore.exceptions import ClientError

        # Create IAM user
        try:
            iam.get_user(UserName=username)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                logger.info("    creating IAM user %s...", username)
                iam.create_user(UserName=username)
            else:
                raise

        # Attach SES send policy
        iam.put_user_policy(
            UserName=username,
            PolicyName="ses-send",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["ses:SendRawEmail"],
                    "Resource": "*",
                }],
            }),
        )

        # Delete existing access keys before creating new one
        existing_keys = iam.list_access_keys(UserName=username)
        for key in existing_keys["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])

        # Create access key and derive SMTP password
        access_key = iam.create_access_key(UserName=username)["AccessKey"]
        smtp_password = derive_smtp_password(access_key["SecretAccessKey"], state.region)

        save_credential(domain, {
            "host": smtp_host,
            "port": smtp_port,
            "username": access_key["AccessKeyId"],
            "password": smtp_password,
        })
        logger.info("    SMTP credentials saved for %s", domain)

    def remove() -> None:
        from botocore.exceptions import ClientError

        logger.info("    deleting SMTP user %s...", username)

        def ignore_not_found(fn: Callable[[], None]) -> None:
            try:
                fn()
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    return
                raise

        # Delete access keys
        try:
            existing_keys = iam.list_access_keys(UserName=username)
            for key in existing_keys["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        # Delete policy and user
        ignore_not_found(lambda: iam.delete_user_policy(UserName=username, PolicyName="ses-send"))
        ignore_not_found(lambda: iam.delete_user(UserName=username))

        remove_credential(domain)

    path: Path = ("smtp_users", domain)
    set_tree(tree, path, value, push, remove)


# Fetch remote state

def fetch_smtp_users(remote: ConfigTree, known_domains: set[str]) -> int:
    """Fetch existing IAM SMTP users into the remote tree. Returns count."""
    from botocore.exceptions import ClientError
    iam = state.iam
    if iam is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)

    credentials = load_credentials()
    count = 0
    for domain in known_domains:
        username = f"ses-smtp-{domain.replace('.', '-')}"
        try:
            iam.get_user(UserName=username)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                continue
            raise
        cred = credentials.get(domain, {})
        make_smtp_user(remote, domain, remote_data={
            "username": username,
            "host": cred.get("host"),
            "port": cred.get("port"),
        })
        count += 1
    return count


def fetch_identities(
    remote: ConfigTree,
    dkim_tokens: dict[str, list[str]],
) -> set[str]:
    """Fetch all SES domain identities into the remote tree. Returns domain names."""
    sesv2 = state.sesv2
    if sesv2 is None:
        msg = "SES not initialized"
        raise RuntimeError(msg)

    domains: set[str] = set()
    next_token: str | None = None
    while True:
        kwargs: dict[str, str] = {}
        if next_token:
            kwargs["NextToken"] = next_token
        response = sesv2.list_email_identities(**kwargs)
        for identity in response["EmailIdentities"]:
            name = identity["IdentityName"]
            if identity["IdentityType"] == "DOMAIN":
                make_identity(remote, name)
                details = sesv2.get_email_identity(EmailIdentity=name)
                tokens = details.get("DkimAttributes", {}).get("Tokens", [])
                if tokens:
                    dkim_tokens[name] = list(tokens)
                domains.add(name)
        if "NextToken" not in response:
            break
        next_token = response["NextToken"]
    return domains


def fetch_all() -> tuple[ConfigTree, dict[str, list[str]]]:
    """Fetch everything from remote. Returns (remote tree, dkim_tokens)."""
    remote: ConfigTree = {}

    logger.info("  fetching identities...")
    dkim_tokens: dict[str, list[str]] = {}
    identity_domains = fetch_identities(remote, dkim_tokens)

    logger.info("  fetching SMTP users...")
    smtp_user_count = fetch_smtp_users(remote, identity_domains)

    logger.info("  %d identities, %d SMTP users", len(identity_domains), smtp_user_count)

    logger.info("  SMTP credentials:")
    log_credentials()

    return remote, dkim_tokens
