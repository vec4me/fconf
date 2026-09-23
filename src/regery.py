"""Regery domain registrar API client and declarative resource builders."""

from __future__ import annotations

import logging
import os
from typing import Final, Literal, cast
import requests
import src.reconciliation as reconciliation

logger = logging.getLogger(__name__)

HTTP_OK: Final = 200
MAX_PAGES: Final = 100
DEFAULT_LIMIT: Final = 50

HttpMethod = Literal["get", "patch", "post"]
Client = dict[str, str]


def initializeClient(apikey: str | None = None, apisecret: str | None = None) -> Client:
    """Return a Regery API client initialized from explicit or environment credentials."""
    key = apikey if apikey is not None else os.getenv("REGERY_API_KEY")
    secret = apisecret if apisecret is not None else os.getenv("REGERY_API_SECRET")
    if key is None:
        raise ValueError("REGERY_API_KEY is required")
    if secret is None:
        raise ValueError("REGERY_API_SECRET is required")
    return {
        "Authorization": f"{key}:{secret}",
        "Content-Type": "application/json",
    }


def sendRequest(
    client: Client,
    method: HttpMethod,
    url: str,
    payload: dict[str, object] | None = None,
) -> object:
    """Execute an HTTP request against the Regery API."""
    response = requests.request(
        method,
        f"https://api.regery.com/{url}",
        headers=client,
        json=payload,
        timeout=30,
    )
    if response.status_code == HTTP_OK:
        return response.json()
    try:
        detail = response.json()
    except ValueError:
        detail = response.text[:200]
    message = f"API {method.upper()} {url}: {detail}"
    raise RuntimeError(message)


def patch(client: Client, url: str, payload: dict[str, object]) -> object:
    """Send a PATCH request."""
    return sendRequest(client, "patch", url, payload)


def paginate(client: Client, url: str) -> list[dict[str, object]]:
    """Fetch all domains from the Regery API with pagination."""
    results: list[dict[str, object]] = []
    offset = 0
    page = 0
    while page < MAX_PAGES:
        response = requests.get(
            f"https://api.regery.com/{url}",
            headers=client,
            params={"offset": offset, "limit": DEFAULT_LIMIT},
            timeout=30,
        )
        if response.status_code != HTTP_OK:
            try:
                detail = response.json()
            except ValueError:
                detail = response.text[:200]
            message = f"paginate {url} offset {offset}: {detail}"
            raise RuntimeError(message)
        body = response.json()
        domains: list[dict[str, object]] = body["domains"]
        if not domains:
            break
        results.extend(domains)
        if offset + len(domains) >= body["total"]:
            break
        offset += len(domains)
        page += 1
    return results


def DomainValue(domain: dict[str, object]) -> dict[str, object]:
    """Extract the diffable value from a domain response."""
    nameservers = domain["nameservers"]
    nameserverlist: list[str] = []
    if isinstance(nameservers, dict) and "list" in nameservers:
        nameserverlist = sorted(cast("list[str]", nameservers["list"]))
    return {
        "autoRenew": domain["autoRenew"],
        "nameservers": nameserverlist,
        "contacts": domain["contacts"],
    }


# Resource values
def DomainValueFromConfiguration(
    *,
    autorenew: bool,
    nameservers: list[str],
    contacts: dict[str, object],
) -> dict[str, object]:
    """Build a domain value dict from explicit arguments."""
    return {
        "autoRenew": autorenew,
        "nameservers": sorted(nameservers),
        "contacts": contacts,
    }


def declareDomain(
    tree: reconciliation.ConfigTree,
    name: str,
    *,
    autorenew: bool,
    nameservers: list[str],
    contacts: dict[str, object],
) -> None:
    """Declare one desired Regery domain value."""
    value = DomainValueFromConfiguration(autorenew=autorenew, nameservers=nameservers, contacts=contacts)
    reconciliation.setValue(tree, ("domains", name), value)


def execute(client: Client, operation: dict[str, object]) -> reconciliation.TransitionResult:
    """Apply one planned Regery domain transition."""
    action = str(operation["action"])
    path = cast("reconciliation.Path", operation["path"])
    try:
        if action == "remove":
            raise RuntimeError(f"Regery domain does not support removal: {path[1]}")
        value = cast("dict[str, object]", operation["after"])
        patch(client, f"v1/domains/{path[1]}", {
            "autoRenew": value["autoRenew"],
            "nameservers": {"provider": None, "list": value["nameservers"]},
            "contacts": value["contacts"],
        })
    except Exception as error:
        return {"completed_steps": [], "error": str(error)}
    return {"completed_steps": ["push" if action == "push" else "replace"], "error": None}


# Fetch remote state
def fetchState(client: Client, managednames: set[str]) -> reconciliation.ConfigTree:
    """Fetch Regery state belonging to explicitly managed domains."""
    observed: reconciliation.ConfigTree = {}

    logger.info("  fetching domains...")
    domains = paginate(client, "v1/domains")

    manageddomains = [domain for domain in domains if str(domain["name"]) in managednames]
    for domain in manageddomains:
        reconciliation.setValue(observed, ("domains", str(domain["name"])), DomainValue(domain))

    logger.info("  %d managed domains", len(manageddomains))

    return observed


def reconcile(configuration: dict[str, object], nameservers: dict[str, list[str]], *, apply: bool, planformat: str) -> None:
    """Reconcile Regery domains using Cloudflare nameserver observations."""
    regeryclient = initializeClient()
    contactid = os.environ["REGERY_CONTACT_ID"]
    roles = cast("list[str]", configuration["contact_roles"])
    contacts: dict[str, object] = {
        **{role: contactid for role in roles},
        "services": configuration["services"],
        "disclose": configuration["disclose"],
    }
    managednames = set(cast("list[str]", configuration["domains"]))
    observed = fetchState(regeryclient, managednames)
    local: reconciliation.ConfigTree = {}
    for name in sorted(managednames):
        declareDomain(local, name=name, autorenew=bool(configuration["auto_renew"]), nameservers=nameservers[name], contacts=contacts)
    executor = lambda operation: execute(regeryclient, operation)
    applied = reconciliation.runValues(observed, local, {}, {}, executor, apply=apply, planformat=planformat)
    if applied:
        verified = fetchState(regeryclient, managednames)
        reconciliation.verifyConvergence(verified, local, {}, {})
