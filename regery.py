"""Regery domain registrar API client and declarative resource builders."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from provider import ConfigTree, Path

logger = logging.getLogger(__name__)

HTTP_OK = 200
MAX_PAGES = 100
DEFAULT_LIMIT = 50


class State:
    """Module-level mutable state for Regery API credentials."""

    def __init__(self) -> None:
        """Initialize empty credentials."""
        self.headers: dict[str, str] = {}


state = State()


def init(api_key: str | None = None, api_secret: str | None = None) -> None:
    """Initialize Regery API credentials."""
    key = api_key if api_key is not None else os.getenv("REGERY_API_KEY")
    secret = api_secret if api_secret is not None else os.getenv("REGERY_API_SECRET")
    state.headers = {
        "Authorization": f"{key}:{secret}",
        "Content-Type": "application/json",
    }


def perform(
    method: Literal["get", "patch", "post"],
    url: str,
    json: dict[str, object] | None = None,
) -> object:
    """Execute an HTTP request against the Regery API."""
    import requests
    response = requests.request(
        method,
        f"https://api.regery.com/{url}",
        headers=state.headers,
        json=json,
        timeout=30,
    )
    if response.status_code == HTTP_OK:
        return response.json()
    try:
        detail = response.json()
    except ValueError:
        detail = response.text[:200]
    msg = f"API {method.upper()} {url}: {detail}"
    raise RuntimeError(msg)


def patch(url: str, data: dict[str, object]) -> object:
    """Send a PATCH request."""
    return perform("patch", url, data)


def paginate(url: str) -> list[dict[str, object]]:
    """Fetch all domains from the Regery API with pagination."""
    import requests
    results: list[dict[str, object]] = []
    offset = 0
    page = 0
    while page < MAX_PAGES:
        response = requests.get(
            f"https://api.regery.com/{url}",
            headers=state.headers,
            params={"offset": offset, "limit": DEFAULT_LIMIT},
            timeout=30,
        )
        if response.status_code != HTTP_OK:
            try:
                detail = response.json()
            except ValueError:
                detail = response.text[:200]
            msg = f"paginate {url} offset {offset}: {detail}"
            raise RuntimeError(msg)
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


def domain_value(domain: dict[str, object]) -> dict[str, object]:
    """Extract the diffable value from a domain response."""
    nameservers = domain["nameservers"]
    return {
        "autoRenew": domain["autoRenew"],
        "nameservers": sorted(nameservers["list"]) if isinstance(nameservers, dict) and "list" in nameservers else [],
        "contacts": domain["contacts"],
    }


# Resource makers
def build_domain_value(
    *,
    auto_renew: bool = True,
    nameservers: list[str] | None = None,
    contacts: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build a domain value dict from explicit arguments."""
    return {
        "autoRenew": auto_renew,
        "nameservers": sorted(nameservers) if nameservers else [],
        "contacts": contacts if contacts is not None else {},
    }


def make_domain(    tree: ConfigTree,
    name: str | None = None,
    *,
    auto_renew: bool | None = None,
    nameservers: list[str] | None = None,
    contacts: dict[str, object] | None = None,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a domain node in the config tree."""
    from provider import set_tree
    if remote_data:
        name = str(remote_data["name"])
        value = domain_value(remote_data)
    else:
        if name is None:
            msg = "domain name is required"
            raise ValueError(msg)
        value = build_domain_value(
            auto_renew=auto_renew,
            nameservers=nameservers,
            contacts=contacts,
        )

    def push() -> None:
        patch(f"v1/domains/{name}", {
            "autoRenew": value["autoRenew"],
            "nameservers": {"provider": None, "list": value["nameservers"]},
            "contacts": value["contacts"],
        })

    def remove() -> None:
        pass  # can't delete a domain via API

    path: Path = ("domains", str(name))
    set_tree(tree, path, value, push, remove)


# Fetch remote state
def fetch_all() -> ConfigTree:
    """Fetch all domains from Regery. Returns remote tree."""
    remote: ConfigTree = {}

    logger.info("  fetching domains...")
    domains = paginate("v1/domains")

    for domain in domains:
        make_domain(remote, remote_data=domain)

    logger.info("  %d domains", len(domains))

    return remote
