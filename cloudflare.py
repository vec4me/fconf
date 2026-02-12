"""Cloudflare API client and declarative resource builders."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from provider import ConfigTree, Path

logger = logging.getLogger(__name__)

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
MAX_PAGES = 100
PER_PAGE = 10
DNS_TXT_MAX = 255

class State:
    """Module-level mutable state for Cloudflare API credentials."""

    def __init__(self) -> None:
        """Initialize empty credentials."""
        self.headers: dict[str, str] = {}
        self.account_id: str | None = None


state = State()


def init(
    api_token: str | None = None,
    account_id: str | None = None,
) -> None:
    """Initialize Cloudflare API credentials."""
    state.account_id = account_id if account_id is not None else os.getenv("CLOUDFLARE_ACCOUNT_ID")
    token = api_token if api_token is not None else os.getenv("CLOUDFLARE_API_TOKEN")
    state.headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def perform(
    method: Literal["delete", "get", "patch", "post", "put"],
    url: str,
    json: dict[str, object] | None = None,
) -> object:
    """Execute an HTTP request against the Cloudflare API."""
    import requests
    response = requests.request(
        method,
        f"https://api.cloudflare.com/client/v4/{url}",
        headers=state.headers,
        json=json,
        timeout=30,
    )
    if response.status_code in (HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT):
        if response.status_code == HTTP_NO_CONTENT:
            return True
        return response.json()["result"]
    try:
        detail = response.json()["errors"]
    except (KeyError, ValueError):
        detail = response.text[:200]
    msg = f"API {method.upper()} {url}: {detail}"
    raise RuntimeError(msg)


def delete(url: str) -> object:
    """Send a DELETE request."""
    return perform("delete", url)


def get(url: str) -> object:
    """Send a GET request."""
    return perform("get", url)


def patch(url: str, data: dict[str, object]) -> object:
    """Send a PATCH request."""
    return perform("patch", url, data)


def post(url: str, data: dict[str, object]) -> object:
    """Send a POST request."""
    return perform("post", url, data)


def put(url: str, data: dict[str, object]) -> object:
    """Send a PUT request."""
    return perform("put", url, data)


# String helpers
def quote(string: str) -> str:
    """Wrap a string in double quotes if it contains '=' and isn't already quoted."""
    if "=" in string and not (string.startswith('"') and string.endswith('"')):
        return f'"{string}"'
    return string


def split_txt(content: str) -> str:
    """Split long TXT content into 255-byte DNS strings matching Cloudflare's API format."""
    is_quoted = content.startswith('"') and content.endswith('"')
    inner = content[1:-1] if is_quoted else content
    if len(inner) <= DNS_TXT_MAX:
        return content
    chunks = [inner[i:i + DNS_TXT_MAX] for i in range(0, len(inner), DNS_TXT_MAX)]
    return " ".join(f'"{chunk}"' for chunk in chunks)


def filter_keys(source: dict[str, object], skip: tuple[str, ...]) -> dict[str, object]:
    """Return a copy of source with the specified keys removed."""
    return {k: v for k, v in source.items() if k not in skip}


# Resource makers
def make_setting(
    tree: ConfigTree,
    zone: dict[str, object],
    setting_id: str | None = None,
    setting_value: object = None,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a zone setting node in the config tree."""
    from provider import set_tree
    zone_name = zone["name"]
    zone_id = zone["id"]

    skip_keys = ("editable", "modified_on", "certificate_status", "validation_errors", "time_remaining")
    if remote_data:
        setting_id = str(remote_data["id"])
        value: dict[str, object] = filter_keys(remote_data, skip_keys)
    else:
        if setting_id is None:
            msg = f"{zone_name} setting, missing id"
            raise ValueError(msg)
        value = {"id": setting_id, "value": setting_value}

    def push() -> None:
        patch(f"zones/{zone_id}/settings/{setting_id}", value)

    def remove() -> None:
        pass  # can't remove a setting, only change it

    path: Path = ("zones", str(zone_name), "settings", str(setting_id))
    set_tree(tree, path, value, push, remove)


def make_dnssec(
    tree: ConfigTree,
    zone: dict[str, object],
    status: str = "disabled",
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a DNSSEC node in the config tree."""
    from provider import set_tree
    zone_name = zone["name"]
    zone_id = zone["id"]

    skip_keys = (
        "ds", "key_tag", "algorithm", "key_type", "public_key",
        "digest", "digest_type", "digest_algorithm", "modified_on", "flags",
    )
    value: dict[str, object] = filter_keys(remote_data, skip_keys) if remote_data else {"status": status}

    def push() -> None:
        patch(f"zones/{zone_id}/dnssec", value)

    def remove() -> None:
        pass  # can't remove dnssec, only change status

    path: Path = ("zones", str(zone_name), "dnssec")
    set_tree(tree, path, value, push, remove)


def build_record_from_remote_data(
    zone_name: str,
    remote_data: dict[str, object],
) -> tuple[str, str, str, dict[str, object], str | None]:
    """Extract record fields from a remote record dict."""
    record_id = str(remote_data["id"])
    name_str = str(remote_data["name"])
    if name_str == zone_name:
        name = "@"
    elif name_str.endswith(f".{zone_name}"):
        name = name_str[: -(1 + len(zone_name))]
    else:
        name = name_str
    content = str(remote_data["content"])
    record_type = str(remote_data["type"])
    skip: tuple[str, ...] = ("id", "zone_id", "zone_name", "created_on", "modified_on", "meta", "proxiable")
    value: dict[str, object] = filter_keys(remote_data, skip)
    return name, content, record_type, value, record_id


def build_record_from_args(    zone_name: str,
    name: str,
    record_type: str,
    content: str,
    *,
    proxied: bool,
    priority: int | None,
    ttl: int,
) -> dict[str, object]:
    """Build a record value dict from explicit arguments."""
    if record_type in ("TXT", "MX"):
        proxied = False

    if name == zone_name:
        logger.warning("please use @ for the record name instead of %s", zone_name)

    content = quote(content)
    if record_type == "TXT":
        content = split_txt(content)
    full_name = zone_name if name == "@" else f"{name}.{zone_name}"

    value: dict[str, object] = {
        "content": content,
        "name": full_name,
        "proxied": proxied,
        "ttl": ttl,
        "type": record_type,
        "comment": None,
        "tags": [],
        "settings": {"flatten_cname": False} if record_type == "CNAME" else {},
    }
    if priority:
        value["priority"] = priority

    return value


def remove_dns_record(zone_id: str, record_id: str | None) -> None:
    """Delete a DNS record."""
    try:
        delete(f"zones/{zone_id}/dns_records/{record_id}")
    except RuntimeError as e:
        if "does not exist" in str(e):
            return
        raise


def make_record(    tree: ConfigTree,
    zone: dict[str, object],
    name: str | None = None,
    record_type: str | None = None,
    content: str | None = None,
    *,
    proxied: bool = True,
    priority: int | None = None,
    ttl: int = 1,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a DNS record node in the config tree."""
    from provider import set_tree
    zone_name = str(zone["name"])
    zone_id = str(zone["id"])
    record_id: str | None = None

    if remote_data:
        name, content, record_type, value, record_id = build_record_from_remote_data(zone_name, remote_data)
    else:
        if content is None:
            msg = f"{zone_name} record, missing content"
            raise ValueError(msg)
        if name is None:
            msg = f"{zone_name} record, missing name"
            raise ValueError(msg)
        if record_type is None:
            msg = f"{zone_name} record, missing type"
            raise ValueError(msg)
        value = build_record_from_args(
            zone_name, name, record_type, content,
            proxied=proxied, priority=priority, ttl=ttl,
        )
        content = str(value["content"])
        record_type = str(value["type"])

    def push() -> None:
        post(f"zones/{zone_id}/dns_records", value)

    def remove() -> None:
        remove_dns_record(zone_id, record_id)

    path: Path = ("zones", zone_name, "records", f"{name}/{record_type}/{content}")
    set_tree(tree, path, value, push, remove)


def build_srv_from_remote_data(
    zone_name: str,
    remote_data: dict[str, object],
) -> tuple[str, str, dict[str, object], str]:
    """Extract SRV record fields from a remote record dict."""
    record_id = str(remote_data["id"])
    name_str = str(remote_data["name"]).replace(f".{zone_name}", "")
    parts = name_str.split(".")
    service = parts[0]
    proto = parts[1] if len(parts) > 1 else ""
    data = remote_data["data"]
    target = str(data["target"])
    value: dict[str, object] = {
        "name": str(remote_data["name"]),
        "type": remote_data["type"],
        "data": {
            "service": service,
            "proto": proto,
            "name": zone_name,
            "priority": data["priority"],
            "weight": data["weight"],
            "port": data["port"],
            "target": target,
        },
        "ttl": remote_data["ttl"],
    }
    name = f"{service}.{proto}"
    return name, target, value, record_id


def make_srv_record(
    tree: ConfigTree,
    zone: dict[str, object],
    service: str | None = None,
    proto: str | None = None,
    target: str | None = None,
    port: int | None = None,
    priority: int = 10,
    weight: int = 10,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build an SRV DNS record node in the config tree."""
    from provider import set_tree
    zone_name = str(zone["name"])
    zone_id = zone["id"]
    record_id: str | None = None

    if remote_data:
        name, target, value, record_id = build_srv_from_remote_data(zone_name, remote_data)
    else:
        if service is None:
            msg = f"{zone_name} SRV record, missing service"
            raise ValueError(msg)
        if proto is None:
            msg = f"{zone_name} SRV record, missing proto"
            raise ValueError(msg)
        if target is None:
            msg = f"{zone_name} SRV record, missing target"
            raise ValueError(msg)
        if port is None:
            msg = f"{zone_name} SRV record, missing port"
            raise ValueError(msg)
        name = f"{service}.{proto}"
        value: dict[str, object] = {
            "name": f"{name}.{zone_name}",
            "type": "SRV",
            "data": {
                "service": service,
                "proto": proto,
                "name": zone_name,
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": target,
            },
            "ttl": 1,  # auto
        }

    def push() -> None:
        post(f"zones/{zone_id}/dns_records", value)

    def remove() -> None:
        delete(f"zones/{zone_id}/dns_records/{record_id}")

    path: Path = ("zones", zone_name, "records", f"{name}/SRV/{target}")
    set_tree(tree, path, value, push, remove)


def make_route(
    tree: ConfigTree,
    zone: dict[str, object],
    pattern: str | None = None,
    script: str | None = None,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a Workers route node in the config tree."""
    from provider import set_tree
    zone_name = str(zone["name"])
    zone_id = zone["id"]
    route_id: str | None = None

    if remote_data:
        route_id = str(remote_data["id"])
        pattern = str(remote_data["pattern"])
        value: dict[str, object] = filter_keys(remote_data, ("id",))
    else:
        if pattern is None:
            msg = f"{zone_name} route, missing pattern"
            raise ValueError(msg)
        if script is None:
            msg = f"{zone_name} route, missing script"
            raise ValueError(msg)
        value = {"pattern": pattern, "script": script, "request_limit_fail_open": False}

    def remove() -> None:
        delete(f"zones/{zone_id}/workers/routes/{route_id}")

    def push() -> None:
        post(f"zones/{zone_id}/workers/routes", value)

    path: Path = ("zones", zone_name, "routes", str(pattern))
    set_tree(tree, path, value, push, remove)


def get_redirect_rules(zone: dict[str, object]) -> dict[str, object] | None:
    """Fetch the redirect ruleset for a zone. Returns None if no ruleset exists."""
    try:
        result = get(f"zones/{zone['id']}/rulesets/phases/http_request_dynamic_redirect/entrypoint")
    except RuntimeError as e:
        if "not_found" in str(e).lower() or "could not find" in str(e).lower():
            return None
        raise
    if isinstance(result, dict):
        return result
    return None


def make_redirect_rule(    tree: ConfigTree,
    zone: dict[str, object],
    expression: str | None = None,
    target_url: str | None = None,
    status_code: int = 301,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a redirect rule node in the config tree."""
    from provider import set_tree
    zone_name = str(zone["name"])
    zone_id = zone["id"]
    rule_id: str | None = None

    if remote_data:
        expression = str(remote_data["expression"])
        rule_id = str(remote_data["id"])
        skip_keys = ("id", "ref", "version", "last_updated")
        value: dict[str, object] = filter_keys(remote_data, skip_keys)
    else:
        if expression is None:
            msg = f"{zone_name} redirect rule, missing expression"
            raise ValueError(msg)
        if target_url is None:
            msg = f"{zone_name} redirect rule, missing target_url"
            raise ValueError(msg)
        value = {
            "expression": expression,
            "action": "redirect",
            "action_parameters": {
                "from_value": {
                    "target_url": {"expression": target_url},
                    "status_code": status_code,
                    "preserve_query_string": True,
                },
            },
            "enabled": True,
        }

    def remove() -> None:
        ruleset = get_redirect_rules(zone)
        if ruleset and ruleset["rules"]:
            new_rules = [rule for rule in ruleset["rules"] if rule["id"] != rule_id]
            put(f"zones/{zone_id}/rulesets/{ruleset['id']}", {"rules": new_rules})

    def push() -> None:
        ruleset = get_redirect_rules(zone)
        if ruleset:
            existing_rules = [*ruleset["rules"], value]
            put(f"zones/{zone_id}/rulesets/{ruleset['id']}", {"rules": existing_rules})
        else:
            post(f"zones/{zone_id}/rulesets", {
                "name": "Redirect Rules",
                "kind": "zone",
                "phase": "http_request_dynamic_redirect",
                "rules": [value],
            })

    key = str(expression)
    path: Path = ("zones", zone_name, "redirect_rules", key)
    set_tree(tree, path, value, push, remove)


def make_page_domain(
    tree: ConfigTree,
    page_name: str,
    hostname: str | None = None,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a Pages custom domain node in the config tree."""
    from provider import set_tree
    skip_keys = (
        "id", "created_on", "status", "validation_data",
        "verification_data", "domain_id", "certificate_authority", "zone_tag",
    )
    if remote_data:
        hostname = str(remote_data["name"])
        value: dict[str, object] = filter_keys(remote_data, skip_keys)
    else:
        if hostname is None:
            msg = f"{page_name} page domain, missing hostname"
            raise ValueError(msg)
        value = {"name": hostname}

    def remove() -> None:
        delete(f"accounts/{state.account_id}/pages/projects/{page_name}/domains/{hostname}")

    def push() -> None:
        post(f"accounts/{state.account_id}/pages/projects/{page_name}/domains", value)

    path: Path = ("page_domains", page_name, str(hostname))
    set_tree(tree, path, value, push, remove)


def make_worker_domain(
    tree: ConfigTree,
    worker_name: str,
    zone: dict[str, object],
    hostname: str | None = None,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build a Workers custom domain node in the config tree."""
    from provider import set_tree
    zone_id = zone["id"]
    domain_id: str | None = None

    skip_keys = ("id", "zone_name", "cert_id")
    if remote_data:
        domain_id = str(remote_data["id"])
        hostname = str(remote_data["hostname"])
        value: dict[str, object] = filter_keys(remote_data, skip_keys)
    else:
        if hostname is None:
            msg = f"{worker_name} worker domain, missing hostname"
            raise ValueError(msg)
        value = {
            "hostname": hostname,
            "zone_id": zone_id,
            "service": worker_name,
            "environment": "production",
        }

    def remove() -> None:
        delete(f"accounts/{state.account_id}/workers/domains/{domain_id}")

    def push() -> None:
        put(f"accounts/{state.account_id}/workers/domains", value)

    path: Path = ("worker_domains", str(hostname))
    set_tree(tree, path, value, push, remove)


def make_email_routing_catch_all(
    tree: ConfigTree,
    zone: dict[str, object],
    forward_to: str | None = None,
    *,
    remote_data: dict[str, object] | None = None,
) -> None:
    """Build an email routing catch-all rule node in the config tree."""
    from provider import set_tree
    zone_name = str(zone["name"])
    zone_id = str(zone["id"])

    if remote_data:
        value: dict[str, object] = {
            "enabled": remote_data.get("enabled", False),
            "actions": remote_data.get("actions", []),
            "matchers": remote_data.get("matchers", []),
        }
    else:
        if forward_to is None:
            msg = f"{zone_name} email routing catch-all, missing forward_to"
            raise ValueError(msg)
        value = {
            "enabled": True,
            "actions": [{"type": "forward", "value": [forward_to]}],
            "matchers": [{"type": "all"}],
        }

    def push() -> None:
        try:
            post(f"zones/{zone_id}/email/routing/enable", {})
        except RuntimeError as e:
            if "already enabled" not in str(e).lower():
                raise
        put(f"zones/{zone_id}/email/routing/rules/catch_all", value)

    def remove() -> None:
        put(f"zones/{zone_id}/email/routing/rules/catch_all", {
            "enabled": False,
            "actions": [{"type": "drop"}],
            "matchers": [{"type": "all"}],
        })

    path: Path = ("zones", zone_name, "email_routing_catch_all")
    set_tree(tree, path, value, push, remove)


def ensure_destination_addresses(forward_addresses: set[str]) -> None:
    """Ensure all required email routing destination addresses exist at the account level."""
    existing = paginate(f"accounts/{state.account_id}/email/routing/addresses")
    verified = {addr["email"] for addr in existing if addr.get("verified")}
    pending = {addr["email"] for addr in existing if not addr.get("verified")}

    for address in forward_addresses:
        if address in verified:
            continue
        if address in pending:
            logger.warning("  destination %s is pending verification", address)
            continue
        logger.info("  creating destination address %s...", address)
        post(f"accounts/{state.account_id}/email/routing/addresses", {"email": address})
        logger.warning("  destination %s needs verification - check inbox", address)


# Fetchers
def paginate(url: str) -> list[dict[str, object]]:
    """Fetch all pages from a paginated Cloudflare API endpoint."""
    import requests
    results: list[dict[str, object]] = []
    page = 1
    separator = "&" if "?" in url else "?"
    while page < MAX_PAGES:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/{url}{separator}per_page={PER_PAGE}&page={page}",
            headers=state.headers,
            timeout=30,
        )
        if response.status_code not in (HTTP_OK, HTTP_CREATED):
            try:
                detail = response.json()["errors"]
            except (KeyError, ValueError):
                detail = response.text[:200]
            msg = f"paginate {url} page {page}: {detail}"
            raise RuntimeError(msg)
        body = response.json()
        data: list[dict[str, object]] = body["result"]
        if not data:
            break
        results.extend(data)
        if "result_info" not in body:
            break
        info = body["result_info"]
        total_pages = (
            info["total_pages"]
            if "total_pages" in info
            else -(-info["total_count"] // info["per_page"])
        )
        if page >= total_pages:
            break
        page += 1
    return results


def fetch_zone(
    remote: ConfigTree,
    zone: dict[str, object],
    setting_ids: set[str],
    all_missing: set[str],
) -> None:
    """Fetch and process all remote state for a single zone."""
    zone_id = zone["id"]

    records = paginate(f"zones/{zone_id}/dns_records")
    routes = paginate(f"zones/{zone_id}/workers/routes")
    settings = paginate(f"zones/{zone_id}/settings")
    dnssec = get(f"zones/{zone_id}/dnssec")

    zone["settings"] = {setting["id"]: setting for setting in settings}
    zone["dnssec"] = dnssec

    for record in records:
        if record["type"] == "AAAA" and str(record["content"]).startswith("100::"):
            continue
        if record.get("meta", {}).get("auto_added"):
            continue
        if record.get("locked"):
            continue
        if record["type"] == "SRV":
            make_srv_record(remote, zone, remote_data=record)
        else:
            make_record(remote, zone, remote_data=record)
    for route in routes:
        make_route(remote, zone, remote_data=route)

    try:
        catch_all = get(f"zones/{zone_id}/email/routing/rules/catch_all")
        if isinstance(catch_all, dict) and catch_all.get("enabled"):
            make_email_routing_catch_all(remote, zone, remote_data=catch_all)
    except RuntimeError as e:
        if "not_found" not in str(e).lower() and "not enabled" not in str(e).lower():
            raise
        # email routing not enabled for this zone

    for setting in zone["settings"].values():
        if setting["editable"] and setting["id"] in setting_ids:
            make_setting(remote, zone, remote_data=setting)
        elif setting["editable"]:
            all_missing.add(str(setting["id"]))
        else:
            pass  # non-editable setting, skip
    if zone.get("dnssec"):
        make_dnssec(remote, zone, remote_data=zone["dnssec"])
    redirect_ruleset = get_redirect_rules(zone)
    if redirect_ruleset and redirect_ruleset.get("rules"):
        for rule in redirect_ruleset["rules"]:
            make_redirect_rule(remote, zone, remote_data=rule)

def fetch_all(
    setting_ids: set[str],
    zone_list: list[dict[str, object]] | None = None,
) -> tuple[ConfigTree, dict[str, dict[str, object]], dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    """Fetch everything from remote. Returns (remote, zones, workers, pages)."""
    remote: ConfigTree = {}

    logger.info("  fetching zones...")
    if zone_list is None:
        zone_list = paginate("zones")
    zones: dict[str, dict[str, object]] = {zone["id"]: zone for zone in zone_list}
    logger.info("  fetching workers...")
    workers: dict[str, dict[str, object]] = {
        worker["id"]: worker for worker in paginate(f"accounts/{state.account_id}/workers/scripts")
    }
    logger.info("  fetching pages...")
    pages: dict[str, dict[str, object]] = {
        project["name"]: project for project in paginate(f"accounts/{state.account_id}/pages/projects")
    }

    logger.info("  fetching page domains...")
    for page in pages.values():
        for domain in paginate(
            f"accounts/{state.account_id}/pages/projects/{page['name']}/domains",
        ):
            make_page_domain(remote, str(page["name"]), remote_data=domain)

    logger.info("  fetching zone details...")
    all_missing: set[str] = set()
    for zone in zones.values():
        logger.info("    %s", zone["name"])
        fetch_zone(remote, zone, setting_ids, all_missing)
    for setting_id in sorted(all_missing):
        logger.info("  missing setting: %s", setting_id)

    logger.info("  %d zones, %d workers, %d pages", len(zones), len(workers), len(pages))

    logger.info("  fetching worker domains...")
    for worker_domain in paginate(f"accounts/{state.account_id}/workers/domains"):
        for zone in zones.values():
            if zone["id"] == worker_domain["zone_id"]:
                make_worker_domain(remote, str(worker_domain["service"]), zone, remote_data=worker_domain)
                break

    return remote, zones, workers, pages
