from __future__ import annotations

import os
from typing import Any, Callable, Generator, Literal, TypedDict

import requests


# Type definitions
class LeafNode(TypedDict):
    value: Any
    push: Callable[[], None]
    remove: Callable[[], None]


ConfigTree = dict[str, "ConfigTree | LeafNode"]
Path = tuple[str, ...]
Diff = tuple[Literal["remove", "push", "update"], Path, LeafNode]

# Global state
cloud: ConfigTree = {}
local: ConfigTree = {}
zones: dict[str, dict[str, Any]] = {}
workers: dict[str, dict[str, Any]] = {}
pages: dict[str, dict[str, Any]] = {}
missing_settings: set[str] = set()


# Tree utilities for nested config structure
def set_tree(
    tree: ConfigTree,
    path: Path,
    value: ConfigValue,
    push_fn: Callable[[], None],
    remove_fn: Callable[[], None],
) -> None:
    """Set a value at a path in a nested dict tree."""
    for key in path[:-1]:
        if key not in tree:
            tree[key] = {}
        tree = tree[key]  # type: ignore
    tree[path[-1]] = {"value": value, "push": push_fn, "remove": remove_fn}


def diff_trees(
    cloud: ConfigTree, local: ConfigTree, path: Path = ()
) -> Generator[Diff, None, None]:
    """Yield (action, path, node) for all differences between trees."""
    cloud_keys = set(cloud.keys()) if isinstance(cloud, dict) else set()
    local_keys = set(local.keys()) if isinstance(local, dict) else set()

    # In cloud but not local -> remove
    for key in cloud_keys - local_keys:
        node = cloud[key]
        if "value" in node:
            yield ("remove", path + (key,), node)  # type: ignore
        else:
            yield from diff_trees(node, {}, path + (key,))  # type: ignore

    # In local but not cloud -> push
    for key in local_keys - cloud_keys:
        node = local[key]
        if "value" in node:
            yield ("push", path + (key,), node)  # type: ignore
        else:
            yield from diff_trees({}, node, path + (key,))  # type: ignore

    # In both -> recurse or compare values
    for key in cloud_keys & local_keys:
        cloud_node = cloud[key]
        local_node = local[key]
        if "value" in cloud_node and "value" in local_node:
            # Leaf nodes - compare values
            if cloud_node["value"] != local_node["value"]:
                yield ("update", path + (key,), local_node)  # type: ignore
        elif "value" not in cloud_node and "value" not in local_node:
            # Both are intermediate nodes - recurse
            yield from diff_trees(cloud_node, local_node, path + (key,))  # type: ignore
        else:
            # Mismatch: one is leaf, one is intermediate (shouldn't happen)
            if "value" in cloud_node:
                yield ("remove", path + (key,), cloud_node)  # type: ignore
            if "value" in local_node:
                yield ("push", path + (key,), local_node)  # type: ignore


# DNS constants
ADDRESS, CNAME, TEXT, MAIL = "A", "CNAME", "TXT", "MX"
PROXIED, UNPROXIED = True, False
ROOT, WWW = "@", "www"
AUTO, RESPECT_HEADERS = 1, 0
ONE_WEEK, TWO_HOURS = 604800, 7200

VPS: str | None = os.getenv("VPS")

CLOUDFLARE_ACCOUNT_ID: str | None = os.getenv("CLOUDFLARE_ACCOUNT_ID")
CLOUDFLARE_API_TOKEN: str | None = os.getenv("CLOUDFLARE_API_TOKEN")

CLOUDFLARE_HEADERS: dict[str, str] = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "Content-Type": "application/json",
}

def perform(method: str, url: str, json: dict[str, Any] | None = None) -> Any | Literal[False]:
    response = getattr(requests, method)(
        f"https://api.cloudflare.com/client/v4/{url}",
        headers=CLOUDFLARE_HEADERS,
        json=json,
    )
    if response.status_code in (200, 204):
        if not response.text:
            return True
        return response.json().get("result", True)
    else:
        try:
            errors = response.json().get("errors", [])
            print(f"  API error: {errors}")
        except:
            print(f"  API error: {response.status_code} {response.text[:200]}")
        return False


def delete(url: str) -> Any | Literal[False]:
    return perform("delete", url)


def get(url: str) -> Any | Literal[False]:
    return perform("get", url)


def patch(url: str, data: dict[str, Any]) -> Any | Literal[False]:
    return perform("patch", url, data)


def post(url: str, data: dict[str, Any]) -> Any | Literal[False]:
    return perform("post", url, data)


def put(url: str, data: dict[str, Any]) -> Any | Literal[False]:
    return perform("put", url, data)


# Settings overrides
overrides: dict[str, Any] = {
    "0rtt": "on",  # Extra performance
    "always_online": "off",  # This is cool, but bad for debugging.
    "always_use_https": "off",  # Never always do anything.
    "automatic_https_rewrites": "off",
    "brotli": "on",  # Transparent
    "browser_check": "off",
    "development_mode": "off",
    "early_hints": "off",
    "email_obfuscation": "off",  # Stupid
    "filter_logs_to_cloudflare": "off",
    "hotlink_protection": "off",  # Stupid
    "http3": "on",  # Support HTTP/3
    "ip_geolocation": "on",
    "ipv6": "on",  # Support IPv6
    "log_to_cloudflare": "on",
    "opportunistic_encryption": "off",
    "opportunistic_onion": "off",
    "pq_keyex": "off",
    "privacy_pass": "off",
    "pseudo_ipv4": "off",  # Pseudo-stuff isn't good.
    "replace_insecure_js": "off",
    "rocket_loader": "off",
    "server_side_exclude": "off",
    "ssl": "flexible",
    "tls_1_2_only": "off",  # Don't force stuff.
    "tls_1_3": "zrt",  # More support (zrt = on + 0rtt)
    "tls_client_auth": "off",
    "visitor_ip": "on",
    "waf": "off",
    "websockets": "on",
    "ech": "off",
    "orange_to_orange": "off",
    "response_buffering": "off",
    "mirage": "off",
    "webp": "off",
    "polish": "off",
    "prefetch_preload": "off",
    "http2": "on",
    "true_client_ip_header": "off",
    "origin_error_page_pass_thru": "off",
    "sort_query_string_for_cache": "off",
    "proxy_read_timeout": 100,
    "long_lived_grpc": "off",
    "advanced_ddos": "off",
    "cache_level": "aggressive",
    "cname_flattening": "flatten_at_root",
    "min_tls_version": "1.0",  # This is supposed to be a string.
    "security_level": "essentially_off",
    "browser_cache_ttl": RESPECT_HEADERS,
    "challenge_ttl": ONE_WEEK,
    "edge_cache_ttl": TWO_HOURS,
    "max_upload": 100,  # This is supposed to be a number for some reason.
    "minify": {"css": "off", "html": "off", "js": "off"},
    "mobile_redirect": {"status": "off", "mobile_subdomain": None, "strip_uri": False},
    "security_header": {
        "strict_transport_security": {
            "enabled": False,
            "max_age": 0,
            "include_subdomains": False,
            "preload": False,
            "nosniff": False,
        }
    },
    "ciphers": [],
    "origin_max_http_version": "1",
}

# Zone-specific configuration overrides
ZONE_CONFIG: dict[str, dict[str, Any]] = {
    "hiroshimajobnavi.com": {
        "address": "34.111.141.225",
        "ssl": "full",
    },
    "bestratereview.com": {
        "google_verification": "1O4KHQCY_QaBmRlMHA_WUU3LGeqjmKr_4JN25L5_ybQ",
        "mail_server": "smtp.google.com",
    },
    "clarkn.co.jp": {
        "google_verification": "ZsBDgLNcr70Rc7e6dF47J7pbLp435l1CF-hHyf6EaQM",
        "mail_server": "smtp.google.com",
    },
    "southtowntattoocollective.com": {
        "redirect_to": "tattoocollectivereno.com",
        "short_name": "tattoocollectivereno",
    },
    "vec4me.com": {
        "index_redirect": True,
    },
}

# Email routing targets by zone name
EMAIL_TARGETS: dict[str, str] = {
    "tattoocollectivereno.com": "tattoocollectivereno@gmail.com",
    "southtowntattoocollective.com": "tattoocollectivereno@gmail.com",
    "je.gy": "vec4me@icloud.com",
}
EMAIL_DEFAULT = "jeff@je.gy"
EMAIL_BRR = "brr"

# Address for brr child zones
BRR_ADDRESS = "35.192.114.80"

CLOUDFLARE_DKIM = (
    '"v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA'
    'iweykoi+o48IOGuP7GR3X0MOExCUDY/BCRHoWBnh3rChl7WhdyCxW3jgq1daEjPPqoi7sJvdg5hE'
    'QVsgVRQP4DcnQDVjGMbASQtrY4WmB1VebF+RPJB2ECPsEDTpeiI5ZyUAwJaVX7r6bznU67g7LvFq'
    '35yIo4sdlmtZGV+i0H4cpYH9+3JJ78k" "m4KXwaf9xUJCWF6nxeD+qG6Fyruw1Qlbds2r85U9dk'
    'NDVAS3gioCvELryh1TxKGiVTkg4wqHTyHfWsp7KD3WQHYJn0RyfJJu6YEmL77zonn7p2SRMvTMP3'
    'ZEXibnC9gz3nnhR6wcYL8Q7zXypKTMD58bTixDSJwIDAQAB"'
)


def make_setting(
    zone: dict[str, Any],
    setting_id: str | None = None,
    setting_value: ConfigValue = None,
    cloudee: dict[str, Any] | None = None,
) -> None:
    zone_name = zone["name"]
    zone_id = zone["id"]

    if cloudee:
        setting_id = cloudee["id"]
        value = {k: v for k, v in cloudee.items() if k not in ("editable", "modified_on", "certificate_status", "validation_errors", "time_remaining")}
    else:
        assert setting_id is not None, f"{zone_name} setting, missing id"
        value = {"id": setting_id, "value": setting_value}

    def push() -> None:
        patch(f"zones/{zone_id}/settings/{setting_id}", value)

    def remove() -> None:
        pass  # can't remove a setting, only change it

    path: Path = ("zones", zone_name, "settings", setting_id)  # type: ignore
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def make_dnssec(
    zone: dict[str, Any],
    status: str = "disabled",
    cloudee: dict[str, Any] | None = None,
) -> None:
    zone_name = zone["name"]
    zone_id = zone["id"]

    if cloudee:
        value = {k: v for k, v in cloudee.items() if k not in ("ds", "key_tag", "algorithm", "key_type", "public_key", "digest", "digest_type", "digest_algorithm", "modified_on", "flags")}
    else:
        value = {"status": status}

    def push() -> None:
        patch(f"zones/{zone_id}/dnssec", value)

    def remove() -> None:
        pass  # can't remove dnssec, only change status

    path: Path = ("zones", zone_name, "dnssec")
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def make_record(
    zone: dict[str, Any],
    name: str | None = None,
    content: str | None = None,
    type: str | None = None,
    proxied: bool = PROXIED,
    priority: int | None = None,
    ttl: int = AUTO,
    cloudee: dict[str, Any] | None = None,
) -> None:
    zone_name = zone["name"]
    zone_id = zone["id"]
    record_id: str | None = None

    if cloudee:
        record_id = cloudee["id"]
        # Normalize name for the key
        if cloudee["name"] == zone_name:
            name = ROOT
        elif cloudee["name"] and cloudee["name"].endswith(f".{zone_name}"):
            name = cloudee["name"][0 : -(1 + len(zone_name))]
        else:
            name = cloudee["name"]
        content = cloudee["content"]
        type = cloudee["type"]
        # Filter priority for MX records (managed by Email Routing)
        skip = ("id", "zone_id", "zone_name", "created_on", "modified_on", "meta", "comment", "tags", "proxiable", "settings")
        if cloudee["type"] == "MX":
            skip = (*skip, "priority")
        value = {k: v for k, v in cloudee.items() if k not in skip}
    else:
        assert content is not None, f"{zone_name} record, missing content"

        if type is None:
            if ipv4_address(content):
                type = ADDRESS
            elif weird(content):
                type = TEXT
            else:
                type = CNAME

        if type in (TEXT, MAIL):
            proxied = UNPROXIED

        if name == zone_name:
            print(f"please use @ for the record name instead of {zone_name}")

        content = quote_if_weird(content)
        full_name = zone_name if name == ROOT else f"{name}.{zone_name}"

        assert name is not None, f"{zone_name} record, missing name"
        assert type is not None, f"{zone_name} record, missing type"

        value = {
            "content": content,
            "name": full_name,
            "proxied": proxied,
            "ttl": ttl,
            "type": type,
        }
        # Don't include priority for MX (managed by Email Routing)
        if priority is not None and type != MAIL:
            value["priority"] = priority

    def push() -> None:
        post(f"zones/{zone_id}/dns_records", value)

    def remove() -> None:
        delete(f"zones/{zone_id}/dns_records/{record_id}")

    path: Path = ("zones", zone_name, "records", f"{name}/{type}/{content}")
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def make_route(
    zone: dict[str, Any],
    pattern: str | None = None,
    script: str | None = None,
    cloudee: dict[str, Any] | None = None,
) -> None:
    zone_name = zone["name"]
    zone_id = zone["id"]
    route_id: str | None = None

    if cloudee:
        route_id = cloudee["id"]
        pattern = cloudee["pattern"]
        value = {k: v for k, v in cloudee.items() if k not in ("id", "request_limit_fail_open")}
    else:
        assert pattern is not None, f"{zone_name} route, missing pattern"
        assert script is not None, f"{zone_name} route, missing script"
        value = {"pattern": pattern, "script": script}

    def remove() -> None:
        delete(f"zones/{zone_id}/workers/routes/{route_id}")

    def push() -> None:
        post(f"zones/{zone_id}/workers/routes", value)

    path: Path = ("zones", zone_name, "routes", pattern)  # type: ignore
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def make_rule(
    zone: dict[str, Any],
    target: str | None = None,
    enabled: bool = True,
    cloudee: dict[str, Any] | None = None,
) -> None:
    zone_name = zone["name"]
    zone_id = zone["id"]
    rule_id: str | None = None

    if cloudee:
        rule_id = cloudee["id"]
        actions = cloudee.get("actions", [])
        if actions and len(actions) > 0:
            action = actions[0]
            if action.get("type") != "drop" and action.get("value"):
                target = action["value"][0]
        if target is None:
            return  # Skip "drop" rules or rules without targets
        value = {k: v for k, v in cloudee.items() if k not in ("id", "tag", "name", "priority")}
    else:
        if target is None:
            return
        value = {
            "matchers": [{"type": "all"}],
            "actions": [
                {
                    "type": "forward" if "@" in target else "worker",
                    "value": [target],
                }
            ],
            "enabled": enabled,
        }

    def remove() -> None:
        delete(f"zones/{zone_id}/email/routing/rules/{rule_id}")

    def push() -> None:
        post(f"zones/{zone_id}/email/routing/rules", value)

    path: Path = ("zones", zone_name, "email_rules", target)  # type: ignore
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def make_email_routing(zone: dict[str, Any], target: str) -> None:
    """Create email rule and required Cloudflare MX/DKIM records."""
    make_rule(zone, target=target)
    # Cloudflare email routing requires these MX records
    make_record(zone, ROOT, "route1.mx.cloudflare.net", MAIL, UNPROXIED, priority=84)
    make_record(zone, ROOT, "route2.mx.cloudflare.net", MAIL, UNPROXIED, priority=5)
    make_record(zone, ROOT, "route3.mx.cloudflare.net", MAIL, UNPROXIED, priority=2)
    # Cloudflare DKIM record
    make_record(zone, "cf2024-1._domainkey", CLOUDFLARE_DKIM)


def get_redirect_rules(zone: dict[str, Any]) -> dict[str, Any] | None:
    return get(f"zones/{zone['id']}/rulesets/phases/http_request_dynamic_redirect/entrypoint") or None


def make_redirect_rule(
    zone: dict[str, Any],
    expression: str | None = None,
    target_url: str | None = None,
    status_code: int = 301,
    cloudee: dict[str, Any] | None = None,
) -> None:
    zone_name = zone["name"]
    zone_id = zone["id"]
    id: str | None = None

    if cloudee:
        expression = cloudee["expression"]
        id = cloudee["id"]
        # Copy exactly what Cloudflare gave us, minus id/ref/version
        value = {k: v for k, v in cloudee.items() if k not in ("id", "ref", "version", "last_updated")}
    else:
        assert expression is not None, f"{zone_name} redirect rule, missing expression"
        assert target_url is not None, f"{zone_name} redirect rule, missing target_url"
        # Build exactly what Cloudflare would store
        value = {
            "expression": expression,
            "action": "redirect",
            "action_parameters": {
                "from_value": {
                    "target_url": {"expression": target_url},
                    "status_code": status_code,
                    "preserve_query_string": True,
                }
            },
            "enabled": True,
        }

    def remove() -> None:
        ruleset = get_redirect_rules(zone)
        if ruleset and ruleset.get("rules"):
            new_rules = [r for r in ruleset["rules"] if r["id"] != id]
            put(f"zones/{zone_id}/rulesets/{ruleset['id']}", {"rules": new_rules})

    def push() -> None:
        ruleset = get_redirect_rules(zone)
        if ruleset and ruleset.get("id"):
            existing_rules = list(ruleset.get("rules", []))
            existing_rules.append(value)
            put(f"zones/{zone_id}/rulesets/{ruleset['id']}", {"rules": existing_rules})
        else:
            post(f"zones/{zone_id}/rulesets", {
                "name": "Redirect Rules",
                "kind": "zone",
                "phase": "http_request_dynamic_redirect",
                "rules": [value],
            })

    key = expression or cloudee["expression"]  # type: ignore
    path: Path = ("zones", zone_name, "redirect_rules", key)
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def get_workers() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    page = 1
    while page < 100:
        data = get(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/workers/scripts?page={page}")
        if not data:
            break
        before = len(result)
        for worker in data:
            result[worker["id"]] = worker
        if len(result) == before:  # no new workers
            break
        page += 1
    return result


def get_pages() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    page = 1
    while page < 100:
        data = get(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects?page={page}")
        if not data:
            break
        before = len(result)
        for p in data:
            result[p["name"]] = p
        if len(result) == before:  # no new pages
            break
        page += 1
    return result


def get_worker_domains() -> list[dict[str, Any]]:
    result = get(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/workers/domains")
    return result if result else []


def get_zones() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    page = 1
    while data := get(f"zones?per_page=69&page={page}"):
        for zone in data:
            result[zone["id"]] = zone
        if len(data) < 69:
            break
        page += 1
    return result


def fetch_all() -> None:
    """Fetch everything from cloud."""
    global zones, workers, pages, cloud, missing_settings
    cloud = {}
    missing_settings = set()

    print("  fetching zones...")
    zones = get_zones()
    print("  fetching workers...")
    workers = get_workers()
    print("  fetching pages...")
    pages = get_pages()

    # Fetch page domains
    print("  fetching page domains...")
    for page in pages.values():
        domains = get(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects/{page['name']}/domains")
        page["domains"] = domains if domains else []
        for domain in page["domains"]:
            make_page_domain(page["name"], cloudee=domain)

    # Fetch zone details
    print("  fetching zone details...")
    for zone in zones.values():
        zone_name = zone["name"]
        zone_id = zone["id"]

        records = get(f"zones/{zone_id}/dns_records") or []
        routes = get(f"zones/{zone_id}/workers/routes") or []
        rules = get(f"zones/{zone_id}/email/routing/rules") or []
        settings = get(f"zones/{zone_id}/settings") or []
        dnssec = get(f"zones/{zone_id}/dnssec") or {}

        zone["records"] = {r["id"]: r for r in records}
        zone["routes"] = {r["id"]: r for r in routes}
        zone["rules"] = {r["id"]: r for r in rules}
        zone["settings"] = {s["id"]: s for s in settings}
        zone["dnssec"] = dnssec

        for record in records:
            if record["type"] == "AAAA" and record["content"].startswith("100::"):
                continue  # Skip Cloudflare pseudo IPv6 addresses
            make_record(zone, cloudee=record)
        for route in routes:
            make_route(zone, cloudee=route)
        for rule in rules:
            make_rule(zone, cloudee=rule)
        for setting in settings:
            if setting.get("editable") and setting["id"] in overrides:
                make_setting(zone, cloudee=setting)
            elif setting.get("editable") and setting["id"] not in overrides:
                missing_settings.add(setting["id"])
        if dnssec:
            make_dnssec(zone, cloudee=dnssec)

        redirect_ruleset = get_redirect_rules(zone)
        if redirect_ruleset and redirect_ruleset.get("rules"):
            for rule in redirect_ruleset["rules"]:
                make_redirect_rule(zone, cloudee=rule)

    # Fetch worker domains
    print("  fetching worker domains...")
    for wd in get_worker_domains():
        for zone in zones.values():
            if zone["id"] == wd["zone_id"]:
                make_worker_domain(wd["service"], zone, cloudee=wd)
                break


def build_local_config(used_services: set[str]) -> None:
    """Build local (desired) configuration for all zones."""
    global local
    local = {}

    print("  building local config...")
    for zone in zones.values():
        configure_email(zone)
        configure_dns(zone)
        configure_redirects(zone)
        configure_domains(zone, used_services)
        configure_settings_local(zone)


def configure_settings_local(zone: dict[str, Any]) -> None:
    """Build local settings config (only for settings that exist in zone)."""
    for setting_id, setting in zone.get("settings", {}).items():
        if setting.get("editable") and setting_id in overrides:
            value = overrides[setting_id]
            zone_override = get_zone_config(zone, setting_id)
            if zone_override is not None:
                value = zone_override
            make_setting(zone, setting_id, value)
    # DNSSEC should always be disabled
    if zone.get("dnssec"):
        make_dnssec(zone, "disabled")


def quote_if_weird(string: str) -> str:
    if weird(string):
        return quote(string)
    return string


def ipv4_address(string: str) -> bool:
    parts = string.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def number(zone: dict[str, Any]) -> bool:
    parts = zone["name"].split(".")
    return all(part.isdigit() for part in parts[0] if part)


def standard(zone: dict[str, Any]) -> bool:
    return not number(zone) and zone["name"].split(".")[-1] in {"com", "net", "org", "jp"}


def vowel_consonant_boundary(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return (a[-1].lower() in "aeiou") != (b[0].lower() in "aeiou")


def short(zone: dict[str, Any]) -> str:
    parts = zone["name"].split(".")

    # Numeric zones -> just return first part
    if number(zone):
        return parts[0]

    # Standard zones (.com, .net, .org, .jp) -> just return first part
    if standard(zone):
        return parts[0]

    # Non-standard zones: use vowel/consonant boundary logic
    first = parts[0]
    rest = "".join(parts[1:])
    if vowel_consonant_boundary(first, rest):
        return first + rest
    return first


def pair(zone: dict[str, Any]) -> tuple[str, str]:
    www, root = f"www.{zone['name']}", zone["name"]
    return (www, root) if standard(zone) else (root, www)


def quoted(string: str) -> bool:
    return string[0] == '"' and string[-1] == '"'


def quote(string: str) -> str:
    return string if quoted(string) else f'"{string}"'


def weird(string: str) -> bool:
    return "=" in string


def brr_child(zone: dict[str, Any]) -> bool:
    return "rate" in zone["name"] and zone["name"] != "bestratereview.com"


def zone_short_name(zone: dict[str, Any]) -> str:
    """Get the short name used to match workers/pages for this zone."""
    return ZONE_CONFIG.get(zone["name"], {}).get("short_name", short(zone))


def find_service(collection: dict[str, Any], name: str, suffixes: list[str]) -> str | None:
    """Find a service by name with optional suffixes."""
    for suffix in suffixes:
        key = f"{name}{suffix}" if suffix else name
        if key in collection:
            return key
    return None


def zone_worker(zone: dict[str, Any]) -> str | None:
    """Returns the worker id if this zone is served by a Worker."""
    return find_service(workers, zone_short_name(zone), ["", "-website"])


def zone_page(zone: dict[str, Any]) -> str | None:
    """Returns the page id if this zone is served by a Page."""
    return find_service(pages, zone_short_name(zone), ["", "-website"])


def zone_api_worker(zone: dict[str, Any]) -> str | None:
    """Returns the API worker id (-api suffix, or exact match fallback)."""
    return find_service(workers, zone_short_name(zone), ["-api", ""])


def zone_type(zone: dict[str, Any]) -> Literal["worker", "page"] | None:
    """Returns 'worker', 'page', or None based on what serves this zone."""
    if zone_worker(zone):
        return "worker"
    if zone_page(zone):
        return "page"
    return None  # Falls back to VPS/origin


def make_page_domain(
    page_name: str,
    hostname: str | None = None,
    cloudee: dict[str, Any] | None = None,
) -> None:
    if cloudee:
        hostname = cloudee["name"]
        value = {k: v for k, v in cloudee.items() if k not in ("id", "created_on", "status", "validation_data", "verification_data", "domain_id", "certificate_authority", "zone_tag")}
    else:
        assert hostname is not None, f"{page_name} page domain, missing hostname"
        value = {"name": hostname}

    def remove() -> None:
        delete(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects/{page_name}/domains/{hostname}")

    def push() -> None:
        post(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects/{page_name}/domains", value)

    path: Path = ("page_domains", page_name, hostname)  # type: ignore
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def make_worker_domain(
    worker_name: str,
    zone: dict[str, Any],
    hostname: str | None = None,
    cloudee: dict[str, Any] | None = None,
) -> None:
    zone_id = zone["id"]
    domain_id: str | None = None

    if cloudee:
        domain_id = cloudee["id"]
        hostname = cloudee["hostname"]
        value = {k: v for k, v in cloudee.items() if k not in ("id", "zone_name", "cert_id")}
    else:
        assert hostname is not None, f"{worker_name} worker domain, missing hostname"
        value = {
            "hostname": hostname,
            "zone_id": zone_id,
            "service": worker_name,
            "environment": "production",
        }

    def remove() -> None:
        delete(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/workers/domains/{domain_id}")

    def push() -> None:
        put(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/workers/domains", value)

    path: Path = ("worker_domains", hostname)  # type: ignore
    tree = cloud if cloudee else local
    set_tree(tree, path, value, push, remove)


def get_cloud_node(path: Path) -> LeafNode | None:
    """Get the cloud node at a path."""
    tree = cloud
    for key in path[:-1]:
        if key not in tree:
            return None
        tree = tree[key]  # type: ignore
    node = tree.get(path[-1])
    return node if node and "value" in node else None  # type: ignore


def run_deltas() -> None:
    diffs: list[Diff] = list(diff_trees(cloud, local))

    if not diffs:
        print("no changes")
        return

    for action, path, node in diffs:
        path_str = "/".join(path)
        if action == "remove":
            print(f"remove: {path_str}")
        elif action == "push":
            print(f"push: {path_str} = {node['value']}")
        elif action == "update":
            cloud_node = get_cloud_node(path)
            print(f"update: {path_str}")
            print(f"  cloud: {cloud_node['value'] if cloud_node else None}")
            print(f"  local: {node['value']}")

    confirm = input("\nproceed with writes? [y/N] ")
    if confirm.lower() != "y":
        print("aborted")
        return

    for action, path, node in diffs:
        if action == "remove":
            node["remove"]()
        elif action == "push":
            node["push"]()
        elif action == "update":
            # For updates: remove old, then push new
            cloud_node = get_cloud_node(path)
            if cloud_node:
                cloud_node["remove"]()
            node["push"]()


def get_zone_config(zone: dict[str, Any], key: str, default: Any = None) -> Any:
    """Get a zone-specific config value, or default if not set."""
    return ZONE_CONFIG.get(zone["name"], {}).get(key, default)


def configure_email(zone: dict[str, Any]) -> None:
    """Configure email routing for a zone."""
    config = ZONE_CONFIG.get(zone["name"], {})

    # Zones with custom mail servers (Google Workspace, etc.) don't use Cloudflare email routing
    if "mail_server" in config:
        if "google_verification" in config:
            make_record(zone, ROOT, f"google-site-verification={config['google_verification']}")
        make_record(zone, ROOT, config["mail_server"], MAIL, UNPROXIED, priority=1)
        return

    # Determine email target
    if brr_child(zone):
        target = EMAIL_BRR
    else:
        target = EMAIL_TARGETS.get(zone["name"], EMAIL_DEFAULT)

    make_email_routing(zone, target=target)


def configure_dns(zone: dict[str, Any]) -> None:
    """Configure DNS records for a zone."""
    ztype = zone_type(zone)
    first, second = pair(zone)

    # Determine address
    address = get_zone_config(zone, "address")
    if not address:
        if "rate" in zone["name"]:
            address = BRR_ADDRESS
        else:
            address = VPS

    # DNS records for root/www
    if ztype == "page":
        # Pages need CNAME records pointing to pages.dev
        # Use short name (without -website suffix) for the pages.dev target
        pages_target = f"{zone_short_name(zone)}.pages.dev"
        if standard(zone):
            make_record(zone, WWW, pages_target)
            make_record(zone, ROOT, pages_target)
        else:
            make_record(zone, ROOT, pages_target)
            make_record(zone, WWW, pages_target)
    elif ztype != "worker":
        # Workers Domains API handles DNS automatically; VPS zones need A records
        if standard(zone):
            make_record(zone, WWW, address)
            make_record(zone, ROOT, address)
        else:
            make_record(zone, ROOT, address)
            make_record(zone, WWW, address)

    # Mail records (SPF, DMARC)
    make_record(
        zone,
        ROOT,
        "v=spf1 include:icloud.com include:_spf.mx.cloudflare.net include:_spf.google.com ~all",
    )
    make_record(zone, "_dmarc", "v=DMARC1; p=quarantine;")

    # Mail tracking (unsubscribes, etc.)
    make_record(zone, "mail", "mail.vec4me.workers.dev")
    make_route(zone, f"mail.{zone['name']}/unsubscribe*", "mail")

    # API subdomain (for zones with a corresponding -api worker)
    api_worker = zone_api_worker(zone)
    if api_worker:
        make_record(zone, "api", f"{api_worker}.vec4me.workers.dev")
        make_route(zone, f"api.{zone['name']}/*", api_worker)


def configure_redirects(zone: dict[str, Any]) -> None:
    """Configure redirect rules for a zone."""
    first, second = pair(zone)
    config = ZONE_CONFIG.get(zone["name"], {})

    # Standard redirects: second -> first, fbclid cleanup
    make_redirect_rule(
        zone,
        f'(http.host eq "{second}")',
        f'concat("https://{first}", http.request.uri.path)'
    )
    make_redirect_rule(
        zone,
        f'(http.host eq "{first}" and starts_with(http.request.uri.path, "/fbclid"))',
        f'concat("https://{first}/", "")'
    )

    # Zone-specific redirects
    if config.get("index_redirect"):
        make_redirect_rule(
            zone,
            f'(http.host eq "{first}" and http.request.uri.path eq "/")',
            f'concat("https://{first}/index.htm", "")'
        )
    elif "redirect_to" in config:
        target = config["redirect_to"]
        make_redirect_rule(
            zone,
            f'(http.host eq "www.{zone["name"]}")',
            f'concat("https://www.{target}", http.request.uri.path)'
        )
        make_redirect_rule(
            zone,
            f'(http.host eq "{zone["name"]}")',
            f'concat("https://{target}", http.request.uri.path)'
        )
    elif brr_child(zone):
        make_redirect_rule(
            zone,
            f'(http.host eq "www.{zone["name"]}")',
            'concat("https://www.bestratereview.com", http.request.uri.path)'
        )
        make_redirect_rule(
            zone,
            f'(http.host eq "{zone["name"]}")',
            'concat("https://bestratereview.com", http.request.uri.path)'
        )


def configure_domains(zone: dict[str, Any], used_services: set[str]) -> None:
    """Configure worker/page domains for a zone."""
    ztype = zone_type(zone)
    first, second = pair(zone)

    # Meet subdomain (all zones)
    make_worker_domain("clarkn-meet", zone, f"meet.{zone['name']}")

    # Track API worker as used
    api_worker = zone_api_worker(zone)
    if api_worker:
        used_services.add(api_worker)

    # Worker domains
    worker = zone_worker(zone)
    if worker:
        used_services.add(worker)
    if ztype == "worker" and worker:
        make_worker_domain(worker, zone, first)
        make_worker_domain(worker, zone, second)

    # Page domains
    page = zone_page(zone)
    if page:
        used_services.add(page)
    if ztype == "page" and page:
        make_page_domain(page, first)
        make_page_domain(page, second)


if __name__ == "__main__":
    print("starting...")
    used_services: set[str] = set()

    # Step 1: Fetch everything from cloud
    fetch_all()
    print(f"fetched {len(zones)} zones, {len(workers)} workers, {len(pages)} pages")

    # Step 2: Build local (desired) config
    build_local_config(used_services)

    # Report missing/unused configuration
    for setting_id in sorted(missing_settings):
        print(f"missing setting: {setting_id}")
    for worker_id in workers:
        if worker_id not in used_services:
            print(f"unused worker: {worker_id}")
    for page_name in pages:
        if page_name not in used_services:
            print(f"unused page: {page_name}")

    # Step 3: Show diffs and optionally apply
    run_deltas()
