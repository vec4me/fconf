"""Cloudflare API client and declarative resource builders."""

from __future__ import annotations

import logging
import os
import pathlib
from typing import Any, Callable, Final, Literal, TypeVar, cast
import requests
import src.reconciliation as reconciliation
import src.zone_file as zone_file

ConfigTree = reconciliation.ConfigTree
Path = reconciliation.Path

Resources = dict[Path, dict[str, object]]

HttpMethod = Literal["delete", "get", "patch", "post", "put"]
Observation = TypeVar("Observation")


DnsRecord = dict[str, object]
ZoneSetting = dict[str, object]
Zone = dict[str, object]

logger = logging.getLogger(__name__)

HTTP_OK: Final = 200
HTTP_CREATED: Final = 201
HTTP_NO_CONTENT: Final = 204
MAX_PAGES: Final = 100
PER_PAGE: Final = 10
DNS_TXT_MAX: Final = 255


def observe(zone: Zone, resource: str, operation: Callable[[], Observation]) -> Observation | None:
    """Observe one zone resource, leaving only that resource unmanaged on failure."""
    try:
        return operation()
    except RuntimeError as error:
        zone.setdefault("unavailable", {})[resource] = str(error)
        logger.warning("      leaving %s unmanaged: %s", resource, error)
        return None


Client = dict[str, object]


def initializeClient(
    apitoken: str | None = None,
    accountid: str | None = None,
) -> Client:
    """Create a Cloudflare API client."""
    token = apitoken if apitoken is not None else os.getenv("CLOUDFLARE_API_TOKEN")
    account = accountid if accountid is not None else os.getenv("CLOUDFLARE_ACCOUNT_ID")
    if token is None:
        raise ValueError("CLOUDFLARE_API_TOKEN is required")
    if account is None:
        raise ValueError("CLOUDFLARE_ACCOUNT_ID is required")
    return {
        "accountid": account,
        "headers": {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    }


def sendRequest(
    client: Client,
    method: HttpMethod,
    url: str,
    payload: dict[str, object] | None = None,
) -> object:
    """Execute an HTTP request against the Cloudflare API."""
    response = requests.request(
        method,
        f"https://api.cloudflare.com/client/v4/{url}",
        headers=cast("dict[str, str]", client["headers"]),
        json=payload,
        timeout=30,
    )
    if response.status_code in (HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT):
        if response.status_code == HTTP_NO_CONTENT or not response.text:
            return True
        return response.json()["result"]
    try:
        detail = response.json()["errors"]
    except (KeyError, ValueError):
        detail = response.text[:200]
    message = f"API {method.upper()} {url}: {detail}"
    raise RuntimeError(message)


def delete(client: Client, url: str) -> object:
    """Send a DELETE request."""
    return sendRequest(client, "delete", url)


def get(client: Client, url: str) -> object:
    """Send a GET request."""
    return sendRequest(client, "get", url)


def patch(client: Client, url: str, payload: dict[str, object]) -> object:
    """Send a PATCH request."""
    return sendRequest(client, "patch", url, payload)


def post(client: Client, url: str, payload: dict[str, object]) -> object:
    """Send a POST request."""
    return sendRequest(client, "post", url, payload)


def put(client: Client, url: str, payload: dict[str, object]) -> object:
    """Send a PUT request."""
    return sendRequest(client, "put", url, payload)


# String helpers
def Quoted(string: str) -> str:
    """Wrap a string in double quotes if it contains '=' and isn't already quoted."""
    if "=" in string and not (string.startswith('"') and string.endswith('"')):
        return f'"{string}"'
    return string


def SplitText(content: str) -> str:
    """Split long TXT content into 255-byte DNS strings matching Cloudflare's API format."""
    quoted = content.startswith('"') and content.endswith('"')
    inner = content[1:-1] if quoted else content
    if len(inner) <= DNS_TXT_MAX:
        return content
    chunks = [inner[i:i + DNS_TXT_MAX] for i in range(0, len(inner), DNS_TXT_MAX)]
    return " ".join(f'"{chunk}"' for chunk in chunks)


def WithoutKeys(source: dict[str, object], skip: tuple[str, ...]) -> dict[str, object]:
    """Return a copy of source with the specified keys removed."""
    return {key: value for key, value in source.items() if key not in skip}


def setResource(tree: ConfigTree, resources: Resources, path: Path, value: object, kind: str, **identity: object) -> None:
    """Store one normalized resource value and its provider identity metadata."""
    reconciliation.setValue(tree, path, value)
    resources[path] = {"kind": kind, "push_after": (), **identity}


# Resource makers
def makeSetting(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    settingid: str | None = None,
    settingvalue: object = None,
    remotedata: ZoneSetting | None = None,
) -> None:
    """Build a zone setting node in the config tree."""
    zonename = zone["name"]

    skipkeys = ("editable", "modified_on", "certificate_status", "validation_errors", "time_remaining")
    if remotedata:
        settingid = str(remotedata["id"])
        value: dict[str, object] = WithoutKeys(remotedata, skipkeys)
    else:
        if settingid is None:
            message = f"{zonename} setting, missing id"
            raise ValueError(message)
        value = {"id": settingid, "value": settingvalue}

    path: Path = ("zones", str(zonename), "settings", str(settingid))
    setResource(tree, operations, path, value, "setting", zone=str(zonename), setting=str(settingid))


def makeDnssec(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    status: str | None = None,
    remotedata: dict[str, object] | None = None,
) -> None:
    """Build a DNSSEC node in the config tree."""
    zonename = zone["name"]

    skipkeys = (
        "ds", "key_tag", "algorithm", "key_type", "public_key",
        "digest", "digest_type", "digest_algorithm", "modified_on", "flags",
    )
    if remotedata:
        value: dict[str, object] = WithoutKeys(remotedata, skipkeys)
    else:
        if status is None:
            raise ValueError(f"{zonename} DNSSEC, missing status")
        value = {"status": status}

    path: Path = ("zones", str(zonename), "dnssec")
    setResource(tree, operations, path, value, "dnssec", zone=str(zonename))


def RecordFromRemoteData(
    zonename: str,
    remotedata: DnsRecord,
) -> tuple[str, str, str, dict[str, object], str | None]:
    """Extract record fields from a remote record dict."""
    recordid = str(remotedata["id"])
    namestring = str(remotedata["name"])
    if namestring == zonename:
        name = "@"
    elif namestring.endswith(f".{zonename}"):
        name = namestring[: -(1 + len(zonename))]
    else:
        name = namestring
    content = str(remotedata["content"])
    recordtype = str(remotedata["type"])
    value: dict[str, object] = {
        "content": content,
        "name": remotedata["name"],
        "proxied": remotedata["proxied"],
        "ttl": remotedata["ttl"],
        "type": recordtype,
        "comment": remotedata["comment"],
        "tags": remotedata["tags"],
        "settings": remotedata["settings"],
    }
    if "priority" in remotedata:
        value["priority"] = remotedata["priority"]
    return name, content, recordtype, value, recordid


def makeRecordValue(
    zonename: str,
    name: str,
    recordtype: str,
    content: str,
    *,
    proxied: bool,
    priority: int | None,
    ttl: int,
) -> dict[str, object]:
    """Build a record value dict from explicit arguments."""
    if recordtype in ("TXT", "MX"):
        proxied = False

    if name == zonename:
        logger.warning("please use @ for the record name instead of %s", zonename)

    content = Quoted(content)
    if recordtype == "TXT":
        content = SplitText(content)
    fullname = zonename if name == "@" else f"{name}.{zonename}"

    value: dict[str, object] = {
        "content": content,
        "name": fullname,
        "proxied": proxied,
        "ttl": ttl,
        "type": recordtype,
        "comment": None,
        "tags": [],
        "settings": {"flatten_cname": False} if recordtype == "CNAME" else {},
    }
    if priority:
        value["priority"] = priority

    return value


def removeDnsRecord(client: Client, zoneid: str, recordid: str | None) -> None:
    """Delete a DNS record."""
    try:
        delete(client, f"zones/{zoneid}/dns_records/{recordid}")
    except RuntimeError as error:
        detail = str(error)
        if "does not exist" in detail:
            return
        if "managed by Email Routing" in detail:
            logger.info("leaving Email Routing-managed record %s", recordid)
            return
        raise


def makeRecord(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    name: str | None = None,
    recordtype: str | None = None,
    content: str | None = None,
    *,
    proxied: bool | None = None,
    priority: int | None = None,
    ttl: int | None = None,
    remotedata: DnsRecord | None = None,
) -> None:
    """Build a DNS record node in the config tree."""
    zonename = str(zone["name"])
    recordid: str | None = None

    if remotedata:
        name, content, recordtype, value, recordid = RecordFromRemoteData(zonename, remotedata)
    else:
        if content is None:
            message = f"{zonename} record, missing content"
            raise ValueError(message)
        if name is None:
            message = f"{zonename} record, missing name"
            raise ValueError(message)
        if recordtype is None:
            message = f"{zonename} record, missing type"
            raise ValueError(message)
        if proxied is None:
            raise ValueError(f"{zonename} record, missing proxied")
        if ttl is None:
            raise ValueError(f"{zonename} record, missing ttl")
        value = makeRecordValue(
            zonename, name, recordtype, content,
            proxied=proxied, priority=priority, ttl=ttl,
        )
        content = str(value["content"])
        recordtype = str(value["type"])

    identity = f"{name}/{recordtype}" if recordtype == "CNAME" else f"{name}/{recordtype}/{content}"
    path: Path = ("zones", zonename, "records", identity)
    setResource(tree, operations, path, value, "record", zone=zonename, record_id=recordid)


def SrvFromRemoteData(
    zonename: str,
    remotedata: DnsRecord,
) -> tuple[str, str, dict[str, object], str]:
    """Extract SRV record fields from a remote record dict."""
    recordid = str(remotedata["id"])
    namestring = str(remotedata["name"]).replace(f".{zonename}", "")
    parts = namestring.split(".")
    service = parts[0]
    proto = parts[1] if len(parts) > 1 else ""
    srvdata = cast("dict[str, Any]", remotedata["data"])
    target = str(srvdata["target"])
    value: dict[str, object] = {
        "name": str(remotedata["name"]),
        "type": remotedata["type"],
        "data": {
            "service": service,
            "proto": proto,
            "name": zonename,
            "priority": srvdata["priority"],
            "weight": srvdata["weight"],
            "port": srvdata["port"],
            "target": target,
        },
        "ttl": remotedata["ttl"],
    }
    name = f"{service}.{proto}"
    return name, target, value, recordid


def makeSrvRecord(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    service: str | None = None,
    proto: str | None = None,
    target: str | None = None,
    port: int | None = None,
    priority: int | None = None,
    weight: int | None = None,
    ttl: int | None = None,
    remotedata: DnsRecord | None = None,
) -> None:
    """Build an SRV DNS record node in the config tree."""
    zonename = str(zone["name"])
    recordid: str | None = None

    if remotedata:
        name, target, value, recordid = SrvFromRemoteData(zonename, remotedata)
    else:
        if service is None:
            message = f"{zonename} SRV record, missing service"
            raise ValueError(message)
        if proto is None:
            message = f"{zonename} SRV record, missing proto"
            raise ValueError(message)
        if target is None:
            message = f"{zonename} SRV record, missing target"
            raise ValueError(message)
        if port is None:
            message = f"{zonename} SRV record, missing port"
            raise ValueError(message)
        if priority is None:
            raise ValueError(f"{zonename} SRV record, missing priority")
        if weight is None:
            raise ValueError(f"{zonename} SRV record, missing weight")
        if ttl is None:
            raise ValueError(f"{zonename} SRV record, missing ttl")
        name = f"{service}.{proto}"
        value: dict[str, object] = {
            "name": f"{name}.{zonename}",
            "type": "SRV",
            "data": {
                "service": service,
                "proto": proto,
                "name": zonename,
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": target,
            },
            "ttl": ttl,
        }

    path: Path = ("zones", zonename, "records", f"{name}/SRV/{target}")
    setResource(tree, operations, path, value, "record", zone=zonename, record_id=recordid)


def makeRoute(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    pattern: str | None = None,
    script: str | None = None,
    remotedata: dict[str, object] | None = None,
) -> None:
    """Build a Workers route node in the config tree."""
    zonename = str(zone["name"])
    routeid: str | None = None

    if remotedata:
        routeid = str(remotedata["id"])
        pattern = str(remotedata["pattern"])
        value: dict[str, object] = {
            "pattern": pattern,
            "script": remotedata["script"],
            "request_limit_fail_open": remotedata["request_limit_fail_open"],
        }
    else:
        if pattern is None:
            message = f"{zonename} route, missing pattern"
            raise ValueError(message)
        if script is None:
            message = f"{zonename} route, missing script"
            raise ValueError(message)
        value = {"pattern": pattern, "script": script, "request_limit_fail_open": False}

    path: Path = ("zones", zonename, "routes", str(pattern))
    setResource(tree, operations, path, value, "route", zone=zonename, route_id=routeid)


def getRedirectRules(client: Client, zone: Zone) -> dict[str, Any] | None:
    """Fetch the redirect ruleset for a zone. Returns None if no ruleset exists."""
    try:
        result = get(client, f"zones/{zone['id']}/rulesets/phases/http_request_dynamic_redirect/entrypoint")
    except RuntimeError as error:
        description = str(error).lower()
        if "not_found" in description or "could not find" in description:
            return None
        raise
    if isinstance(result, dict):
        return cast("dict[str, Any]", result)
    return None


def makeRedirectRule(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    expression: str | None = None,
    targeturl: str | None = None,
    statuscode: int | None = None,
    remotedata: dict[str, object] | None = None,
) -> None:
    """Build a redirect rule node in the config tree."""
    zonename = str(zone["name"])
    ruleid: str | None = None

    if remotedata:
        expression = str(remotedata["expression"])
        ruleid = str(remotedata["id"])
        value: dict[str, object] = {
            "expression": expression,
            "action": remotedata["action"],
            "action_parameters": remotedata["action_parameters"],
            "enabled": remotedata["enabled"],
        }
    else:
        if expression is None:
            message = f"{zonename} redirect rule, missing expression"
            raise ValueError(message)
        if targeturl is None:
            message = f"{zonename} redirect rule, missing target_url"
            raise ValueError(message)
        if statuscode is None:
            raise ValueError(f"{zonename} redirect rule, missing status_code")
        value = {
            "expression": expression,
            "action": "redirect",
            "action_parameters": {
                "from_value": {
                    "target_url": {"expression": targeturl},
                    "status_code": statuscode,
                    "preserve_query_string": True,
                },
            },
            "enabled": True,
        }

    key = str(expression)
    path: Path = ("zones", zonename, "redirect_rules", key)
    setResource(tree, operations, path, value, "redirect", zone=zonename, rule_id=ruleid)


def makePageDomain(
    tree: ConfigTree,
    operations: Resources,
    pagename: str,
    hostname: str | None = None,
    remotedata: dict[str, object] | None = None,
) -> None:
    """Build a Pages custom domain node in the config tree."""
    if remotedata:
        hostname = str(remotedata["name"])
        value: dict[str, object] = {"name": hostname}
    else:
        if hostname is None:
            message = f"{pagename} page domain, missing hostname"
            raise ValueError(message)
        value = {"name": hostname}

    path: Path = ("page_domains", pagename, str(hostname))
    setResource(tree, operations, path, value, "page_domain", page=pagename, hostname=str(hostname))


def makeWorkerDomain(
    tree: ConfigTree,
    operations: Resources,
    workername: str,
    zone: Zone,
    hostname: str | None = None,
    remotedata: dict[str, object] | None = None,
) -> None:
    """Build a Workers custom domain node in the config tree."""
    domainid: str | None = None

    skipkeys = ("id", "zone_id", "zone_name", "cert_id")
    if remotedata:
        domainid = str(remotedata["id"])
        hostname = str(remotedata["hostname"])
        value: dict[str, object] = WithoutKeys(remotedata, skipkeys)
    else:
        if hostname is None:
            message = f"{workername} worker domain, missing hostname"
            raise ValueError(message)
        value = {
            "hostname": hostname,
            "service": workername,
            "environment": "production",
            "enabled": True,
            "previews_enabled": False,
        }

    path: Path = ("worker_domains", str(hostname))
    setResource(tree, operations, path, value, "worker_domain", zone=str(zone["name"]), domain_id=domainid)


def makeEmailRoutingCatchAll(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    forwardto: str | None = None,
    *,
    remotedata: dict[str, object] | None = None,
) -> None:
    """Build an email routing catch-all rule node in the config tree."""
    zonename = str(zone["name"])

    if remotedata:
        value: dict[str, object] = {
            "enabled": remotedata["enabled"],
            "actions": remotedata["actions"],
            "matchers": remotedata["matchers"],
        }
    else:
        if forwardto is None:
            message = f"{zonename} email routing catch-all, missing forward_to"
            raise ValueError(message)
        value = {
            "enabled": True,
            "actions": [{"type": "forward", "value": [forwardto]}],
            "matchers": [{"type": "all"}],
        }

    path: Path = ("zones", zonename, "email_routing_catch_all")
    setResource(tree, operations, path, value, "email_routing", zone=zonename)
    if forwardto is not None:
        operations[path]["push_after"] = (("email routing destinations", forwardto),)


def makeEmailRoutingRule(
    tree: ConfigTree,
    operations: Resources,
    zone: Zone,
    source: str | None = None,
    forwardto: str | None = None,
    *,
    remotedata: dict[str, object] | None = None,
) -> None:
    """Build one literal-address Email Routing rule node."""
    zonename = str(zone["name"])
    ruleid: str | None = None
    if remotedata:
        ruleid = str(remotedata["id"])
        matchers = cast("list[dict[str, object]]", remotedata["matchers"])
        literal = next((matcher for matcher in matchers if matcher.get("type") == "literal" and matcher.get("field") == "to"), None)
        if literal is None:
            return
        source = str(literal["value"])
        value: dict[str, object] = {
            "enabled": remotedata["enabled"],
            "actions": remotedata["actions"],
            "matchers": remotedata["matchers"],
        }
    else:
        if source is None or forwardto is None:
            raise ValueError(f"{zonename} email routing rule requires source and destination")
        value = {
            "enabled": True,
            "actions": [{"type": "forward", "value": [forwardto]}],
            "matchers": [{"type": "literal", "field": "to", "value": source}],
        }
    path: Path = ("zones", zonename, "email_routing_rules", str(source))
    setResource(tree, operations, path, value, "email_routing_rule", zone=zonename, rule_id=ruleid)
    if forwardto is not None:
        operations[path]["push_after"] = (("email routing destinations", forwardto),)


def makeDestinationAddress(tree: ConfigTree, operations: Resources, address: str) -> None:
    """Build an account Email Routing destination-address node."""
    path: Path = ("email routing destinations", address)
    setResource(tree, operations, path, address, "destination", address=address)


def fetchDestinationAddresses(client: Client, remote: ConfigTree, operations: Resources, managedaddresses: set[str]) -> None:
    """Observe explicitly managed Email Routing destination addresses."""
    existing = paginate(client, f"accounts/{client['accountid']}/email/routing/addresses")
    for destination in existing:
        address = str(destination["email"])
        if address not in managedaddresses:
            continue
        makeDestinationAddress(remote, operations, address)
        if not destination.get("verified"):
            logger.warning("  destination %s is pending verification", address)


def Dependencies(resources: Resources) -> dict[Path, tuple[Path, ...]]:
    """Return mutation ordering independently of resource identity metadata."""
    return {
        path: cast("tuple[Path, ...]", resource["push_after"])
        for path, resource in resources.items()
        if resource["push_after"]
    }


def pushResource(client: Client, resource: dict[str, object], value: object, zones: dict[str, Zone]) -> None:
    """Create or update one Cloudflare resource."""
    kind = str(resource["kind"])
    zone = zones[str(resource["zone"])] if "zone" in resource else None
    if kind == "setting":
        patch(client, f"zones/{zone['id']}/settings/{resource['setting']}", cast("dict[str, object]", value))
    elif kind == "dnssec":
        patch(client, f"zones/{zone['id']}/dnssec", cast("dict[str, object]", value))
    elif kind == "record":
        post(client, f"zones/{zone['id']}/dns_records", cast("dict[str, object]", value))
    elif kind == "route":
        post(client, f"zones/{zone['id']}/workers/routes", cast("dict[str, object]", value))
    elif kind == "redirect":
        ruleset = getRedirectRules(client, cast("Zone", zone))
        if ruleset:
            rules = cast("list[dict[str, object]]", ruleset["rules"])
            put(client, f"zones/{zone['id']}/rulesets/{ruleset['id']}", {"rules": [*rules, value]})
        else:
            post(client, f"zones/{zone['id']}/rulesets", {"name": "Redirect Rules", "kind": "zone", "phase": "http_request_dynamic_redirect", "rules": [value]})
    elif kind == "page_domain":
        post(client, f"accounts/{client['accountid']}/pages/projects/{resource['page']}/domains", cast("dict[str, object]", value))
    elif kind == "worker_domain":
        put(client, f"accounts/{client['accountid']}/workers/domains", {**cast("dict[str, object]", value), "zone_id": zone["id"]})
    elif kind == "email_routing":
        try:
            post(client, f"zones/{zone['id']}/email/routing/dns", {})
        except RuntimeError as error:
            if "already enabled" not in str(error).lower():
                raise
        put(client, f"zones/{zone['id']}/email/routing/rules/catch_all", cast("dict[str, object]", value))
    elif kind == "email_routing_rule":
        try:
            post(client, f"zones/{zone['id']}/email/routing/dns", {})
        except RuntimeError as error:
            if "already enabled" not in str(error).lower():
                raise
        post(client, f"zones/{zone['id']}/email/routing/rules", cast("dict[str, object]", value))
    elif kind == "destination":
        post(client, f"accounts/{client['accountid']}/email/routing/addresses", {"email": resource["address"]})
        logger.warning("  destination %s needs verification - check inbox", resource["address"])
    else:
        raise RuntimeError(f"unsupported Cloudflare resource kind: {kind}")


def removeResource(client: Client, resource: dict[str, object], zones: dict[str, Zone]) -> None:
    """Remove one Cloudflare resource through its observed identity."""
    kind = str(resource["kind"])
    zone = zones[str(resource["zone"])] if "zone" in resource else None
    if kind == "record":
        removeDnsRecord(client, str(zone["id"]), cast("str | None", resource["record_id"]))
    elif kind == "route":
        delete(client, f"zones/{zone['id']}/workers/routes/{resource['route_id']}")
    elif kind == "redirect":
        ruleset = getRedirectRules(client, cast("Zone", zone))
        if ruleset and ruleset["rules"]:
            rules = cast("list[dict[str, object]]", ruleset["rules"])
            remaining = [rule for rule in rules if rule["id"] != resource["rule_id"]]
            put(client, f"zones/{zone['id']}/rulesets/{ruleset['id']}", {"rules": remaining})
    elif kind == "page_domain":
        delete(client, f"accounts/{client['accountid']}/pages/projects/{resource['page']}/domains/{resource['hostname']}")
    elif kind == "worker_domain":
        delete(client, f"accounts/{client['accountid']}/workers/domains/{resource['domain_id']}")
    elif kind == "email_routing":
        put(client, f"zones/{zone['id']}/email/routing/rules/catch_all", {"enabled": False, "actions": [{"type": "drop"}], "matchers": [{"type": "all"}]})
    elif kind == "email_routing_rule":
        delete(client, f"zones/{zone['id']}/email/routing/rules/{resource['rule_id']}")
    else:
        raise RuntimeError(f"Cloudflare {kind} does not support removal")


def replaceResource(client: Client, observed: dict[str, object], desired: dict[str, object], value: object, zones: dict[str, Zone]) -> None:
    """Replace one Cloudflare resource without exposing an invalid intermediate state."""
    kind = str(desired["kind"])
    zone = zones[str(desired["zone"])] if "zone" in desired else None
    if kind == "record":
        put(client, f"zones/{zone['id']}/dns_records/{observed['record_id']}", cast("dict[str, object]", value))
    elif kind in {"setting", "dnssec"}:
        pushResource(client, desired, value, zones)
    else:
        raise RuntimeError(f"Cloudflare {kind} does not support in-place replacement")


def execute(client: Client, operation: dict[str, object], observed: Resources, desired: Resources, zones: dict[str, Zone]) -> reconciliation.TransitionResult:
    """Apply one planned Cloudflare transition."""
    action = str(operation["action"])
    path = cast("Path", operation["path"])
    completed: list[str] = []
    try:
        if action == "remove":
            removeResource(client, observed[path], zones)
            completed.append("remove")
        elif action == "push":
            pushResource(client, desired[path], operation["after"], zones)
            completed.append("push")
        elif desired[path]["kind"] in {"record", "setting", "dnssec"}:
            replaceResource(client, observed[path], desired[path], operation["after"], zones)
            completed.append("replace")
        else:
            removeResource(client, observed[path], zones)
            completed.append("remove")
            pushResource(client, desired[path], operation["after"], zones)
            completed.append("push")
    except Exception as error:
        return {"completed_steps": completed, "error": str(error)}
    return {"completed_steps": completed, "error": None}


# Fetchers
def paginate(client: Client, url: str) -> list[dict[str, object]]:
    """Fetch all pages from a paginated Cloudflare API endpoint."""
    results: list[dict[str, object]] = []
    page = 1
    separator = "&" if "?" in url else "?"
    while page < MAX_PAGES:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/{url}{separator}per_page={PER_PAGE}&page={page}",
            headers=cast("dict[str, str]", client["headers"]),
            timeout=30,
        )
        if response.status_code not in (HTTP_OK, HTTP_CREATED):
            try:
                detail = response.json()["errors"]
            except (KeyError, ValueError):
                detail = response.text[:200]
            message = f"paginate {url} page {page}: {detail}"
            raise RuntimeError(message)
        body = response.json()
        pageresources: list[dict[str, object]] = body["result"]
        if not pageresources:
            break
        results.extend(pageresources)
        if "result_info" not in body:
            break
        pageinfo = body["result_info"]
        totalpages = (
            pageinfo["total_pages"]
            if "total_pages" in pageinfo
            else -(-pageinfo["total_count"] // pageinfo["per_page"])
        )
        if page >= totalpages:
            break
        page += 1
    return results


def ManagedRecord(record: dict[str, object]) -> bool:
    """Check whether a DNS record is auto-managed and should be skipped."""
    name = str(record.get("name", ""))
    content = str(record.get("content", "")).strip('"').rstrip(".")
    if name == "cf-bounce" or name.startswith("cf-bounce."):
        return True
    if name.startswith("cf2024-1._domainkey."):
        return True
    if record["type"] == "MX" and content.endswith(".mx.cloudflare.net"):
        return True
    if record["type"] == "TXT" and content == "v=spf1 include:_spf.mx.cloudflare.net ~all":
        return True
    if record["type"] == "AAAA" and str(record["content"]).startswith("100::"):
        return True
    meta = cast("dict[str, object]", record.get("meta", {}))
    return bool(meta.get("auto_added")) or bool(record.get("locked"))


def fetchEmailRouting(client: Client, remote: ConfigTree, operations: Resources, zone: Zone) -> None:
    """Fetch catch-all and literal-address Email Routing rules for a zone."""
    try:
        catchallresult = get(client, f"zones/{zone['id']}/email/routing/rules/catch_all")
        if isinstance(catchallresult, dict):
            catchall = cast("dict[str, object]", catchallresult)
            if catchall.get("enabled"):
                makeEmailRoutingCatchAll(remote, operations, zone, remotedata=catchall)
        for rule in paginate(client, f"zones/{zone['id']}/email/routing/rules"):
            if rule.get("enabled"):
                makeEmailRoutingRule(remote, operations, zone, remotedata=rule)
    except RuntimeError as error:
        if "not_found" not in str(error).lower() and "not enabled" not in str(error).lower():
            raise


def fetchZoneSettings(
    client: Client,
    remote: ConfigTree,
    operations: Resources,
    zone: Zone,
    settingids: set[str],
) -> None:
    """Fetch settings, DNSSEC, and redirect rules for a zone."""
    settings = cast("dict[str, dict[str, object]]", zone["settings"])
    for settingid in settingids:
        setting = settings.get(settingid)
        if setting is None:
            setting = cast("dict[str, object]", get(client, f"zones/{zone['id']}/settings/{settingid}"))
        makeSetting(remote, operations, zone, remotedata=setting)
    if zone.get("dnssec"):
        makeDnssec(remote, operations, zone, remotedata=cast("dict[str, object]", zone["dnssec"]))
    redirectruleset = observe(zone, "redirect rules", lambda: getRedirectRules(client, zone))
    if redirectruleset and redirectruleset.get("rules"):
        for rule in cast("list[dict[str, object]]", redirectruleset["rules"]):
            makeRedirectRule(remote, operations, zone, remotedata=rule)


def fetchZone(
    client: Client,
    remote: ConfigTree,
    operations: Resources,
    zone: Zone,
    settingids: set[str],
) -> None:
    """Fetch and process all remote state for a single zone."""
    zoneid = zone["id"]

    records = observe(zone, "DNS records", lambda: paginate(client, f"zones/{zoneid}/dns_records"))
    routes = observe(zone, "worker routes", lambda: paginate(client, f"zones/{zoneid}/workers/routes"))
    settings = observe(zone, "zone settings", lambda: paginate(client, f"zones/{zoneid}/settings"))
    dnssec = observe(zone, "DNSSEC", lambda: get(client, f"zones/{zoneid}/dnssec"))

    zone["settings"] = {setting["id"]: setting for setting in settings or []}
    zone["dnssec"] = dnssec or {}
    for record in records or []:
        if ManagedRecord(record):
            continue
        if record["type"] == "SRV":
            makeSrvRecord(remote, operations, zone, remotedata=record)
        else:
            makeRecord(remote, operations, zone, remotedata=record)
    for route in routes or []:
        makeRoute(remote, operations, zone, remotedata=route)
    observe(zone, "email routing", lambda: fetchEmailRouting(client, remote, operations, zone))
    fetchZoneSettings(client, remote, operations, zone, settingids)

def fetchState(
    client: Client,
    settingids: set[str],
    zonelist: list[Zone] | None = None,
) -> tuple[ConfigTree, Resources, dict[str, Zone], dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    """Fetch everything from remote. Returns (remote, zones, workers, pages)."""
    remote: ConfigTree = {}
    operations: Resources = {}

    logger.info("  fetching zones...")
    if zonelist is None:
        zonelist = paginate(client, "zones")
    zones: dict[str, Zone] = {str(zone["id"]): zone for zone in zonelist}
    logger.info("  fetching workers...")
    workers: dict[str, dict[str, object]] = {
        str(worker["id"]): worker for worker in paginate(client, f"accounts/{client['accountid']}/workers/scripts")
    }
    logger.info("  fetching pages...")
    pages: dict[str, dict[str, object]] = {
        str(project["name"]): project for project in paginate(client, f"accounts/{client['accountid']}/pages/projects")
    }

    logger.info("  fetching page domains...")
    zonenames = {str(zone["name"]) for zone in zones.values()}
    for page in pages.values():
        for domain in paginate(
            client,
            f"accounts/{client['accountid']}/pages/projects/{page['name']}/domains",
        ):
            hostname = str(domain["name"])
            if any(hostname == name or hostname.endswith(f".{name}") for name in zonenames):
                makePageDomain(remote, operations, str(page["name"]), remotedata=domain)

    logger.info("  fetching zone details...")
    for zone in zones.values():
        logger.info("    %s", zone["name"])
        fetchZone(client, remote, operations, zone, settingids)

    logger.info("  %d zones, %d workers, %d pages", len(zones), len(workers), len(pages))

    logger.info("  fetching worker domains...")
    for workerdomain in paginate(client, f"accounts/{client['accountid']}/workers/domains"):
        for zone in zones.values():
            if zone["id"] == workerdomain["zone_id"]:
                makeWorkerDomain(remote, operations, str(workerdomain["service"]), zone, remotedata=workerdomain)
                break

    return remote, operations, zones, workers, pages


def Unknowns(zones: dict[str, Zone]) -> reconciliation.Unknowns:
    """Return explicit unavailable observation boundaries."""
    unknowns: reconciliation.Unknowns = {}
    for zone in zones.values():
        unavailable = cast("dict[str, str]", zone.get("unavailable", {}))
        boundaries = {
            "DNS records": ("zones", str(zone["name"]), "records"),
            "worker routes": ("zones", str(zone["name"]), "routes"),
            "zone settings": ("zones", str(zone["name"]), "settings"),
            "DNSSEC": ("zones", str(zone["name"]), "dnssec"),
            "redirect rules": ("zones", str(zone["name"]), "redirect_rules"),
        }
        for resource, reason in unavailable.items():
            if resource == "email routing":
                unknowns[("zones", str(zone["name"]), "email_routing_catch_all")] = reason
                unknowns[("zones", str(zone["name"]), "email_routing_rules")] = reason
                continue
            if resource in boundaries:
                unknowns[boundaries[resource]] = reason
    return unknowns


def configureDomains(local: reconciliation.ConfigTree, operations: Resources, zone: Zone, configuration: dict[str, object]) -> None:
    """Configure explicitly declared Worker and Pages custom domains."""
    for declaration in cast("list[str]", configuration.get("worker_domains", [])):
        worker, hostname = declaration.split(":", 1)
        makeWorkerDomain(local, operations, worker, zone, hostname)
    for declaration in cast("list[str]", configuration.get("page_domains", [])):
        page, hostname = declaration.split(":", 1)
        makePageDomain(local, operations, page, hostname)


def configureEmail(local: reconciliation.ConfigTree, operations: Resources, zone: Zone, configuration: dict[str, object]) -> None:
    """Configure Cloudflare Email Routing declared by a zone file."""
    for declaration in cast("list[str]", configuration.get("email_forwards", [])):
        source, _separator, destination = declaration.partition("=")
        if source == "*":
            makeEmailRoutingCatchAll(local, operations, zone, forwardto=destination)
        else:
            makeEmailRoutingRule(local, operations, zone, source, destination)


def configureRecords(local: reconciliation.ConfigTree, operations: Resources, zone: Zone, configuration: dict[str, object], directory: pathlib.Path) -> None:
    """Configure DNS records and Worker routes declared by a zone file."""
    name = str(zone["name"])
    path = directory / f"{name}.zone"
    for record in zone_file.readRecords(path, name):
        if record["type"] == "SRV":
            owner = str(record["name"]).split(".", 1)
            makeSrvRecord(local, operations, zone, owner[0], owner[1], str(record["target"]), int(record["port"]), priority=int(record["priority"]), weight=int(record["weight"]), ttl=int(record["ttl"]))
            continue
        makeRecord(local, operations, zone, str(record["name"]), str(record["type"]), str(record["content"]), proxied=bool(record["proxied"]), priority=cast("int | None", record.get("priority")), ttl=int(record["ttl"]))
    for declaration in cast("list[str]", configuration.get("routes", [])):
        pattern, separator, worker = declaration.partition("=")
        if not separator:
            raise ValueError(f"{path}: invalid Worker route: {declaration}")
        makeRoute(local, operations, zone, pattern, worker)


def configureRedirects(local: reconciliation.ConfigTree, operations: Resources, zone: Zone, configuration: dict[str, object]) -> None:
    """Configure redirect rules declared by a zone file."""
    for status, expression, target in cast("list[tuple[int, str, str]]", configuration.get("redirect_rules", [])):
        makeRedirectRule(local, operations, zone, expression, target, status)


def configureSettings(local: reconciliation.ConfigTree, operations: Resources, zone: Zone, configuration: dict[str, object]) -> None:
    """Configure Cloudflare settings and DNSSEC declarations."""
    settings = cast("dict[str, object]", configuration.get("settings", {}))
    for settingid, setting in settings.items():
        makeSetting(local, operations, zone, settingid, setting)
    dnssec = configuration.get("dnssec")
    if dnssec is not None:
        makeDnssec(local, operations, zone, str(dnssec))


def compileDesired(directory: pathlib.Path, configurations: dict[str, dict[str, object]]) -> tuple[reconciliation.ConfigTree, Resources, dict[str, Zone], set[str], set[str]]:
    """Compile configuration into complete desired state without provider observation."""
    desired: reconciliation.ConfigTree = {}
    operations: Resources = {}
    zones: dict[str, Zone] = {name: {"name": name} for name in configurations}
    destinations = {
        declaration.partition("=")[2]
        for configuration in configurations.values()
        for declaration in cast("list[str]", configuration.get("email_forwards", []))
    }
    settingids = {settingid for configuration in configurations.values() for settingid in cast("dict[str, object]", configuration.get("settings", {}))}
    for destination in destinations:
        makeDestinationAddress(desired, operations, destination)
    for name, zone in zones.items():
        configuration = configurations[name]
        configureEmail(desired, operations, zone, configuration)
        configureRecords(desired, operations, zone, configuration, directory)
        configureRedirects(desired, operations, zone, configuration)
        configureDomains(desired, operations, zone, configuration)
        configureSettings(desired, operations, zone, configuration)
    return desired, operations, zones, destinations, settingids


def ReferencedDeployments(configurations: dict[str, dict[str, object]]) -> tuple[set[str], set[str]]:
    """Return Worker and Pages deployment names referenced by zone declarations."""
    workers: set[str] = set()
    pages: set[str] = set()
    for configuration in configurations.values():
        for declaration in cast("list[str]", configuration.get("worker_domains", [])):
            worker, _separator, _hostname = declaration.partition(":")
            workers.add(worker)
        for declaration in cast("list[str]", configuration.get("routes", [])):
            _pattern, _separator, worker = declaration.partition("=")
            workers.add(worker)
        for declaration in cast("list[str]", configuration.get("page_domains", [])):
            page, _separator, _hostname = declaration.partition(":")
            pages.add(page)
    return workers, pages


def reportUnusedDeployments(configurations: dict[str, dict[str, object]], workers: dict[str, dict[str, object]], pages: dict[str, dict[str, object]]) -> None:
    """Report observed deployments that no zone declaration references."""
    usedworkers, usedpages = ReferencedDeployments(configurations)
    for worker in sorted(set(workers) - usedworkers):
        logger.info("unused Worker: %s", worker)
    for page in sorted(set(pages) - usedpages):
        logger.info("unused Pages project: %s", page)


def bindZoneIdentities(zones: dict[str, Zone], observed: list[Zone]) -> None:
    """Bind observed provider identities to precompiled zone mutation operations."""
    byname = {str(zone["name"]): zone for zone in observed}
    missing = set(zones) - set(byname)
    if missing:
        raise RuntimeError("declared Cloudflare zones not found: " + ", ".join(sorted(missing)))
    for name, zone in zones.items():
        zone.update(byname[name])


def reconcile(directory: pathlib.Path, configurations: dict[str, dict[str, object]], *, apply: bool, planformat: str) -> dict[str, Zone]:
    """Reconcile all Cloudflare resources declared by zone files."""
    local, localresources, zones, destinations, settingids = compileDesired(directory, configurations)
    client = initializeClient()
    observedzones = cast("list[Zone]", paginate(client, "zones"))
    bindZoneIdentities(zones, observedzones)
    zonelist = list(zones.values())
    remote, remoteresources, zones, workers, pages = fetchState(client, settingids=settingids, zonelist=zonelist)
    reportUnusedDeployments(configurations, workers, pages)
    unknowns = Unknowns(zones)
    fetchDestinationAddresses(client, remote, remoteresources, destinations)
    dependencies = Dependencies(localresources)
    executor = lambda operation: execute(client, operation, remoteresources, localresources, {str(zone["name"]): zone for zone in zones.values()})
    applied = reconciliation.runValues(remote, local, dependencies, unknowns, executor, apply=apply, planformat=planformat)
    if applied:
        verifiedzones = [zone for zone in paginate(client, "zones") if str(zone["name"]) in configurations]
        verified, verifiedresources, verifiedzonemap, _workers, _pages = fetchState(client, settingids=settingids, zonelist=verifiedzones)
        fetchDestinationAddresses(client, verified, verifiedresources, destinations)
        reconciliation.verifyConvergence(verified, local, dependencies, Unknowns(verifiedzonemap))
    return zones


def fetchNameservers(managednames: set[str]) -> dict[str, list[str]]:
    """Observe authoritative Cloudflare nameservers for explicitly managed zones."""
    client = initializeClient()
    zones = {str(zone["name"]): zone for zone in paginate(client, "zones") if str(zone["name"]) in managednames}
    missingnames = managednames - set(zones)
    if missingnames:
        raise RuntimeError("managed Regery domains missing from Cloudflare: " + ", ".join(sorted(missingnames)))
    return {name: sorted(cast("list[str]", zone.get("name_servers", []))) for name, zone in zones.items()}
