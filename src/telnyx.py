"""Telnyx phone-number and profile reconciliation implementation."""

from __future__ import annotations

import logging
import os
from typing import Any, Final, Literal, cast
import requests
import src.reconciliation as reconciliation

logger = logging.getLogger(__name__)

HTTP_OK: Final = 200
HTTP_CREATED: Final = 201
HTTP_NO_CONTENT: Final = 204
MAX_PAGES: Final = 100
PAGE_SIZE: Final = 100

HttpMethod = Literal["delete", "get", "patch", "post", "put"]


TelnyxData = dict[str, Any]
Client = dict[str, str]


def Project(source: object, template: object, path: str = "") -> object:
    """Project provider data onto the exact shape declared by configuration."""
    if isinstance(template, dict):
        if not isinstance(source, dict):
            raise ValueError(f"Telnyx observation at {path or '<root>'} must be an object")
        projected: dict[str, object] = {}
        for key, value in template.items():
            childpath = f"{path}.{key}" if path else key
            if key not in source:
                raise ValueError(f"Telnyx observation missing declared field: {childpath}")
            projected[key] = Project(source[key], value, childpath)
        return projected
    if isinstance(template, list):
        if not isinstance(source, list):
            raise ValueError(f"Telnyx observation at {path} must be a list")
        return source
    return source


def initializeClient(apikey: str | None = None) -> Client:
    """Create a Telnyx API client."""
    key = apikey if apikey is not None else os.getenv("TELNYX_API_KEY")
    if key is None:
        raise ValueError("TELNYX_API_KEY is required")
    return {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


# Helpers
def sendRequest(
    client: Client,
    method: HttpMethod,
    url: str,
    payload: dict[str, object] | None = None,
) -> object:
    """Execute an HTTP request against the Telnyx API."""
    response = requests.request(
        method, f"https://api.telnyx.com/v2/{url}",
        headers=client, json=payload, timeout=30,
    )
    if response.status_code in (HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT):
        if response.status_code == HTTP_NO_CONTENT:
            return True
        return response.json()["data"]
    try:
        error = response.json()["errors"][0]["detail"]
    except (KeyError, ValueError, IndexError):
        error = response.text[:200]
    message = f"API {method.upper()} {url}: {error}"
    raise RuntimeError(message)


def paginate(client: Client, endpoint: str) -> list[dict[str, object]]:
    """Fetch all pages from a paginated Telnyx API endpoint."""
    results: list[dict[str, object]] = []
    page = 1
    while page < MAX_PAGES:
        response = requests.get(
            f"https://api.telnyx.com/v2/{endpoint}",
            headers=client,
            params={"page[number]": page, "page[size]": PAGE_SIZE},
            timeout=30,
        )
        if response.status_code != HTTP_OK:
            try:
                error = response.json()["errors"][0]["detail"]
            except (KeyError, ValueError, IndexError):
                error = response.text[:200]
            message = f"paginate {endpoint} page {page}: {error}"
            raise RuntimeError(message)
        pagebody = response.json()
        if not pagebody["data"]:
            break
        results.extend(pagebody["data"])
        if page >= pagebody["meta"]["total_pages"]:
            break
        page += 1
    return results


# Fetchers
def fetchState(client: Client, numberconfigurations: dict[str, dict[str, object]]) -> TelnyxData:
    """Fetch remote state belonging to explicitly managed phone numbers."""
    managednumbers = set(numberconfigurations)
    logger.info("  fetching phone numbers...")
    phonenumbers = {
        str(entry["phone_number"]): entry
        for entry in paginate(client, "phone_numbers")
        if str(entry["phone_number"]) in managednumbers
    }
    logger.info("  fetching profiles and connections...")
    messagingnames = {str(configuration["messaging_profile_name"]) for configuration in numberconfigurations.values()}
    voicenames = {str(configuration["outbound_voice_profile_name"]) for configuration in numberconfigurations.values()}
    connectionnames = {str(configuration["credential_connection_name"]) for configuration in numberconfigurations.values()}
    allmessaging = sorted(paginate(client, "messaging_profiles"), key=lambda profile: str(profile["id"]))
    allvoices = sorted(paginate(client, "outbound_voice_profiles"), key=lambda profile: str(profile["id"]))
    allconnections = sorted(paginate(client, "credential_connections"), key=lambda profile: str(profile["id"]))
    messagingsummaries = [profile for profile in allmessaging if str(profile["name"]) in messagingnames]
    voicesummaries = [profile for profile in allvoices if str(profile["name"]) in voicenames]
    connectionsummaries = [profile for profile in allconnections if str(profile["connection_name"]) in connectionnames]
    cleanupresources: list[dict[str, object]] = []
    for kind, profiles, namekey, prefix, managednames in (
        ("messaging_profiles", allmessaging, "name", "msg-", messagingnames),
        ("outbound_voice_profiles", allvoices, "name", "voice-", voicenames),
        ("credential_connections", allconnections, "connection_name", "sip-", connectionnames),
    ):
        seen: set[str] = set()
        for profile in profiles:
            name = str(profile[namekey])
            orphan = kind == "messaging_profiles" and name.startswith(prefix) and name not in managednames and profile.get("phone_numbers_count") == 0
            duplicate = name.startswith(prefix) and name in seen
            if orphan or duplicate:
                cleanupresources.append({"kind": kind, "id": profile["id"], "name": name})
            seen.add(name)
    cleanupids = {str(resource["id"]) for resource in cleanupresources}
    messagingsummaries = [profile for profile in messagingsummaries if str(profile["id"]) not in cleanupids]
    voicesummaries = [profile for profile in voicesummaries if str(profile["id"]) not in cleanupids]
    connectionsummaries = [profile for profile in connectionsummaries if str(profile["id"]) not in cleanupids]
    messagingprofiles = [cast("dict[str, object]", sendRequest(client, "get", f"messaging_profiles/{profile['id']}")) for profile in messagingsummaries]
    voiceprofiles = [cast("dict[str, object]", sendRequest(client, "get", f"outbound_voice_profiles/{profile['id']}")) for profile in voicesummaries]
    credentialconnections = [cast("dict[str, object]", sendRequest(client, "get", f"credential_connections/{profile['id']}")) for profile in connectionsummaries]
    phonenumberdetails = {
        number: {
            "number": cast("dict[str, object]", sendRequest(client, "get", f"phone_numbers/{summary['id']}")),
            "messaging": cast("dict[str, object]", sendRequest(client, "get", f"phone_numbers/{summary['id']}/messaging")),
            "voice": cast("dict[str, object]", sendRequest(client, "get", f"phone_numbers/{summary['id']}/voice")),
        }
        for number, summary in phonenumbers.items()
    }

    logger.info(
        "  %d phone numbers, %d messaging profiles, %d voice profiles, %d credential connections",
        len(phonenumbers), len(messagingprofiles), len(voiceprofiles), len(credentialconnections),
    )

    return {
        "phone_numbers": phonenumbers,
        "messaging_profiles": messagingprofiles,
        "voice_profiles": voiceprofiles,
        "credential_connections": credentialconnections,
        "phone_number_details": phonenumberdetails,
        "cleanup_resources": cleanupresources,
    }


Resources = dict[reconciliation.Path, dict[str, object]]


def ConfigurationTrees(
    profiledata: TelnyxData,
    configuration: dict[str, object],
) -> tuple[reconciliation.ConfigTree, reconciliation.ConfigTree, Resources, Resources, reconciliation.Dependencies]:
    """Build observed and desired Telnyx resource trees."""
    phonenumbers = profiledata["phone_numbers"]
    managednumbers = set(cast("dict[str, object]", configuration["numbers"]))
    missingnumbers = managednumbers - set(phonenumbers)
    if missingnumbers:
        message = f"managed Telnyx numbers not found: {', '.join(sorted(missingnumbers))}"
        raise RuntimeError(message)
    observed: reconciliation.ConfigTree = {}
    desired: reconciliation.ConfigTree = {}
    observedresources: Resources = {}
    desiredresources: Resources = {}
    dependencies: reconciliation.Dependencies = {}
    for resource in profiledata.get("cleanup_resources", []):
        path = ("cleanup", str(resource["kind"]), str(resource["id"]))
        reconciliation.setValue(observed, path, {"name": resource["name"]})
        observedresources[path] = cast("dict[str, object]", resource)
    numbers = cast("dict[str, dict[str, object]]", configuration["numbers"])
    categories = {
        "messaging_profile": ("messaging_profiles", "messaging_profile_name", "messaging_profiles", "name"),
        "outbound_voice_profile": ("outbound_voice_profiles", "outbound_voice_profile_name", "voice_profiles", "name"),
    }
    for configkey, (pathkey, namekey, datakey, observednamekey) in categories.items():
        for numberconfiguration in numbers.values():
            name = str(numberconfiguration[namekey])
            path = (pathkey, name)
            value = {observednamekey: name, **cast("dict[str, object]", configuration[configkey])}
            reconciliation.setValue(desired, path, value)
            desiredresources[path] = {"kind": pathkey, "name": name}
            for resource in profiledata[datakey]:
                if str(resource[observednamekey]) == name:
                    reconciliation.setValue(observed, path, Project(resource, value))
                    observedresources[path] = {"kind": pathkey, "id": resource["id"], "name": name}
                    break
    voiceids = {str(profile["id"]): str(profile["name"]) for profile in profiledata["voice_profiles"]}
    messageids = {str(profile["id"]): str(profile["name"]) for profile in profiledata["messaging_profiles"]}
    connectionids = {str(connection["id"]): str(connection["connection_name"]) for connection in profiledata["credential_connections"]}
    for phonenumber, numberconfiguration in numbers.items():
        voicename = str(numberconfiguration["outbound_voice_profile_name"])
        connectionname = str(numberconfiguration["credential_connection_name"])
        connectionpath = ("credential_connections", connectionname)
        connectionconfiguration = cast("dict[str, object]", configuration["credential_connection"])
        outbound = cast("dict[str, object]", connectionconfiguration["outbound"])
        connectionvalue = {"connection_name": connectionname, "user_name": numberconfiguration["sip_user_name"], **connectionconfiguration, "outbound": {**outbound, "ani_override": phonenumber, "outbound_voice_profile": voicename}}
        reconciliation.setValue(desired, connectionpath, connectionvalue)
        desiredresources[connectionpath] = {"kind": "credential_connections", "name": connectionname}
        dependencies[connectionpath] = (("outbound_voice_profiles", voicename),)
        for connection in profiledata["credential_connections"]:
            if str(connection["connection_name"]) == connectionname:
                normalized = {**connection, "outbound": {**cast("dict[str, object]", connection["outbound"]), "outbound_voice_profile": voiceids[str(cast("dict[str, object]", connection["outbound"])["outbound_voice_profile_id"])]}}
                reconciliation.setValue(observed, connectionpath, Project(normalized, connectionvalue))
                observedresources[connectionpath] = {"kind": "credential_connections", "id": connection["id"], "name": connectionname}
                break
        details = profiledata["phone_number_details"][phonenumber]
        numberid = phonenumbers[phonenumber]["id"]
        messagepath = ("phone_numbers", phonenumber, "messaging")
        messagevalue = {"messaging_profile": str(numberconfiguration["messaging_profile_name"])}
        messaging = cast("dict[str, object]", details["messaging"])
        reconciliation.setValue(desired, messagepath, messagevalue)
        messagingid = messaging.get("messaging_profile_id")
        reconciliation.setValue(observed, messagepath, {"messaging_profile": messageids.get(str(messagingid)) if messagingid is not None else None})
        desiredresources[messagepath] = observedresources[messagepath] = {"kind": "messaging", "number_id": numberid}
        dependencies[messagepath] = (("messaging_profiles", messagevalue["messaging_profile"]),)
        voicepath = ("phone_numbers", phonenumber, "voice")
        voicevalue = {**cast("dict[str, object]", configuration["voice_settings"]), "connection": connectionname}
        if "call_forwarding" in numberconfiguration:
            voicevalue["call_forwarding"] = numberconfiguration["call_forwarding"]
        observedvoice = cast("dict[str, object]", details["voice"])
        connectionid = observedvoice.get("connection_id")
        voice = {**observedvoice, "connection": connectionids.get(str(connectionid)) if connectionid is not None else None}
        reconciliation.setValue(desired, voicepath, voicevalue)
        reconciliation.setValue(observed, voicepath, Project(voice, voicevalue))
        desiredresources[voicepath] = observedresources[voicepath] = {"kind": "voice", "number_id": numberid}
        dependencies[voicepath] = (connectionpath,)
        settingspath = ("phone_numbers", phonenumber, "settings")
        settingsvalue = configuration["number_settings"]
        reconciliation.setValue(desired, settingspath, settingsvalue)
        reconciliation.setValue(observed, settingspath, Project(details["number"], settingsvalue))
        desiredresources[settingspath] = observedresources[settingspath] = {"kind": "settings", "number_id": numberid}
    return observed, desired, observedresources, desiredresources, dependencies


def execute(
    client: Client,
    operation: dict[str, object],
    profiledata: TelnyxData,
    observedresources: Resources,
    desiredresources: Resources,
    sippassword: str,
) -> reconciliation.TransitionResult:
    """Apply one Telnyx resource transition."""
    action = str(operation["action"])
    path = cast("reconciliation.Path", operation["path"])
    completed: list[str] = []
    try:
        resource = observedresources.get(path) if action == "remove" else desiredresources[path]
        kind = str(resource["kind"])
        endpoint = {"messaging_profiles": "messaging_profiles", "outbound_voice_profiles": "outbound_voice_profiles", "credential_connections": "credential_connections"}.get(kind)
        if action == "remove":
            sendRequest(client, "delete", f"{endpoint}/{resource['id']}")
            completed.append("remove")
        else:
            value = cast("dict[str, object]", operation["after"])
            payload = dict(value)
            if kind == "credential_connections":
                outbound = dict(cast("dict[str, object]", payload["outbound"]))
                voicename = str(outbound.pop("outbound_voice_profile"))
                voice = next(profile for profile in profiledata["voice_profiles"] if profile["name"] == voicename)
                payload["outbound"] = {**outbound, "outbound_voice_profile_id": voice["id"]}
                payload["password"] = sippassword
            elif kind == "messaging":
                name = str(payload.pop("messaging_profile"))
                profile = next(profile for profile in profiledata["messaging_profiles"] if profile["name"] == name)
                payload = {"messaging_profile_id": profile["id"]}
            elif kind == "voice":
                name = str(payload.pop("connection"))
                connection = next(item for item in profiledata["credential_connections"] if item["connection_name"] == name)
                payload["connection_id"] = connection["id"]
            target = f"{endpoint}/{observedresources[path]['id']}" if endpoint and action == "replace" else endpoint
            if kind in {"messaging", "voice", "settings"}:
                target = f"phone_numbers/{resource['number_id']}" + ({"messaging": "/messaging", "voice": "/voice", "settings": ""}[kind])
            result = sendRequest(client, "patch" if action == "replace" or kind in {"messaging", "voice", "settings"} else "post", str(target), payload)
            if action == "push" and endpoint and isinstance(result, dict):
                profiledata[{"messaging_profiles": "messaging_profiles", "outbound_voice_profiles": "voice_profiles", "credential_connections": "credential_connections"}[kind]].append(result)
            completed.append("replace" if action == "replace" else "push")
    except Exception as error:
        return {"completed_steps": completed, "error": str(error)}
    return {"completed_steps": completed, "error": None}


def reconcile(configuration: dict[str, object], *, apply: bool, planformat: str) -> None:
    """Reconcile Telnyx against an explicit configuration."""
    client = initializeClient()
    numbers = cast("dict[str, dict[str, object]]", configuration["numbers"])
    remote = fetchState(client, numbers)
    password = os.environ["SIP_PASSWORD"]
    observed, desired, observedresources, desiredresources, dependencies = ConfigurationTrees(remote, configuration)
    executor = lambda operation: execute(client, operation, remote, observedresources, desiredresources, password)
    applied = reconciliation.runValues(observed, desired, dependencies, {}, executor, apply=apply, planformat=planformat)
    if applied:
        verifieddata = fetchState(client, numbers)
        verified, _desired, _observedresources, _desiredresources, verifieddependencies = ConfigurationTrees(verifieddata, configuration)
        reconciliation.verifyConvergence(verified, desired, verifieddependencies, {})
