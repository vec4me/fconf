"""Offline validation for user-authored infrastructure configuration."""

from __future__ import annotations

import logging
import json
import pathlib
import re
import urllib.parse
from typing import cast
import src.zone_file as zone_file

logger = logging.getLogger(__name__)

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_PATTERN = re.compile(r"^\+[1-9][0-9]{7,14}$")


def readConfiguration(directory: pathlib.Path) -> tuple[dict[str, dict[str, object]], dict[str, object], dict[str, object]]:
    """Read the complete authoritative desired configuration."""
    zones = {
        path.name.removesuffix(".zone"): zone_file.readAnnotations(path)
        for path in sorted(directory.glob("*.zone"))
        if not path.name.startswith("_")
    }
    telnyx = cast("dict[str, object]", json.loads((directory / "telnyx.json").read_text(encoding="utf-8")))
    regery = cast("dict[str, object]", json.loads((directory / "regery.json").read_text(encoding="utf-8")))
    return zones, telnyx, regery


def TypeErrors(location: pathlib.Path, value: object, expected: type[object], name: str) -> list[str]:
    """Return an error when a configured value has the wrong exact type."""
    if type(value) is expected:
        return []
    return [f"{location}: {name} must be {expected.__name__}"]


def StringListErrors(location: pathlib.Path, value: object, name: str) -> list[str]:
    """Return errors when a value is not a duplicate-free list of nonempty strings."""
    if not isinstance(value, list):
        return [f"{location}: {name} must be a list"]
    if any(not isinstance(item, str) or not item for item in value):
        return [f"{location}: {name} must contain only nonempty strings"]
    if len(value) != len(set(value)):
        return [f"{location}: {name} contains duplicates"]
    return []


def MappingErrors(location: pathlib.Path, value: object, name: str) -> list[str]:
    """Return an error when a configured value is not a mapping."""
    if isinstance(value, dict):
        return []
    return [f"{location}: {name} must be an object"]


def KeyErrors(location: pathlib.Path, mapping: dict[str, object], required: set[str], optional: set[str]) -> list[str]:
    """Return missing and unknown mapping-key errors."""
    errors: list[str] = []
    missing = required - set(mapping)
    unknown = set(mapping) - required - optional
    for key in sorted(missing):
        errors.append(f"{location}: missing required key: {key}")
    for key in sorted(unknown):
        errors.append(f"{location}: unknown key: {key}")
    return errors


def HostBelongsToZone(hostname: str, zonename: str) -> bool:
    """Return whether a hostname belongs to a zone."""
    host = hostname.lower().rstrip(".")
    zone = zonename.lower().rstrip(".")
    return host == zone or host.endswith(f".{zone}")


def checkZone(path: pathlib.Path, zonename: str, configuration: dict[str, object]) -> list[str]:
    """Return validation errors for one zone configuration."""
    errors: list[str] = []
    try:
        zone_file.readRecords(path, zonename)
    except Exception as error:
        return [f"{path}: {error}"]
    for sourcepath, line in zone_file.readZoneLines(path):
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("$"):
            errors.append(f"{sourcepath}: unsupported inherited directive after include expansion: {line}")
            continue
        words = stripped.split()
        if len(words) < 5 or not words[0].endswith(".") or not words[1].isdigit() or words[2] != "IN":
            errors.append(f"{sourcepath}: record must declare an absolute owner, TTL, and IN class: {line}")
            continue
        if not HostBelongsToZone(words[0], zonename):
            errors.append(f"{sourcepath}: record owner is outside {zonename}: {words[0]}")
    for relationship in ("page_domains", "worker_domains"):
        for declaration in cast("list[str]", configuration.get(relationship, [])):
            _service, separator, hostname = declaration.partition(":")
            if not separator or not HostBelongsToZone(hostname, zonename):
                errors.append(f"{path}: {relationship} hostname is outside {zonename}: {declaration}")
    for declaration in cast("list[str]", configuration.get("routes", [])):
        pattern, separator, _worker = declaration.partition("=")
        hostname = pattern.split("/", 1)[0].removeprefix("*.")
        if not separator or not HostBelongsToZone(hostname, zonename):
            errors.append(f"{path}: Worker route is outside {zonename}: {declaration}")
    destination = configuration.get("email_forward")
    if destination is not None and EMAIL_PATTERN.fullmatch(str(destination)) is None:
        errors.append(f"{path}: invalid email-forward address: {destination}")
    return errors


def checkConfiguration(
    directory: pathlib.Path,
    zones: dict[str, dict[str, object]],
    telnyx: dict[str, object],
    regery: dict[str, object],
) -> None:
    """Validate every local declaration without accessing a provider."""
    errors: list[str] = []
    telnyxpath = directory / "telnyx.json"
    regerypath = directory / "regery.json"
    errors.extend(KeyErrors(telnyxpath, telnyx, {"messaging_profile", "outbound_voice_profile", "credential_connection", "voice_settings", "number_settings", "numbers"}, set()))
    errors.extend(KeyErrors(regerypath, regery, {"auto_renew", "contact_roles", "services", "disclose", "domains"}, set()))
    if errors:
        raise ValueError("configuration invalid:\n" + "\n".join(f"  {error}" for error in errors))
    for key in ("messaging_profile", "outbound_voice_profile", "credential_connection", "voice_settings", "number_settings", "numbers"):
        errors.extend(MappingErrors(telnyxpath, telnyx[key], key))
    errors.extend(TypeErrors(regerypath, regery["auto_renew"], bool, "auto_renew"))
    errors.extend(TypeErrors(regerypath, regery["disclose"], bool, "disclose"))
    errors.extend(StringListErrors(regerypath, regery["contact_roles"], "contact_roles"))
    errors.extend(StringListErrors(regerypath, regery["services"], "services"))
    errors.extend(StringListErrors(regerypath, regery["domains"], "domains"))
    if errors:
        raise ValueError("configuration invalid:\n" + "\n".join(f"  {error}" for error in errors))
    messaging = cast("dict[str, object]", telnyx["messaging_profile"])
    voice = cast("dict[str, object]", telnyx["outbound_voice_profile"])
    connection = cast("dict[str, object]", telnyx["credential_connection"])
    voicesettings = cast("dict[str, object]", telnyx["voice_settings"])
    numbersettings = cast("dict[str, object]", telnyx["number_settings"])
    errors.extend(KeyErrors(telnyxpath, messaging, {"webhook_url", "webhook_api_version", "whitelisted_destinations"}, set()))
    errors.extend(KeyErrors(telnyxpath, voice, {"traffic_type", "service_plan", "whitelisted_destinations"}, set()))
    errors.extend(KeyErrors(telnyxpath, connection, {"sip_uri_calling_preference", "inbound", "outbound"}, set()))
    errors.extend(KeyErrors(telnyxpath, voicesettings, {"media_features"}, set()))
    errors.extend(KeyErrors(telnyxpath, numbersettings, {"number_level_routing", "external_pin", "hd_voice_enabled"}, set()))
    if errors:
        raise ValueError("configuration invalid:\n" + "\n".join(f"  {error}" for error in errors))
    webhook = urllib.parse.urlparse(str(messaging["webhook_url"]))
    if webhook.scheme != "https" or not webhook.netloc:
        errors.append(f"{telnyxpath}: webhook_url must be an absolute HTTPS URL")
    for mapping, keys in (
        (messaging, ("webhook_url", "webhook_api_version")),
        (voice, ("traffic_type", "service_plan")),
        (connection, ("sip_uri_calling_preference",)),
        (numbersettings, ("number_level_routing", "external_pin")),
    ):
        for key in keys:
            if not isinstance(mapping[key], str) or not mapping[key]:
                errors.append(f"{telnyxpath}: {key} must be a nonempty string")
    errors.extend(StringListErrors(telnyxpath, messaging["whitelisted_destinations"], "messaging_profile.whitelisted_destinations"))
    errors.extend(StringListErrors(telnyxpath, voice["whitelisted_destinations"], "outbound_voice_profile.whitelisted_destinations"))
    errors.extend(TypeErrors(telnyxpath, numbersettings["hd_voice_enabled"], bool, "number_settings.hd_voice_enabled"))
    for parent, key, required in (
        (connection, "inbound", {"generate_ringback_tone"}),
        (connection, "outbound", {"ani_override_type", "generate_ringback_tone", "instant_ringback_enabled"}),
        (voicesettings, "media_features", {"t38_fax_gateway_enabled", "rtp_auto_adjust_enabled"}),
    ):
        nested = parent[key]
        errors.extend(MappingErrors(telnyxpath, nested, key))
        if isinstance(nested, dict):
            errors.extend(KeyErrors(telnyxpath, nested, required, set()))
    if errors:
        raise ValueError("configuration invalid:\n" + "\n".join(f"  {error}" for error in errors))
    inbound = cast("dict[str, object]", connection["inbound"])
    outbound = cast("dict[str, object]", connection["outbound"])
    media = cast("dict[str, object]", voicesettings["media_features"])
    errors.extend(TypeErrors(telnyxpath, inbound["generate_ringback_tone"], bool, "credential_connection.inbound.generate_ringback_tone"))
    errors.extend(TypeErrors(telnyxpath, outbound["generate_ringback_tone"], bool, "credential_connection.outbound.generate_ringback_tone"))
    errors.extend(TypeErrors(telnyxpath, outbound["instant_ringback_enabled"], bool, "credential_connection.outbound.instant_ringback_enabled"))
    errors.extend(TypeErrors(telnyxpath, media["t38_fax_gateway_enabled"], bool, "voice_settings.media_features.t38_fax_gateway_enabled"))
    errors.extend(TypeErrors(telnyxpath, media["rtp_auto_adjust_enabled"], bool, "voice_settings.media_features.rtp_auto_adjust_enabled"))
    if not isinstance(outbound["ani_override_type"], str) or not outbound["ani_override_type"]:
        errors.append(f"{telnyxpath}: credential_connection.outbound.ani_override_type must be a nonempty string")
    workers: set[str] = set()
    pages: set[str] = set()
    for zonename, configuration in zones.items():
        errors.extend(checkZone(directory / f"{zonename}.zone", zonename, configuration))
        for declaration in cast("list[str]", configuration.get("worker_domains", [])):
            worker, separator, _hostname = declaration.partition(":")
            if separator:
                workers.add(worker)
        for declaration in cast("list[str]", configuration.get("page_domains", [])):
            page, separator, _hostname = declaration.partition(":")
            if separator:
                pages.add(page)
        for declaration in cast("list[str]", configuration.get("routes", [])):
            _pattern, separator, worker = declaration.partition("=")
            if separator:
                workers.add(worker)
    numbers = cast("dict[str, dict[str, object]]", telnyx["numbers"])
    for number, configuration in numbers.items():
        errors.extend(KeyErrors(telnyxpath, configuration, {
            "credential_connection_name",
            "messaging_profile_name",
            "outbound_voice_profile_name",
            "sip_user_name",
        }, {"call_forwarding"}))
        if PHONE_PATTERN.fullmatch(number) is None:
            errors.append(f"{telnyxpath}: invalid managed number: {number}")
        for key in ("credential_connection_name", "messaging_profile_name", "outbound_voice_profile_name", "sip_user_name"):
            if key in configuration and (not isinstance(configuration[key], str) or not configuration[key]):
                errors.append(f"{telnyxpath}: {number}.{key} must be a nonempty string")
        if "call_forwarding" in configuration:
            forwarding = cast("dict[str, object]", configuration["call_forwarding"])
            forwardingerrors = KeyErrors(telnyxpath, forwarding, {"call_forwarding_enabled", "forwards_to", "forwarding_type"}, set())
            errors.extend(forwardingerrors)
            if not forwardingerrors:
                destination = forwarding["forwards_to"]
                if PHONE_PATTERN.fullmatch(str(destination)) is None:
                    errors.append(f"{telnyxpath}: invalid forwarding number: {destination}")
                errors.extend(TypeErrors(telnyxpath, forwarding["call_forwarding_enabled"], bool, f"{number}.call_forwarding.call_forwarding_enabled"))
                if not isinstance(forwarding["forwarding_type"], str) or not forwarding["forwarding_type"]:
                    errors.append(f"{telnyxpath}: {number}.call_forwarding.forwarding_type must be a nonempty string")
    domains = cast("list[str]", regery["domains"])
    if len(domains) != len(set(domains)):
        errors.append(f"{regerypath}: duplicate managed domains")
    for domain in domains:
        if domain not in zones:
            errors.append(f"{regerypath}: managed domain has no zone file: {domain}")
    if errors:
        raise ValueError("configuration invalid:\n" + "\n".join(f"  {error}" for error in errors))
    logger.info("configuration valid: %d zones, %d Workers, %d Pages projects, %d Telnyx numbers, %d Regery domains", len(zones), len(workers), len(pages), len(numbers), len(domains))
