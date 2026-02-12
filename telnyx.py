"""Telnyx API client for phone number and profile management."""

from __future__ import annotations

import logging
import os
from typing import Literal

logger = logging.getLogger(__name__)

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
MAX_PAGES = 100
PAGE_SIZE = 100


class State:
    """Module-level mutable state for Telnyx API credentials."""

    def __init__(self) -> None:
        """Initialize empty credentials."""
        self.headers: dict[str, str] = {}


state = State()


def init(api_key: str | None = None) -> None:
    """Initialize Telnyx API credentials."""
    key = api_key if api_key is not None else os.getenv("TELNYX_API_KEY")
    state.headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


# Helpers
def call_api(
    method: Literal["delete", "get", "patch", "post", "put"],
    url: str,
    json: dict[str, object] | None = None,
) -> object:
    """Execute an HTTP request against the Telnyx API."""
    import requests

    response = requests.request(
        method, f"https://api.telnyx.com/v2/{url}",
        headers=state.headers, json=json, timeout=30,
    )
    if response.status_code in (HTTP_OK, HTTP_CREATED, HTTP_NO_CONTENT):
        if response.status_code == HTTP_NO_CONTENT:
            return True
        return response.json()["data"]
    try:
        err = response.json()["errors"][0]["detail"]
    except (KeyError, ValueError, IndexError):
        err = response.text[:200]
    msg = f"API {method.upper()} {url}: {err}"
    raise RuntimeError(msg)


def paginate(endpoint: str) -> list[dict[str, object]]:
    """Fetch all pages from a paginated Telnyx API endpoint."""
    import requests
    results: list[dict[str, object]] = []
    page = 1
    while page < MAX_PAGES:
        response = requests.get(
            f"https://api.telnyx.com/v2/{endpoint}",
            headers=state.headers,
            params={"page[number]": page, "page[size]": PAGE_SIZE},
            timeout=30,
        )
        if response.status_code != HTTP_OK:
            try:
                err = response.json()["errors"][0]["detail"]
            except (KeyError, ValueError, IndexError):
                err = response.text[:200]
            msg = f"paginate {endpoint} page {page}: {err}"
            raise RuntimeError(msg)
        data = response.json()
        if not data["data"]:
            break
        results.extend(data["data"])
        if page >= data["meta"]["total_pages"]:
            break
        page += 1
    return results


# Fetchers
def fetch_all() -> dict[str, object]:
    """Fetch everything from cloud. Returns dict with phone_numbers, msg_profiles, voice_profiles, cred_connections."""
    logger.info("  fetching phone numbers...")
    phone_numbers = {entry["phone_number"]: entry for entry in paginate("phone_numbers")}
    logger.info("  fetching profiles and connections...")
    messaging_profiles = [
        profile for profile in paginate("messaging_profiles") if str(profile["name"]).startswith("msg-")
    ]
    voice_profiles = [
        profile for profile in paginate("outbound_voice_profiles") if str(profile["name"]).startswith("voice-")
    ]
    credential_connections = [
        profile for profile in paginate("credential_connections") if str(profile["connection_name"]).startswith("sip-")
    ]

    logger.info(
        "  %d phone numbers, %d messaging profiles, %d voice profiles, %d credential connections",
        len(phone_numbers), len(messaging_profiles), len(voice_profiles), len(credential_connections),
    )

    return {
        "phone_numbers": phone_numbers,
        "messaging_profiles": messaging_profiles,
        "voice_profiles": voice_profiles,
        "credential_connections": credential_connections,
    }


def unassign_phone_numbers(phone_numbers: dict[str, dict[str, object]]) -> None:
    """Unassign messaging and voice profiles from all phone numbers."""
    logger.info("unassigning...")
    for phone_number, data in phone_numbers.items():
        messaging_result = call_api("patch", f"phone_numbers/{data['id']}/messaging", {"messaging_profile_id": None})
        voice_result = call_api("patch", f"phone_numbers/{data['id']}/voice", {"connection_id": None})
        logger.info(
            "  %s: messaging=%s, voice=%s",
            phone_number,
            "ok" if messaging_result else "FAILED",
            "ok" if voice_result else "FAILED",
        )


def delete_old_profiles(state: dict[str, object]) -> None:
    """Delete existing credential connections, voice profiles, and messaging profiles."""
    logger.info("deleting...")
    for profile in state["credential_connections"]:
        call_api("delete", f"credential_connections/{profile['id']}")
    for profile in state["voice_profiles"]:
        call_api("delete", f"outbound_voice_profiles/{profile['id']}")
    for profile in state["messaging_profiles"]:
        call_api("delete", f"messaging_profiles/{profile['id']}")


def create_phone_config(
    phone_number: str,
    data: dict[str, object],
    webhook_url: str,
    voice_destinations: list[str],
    sip_password: str,
    *,
    external_pin: str,
    number_config: dict[str, dict[str, object]],
) -> None:
    """Create messaging profile, voice profile, and credential connection for a phone number."""
    logger.info("  %s", phone_number)
    messaging_profile = call_api("post", "messaging_profiles", {
        "name": f"msg-{phone_number}",
        "webhook_url": webhook_url,
        "webhook_api_version": "2",
        "whitelisted_destinations": ["*"],
    })
    logger.info("    messaging profile: ok")

    voice_profile = call_api("post", "outbound_voice_profiles", {
        "name": f"voice-{phone_number}",
        "traffic_type": "conversational",
        "service_plan": "global",
        "whitelisted_destinations": voice_destinations,
    })
    logger.info("    outbound voice profile: ok")

    connection = call_api("post", "credential_connections", {
        "connection_name": f"sip-{phone_number}",
        "user_name": f"user{phone_number[-4:]}",
        "password": sip_password,
        "sip_uri_calling_preference": "unrestricted",
        "inbound": {
            "generate_ringback_tone": False,
        },
        "outbound": {
            "ani_override": phone_number,
            "ani_override_type": "always",
            "outbound_voice_profile_id": voice_profile["id"],            "generate_ringback_tone": False,
            "instant_ringback_enabled": False,
        },
    })
    logger.info("    credential connection: ok")

    apply_voice_settings(phone_number, data, connection, external_pin=external_pin, number_config=number_config)
    call_api(
        "patch",
        f"phone_numbers/{data['id']}/messaging",
        {"messaging_profile_id": messaging_profile["id"]},
    )


def apply_voice_settings(
    phone_number: str,
    data: dict[str, object],
    connection: object,
    *,
    external_pin: str,
    number_config: dict[str, dict[str, object]],
) -> None:
    """Apply voice settings and number-level config to a phone number."""
    voice_settings: dict[str, object] = {
        "connection_id": connection["id"],
        "media_features": {
            "t38_fax_gateway_enabled": True,
            "rtp_auto_adjust_enabled": False,
        },
    }
    if phone_number in number_config and "call_forwarding" in number_config[phone_number]:
        voice_settings["call_forwarding"] = number_config[phone_number]["call_forwarding"]

    voice_result = call_api("patch", f"phone_numbers/{data['id']}/voice", voice_settings)
    media_features = voice_result["media_features"]
    logger.info(
        "    voice: hd=%s, rtp_auto=%s, t38=%s",
        media_features["hd_voice_enabled"],
        media_features["rtp_auto_adjust_enabled"],
        media_features["t38_fax_gateway_enabled"],
    )
    result = call_api("patch", f"phone_numbers/{data['id']}", {
        "number_level_routing": "disabled",
        "external_pin": external_pin,
        "hd_voice_enabled": False,
    })
    logger.info("    external_pin: %s", result["external_pin"])

def cleanup_profiles() -> None:
    """Remove orphaned messaging profiles and deduplicate voice/credential profiles."""
    logger.info("cleanup...")
    for profile in paginate("messaging_profiles"):
        if str(profile["name"]).startswith("msg-") and profile["phone_numbers_count"] == 0:
            call_api("delete", f"messaging_profiles/{profile['id']}")

    def deduplicate(endpoint: str, prefix: str, name_key: str = "name") -> None:
        seen: set[str] = set()
        for profile in paginate(endpoint):
            name = str(profile[name_key])
            if name.startswith(prefix):
                if name in seen:
                    call_api("delete", f"{endpoint}/{profile['id']}")
                else:
                    seen.add(name)

    deduplicate("outbound_voice_profiles", "voice-")
    deduplicate("credential_connections", "sip-", "connection_name")

    logger.info("done")


# Configure
def configure(
    state: dict[str, object],
    webhook_url: str,
    voice_destinations: list[str],
    sip_password: str,
    *,
    external_pin: str,
    number_config: dict[str, dict[str, object]],
) -> None:
    """Recreate all Telnyx profiles and connections for managed phone numbers."""
    phone_numbers: dict[str, dict[str, object]] = state["phone_numbers"]
    if not phone_numbers:
        return

    logger.info("\nwill recreate profiles for: %s", ", ".join(phone_numbers.keys()))
    if input("proceed? [y/N] ").lower() != "y":
        return

    logger.info("")
    unassign_phone_numbers(phone_numbers)
    delete_old_profiles(state)

    logger.info("creating...")
    for phone_number, data in phone_numbers.items():
        create_phone_config(
            phone_number, data, webhook_url, voice_destinations, sip_password,
            external_pin=external_pin, number_config=number_config,
        )

    cleanup_profiles()
