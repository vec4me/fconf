from __future__ import annotations

import os
from typing import Any

import requests

TELNYX_API_KEY = os.getenv("TELNYX_API_KEY")
TELNYX_HEADERS = {"Authorization": f"Bearer {TELNYX_API_KEY}", "Content-Type": "application/json"}
DEFAULT_CONNECTION_ID = os.getenv("TELNYX_CONNECTION_ID")


def api(method: str, url: str, json: dict[str, Any] | None = None) -> Any | None:
    r = getattr(requests, method)(f"https://api.telnyx.com/v2/{url}", headers=TELNYX_HEADERS, json=json)
    if r.status_code in (200, 201, 204):
        return r.json().get("data", True) if r.text else True
    try:
        err = r.json().get("errors", [{}])[0].get("detail", r.text[:200])
    except:
        err = r.text[:200]
    print(f"      error: {err}")
    return None


def paginate(endpoint: str) -> list[dict[str, Any]]:
    results, page = [], 1
    while page < 100:
        r = requests.get(f"https://api.telnyx.com/v2/{endpoint}", headers=TELNYX_HEADERS, params={"page[number]": page, "page[size]": 100})
        if r.status_code != 200:
            break
        data = r.json()
        if not data.get("data"):
            break
        results.extend(data["data"])
        if page >= data.get("meta", {}).get("total_pages", 1):
            break
        page += 1
    return results


def main() -> None:
    # Fetch
    print("fetching...")
    phone_numbers = {pn["phone_number"]: pn for pn in paginate("phone_numbers")}
    msg_profiles = [p for p in paginate("messaging_profiles") if p["name"].startswith("msg-")]
    voice_profiles = [p for p in paginate("outbound_voice_profiles") if p["name"].startswith("voice-")]
    cred_connections = [p for p in paginate("credential_connections") if p["connection_name"].startswith("sip-")]

    print(f"  {len(phone_numbers)} phone numbers")
    print(f"  {len(msg_profiles)} messaging profiles (msg-*)")
    print(f"  {len(voice_profiles)} outbound voice profiles (voice-*)")
    print(f"  {len(cred_connections)} credential connections (sip-*)")

    if not phone_numbers:
        return

    # Confirm
    print(f"\nwill recreate profiles for: {', '.join(phone_numbers.keys())}")
    if input("proceed? [y/N] ").lower() != "y":
        return

    # Unassign all numbers from messaging profiles and connections
    print("\nunassigning...")
    for pn, data in phone_numbers.items():
        r1 = api("patch", f"phone_numbers/{data['id']}/messaging", {"messaging_profile_id": None})
        r2 = api("patch", f"phone_numbers/{data['id']}/voice", {"connection_id": None})
        print(f"  {pn}: msg={'ok' if r1 else 'FAILED'}, voice={'ok' if r2 else 'FAILED'}")

    # Delete in order: connections first (they reference voice profiles), then voice profiles, then messaging
    print("deleting...")
    for p in cred_connections:
        api("delete", f"credential_connections/{p['id']}")
    for p in voice_profiles:
        api("delete", f"outbound_voice_profiles/{p['id']}")
    for p in msg_profiles:
        api("delete", f"messaging_profiles/{p['id']}")

    # Create and assign
    print("creating...")
    for pn, data in phone_numbers.items():
        print(f"  {pn}")
        mp = api("post", "messaging_profiles", {
            "name": f"msg-{pn}",
            "webhook_url": "https://sms-cloudflare-central.vec4me.workers.dev/",
            "webhook_api_version": "2",
            "whitelisted_destinations": ["*"],
        })
        print(f"    messaging profile: {'ok' if mp else 'FAILED'}")

        ovp = api("post", "outbound_voice_profiles", {
            "name": f"voice-{pn}",
            "traffic_type": "conversational",
            "service_plan": "global",
            "whitelisted_destinations": ["US", "CA", "MX", "JP"],
        })
        print(f"    outbound voice profile: {'ok' if ovp else 'FAILED'}")

        conn = api("post", "credential_connections", {
            "connection_name": f"sip-{pn}",
            "user_name": f"user{pn[-4:]}",
            "password": "DooDooFarter",
            "sip_uri_calling_preference": "unrestricted",
            "inbound": {
                "generate_ringback_tone": False,
            },
            "outbound": {
                "ani_override": pn,
                "ani_override_type": "always",
                "outbound_voice_profile_id": ovp["id"] if ovp else None,
                "generate_ringback_tone": False,
                "instant_ringback_enabled": False,
            },
        })
        print(f"    credential connection: {'ok' if conn else 'FAILED'}")

        voice_settings = {
            "connection_id": conn["id"] if conn else DEFAULT_CONNECTION_ID,
            "media_features": {
                "t38_fax_gateway_enabled": True,
                "rtp_auto_adjust_enabled": False,
            },
        }
        if pn == "+17752000767":
            voice_settings["call_forwarding"] = {
                "call_forwarding_enabled": True,
                "forwards_to": "+819094141337",
                "forwarding_type": "always",
            }
        voice_result = api("patch", f"phone_numbers/{data['id']}/voice", voice_settings)
        if isinstance(voice_result, dict):
            mf = voice_result.get("media_features", {})
            print(f"    voice: hd={mf.get('hd_voice_enabled')}, rtp_auto={mf.get('rtp_auto_adjust_enabled')}, t38={mf.get('t38_fax_gateway_enabled')}")
        else:
            print(f"    voice settings: {'ok' if voice_result else 'FAILED'}")
        result = api("patch", f"phone_numbers/{data['id']}", {
            "number_level_routing": "disabled",
            "external_pin": "5669",
            "hd_voice_enabled": False,
        })
        if result:
            print(f"    external_pin: {result.get('external_pin', 'not in response')}")
        if mp:
            api("patch", f"phone_numbers/{data['id']}/messaging", {"messaging_profile_id": mp["id"]})

    # Cleanup any remaining duplicates
    print("cleanup...")
    keep_ids = set()
    for p in paginate("messaging_profiles"):
        if p["name"].startswith("msg-") and p.get("phone_numbers_count", 0) > 0:
            keep_ids.add(p["id"])
    for p in paginate("messaging_profiles"):
        if p["name"].startswith("msg-") and p["id"] not in keep_ids:
            api("delete", f"messaging_profiles/{p['id']}")

    seen = set()
    for p in paginate("outbound_voice_profiles"):
        if p["name"].startswith("voice-"):
            if p["name"] in seen:
                api("delete", f"outbound_voice_profiles/{p['id']}")
            else:
                seen.add(p["name"])

    seen = set()
    for p in paginate("credential_connections"):
        if p["connection_name"].startswith("sip-"):
            if p["connection_name"] in seen:
                api("delete", f"credential_connections/{p['id']}")
            else:
                seen.add(p["connection_name"])

    print("done")


if __name__ == "__main__":
    main()
