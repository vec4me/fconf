"""CLI entry point for managing Cloudflare, SES, Telnyx, and Regery infrastructure."""

from __future__ import annotations

import logging
import os
from typing import Any, Final, Literal, TypedDict, cast

import cloudflare
import provider
import regery
import ses
import telnyx
from cloudflare import Zone
from provider import ConfigTree

logger = logging.getLogger(__name__)

HostingType = Literal["worker", "page"] | None


class ZoneConfig(TypedDict, total=False):
    """Per-zone configuration options."""

    address: str
    ssl: str
    sip_server: str
    google_verification: str
    mail_server: str
    additional_records: list[tuple[str, str, str, bool]]
    worker_domains: list[tuple[str, str]]
    redirect_to: str
    short_name: str
    retro_index: bool
    icloud_mail: bool

# ============================================================
# Cloudflare
# ============================================================

CF_DKIM_RECORD: Final = (
    "v=DKIM1; h=sha256; k=rsa;"
    " p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiweykoi+o48IOGuP7GR3X0MOExCUDY"
    "/BCRHoWBnh3rChl7WhdyCxW3jgq1daEjPPqoi7sJvdg5hEQVsgVRQP4DcnQDVjGMbASQtrY4WmB1"
    "VebF+RPJB2ECPsEDTpeiI5ZyUAwJaVX7r6bznU67g7LvFq35yIo4sdlmtZGV+i0H4cpYH9+3JJ78"
    "km4KXwaf9xUJCWF6nxeD+qG6Fyruw1Qlbds2r85U9dkNDVAS3gioCvELryh1TxKGiVTkg4wqHTyH"
    "fWsp7KD3WQHYJn0RyfJJu6YEmL77zonn7p2SRMvTMP3ZEXibnC9gz3nnhR6wcYL8Q7zXypKTMD58"
    "bTixDSJwIDAQAB"
)

ZONE_CONFIG: Final[dict[str, ZoneConfig]] = {
    "hiroshimajobnavi.com": {
        "address": "34.111.141.225",
        "ssl": "full",
    },
    "notatel.com": {
        "sip_server": "sip.telnyx.com",
    },
    "bestratereview.com": {
        "google_verification": "1O4KHQCY_QaBmRlMHA_WUU3LGeqjmKr_4JN25L5_ybQ",
        "mail_server": "smtp.google.com",
    },
    "clarkn.co.jp": {
        "google_verification": "ZsBDgLNcr70Rc7e6dF47J7pbLp435l1CF-hHyf6EaQM",
        "mail_server": "smtp.google.com",
        "additional_records": [
            ("uni", "A", "219.211.176.140", False),
            ("@", "TXT", "google-site-verification=ZH2D3QODde7h7X2yI299oREgSXmMcPbtKjtl122vmqg", False),
        ],
        "worker_domains": [("clarkn-meet", "meet")],
    },
    "southtowntattoocollective.com": {
        "redirect_to": "tattoocollectivereno.com",
        "short_name": "tattoocollectivereno",
    },
    "vec4me.com": {
        "retro_index": True,
    },
    "je.gy": {
        "short_name": "jegy",
        "icloud_mail": True,
    },
}


# Helpers

def get_config(zone: Zone, key: str) -> object:
    """Get a configuration value for a zone by key."""
    return ZONE_CONFIG.get(str(zone["name"]), {}).get(key)


def is_brr_child(zone: Zone) -> bool:
    """Check whether a zone is a child of bestratereview.com."""
    return "rate" in str(zone["name"]) and zone["name"] != "bestratereview.com"


def is_www_primary(zone: Zone) -> bool:
    """Check whether www is the primary hostname for a zone."""
    parts = str(zone["name"]).split(".")
    return not parts[0].isdigit() and parts[-1] in {"com", "net", "org", "jp"}


def get_hostnames(zone: Zone) -> tuple[str, str]:
    """Return (primary, secondary) hostnames for a zone."""
    www, root = f"www.{zone['name']}", str(zone["name"])
    return (www, root) if is_www_primary(zone) else (root, www)


def get_short_name(zone: Zone) -> str:
    """Return the short name for a zone, respecting settings."""
    override = get_config(zone, "short_name")
    if override is not None:
        return str(override)
    return str(zone["name"]).split(".")[0]


def find_service(collection: dict[str, object], name: str, suffixes: list[str]) -> str | None:
    """Find a service in a collection by trying name+suffix combinations."""
    for suffix in suffixes:
        key = f"{name}{suffix}"
        if key in collection:
            return key
    return None


def find_worker(workers: dict[str, object], zone: Zone) -> str | None:
    """Find the worker associated with a zone."""
    return find_service(workers, get_short_name(zone), ["", "-website"])


def find_page(pages: dict[str, object], zone: Zone) -> str | None:
    """Find the page associated with a zone."""
    return find_service(pages, get_short_name(zone), ["", "-website"])


def find_api_worker(workers: dict[str, object], zone: Zone) -> str | None:
    """Find the API worker associated with a zone."""
    return find_service(workers, get_short_name(zone), ["-api", ""])


def get_hosting_type(
    workers: dict[str, object],
    pages: dict[str, object],
    zone: Zone,
) -> HostingType:
    """Determine whether a zone is backed by a worker or a page."""
    if find_worker(workers, zone):
        return "worker"
    if find_page(pages, zone):
        return "page"
    return None


# Email

def configure_cf_email(
    local: ConfigTree,
    zone: Zone,
    forward_to: str,
    dkim_tokens: dict[str, list[str]] | None,
) -> None:
    """Configure Cloudflare Email Routing and SES outbound DNS for a zone."""
    name = str(zone["name"])
    is_icloud = get_config(zone, "icloud_mail") is not None

    spf_includes = "include:_spf.mx.cloudflare.net include:amazonses.com"
    if is_icloud:
        spf_includes += " include:icloud.com"
    cloudflare.make_record(local, zone, "@", "TXT", f"v=spf1 {spf_includes} ~all")

    # Cloudflare Email Routing MX
    cloudflare.make_record(local, zone, "@", "MX", "route1.mx.cloudflare.net", priority=10)
    cloudflare.make_record(local, zone, "@", "MX", "route2.mx.cloudflare.net", priority=20)
    cloudflare.make_record(local, zone, "@", "MX", "route3.mx.cloudflare.net", priority=30)

    # Cloudflare Email Routing DKIM
    cloudflare.make_record(local, zone, "cf2024-1._domainkey", "TXT", CF_DKIM_RECORD)

    # SES outbound DKIM
    if dkim_tokens and name in dkim_tokens:
        for token in dkim_tokens[name]:
            cloudflare.make_record(
                local, zone, f"{token}._domainkey", "CNAME",
                f"{token}.dkim.amazonses.com", proxied=False,
            )

    # iCloud DKIM
    if is_icloud:
        cloudflare.make_record(
            local, zone, "sig1._domainkey", "CNAME",
            f"sig1.dkim.{name}.at.icloudmailadmin.com", proxied=False,
        )

    cloudflare.make_email_routing_catch_all(local, zone, forward_to=forward_to)


def configure_google_email(local: ConfigTree, zone: Zone) -> None:
    """Configure Google-based email DNS records for a zone."""
    mail_server = get_config(zone, "mail_server")
    google_verification = get_config(zone, "google_verification")
    if google_verification is not None:
        cloudflare.make_record(local, zone, "@", "TXT", f"google-site-verification={google_verification}")
    cloudflare.make_record(local, zone, "@", "MX", str(mail_server), priority=1)
    cloudflare.make_record(local, zone, "@", "TXT", "v=spf1 include:_spf.google.com ~all")


def configure_email(
    local: ConfigTree,
    zone: Zone,
    dkim_tokens: dict[str, list[str]] | None = None,
    forward_to: str | None = None,
) -> None:
    """Configure email DNS records for a zone based on its email provider."""
    mail_server = get_config(zone, "mail_server")
    if mail_server is not None:
        configure_google_email(local, zone)
        return

    if forward_to is None:
        msg = f"forward_to must be set for email routing domain {zone['name']}"
        raise ValueError(msg)
    configure_cf_email(local, zone, forward_to, dkim_tokens)


# DNS

def configure_dns(
    local: ConfigTree,
    workers: dict[str, object],
    zone: Zone,
    vps: str | None,
    hosting_type: HostingType,
) -> None:
    """Configure DNS records for a zone including A/CNAME, DMARC, mail, and API records."""
    address = get_config(zone, "address")
    if not address:
        address = "35.192.114.80" if "rate" in str(zone["name"]) else vps

    primary_label, secondary_label = ("www", "@") if is_www_primary(zone) else ("@", "www")

    if hosting_type == "page":
        pages_target = f"{get_short_name(zone)}.pages.dev"
        cloudflare.make_record(local, zone, primary_label, "CNAME", pages_target)
        cloudflare.make_record(local, zone, secondary_label, "CNAME", pages_target)
    elif hosting_type == "worker":
        pass  # worker domains handle DNS records
    else:
        cloudflare.make_record(local, zone, primary_label, "A", str(address))
        cloudflare.make_record(local, zone, secondary_label, "A", str(address))

    cloudflare.make_record(local, zone, "_dmarc", "TXT", "v=DMARC1; p=quarantine;")

    cloudflare.make_record(local, zone, "mail", "CNAME", "mail.vec4me.workers.dev")
    cloudflare.make_route(local, zone, f"mail.{zone['name']}/unsubscribe*", "mail")

    api_worker = find_api_worker(workers, zone)
    if api_worker:
        cloudflare.make_record(local, zone, "api", "CNAME", f"{api_worker}.vec4me.workers.dev")
        cloudflare.make_route(local, zone, f"api.{zone['name']}/*", api_worker)

    configure_sip_records(local, zone)
    configure_additional_records(local, zone)


def configure_sip_records(local: ConfigTree, zone: Zone) -> None:
    """Configure SIP DNS records for a zone if applicable."""
    sip_server = get_config(zone, "sip_server")
    if sip_server:
        cloudflare.make_record(local, zone, "sip", "CNAME", str(sip_server), proxied=False)
        cloudflare.make_srv_record(local, zone, "_sip", "_udp", f"sip.{zone['name']}", port=5060)


def configure_additional_records(local: ConfigTree, zone: Zone) -> None:
    """Configure any additional DNS records specified in zone config."""
    additional_records = get_config(zone, "additional_records")
    if additional_records:
        records = cast("list[tuple[str, str, str, bool]]", additional_records)
        for name, record_type, content, proxied in records:
            cloudflare.make_record(local, zone, name, record_type, content, proxied=proxied)


# Redirects

def configure_redirects(local: ConfigTree, zone: Zone) -> None:
    """Configure redirect rules for a zone."""
    primary, secondary = get_hostnames(zone)

    cloudflare.make_redirect_rule(
        local, zone,
        f'(http.host eq "{secondary}")',
        f'concat("https://{primary}", http.request.uri.path)',
    )
    cloudflare.make_redirect_rule(
        local, zone,
        f'(http.host eq "{primary}" and starts_with(http.request.uri.path, "/fbclid"))',
        f'concat("https://{primary}/", "")',
    )

    configure_special_redirects(local, zone, primary)


def configure_special_redirects(
    local: ConfigTree,
    zone: Zone,
    primary: str,
) -> None:
    """Configure special redirect rules (retro index, redirect_to, BRR child)."""
    if get_config(zone, "retro_index") is not None:
        cloudflare.make_redirect_rule(
            local, zone,
            f'(http.host eq "{primary}" and http.request.uri.path eq "/")',
            f'concat("https://{primary}/index.htm", "")',
        )
    elif (redirect_to := get_config(zone, "redirect_to")) is not None:
        cloudflare.make_redirect_rule(
            local, zone,
            f'(http.host eq "www.{zone["name"]}")',
            f'concat("https://www.{redirect_to}", http.request.uri.path)',
        )
        cloudflare.make_redirect_rule(
            local, zone,
            f'(http.host eq "{zone["name"]}")',
            f'concat("https://{redirect_to}", http.request.uri.path)',
        )
    elif is_brr_child(zone):
        cloudflare.make_redirect_rule(
            local, zone,
            f'(http.host eq "www.{zone["name"]}")',
            'concat("https://www.bestratereview.com", http.request.uri.path)',
        )
        cloudflare.make_redirect_rule(
            local, zone,
            f'(http.host eq "{zone["name"]}")',
            'concat("https://bestratereview.com", http.request.uri.path)',
        )
    else:
        pass  # no special redirects for this zone


# Domains

def configure_domains(
    local: ConfigTree,
    workers: dict[str, object],
    pages: dict[str, object],
    zone: Zone,
    used_services: set[str],
    hosting_type: HostingType,
) -> None:
    """Configure worker and page custom domains for a zone."""
    primary, secondary = get_hostnames(zone)

    worker_domains = get_config(zone, "worker_domains")
    if worker_domains:
        domains = cast("list[tuple[str, str]]", worker_domains)
        for worker_name, subdomain in domains:
            cloudflare.make_worker_domain(local, worker_name, zone, f"{subdomain}.{zone['name']}")
            used_services.add(worker_name)

    api_worker = find_api_worker(workers, zone)
    if api_worker:
        used_services.add(api_worker)

    worker = find_worker(workers, zone)
    if worker:
        used_services.add(worker)
    if hosting_type == "worker" and worker:
        cloudflare.make_worker_domain(local, worker, zone, primary)
        cloudflare.make_worker_domain(local, worker, zone, secondary)

    page = find_page(pages, zone)
    if page:
        used_services.add(page)
    if hosting_type == "page" and page:
        cloudflare.make_page_domain(local, page, primary)
        cloudflare.make_page_domain(local, page, secondary)


# Settings

def configure_settings(
    local: ConfigTree,
    zone: Zone,
    settings: dict[str, object],
) -> None:
    """Configure zone settings from settings, respecting per-zone config."""
    zone_settings = cast("dict[str, dict[str, Any]]", zone["settings"])
    for setting_id, setting in zone_settings.items():
        if setting["editable"] and setting_id in settings:
            value = settings[setting_id]
            zone_override = get_config(zone, setting_id)
            if zone_override is not None:
                value = zone_override
            cloudflare.make_setting(local, zone, setting_id, value)
    if zone["dnssec"]:
        cloudflare.make_dnssec(local, zone, "disabled")


# Regery

def configure_regery(
    local: ConfigTree,
    zones: dict[str, Zone],
    contact_id: str,
) -> None:
    """Configure Regery domains to use Cloudflare nameservers with auto-renew."""
    for zone in zones.values():
        name = str(zone["name"])
        nameservers = cast("list[str]", zone.get("name_servers", []))
        regery.make_domain(
            local,
            name=name,
            auto_renew=True,
            nameservers=sorted(nameservers),
            contacts={
                "registrant": contact_id,
                "admin": contact_id,
                "tech": contact_id,
                "billing": contact_id,
                "services": ["proxy"],
                "disclose": False,
            },
        )


# SES

def configure_ses(
    local: ConfigTree,
    domains: list[str],
) -> None:
    """Configure SES outbound infrastructure (identities + SMTP users)."""
    for domain in domains:
        ses.make_identity(local, domain)
        ses.make_smtp_user(local, domain)


# ============================================================
# Main
# ============================================================

DEFAULT_SETTINGS: Final[dict[str, object]] = {
    "0rtt": "on",
    "always_online": "off",
    "always_use_https": "off",
    "automatic_https_rewrites": "off",
    "brotli": "on",
    "browser_check": "off",
    "development_mode": "off",
    "early_hints": "off",
    "email_obfuscation": "off",
    "filter_logs_to_cloudflare": "off",
    "hotlink_protection": "off",
    "http3": "on",
    "ip_geolocation": "on",
    "ipv6": "on",
    "log_to_cloudflare": "on",
    "opportunistic_encryption": "off",
    "opportunistic_onion": "off",
    "pq_keyex": "off",
    "privacy_pass": "off",
    "pseudo_ipv4": "off",
    "replace_insecure_js": "off",
    "rocket_loader": "off",
    "server_side_exclude": "off",
    "ssl": "flexible",
    "tls_1_2_only": "off",
    "tls_1_3": "zrt",
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
    "min_tls_version": "1.0",
    "security_level": "essentially_off",
    "browser_cache_ttl": 0,
    "challenge_ttl": 604800,
    "edge_cache_ttl": 7200,
    "max_upload": 100,
    "minify": {"css": "off", "html": "off", "js": "off"},
    "mobile_redirect": {"status": "off", "mobile_subdomain": None, "strip_uri": False},
    "security_header": {
        "strict_transport_security": {
            "enabled": False,
            "max_age": 0,
            "include_subdomains": False,
            "preload": False,
            "nosniff": False,
        },
    },
    "ciphers": [],
    "origin_max_http_version": "1",
}


def run_ses_fetch(
    aws_region: str | None,
) -> tuple[ConfigTree, dict[str, list[str]]]:
    """Initialize SES and fetch remote state. Returns (remote_tree, dkim_tokens)."""
    if aws_region is None:
        return {}, {}
    ses.init(aws_region)
    logger.info("=== SES ===")
    return ses.fetch_all()


def run_cloudflare(
    settings: dict[str, object],
    vps: str | None,
    dkim_tokens: dict[str, list[str]],
    email_routing_domains: dict[str, str],
    zone_list: list[Zone] | None = None,
) -> dict[str, Zone]:
    """Run the Cloudflare declarative configuration. Returns zones dict."""
    logger.info("\n=== Cloudflare ===")
    used_services: set[str] = set()

    remote, zones, workers, pages = cloudflare.fetch_all(setting_ids=set(settings.keys()), zone_list=zone_list)

    local: ConfigTree = {}
    for zone in zones.values():
        hosting_type = get_hosting_type(workers, pages, zone)
        forward_to = email_routing_domains.get(str(zone["name"]))
        configure_email(local, zone, dkim_tokens, forward_to)
        configure_dns(local, workers, zone, vps, hosting_type)
        configure_redirects(local, zone)
        configure_domains(local, workers, pages, zone, used_services, hosting_type)
        configure_settings(local, zone, settings)

    for worker_id in workers:
        if worker_id not in used_services:
            logger.info("unused worker: %s", worker_id)
    for page_name in pages:
        if page_name not in used_services:
            logger.info("unused page: %s", page_name)

    provider.run_deltas(remote, local)

    return zones


def run_ses_apply(
    ses_remote: ConfigTree,
    ses_domains: list[str],
) -> None:
    """Run the SES declarative configuration."""
    if not ses_domains:
        return
    logger.info("\n=== SES ===")
    local: ConfigTree = {}
    configure_ses(local, ses_domains)
    provider.run_deltas(ses_remote, local)


def main() -> None:
    """Run the full infrastructure configuration pipeline."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    vps = os.getenv("VPS")
    aws_region = os.getenv("AWS_REGION")

    email_forwards: dict[str, str] = {
        "tattoocollectivereno.com": "tattoocollectivereno@gmail.com",
        "southtowntattoocollective.com": "tattoocollectivereno@gmail.com",
        "hiroshimajobnavi.com": "info@clarkn.co.jp",
    }
    email_default_forward = "vec4me@icloud.com"

    cloudflare.init()
    telnyx.init()
    regery.init()

    google_domains = {name for name, config in ZONE_CONFIG.items() if "mail_server" in config}
    zone_list = cloudflare.paginate("zones")
    email_routing_domains: dict[str, str] = {}
    for zone in zone_list:
        name = str(zone["name"])
        if name not in google_domains:
            email_routing_domains[name] = email_forwards.get(name, email_default_forward)

    ses_remote, dkim_tokens = run_ses_fetch(aws_region)
    ses_domains = list(email_routing_domains.keys())

    cloudflare.ensure_destination_addresses(set(email_routing_domains.values()))
    zones = run_cloudflare(DEFAULT_SETTINGS, vps, dkim_tokens, email_routing_domains, zone_list=zone_list)
    run_ses_apply(ses_remote, ses_domains)

    sip_password = os.getenv("SIP_PASSWORD", "")

    logger.info("\n=== Telnyx ===")
    telnyx_data = telnyx.fetch_all()
    telnyx.configure(
        telnyx_data,
        webhook_url="https://sms-cloudflare-central.vec4me.workers.dev/",
        voice_destinations=["US", "CA", "MX", "JP"],
        sip_password=sip_password,
        external_pin="5669",
        number_config={
            "+17752000767": {
                "call_forwarding": {
                    "call_forwarding_enabled": True,
                    "forwards_to": "+819094141337",
                    "forwarding_type": "always",
                },
            },
        },
    )

    regery_contact_id = os.getenv("REGERY_CONTACT_ID", "")

    logger.info("\n=== Regery ===")
    regery_remote = regery.fetch_all()

    local: ConfigTree = {}
    configure_regery(local, zones, regery_contact_id)
    provider.run_deltas(regery_remote, local)


if __name__ == "__main__":
    main()
