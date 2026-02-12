"""CLI entry point for managing Cloudflare, SES, Telnyx, and Regery infrastructure."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import cloudflare as cf
import provider
import regery
import ses
import telnyx

if TYPE_CHECKING:
    from provider import ConfigTree

logger = logging.getLogger(__name__)

# ============================================================
# Cloudflare
# ============================================================

ZONE_CONFIG: dict[str, dict[str, object]] = {
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
        "additional_records": [("uni", "219.211.176.140", False)],
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
    },
}


# Helpers

def get_config(zone: dict[str, object], key: str) -> object:
    """Get a configuration value for a zone by key."""
    return ZONE_CONFIG.get(str(zone["name"]), {}).get(key)


def is_brr_child(zone: dict[str, object]) -> bool:
    """Check whether a zone is a child of bestratereview.com."""
    return "rate" in str(zone["name"]) and zone["name"] != "bestratereview.com"


def is_www_primary(zone: dict[str, object]) -> bool:
    """Check whether www is the primary hostname for a zone."""
    name = str(zone["name"])
    return not name.split(".")[0].isdigit() and name.split(".")[-1] in {"com", "net", "org", "jp"}


def get_hostnames(zone: dict[str, object]) -> tuple[str, str]:
    """Return (primary, secondary) hostnames for a zone."""
    www, root = f"www.{zone['name']}", str(zone["name"])
    return (www, root) if is_www_primary(zone) else (root, www)


def get_short_name(zone: dict[str, object]) -> str:
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


def find_worker(workers: dict[str, object], zone: dict[str, object]) -> str | None:
    """Find the worker associated with a zone."""
    return find_service(workers, get_short_name(zone), ["", "-website"])


def find_page(pages: dict[str, object], zone: dict[str, object]) -> str | None:
    """Find the page associated with a zone."""
    return find_service(pages, get_short_name(zone), ["", "-website"])


def find_api_worker(workers: dict[str, object], zone: dict[str, object]) -> str | None:
    """Find the API worker associated with a zone."""
    return find_service(workers, get_short_name(zone), ["-api", ""])


def get_hosting_type(
    workers: dict[str, object],
    pages: dict[str, object],
    zone: dict[str, object],
) -> str | None:
    """Determine whether a zone is backed by a worker or a page."""
    if find_worker(workers, zone):
        return "worker"
    if find_page(pages, zone):
        return "page"
    return None


# Email

def configure_ses_email(
    local: ConfigTree,
    zone: dict[str, object],
    aws_region: str,
    dkim_tokens: dict[str, list[str]] | None,
) -> None:
    """Configure SES-based email DNS records for a zone."""
    name = str(zone["name"])
    cf.make_record(local, zone, "@", f"inbound-smtp.{aws_region}.amazonaws.com", "MX", priority=10)
    cf.make_record(local, zone, "@", "v=spf1 include:amazonses.com ~all")
    if dkim_tokens and name in dkim_tokens:
        for token in dkim_tokens[name]:
            cf.make_record(
                local, zone, f"{token}._domainkey",
                f"{token}.dkim.amazonses.com", proxied=False,
            )


def configure_google_email(local: ConfigTree, zone: dict[str, object]) -> None:
    """Configure Google-based email DNS records for a zone."""
    mail_server = get_config(zone, "mail_server")
    google_verification = get_config(zone, "google_verification")
    if google_verification is not None:
        cf.make_record(local, zone, "@", f"google-site-verification={google_verification}")
    cf.make_record(local, zone, "@", str(mail_server), "MX", priority=1)
    cf.make_record(local, zone, "@", "v=spf1 include:_spf.google.com ~all")


def configure_email(
    local: ConfigTree,
    zone: dict[str, object],
    aws_region: str | None,
    dkim_tokens: dict[str, list[str]] | None = None,
) -> None:
    """Configure email DNS records for a zone based on its email provider."""
    name = str(zone["name"])

    mail_server = get_config(zone, "mail_server")
    if mail_server is not None:
        configure_google_email(local, zone)
        return

    if aws_region is None:
        msg = f"AWS_REGION must be set for SES domain {name}"
        raise ValueError(msg)
    configure_ses_email(local, zone, aws_region, dkim_tokens)


# DNS

def configure_dns(
    local: ConfigTree,
    workers: dict[str, object],
    pages: dict[str, object],
    zone: dict[str, object],
    vps: str | None,
) -> None:
    """Configure DNS records for a zone including A/CNAME, DMARC, mail, and API records."""
    hosting_type = get_hosting_type(workers, pages, zone)
    address = get_config(zone, "address")
    if not address:
        address = "35.192.114.80" if "rate" in str(zone["name"]) else vps

    primary_label, secondary_label = ("www", "@") if is_www_primary(zone) else ("@", "www")

    if hosting_type == "page":
        pages_target = f"{get_short_name(zone)}.pages.dev"
        cf.make_record(local, zone, primary_label, pages_target)
        cf.make_record(local, zone, secondary_label, pages_target)
    elif hosting_type == "worker":
        pass  # worker domains handle DNS records
    else:
        cf.make_record(local, zone, primary_label, str(address))
        cf.make_record(local, zone, secondary_label, str(address))

    cf.make_record(local, zone, "_dmarc", "v=DMARC1; p=quarantine;")

    cf.make_record(local, zone, "mail", "mail.vec4me.workers.dev")
    cf.make_route(local, zone, f"mail.{zone['name']}/unsubscribe*", "mail")

    api_worker = find_api_worker(workers, zone)
    if api_worker:
        cf.make_record(local, zone, "api", f"{api_worker}.vec4me.workers.dev")
        cf.make_route(local, zone, f"api.{zone['name']}/*", api_worker)

    configure_sip_records(local, zone)
    configure_additional_records(local, zone)


def configure_sip_records(local: ConfigTree, zone: dict[str, object]) -> None:
    """Configure SIP DNS records for a zone if applicable."""
    sip_server = get_config(zone, "sip_server")
    if sip_server:
        cf.make_record(local, zone, "sip", str(sip_server), proxied=False)
        cf.make_srv_record(local, zone, "_sip", "_udp", f"sip.{zone['name']}", port=5060)


def configure_additional_records(local: ConfigTree, zone: dict[str, object]) -> None:
    """Configure any additional DNS records specified in zone config."""
    additional_records = get_config(zone, "additional_records")
    if additional_records:
        for name, content, proxied in additional_records:
            cf.make_record(local, zone, name, content, proxied=proxied)


# Redirects

def configure_redirects(local: ConfigTree, zone: dict[str, object]) -> None:
    """Configure redirect rules for a zone."""
    primary, secondary = get_hostnames(zone)

    cf.make_redirect_rule(
        local, zone,
        f'(http.host eq "{secondary}")',
        f'concat("https://{primary}", http.request.uri.path)',
    )
    cf.make_redirect_rule(
        local, zone,
        f'(http.host eq "{primary}" and starts_with(http.request.uri.path, "/fbclid"))',
        f'concat("https://{primary}/", "")',
    )

    configure_special_redirects(local, zone, primary)


def configure_special_redirects(
    local: ConfigTree,
    zone: dict[str, object],
    primary: str,
) -> None:
    """Configure special redirect rules (retro index, redirect_to, BRR child)."""
    if get_config(zone, "retro_index") is not None:
        cf.make_redirect_rule(
            local, zone,
            f'(http.host eq "{primary}" and http.request.uri.path eq "/")',
            f'concat("https://{primary}/index.htm", "")',
        )
    elif (redirect_to := get_config(zone, "redirect_to")) is not None:
        cf.make_redirect_rule(
            local, zone,
            f'(http.host eq "www.{zone["name"]}")',
            f'concat("https://www.{redirect_to}", http.request.uri.path)',
        )
        cf.make_redirect_rule(
            local, zone,
            f'(http.host eq "{zone["name"]}")',
            f'concat("https://{redirect_to}", http.request.uri.path)',
        )
    elif is_brr_child(zone):
        cf.make_redirect_rule(
            local, zone,
            f'(http.host eq "www.{zone["name"]}")',
            'concat("https://www.bestratereview.com", http.request.uri.path)',
        )
        cf.make_redirect_rule(
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
    zone: dict[str, object],
    used_services: set[str],
) -> None:
    """Configure worker and page custom domains for a zone."""
    hosting_type = get_hosting_type(workers, pages, zone)
    primary, secondary = get_hostnames(zone)

    worker_domains = get_config(zone, "worker_domains")
    if worker_domains:
        for worker_name, subdomain in worker_domains:
            cf.make_worker_domain(local, worker_name, zone, f"{subdomain}.{zone['name']}")
            used_services.add(worker_name)

    api_worker = find_api_worker(workers, zone)
    if api_worker:
        used_services.add(api_worker)

    worker = find_worker(workers, zone)
    if worker:
        used_services.add(worker)
    if hosting_type == "worker" and worker:
        cf.make_worker_domain(local, worker, zone, primary)
        cf.make_worker_domain(local, worker, zone, secondary)

    page = find_page(pages, zone)
    if page:
        used_services.add(page)
    if hosting_type == "page" and page:
        cf.make_page_domain(local, page, primary)
        cf.make_page_domain(local, page, secondary)


# Settings

def configure_settings(
    local: ConfigTree,
    zone: dict[str, object],
    settings: dict[str, object],
) -> None:
    """Configure zone settings from settings, respecting per-zone config."""
    for setting_id, setting in zone["settings"].items():
        if setting["editable"] and setting_id in settings:
            value = settings[setting_id]
            zone_override = get_config(zone, setting_id)
            if zone_override is not None:
                value = zone_override
            cf.make_setting(local, zone, setting_id, value)
    if zone["dnssec"]:
        cf.make_dnssec(local, zone, "disabled")


# Regery

def configure_regery(
    local: ConfigTree,
    zones: dict[str, dict[str, object]],
    contact_id: str,
) -> None:
    """Configure Regery domains to use Cloudflare nameservers with auto-renew."""
    for zone in zones.values():
        name = str(zone["name"])
        nameservers = zone.get("name_servers", [])
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
    domains: dict[str, str],
    bucket_name: str,
) -> None:
    """Configure SES infrastructure and receipt rules for email forwarding."""
    ses.make_lambda_fn(local, bucket_name, domains)

    rule_set_name = "main"
    ses.make_rule_set(local, rule_set_name, active=True)

    lambda_arn = ses.get_lambda_arn()
    for domain in domains:
        ses.make_identity(local, domain)
        ses.make_receipt_rule(
            local,
            rule_set_name,
            rule_name=f"{domain}-catch-all",
            recipients=[domain],
            actions=[
                {"S3Action": {"BucketName": bucket_name, "ObjectKeyPrefix": ""}},
                {"LambdaAction": {"FunctionArn": lambda_arn, "InvocationType": "Event"}},
            ],
        )


# ============================================================
# Main
# ============================================================

def build_settings() -> dict[str, object]:
    """Build the zone settings settings dict."""
    return {
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
    ses_domains: dict[str, str],
    ses_bucket: str,
    aws_region: str | None,
) -> tuple[ConfigTree, dict[str, list[str]]]:
    """Initialize SES and fetch cloud state. Returns (cloud_tree, dkim_tokens)."""
    if not ses_domains:
        return {}, {}
    if aws_region is None:
        msg = "AWS_REGION must be set when ses_domains is configured"
        raise ValueError(msg)
    ses.init(aws_region)
    logger.info("=== SES ===")
    return ses.fetch_all(ses_bucket)


def run_cloudflare(
    settings: dict[str, object],
    aws_region: str | None,
    vps: str | None,
    dkim_tokens: dict[str, list[str]],
) -> dict[str, dict[str, object]]:
    """Run the Cloudflare declarative configuration. Returns zones dict."""
    logger.info("\n=== Cloudflare ===")
    used_services: set[str] = set()

    cloud, zones, workers, pages = cf.fetch_all(setting_ids=set(settings.keys()))

    local: ConfigTree = {}
    for zone in zones.values():
        configure_email(local, zone, aws_region, dkim_tokens)
        configure_dns(local, workers, pages, zone, vps)
        configure_redirects(local, zone)
        configure_domains(local, workers, pages, zone, used_services)
        configure_settings(local, zone, settings)

    for worker_id in workers:
        if worker_id not in used_services:
            logger.info("unused worker: %s", worker_id)
    for page_name in pages:
        if page_name not in used_services:
            logger.info("unused page: %s", page_name)

    provider.run_deltas(cloud, local)

    return zones


def run_ses_apply(
    ses_cloud: ConfigTree,
    ses_domains: dict[str, str],
    ses_bucket: str,
) -> None:
    """Run the SES declarative configuration."""
    if not ses_domains:
        return
    logger.info("\n=== SES ===")
    local: ConfigTree = {}
    configure_ses(local, ses_domains, ses_bucket)
    provider.run_deltas(ses_cloud, local)


def main() -> None:
    """Run the full infrastructure configuration pipeline."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    vps = os.getenv("VPS")
    aws_region = os.getenv("AWS_REGION")

    settings = build_settings()

    ses_forwards: dict[str, str] = {
        "tattoocollectivereno.com": "tattoocollectivereno@gmail.com",
        "southtowntattoocollective.com": "tattoocollectivereno@gmail.com",
    }
    ses_default_forward = "vec4me@icloud.com"
    ses_bucket = "vec4me-ses-forwarder"

    cf.init()
    telnyx.init()
    regery.init()

    google_domains = {name for name, config in ZONE_CONFIG.items() if "mail_server" in config}
    zone_list = cf.paginate("zones")
    ses_domains: dict[str, str] = {}
    for zone in zone_list:
        name = str(zone["name"])
        if name not in google_domains:
            ses_domains[name] = ses_forwards.get(name, ses_default_forward)

    ses_cloud, dkim_tokens = run_ses_fetch(ses_domains, ses_bucket, aws_region)
    zones = run_cloudflare(settings, aws_region, vps, dkim_tokens)
    run_ses_apply(ses_cloud, ses_domains, ses_bucket)

    sip_password = os.getenv("SIP_PASSWORD", "")

    logger.info("\n=== Telnyx ===")
    state = telnyx.fetch_all()
    telnyx.configure(
        state,
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
    regery_cloud = regery.fetch_all()

    local: ConfigTree = {}
    configure_regery(local, zones, regery_contact_id)
    provider.run_deltas(regery_cloud, local)


if __name__ == "__main__":
    main()
