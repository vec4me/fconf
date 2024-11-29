# Cloudflare Linter by Jeffrey Skinner <jeff@je.gy> a.k.a. blocksrey
# I should do patching instead of deleting everything and rewriting.

API_TOKEN = "PauifCWEbEo7RJehPHQ7t9xuMYE93LNPwNpy5Q-b"
ACCOUNT_ID = "a1de4b4bea97ddf530554ad8b89a6ace"
URL_LINTER_WORKER_NAME = "forward" # Forward was not a good name. LOL
MAILCHANNELS_ID = "truckee00"

get_length = len

import requests
import json
import re

ADDRESS = "A"
WILD = "*"
CNAME = "CNAME"
FLATTEN = True
UNFLATTEN = False
PROXIED = True
UNPROXIED = False
ROOT = "@"
TEXT = "TXT"
WWW = "www"
GATEWAY = "1.1.1.1"
VPS = "5.78.116.190"
AUTO = 1
RESPECT_HEADERS = 0 # Apparently 0 is the equivalent of "respect headers."
GOOGLE_SITE_VERIFICATION = "google-site-verification=BwEFkZFAZLbcyX6mlw0Azb-aZTIsf11vanr6UX6_lX4"
ONE_DAY = 86400
ONE_WEEK = 604800
TWO_HOURS = 7200

DEFAULT_AS_HEADERS = {
	"Authorization": f"Bearer {API_TOKEN}",
	"Content-Type": "application/json"
}

types = {}
types["delete"] = requests.delete
types["get"] = requests.get
types["patch"] = requests.patch
types["post"] = requests.post

def perform(type, url, json = None):
	response = types[type](f"https://api.cloudflare.com/client/v4/{url}", headers = DEFAULT_AS_HEADERS, json = json)
	if response.status_code == 200:
		return response.json()["result"]
	else:
		print(f"{response.json()["errors"][0]["message"]}: {url}")

def get_69_zones():
	return perform("get", "zones?per_page=69")

def get_records(zone):
	records = perform("get", f"zones/{zone["id"]}/dns_records")
	for record in records:
		if record["name"] == zone["name"]:
			record["name"] = ROOT
		elif record["name"].endswith(f".{zone["name"]}"):
			record["name"] = record["name"][0:-(1 + len(zone["name"]))]
	return records

def get_formatted_record(record):
	return f"{record["zone_name"]}'s record [{record["type"]}, {record["name"]}, {record["content"]}]"

def delete_record(record):
	print(f"Delete {get_formatted_record(record)}")
	perform("delete", f"zones/{record["zone_id"]}/dns_records/{record["id"]}")

def get_settings(zone):
	return perform("get", f"zones/{zone["id"]}/settings")

def do_spf_records(zone):
	records = get_records(zone)
	for record in records:
		if "v=spf1" in record["content"]:
			delete_record(record)
	url = f"zones/{zone["id"]}/dns_records"
	# "ttl": ONE_DAY, # https://community.cloudflare.com/t/adding-an-spf-record-to-our-dns/538913
	create_record(zone, TEXT, ROOT, "v=spf1 include:icloud.com include:_spf.mx.cloudflare.net include:_spf.google.com include:relay.mailchannels.net ~all")

override_levels = {}

override_levels["0rtt"] = "on" # Extra performance
override_levels["always_online"] = "off" # This is cool, but bad for debugging.
override_levels["always_use_https"] = "off" # Never always do anything.
override_levels["automatic_https_rewrites"] = "off"
override_levels["brotli"] = "on" # Transparent
override_levels["browser_check"] = "off"
override_levels["development_mode"] = "off"
override_levels["early_hints"] = "off"
override_levels["email_obfuscation"] = "off" # Stupid
override_levels["filter_logs_to_cloudflare"] = "off"
override_levels["hotlink_protection"] = "off" # Stupid
override_levels["http3"] = "on" # Support HTTP/3
override_levels["ip_geolocation"] = "on"
override_levels["ipv6"] = "on" # Support IPv6
override_levels["log_to_cloudflare"] = "on"
override_levels["opportunistic_encryption"] = "off"
override_levels["opportunistic_onion"] = "off"
override_levels["orange_to_orange"] = "off"
override_levels["pq_keyex"] = "off"
override_levels["privacy_pass"] = "off"
override_levels["pseudo_ipv4"] = "off" # Pseudo-stuff isn't good.
override_levels["replace_insecure_js"] = "off"
override_levels["rocket_loader"] = "off"
override_levels["server_side_exclude"] = "off"
override_levels["ssl"] = "flexible"
# override_levels["ssl"] = "full"
override_levels["tls_1_2_only"] = "off" # Don't force stuff.
override_levels["tls_1_3"] = "zrt" # More support (zrt = on + 0rtt)
override_levels["tls_client_auth"] = "off"
override_levels["visitor_ip"] = "on"
override_levels["waf"] = "off"
override_levels["websockets"] = "on"
override_levels["ech"] = "off"

# override_levels["universal_ssl"] = ""
# override_levels["response_buffering"] = "off"
# override_levels["mirage"] = "off"
# override_levels["binary_ast"] = "off"

override_levels["cache_level"] = "aggressive"
override_levels["cname_flattening"] = "flatten_at_root"
override_levels["min_tls_version"] = "1.0" # This is supposed to be a string.
override_levels["security_level"] = "essentially_off"

override_levels["browser_cache_ttl"] = RESPECT_HEADERS
override_levels["challenge_ttl"] = ONE_WEEK
override_levels["edge_cache_ttl"] = TWO_HOURS
override_levels["max_upload"] = 100 # This is supposed to be a number for some reason.

override_levels["minify"] = {"css": "off", "html": "off", "js": "off"}
override_levels["mobile_redirect"] = {"status": "off", "mobile_subdomain": None, "strip_uri": False}
override_levels["security_header"] = {"strict_transport_security": {"enabled": False, "max_age": 0, "include_subdomains": False, "preload": False, "nosniff": False}}

override_levels["ciphers"] = []

def add_redirect(zone, url0, url1):
	print(f"Add rule {url0} -> {url1} to {zone["name"]}")
	payload_as_json = {
		"targets": [
			{
				"target": "url",
				"constraint": {
					"operator": "matches",
					"value": url0
				}
			}
		],
		"actions": [
			{
				"id": "forwarding_url",
				"value": {
					"url": url1,
					"status_code": 301
				}
			}
		],
		"priority": 1, # LMAO
		"status": "active"
	}
	perform("post", f"zones/{zone["id"]}/pagerules", payload_as_json)

def delete_page_rule(zone, rule):
	print(f"Delete rule {rule} from {zone["name"]}")
	url = f"zones/{zone["id"]}/pagerules/{rule["id"]}"
	perform("delete", url)

def get_page_rules(zone):
	url = f"zones/{zone["id"]}/pagerules"
	rules = perform("get", url)
	return rules

def delete_page_rules(zone):
	# Todo, something's broken here, can't seem to get the page rules.
	rules = get_page_rules(zone)
	for rule in rules:
		delete_page_rule(zone, rule)

def do_page_rules(zone):
	delete_page_rules(zone)

	if zone["name"] == "blocksrey.com":
		add_redirect(zone, f"https://www.{zone["name"]}/", f"https://www.{zone["name"]}/index.htm")
		add_redirect(zone, f"https://www.{zone["name"]}/?*", f"https://www.{zone["name"]}/index.htm")
	elif zone["name"] == "southtowntattoocollective.com":
		add_redirect(zone, f"https://*southtowntattoocollective.com/*", f"https://$1tattoocollectivereno.com/$2") # This works for now.
	else:
		primary, secondary = get_web_pair(zone)
		add_redirect(zone, f"https://{secondary}/*", f"https://{primary}/$1")

def is_page_responding(domain):
	try:
		requests.head(f"https://{domain}")
		return True
	except:
		return False

def create_page_domain_from_zone(zone, domain):
	short_name = get_short_name(zone)
	primary, secondary = get_web_pair(zone)
	for page in pages:
		if page["name"] == short_name:
			create_page_domain(page, primary)

def do_web_records(zone):
	delete_web_records(zone)

	revert = None
	if zone["name"] == "southtowntattoocollective.com":
		revert = "southtowntattoocollective.com"
		zone["name"] = "tattoocollectivereno.com"

	domain = f"{get_short_name(zone)}.pages.dev"
	if not is_page_responding(domain):
		domain = VPS

	if is_og(zone):
		easy_create_record(zone, WWW, domain, PROXIED)
		easy_create_record(zone, ROOT, domain, PROXIED)
	else:
		easy_create_record(zone, ROOT, domain, PROXIED)
		easy_create_record(zone, WWW, domain, PROXIED)

	# create_page_domain_from_zone(zone, domain)

	if revert:
		zone["name"] = revert
		revert = None

def do_settings(zone):
	settings = get_settings(zone)
	for setting in settings:
		if not setting["editable"]:
			continue
		try:
			override_level = override_levels[setting["id"]]
			if override_level != setting["value"]:
				payload_as_json = {
					"value": override_level
				}
				print(f"{setting["id"]} = {setting["value"]} -> {payload_as_json["value"]}")
				perform("patch", f"zones/{zone["id"]}/settings/{setting["id"]}", payload_as_json)
		except:
			print(f"Missing override {setting["id"]} = {setting["value"]}")
	if True:
		perform("patch", f"zones/{zone["id"]}/dnssec", {"status": "disabled"})
		perform("patch", f"zones/{zone["id"]}/settings/origin_max_http_version", {"value": "1"})
		perform("patch", f"zones/{zone["id"]}/url_normalization", {"scope": "incoming", "type": "rfc_3986"})

def set_proxied(record, proxied):
	url = f"zones/{record["zone_id"]}/dns_records/{record["id"]}"
	payload_as_json = {
		"content": record["content"],
		"name": record["name"],
		"proxied": proxied,
		"ttl": record["ttl"],
		"type": record["type"]
	}
	perform("post", url, payload_as_json)

def quote_if_space(string):
	if " " in string:
		return f'"{string}"'
	return string

def create_record(zone, type, name, content, proxied = UNPROXIED):
	print(f"Create {zone["name"]}'s record [{type}, {name}, {content}]")
	# Prioritize zone name given that @ = zone name.
	if name == ROOT:
		name = zone["name"]
	url = f"zones/{zone["id"]}/dns_records"
	payload_as_json = {
		"content": quote_if_space(content),
		"name": name,
		"proxied": proxied,
		"ttl": AUTO,
		"type": type
	}
	perform("post", url, payload_as_json)

# This is not true in the general sense but should work for our use case.
def is_ip_address(address):
	return address.count(".") == 3

def easy_create_record(zone, name, content, proxied = UNPROXIED):
	if is_ip_address(content):
		create_record(zone, ADDRESS, name, content, proxied)
	elif contains_weird(content):
		create_record(zone, TEXT, name, content, proxied)
	else:
		create_record(zone, CNAME, name, content, proxied)

def do_fast_vps_record(zone):
	print(f"Do fast VPS record {zone["name"]}")
	# if zone["name"] != "je.gy":
	# 	easy_create_record(zone, WWW, "pan.je.gy")
	# else:
		# create_record(zone, ADDRESS, ROOT, VPS) # Pan (Hetzner US)
	# create_record(zone, ADDRESS, WILD, VPS) # Pan (Hetzner US)
	# easy_create_record(zone, WILD, "fe46fb907541b3e9d66a6f721dc11258.serveo.net")
	# create_record(zone, ADDRESS, WILD, VPS)
	# easy_create_record(zone, WILD, f"{get_short_name(zone)}.pages.dev") # Pages

def is_og(zone):
	parts = zone["name"].split(".")
	is_og = parts[1] == "com" or parts[1] == "net" or parts[1] == "org"
	return is_og

def get_short_name(zone):
	is_og = is_og(zone)
	parts = zone["name"].split(".")
	short_name = is_og and parts[0] or zone["name"].replace(".", "")
	return short_name

def delete_web_records(zone):
	records = get_records(zone)
	for record in records:
		if is_web(record):
			delete_record(record)

def is_web(record):
	return (is_cname(record) or record["type"] == ADRESS) and (record["type"] == ROOT or record["type"] == WWW)

def get_web_pair(zone):
	www = f"www.{zone["name"]}"
	root = zone["name"]
	if is_og(zone):
		return www, root
	else:
		return root, www

def do_cname_records(zone):
	# We gotta delete

	www = None
	root = None

	records = get_records(zone)

	if not records:
		print(f"No DNS records for {zone["name"]}")
		return

	for record in records:
		if is_web(record):
			if record["type"] == WWW:
				www = record
				target = record["content"]
			elif record["type"] == ROOT:
				root = record
				target = record["content"]

	if not www and root:
		easy_create_record(zone, WWW, root["content"])
		delete_record(root)
		# print(f"Created www subs record for {record["zone_name"]}")
	elif www and root and www["content"] != root["content"]:
		# print(f"Subs are pointing to different targets for {record["zone_name"]}")
		delete_record(root)
	if not root and www:
		easy_create_record(zone, record["zone_name"], target)
		# print(f"{record["zone_name"]} is missing a root sub but has www")
		pass

	# if root:
	# 	delete_record(root)

def delete_dev_records(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == "dev":
			delete_record(record)

def do_dev_records(zone):
	records = get_records(zone)
	delete_dev_records(zone)
	create_record(zone, ADDRESS, "dev", VPS, PROXIED)

def Is(record, type):
	return record["type"] == type

# def delete_a_and_cname_records(records):
# 	for record in records:
# 		if record["type"] == ADDRESS or Is(record, CNAME)):
# 			delete_record(record)

def delete_text_records(zone):
	records = get_records(zone)
	for record in records:
		if Is(record, TEXT):
			delete_record(record)

# def proxy_and_lint_records(records):
# 	for record in records:
# 		if record["type"] == ADRESS:
# 			if record["name"] == ROOT or record["name"] == WWW:
# 				# set_proxied(record, PROXIED)
# 				set_proxied(record, PROXIED) # We're gonna turn off proxying for now because it's faster.
# 			elif record["proxied"]:
# 				set_proxied(record, UNPROXIED)

def do_world_records_and_proxy(zone):
	records = get_records(zone)
	for record in records:
		if is_web(record):
			if Is(record, ADDRESS):
				set_proxied(record, PROXIED)

def add_route(zone, script, pattern):
	print(f"Add {zone["name"]}'s worker route {pattern}")
	payload_as_json = {
		"pattern": pattern,
		"script": script
	}
	perform("post", f"zones/{zone["id"]}/workers/routes", payload_as_json)

def get_routes(zone):
	return perform("get", f"zones/{zone["id"]}/workers/routes")

def delete_route(zone, route):
	print(f"Delete {zone["name"]}'s worker route {route["pattern"]}")
	perform("delete", f"zones/{zone["id"]}/workers/routes/{route["id"]}")

def delete_api_routes(zone):
	routes = get_routes(zone)
	for route in routes:
		if route["pattern"] == f"api.{zone["name"]}/":
			delete_route(zone, route)

def do_api_routes(zone):
	delete_api_routes(zone)
	add_route(zone, get_short_name(zone), f"api.{zone["name"]}/")

def delete_wildcards(records):
	for record in records:
		if record["name"] == WILD:
			delete_record(record)

def delete_root_cname_records(records):
	for record in records:
		if record["type"] == ROOT and Is(record, CNAME):
			delete_record(record)

def delete_root_txt_records(records):
	for record in records:
		if record["type"] == ROOT and Is(record, TEXT):
			delete_record(record)

def delete_url_linter_routes(zone):
	routes = get_routes(zone)
	for route in routes:
		if route["script"] == URL_LINTER_WORKER_NAME:
			delete_route(zone, route)

def do_url_linter_routes(zone):
	delete_url_linter_routes(zone)

	# Forward should really be called lint URL or something different.
	if is_og(zone):
		add_route(zone, URL_LINTER_WORKER_NAME, f"www.{zone["name"]}/*")
	else:
		add_route(zone, URL_LINTER_WORKER_NAME, f"{zone["name"]}/*")

	# if zone["name"] == "leetforms.com":
	# 	add_route(zone, "leetforms", f"tattoocollectivereno.leetforms.com/")
	# add_route(zone, URL_LINTER_WORKER_NAME, f"*{zone["name"]}/*")

def delete_api_records(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == "api":
			delete_record(record)

def do_api_records(zone):
	delete_api_records(zone)
	easy_create_record(zone, "api", f"{get_short_name(zone)}.blocksrey.workers.dev", PROXIED)

def get_pages():
	return perform("get", f"accounts/{ACCOUNT_ID}/pages/projects")

def create_page_domain(page, domain):
	url = f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains"
	payload_as_json = {
		"domains": [f"https://{domain}"]
	}
	perform("post", url, payload_as_json)

def get_page_domains(page):
	url = f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains"
	page_domains = perform("get", url)
	return page_domains

def delete_page_domain(page_domain):
	url = f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains/{page_domain["name"]}"
	perform("delete", url)

def delete_page_domains(page):
	page_domains = get_page_domains(page)
	for page_domain in page_domains:
		delete_page_domains(page_domain)

# Make a function to lint URLs (ensure trailing slashes) on Pages, Workers, etc.

def do_google_search_console_records(zone):
	create_record(zone, TEXT, ROOT, GOOGLE_SITE_VERIFICATION)

def autofy_records(zone):
	records = get_records(zone)
	for record in records:
		if record["ttl"] != AUTO:
			url = f"zones/{record["zone_id"]}/dns_records/{record["id"]}"
			payload_as_json = {
				"ttl": AUTO
			}
			perform("patch", url, payload_as_json)

def proxify_records(zone, proxied = PROXIED):
	records = get_records(zone)
	for record in records:
		# Construct the API endpoint URL for each record
		url = f"zones/{record["zone_id"]}/dns_records/{record["id"]}"
		# Create the payload, preserving TTL and proxied settings
		payload_as_json = {
			"proxied": proxied
		}
		# Perform the patch request to update the record
		perform("patch", url, payload_as_json)

def tell_me_page_domain_stuff():
	pages = get_pages()
	for page in pages:
		page_domains = get_page_domains(page)
		if get_length(page_domains) != 1:
			print(f"{page["name"]} should only have 1 domain.")

def delete_dmarc_records(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == "_dmarc":
			delete_record(record)

def do_dmarc_records(zone):
	delete_dmarc_records(zone)
	easy_create_record(zone, "_dmarc", "v=DMARC1; p=quarantine;")
	# easy_create_record(zone, "_dmarc", "v=DMARC1; p=none;")

def delete_dkim_records(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == "_domainkey":
			delete_record(record)

def flatten_records(zone, flatten = FLATTEN):
	records = get_records(zone)
	for record in records:
		url = f"zones/{record["zone_id"]}/dns_records/{record["id"]}"
		payload_as_json = {
			"flatten": flatten
		}
		perform("patch", url, payload_as_json)

def delete_smtp_server_records(zone):
	records = get_records(zone)
	for record in records:
		if record["content"] == "smtp-server.blocksrey.workers.dev":
			delete_record(record)

def unquoted(string):
	return string[0] != '"' and string[-1] != '"'

def contains_weird(string):
	return bool(re.search(r"\W", string))

def is_tainted(record):
	return record["type"] == TEXT and contains_weird(record["content"]) and unquoted(record["content"])

def delete_tainted_records(zone):
	records = get_records(zone)
	for record in records:
		if is_tainted(record):
			delete_record(record)

# This should be more efficient than do
def ensure_record():
	# Find and patch a record.
	# Otherwise, create a new one.
	pass

def do_mailchannels_records(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == "_mailchannels":
			delete_record(record)
	easy_create_record(zone, "_mailchannels", f"v=mc1 auth={MAILCHANNELS_ID}")

def do_mail_records(zone):
	do_spf_records(zone)
	do_dmarc_records(zone)
	do_mailchannels_records(zone)
	# do_dkim_records(zone)

def brr_funnel(zone):
	return "rate" in zone["name"] and zone["name"] != "bestratereview.com"

def do_brr_stuff():
	zones = get_69_zones()
	for zone in zones:
		if brr_funnel(zone):
			print(zone)

if __name__ == "__main__":
	global pages
	pages = get_pages()
	zones = get_69_zones()
	do_brr_stuff()
	for zone in zones:
		# delete_tainted_records(zone)
		# do_mail_records(zone)
		# do_dmarc_records(zone)
		# do_settings(zone)
		# autofy_records(zone)
		# proxify_records(zone)
		# do_web_records(zone)
		pass
	# for page in pages:
	# 	do_page_rules(page)
	# tell_me_page_domain_stuff()
