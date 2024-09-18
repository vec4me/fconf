# Cloudflare Linter by Jeffrey Skinner <jeff@je.gy> a.k.a. blocksrey
# I should do patching instead of deleting everything and rewriting.

API_TOKEN = "PauifCWEbEo7RJehPHQ7t9xuMYE93LNPwNpy5Q-b"
ACCOUNT_ID = "a1de4b4bea97ddf530554ad8b89a6ace"
URL_LINTER_WORKER_NAME = "forward" # Forward was not a good name. LOL

import requests
import json

ADDRESS = "A"
ALL = "*"
CNAME = "CNAME"
PROXIED = True
ROOT = "@"
TXT = "TXT"
WWW = "www"
GATEWAY = "1.1.1.1"
VPS = "5.78.88.105"

default_as_headers = {
	"Authorization": f"Bearer {API_TOKEN}",
	"Content-Type": "application/json"
}

types = {}
types["delete"] = requests.delete
types["get"] = requests.get
types["patch"] = requests.patch
types["post"] = requests.post

def perform(type, url, json = None):
	response = types[type](f"https://api.cloudflare.com/client/v4/{url}", headers = default_as_headers, json = json)
	if response.status_code == 200:
		return response.json()["result"]
	else:
		print(f"{response.json()["errors"][0]["message"]}: {url}")

def get_69_zones():
	return perform("get", "zones?per_page=69")

def get_records(zone):
	return perform("get", f"zones/{zone["id"]}/dns_records")

def delete_record(record):
	print(f"Delete {record["zone_name"]}'s record {record["name"]}")
	perform("delete", f"zones/{record["zone_id"]}/dns_records/{record["id"]}")

def get_settings(zone):
	return perform("get", f"zones/{zone["id"]}/settings")

def lint_spf_record(zone):
	url = f"zones/{zone["id"]}/dns_records"
	payload_as_json = {
		"content": "v = spf1 include: _spf.mx.cloudflare.net ~all",
		"name": ROOT,
		"ttl": 86400, # https://community.cloudflare.com/t/adding-an-spf-record-to-our-dns/538913
		"type": TXT,
	}
	perform("post", url, payload_as_json)

override_levels = {}

override_levels["0rtt"] = "on" # Extra performance
override_levels["always_online"] = "off" # This is cool but bad for debugging.
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

# override_levels["universal_ssl"] = ""
# override_levels["response_buffering"] = "off"
# override_levels["mirage"] = "off"
# override_levels["binary_ast"] = "off"

override_levels["cache_level"] = "aggressive"
override_levels["cname_flattening"] = "flatten_at_root"
override_levels["min_tls_version"] = "1.0"
override_levels["security_level"] = "essentially_off"

override_levels["browser_cache_ttl"] = 0 # Apparently 0 is the equivalent of "respect headers."
override_levels["challenge_ttl"] = 604800 # 1 week
override_levels["edge_cache_ttl"] = 7200
override_levels["max_upload"] = 100

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
	rules = get_page_rules(zone)
	for rule in rules:
		delete_page_rule(zone, rule)

def do_page_rules(zone):
	delete_page_rules(zone)

	if zone["name"] == "blocksrey.com":
		add_redirect(zone, f"https://www.{zone["name"]}/", f"https://www.{zone["name"]}/index.htm")
		add_redirect(zone, f"https://www.{zone["name"]}/?*", f"https://www.{zone["name"]}/index.htm")
	elif zone["name"] == "southtowntattoocollective.com":
		add_redirect(zone, f"https://*.southtowntattoocollective.com/*", f"https://$1.tattoocollectivereno.com/$2")
	else:
		primary, secondary = get_web_pair(zone)
		add_redirect(zone, f"https://{secondary}/*", f"https://{primary}/$1")

def do_web_records(zone):
	delete_web_records(zone)

	# Point to the tattoocollectivereno page.
	if zone["name"] == "southtowntattoocollective.com":
		create_record(zone, CNAME, WWW, f"tattoocollectivereno.pages.dev", PROXIED)
		create_record(zone, ADDRESS, ROOT, GATEWAY, PROXIED)
	else:
		if get_is_og(zone):
			create_record(zone, CNAME, WWW, f"{get_short_name(zone)}.pages.dev", PROXIED)
			create_record(zone, ADDRESS, ROOT, GATEWAY, PROXIED)
		else:
			create_record(zone, ADDRESS, WWW, GATEWAY, PROXIED)
			create_record(zone, CNAME, ROOT, f"{get_short_name(zone)}.pages.dev", PROXIED)

def do_settings(zone):
	settings = get_settings(zone)
	for setting in settings:
		if not setting["editable"]:
			continue
		try:
			override_level = override_levels[setting["id"]]
			if override_level != setting["value"]:
				patch = {
					"value": override_level
				}
				print(f"{setting["id"]} = {setting["value"]} -> {patch["value"]}")
				perform("patch", f"zones/{zone["id"]}/settings/{setting["id"]}", patch)
		except:
			print(f"Missing override {setting["id"]} = {setting["value"]}")
	if True:
		perform("patch", f"zones/{zone["id"]}/dnssec", {"status": "disabled"})
		perform("patch", f"zones/{zone["id"]}/settings/origin_max_http_version", {"value": "1"})
		perform("patch", f"zones/{zone["id"]}/url_normalization", {"scope": "incoming", "type": "rfc_3986"})

def set_proxied(record, on):
	url = f"zones/{record["zone_id"]}/dns_records/{record["id"]}"
	patch = {
		"type": record["type"],
		"name": record["name"],
		"content": record["content"],
		"proxied": on,
		"ttl": record["ttl"]
	}
	perform("post", url, patch)

def create_record(zone, type, name, content, proxied = False):
	print(f"Create {zone["name"]}'s record [{type}, {name}, {content}]")
	url = f"zones/{zone["id"]}/dns_records"
	payload_as_json = {
		"type": type,
		"name": name,
		"content": content,
		"ttl": 0,
		"proxied": proxied
	}
	perform("post", url, payload_as_json)

def do_fast_vps_record(zone):
	print(f"Do fast VPS record {zone["name"]}")
	# if zone["name"] != "je.gy":
	# 	create_record(zone, CNAME, WWW, "pan.je.gy")
	# else:
		# create_record(zone, ADDRESS, ROOT, VPS) # Pan (Hetzner US)
	# create_record(zone, ADDRESS, ALL, VPS) # Pan (Hetzner US)
	# create_record(zone, CNAME, ALL, "fe46fb907541b3e9d66a6f721dc11258.serveo.net")
	# create_record(zone, ADDRESS, ALL, VPS)
	# create_record(zone, CNAME, ALL, f"{get_short_name(zone)}.pages.dev") # Pages

def get_is_og(zone):
	parts = zone["name"].split(".")
	is_og = parts[1] == "com" or parts[1] == "net" or parts[1] == "org"
	return is_og

def get_short_name(zone):
	is_og = get_is_og(zone)
	parts = zone["name"].split(".")
	short_name = is_og and parts[0] or zone["name"].replace(".", "")
	return short_name

def delete_web_records(zone):
	records = get_records(zone)
	for record in records:
		if get_is_web(record):
			delete_record(record)

def get_is_address(record):
	return record["type"] == ADDRESS

def get_is_cname(record):
	return record["type"] == CNAME

def get_is_www(record):
	return record["name"] == f"www.{record["zone_name"]}"

def get_is_root(record):
	return record["name"] == record["zone_name"]

def get_is_web(record):
	is_cname = get_is_cname(record)
	is_address = get_is_address(record)
	is_root = get_is_root(record)
	is_www = get_is_www(record)
	return (is_cname or is_address) and (is_root or is_www)

def get_web_pair(zone):
	root = zone["name"]
	www = f"www.{zone["name"]}"
	if get_is_og(zone):
		return root, www
	else:
		return www, root

def do_cname_records(zone):
	# We gotta delete

	www = None
	root = None

	records = get_records(zone)

	if not records:
		print(f"No DNS records for {zone["name"]}")
		return

	for record in records:
		if get_is_web(record):
			if get_is_www(record):
				www = record
				target = record["content"]
			elif get_is_root(record):
				root = record
				target = record["content"]

	if not www and root:
		create_record(zone, CNAME, WWW, root["content"])
		delete_record(root)
		# print(f"Created www subs record for {record["zone_name"]}")
	elif www and root and www["content"] != root["content"]:
		# print(f"Subs are pointing to different targets for {record["zone_name"]}")
		delete_record(root)
	if not root and www:
		create_record(zone, CNAME, record["zone_name"], target)
		# print(f"{record["zone_name"]} is missing a root sub but has www")
		pass

	# if root:
	# 	delete_record(root)

def delete_dev_records(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == f"dev.{zone["name"]}":
			delete_record(record)

def do_dev_records(zone):
	records = get_records(zone)
	delete_dev_records(zone)
	create_record(zone, ADDRESS, "dev", VPS, PROXIED)

def delete_a_and_cname_records(records):
	for record in records:
		if record["type"] == ADDRESS or record["type"] == CNAME:
			delete_record(record)

def delete_text_records(records):
	for record in records:
		if record["type"] == TXT:
			delete_record(record)

# def proxy_and_lint_records(records):
# 	for record in records:
# 		if get_is_address(record):
# 			if record["name"] == record["zone_name"] or record["name"] == f"www.{record["zone_name"]}":
# 				# set_proxied(record, True)
# 				set_proxied(record, True) # We're gonna turn off proxying for now because it's faster.
# 			elif record["proxied"]:
# 				set_proxied(record, False)

def do_world_records_and_proxy(zone):
	records = get_records(zone)
	for record in records:
		if get_is_address(record):
			if record["type"] == ADDRESS:
				set_proxied(record, True)

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
		if record["name"] == f"*.{record["zone_name"]}":
			delete_record(record)

def delete_root_cname_records(records):
	for record in records:
		if get_is_root(record) and record["type"] == CNAME:
			delete_record(record)

def delete_root_txt_records(records):
	for record in records:
		if get_is_root(record) and record["type"] == TXT:
			delete_record(record)

def delete_url_linter_routes(zone):
	routes = get_routes(zone)
	for route in routes:
		if route["script"] == URL_LINTER_WORKER_NAME:
			delete_route(zone, route)

def do_url_linter_routes(zone):
	delete_url_linter_routes(zone)

	# Forward should really be called lint URL or something different.
	if get_is_og(zone):
		add_route(zone, URL_LINTER_WORKER_NAME, f"www.{zone["name"]}/*")
	else:
		add_route(zone, URL_LINTER_WORKER_NAME, f"{zone["name"]}/*")

	# if zone["name"] == "leetforms.com":
	# 	add_route(zone, "leetforms", f"tattoocollectivereno.leetforms.com/")
	# add_route(zone, URL_LINTER_WORKER_NAME, f"*{zone["name"]}/*")

def delete_api_records(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == f"api.{zone["name"]}":
			delete_record(record)

def do_api_records(zone):
	delete_api_records(zone)
	create_record(zone, CNAME, "api", f"{get_short_name(zone)}.blocksrey.workers.dev", PROXIED)

def get_pages():
	return perform("get", f"accounts/{ACCOUNT_ID}/pages/projects")

def get_page_domains(page):
	url = f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains"
	page_domains = perform("get", url)
	return page_domains

# def delete_page_domains(page):
# 	url = f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains"
# 	page_domains = perform("delete", url)
# 	return page_domains

def do_page_domains(page):
	url = f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains"
	payload_as_json = {
		"domains": [f"www.{page["name"]}", page["name"]]
	}
	perform("post", url, payload_as_json)

# Make a function to lint URLs (ensure trailing slashes) on Pages, Workers, etc.

if __name__ == "__main__":
	zones = get_69_zones()
	for zone in zones:
		# do_settings(zone)
		# do_dev_records(zone)
		# do_page_rules(zone)
		# do_web_records(zone)
		delete_web_records(zone)
		pass
	pages = get_pages()
	for page in pages:
		pass