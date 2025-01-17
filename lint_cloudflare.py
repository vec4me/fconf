# Cloudflare Linter by Jeffrey Skinner <jeff@je.gy> a.k.a. jskinnerd
# I should do patching instead of deleting everything and rewriting.

ACCOUNT_ID = "a1de4b4bea97ddf530554ad8b89a6ace"
API_TOKEN = "PauifCWEbEo7RJehPHQ7t9xuMYE93LNPwNpy5Q-b"
MAILCHANNELS_ID = "truckee00"
URL_LINTER_WORKER_NAME = "forward" # Forward was not a good name. LOL
VPS = "5.78.116.190"

import requests
import json
import re
import Levenshtein

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
AUTO = 1
RESPECT_HEADERS = 0 # Apparently 0 is the equivalent of "respect headers."
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
		pass
		# print(f"{response.json()["errors"][0]["message"]}: {url}")

def delete(url):
	return perform("delete", url)

def get(url):
	return perform("get", url)

def patch(url, payload):
	return perform("patch", url, payload)

def post(url, payload):
	return perform("post", url, payload)

def get_zones():
	global zones; zones = []
	page = 1
	while (data := get(f"zones?per_page=69&page={page}")):
		zones.extend(data)
		if len(data) < 69:
			break
		page += 1

def get_records():
	global records; records = get(f"zones/{zone["id"]}/dns_records")
	for record in records:
		if record["name"] == zone["name"]:
			record["name"] = ROOT
		elif record["name"].endswith(f".{zone["name"]}"):
			record["name"] = record["name"][0:-(1 + len(zone["name"]))]
		if quoted(record["content"]):
			record["content"] = unquote(record["content"])

def delete_record(record):
	if delete(f"zones/{record["zone_id"]}/dns_records/{record["id"]}"):
		print(f"Delete {record["zone_name"]}'s record [{record["type"]}, {record["name"]}, {record["content"]}]")
	else:
		print("Can't delete record")

def get_settings():
	global settings; settings = get(f"zones/{zone["id"]}/settings")

def delete_spf_record(record):
	if "v=spf1" in record["content"]:
		delete_record(record)

def ensure_spf_records():
	if zone["name"] != "bestratereview.com":
		# ensure_record(ROOT, "v=spf1 include:icloud.com include:_spf.mx.cloudflare.net include:_spf.google.com include:relay.mailchannels.net ~all")
		ensure_record(ROOT, "v=spf1 include:icloud.com include:_spf.mx.cloudflare.net include:_spf.google.com ~all")

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

# Make functions to find extraneous values. Assuming this script represents the goal state, then that basically means we need to keep track of ensures. Then at the end, we compare the tracked ensures with reality ensures, the difference being the extraneous ones.

def ensure_redirect(url0, url1):
	if len(page_rules) >= 2:
		for page_rule in page_rules:
			current_url0 = page_rule["targets"][0]["constraint"]["value"]
			current_url1 = page_rule["actions"][0]["value"]["url"]
			if current_url0 == url0 and current_url1 == url1:
				return True
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
	if post(f"zones/{zone["id"]}/pagerules", payload_as_json):
		print(f"Add rule {url0} -> {url1} to {zone["name"]}")
	else:
		print(f"Can't ensure rule {url0} -> {url1} for {zone["name"]}")
	return False

def delete_page_rule():
	if delete(f"zones/{zone["id"]}/pagerules/{rule["id"]}"):
		print(f"Delete rule {rule} from {zone["name"]}")
	else:
		print("Can't delete page rule")

def get_page_rules():
	global page_rules; page_rules = get(f"zones/{zone["id"]}/pagerules")

def ensure_page_rules():
	primary, secondary = get_web_pair(zone["name"])
	# This fixes the Instagram redirect thing.
	ensure_redirect(f"https://{primary}/fbclid*", f"https://{primary}/")

	if brr_derivative():
		ensure_redirect(f"https://{primary}/*", f"https://www.bestratereview.com/$1")
		ensure_redirect(f"https://{secondary}/*", f"https://www.bestratereview.com/$1")
	elif zone["name"] == "jskinnerd.com":
		ensure_redirect(f"https://{primary}/", f"https://{primary}/index.htm")
	elif zone["name"] == "southtowntattoocollective.com":
		ensure_redirect(f"https://*southtowntattoocollective.com/*", f"https://$1tattoocollectivereno.com/$2") # This works for now.
	else:
		ensure_redirect(f"https://{secondary}/*", f"https://{primary}/$1")

def page_responding(domain):
	try:
		requests.head(f"https://{domain}/")
		return True
	except:
		return False

def ensure_page_domains():
	short_name = get_short_name(zone["name"])
	primary, secondary = get_web_pair(zone["name"])
	if page["name"] == short_name:
		ensure_page_domain(primary)
		ensure_page_domain(secondary)

def ensure_web_records():
	revert = None
	if zone["name"] == "southtowntattoocollective.com":
		revert = "southtowntattoocollective.com"
		zone["name"] = "tattoocollectivereno.com"

	domain = None
	page_domain = get_page_domain()
	if page_domain:
		domain = page_domain
	else:
		if zone["name"] == "bestratereview.com":
			domain = "35.192.114.80"
		else:
			domain = VPS

	if get_og(zone["name"]):
		ensure_record(WWW, domain)
		ensure_record(ROOT, domain)
	else:
		ensure_record(ROOT, domain)
		ensure_record(WWW, domain)

	if revert:
		zone["name"] = revert
		revert = None

def ensure_setting():
	if setting["editable"]:
		try:
			override_level = override_levels[setting["id"]]
			if override_level != setting["value"]:
				payload_as_json = {
					"value": override_level
				}
				if patch(f"zones/{zone["id"]}/settings/{setting["id"]}", payload_as_json):
					print(f"{setting["id"]} = {setting["value"]} -> {payload_as_json["value"]}")
				else:
					print("Can't change setting")
			else:
				# It's already what it needs to be.
				# print(f"{setting["id"]} is already set")
				pass
		except:
			print(f"Missing override {setting["id"]} = {setting["value"]}")
if False:
	if not patch(f"zones/{zone["id"]}/dnssec", {"status": "disabled"}):
		print("Can't do dnssec")
	if not patch(f"zones/{zone["id"]}/settings/origin_max_http_version", {"value": "1"}):
		print("Can't do origin_max_http_version")
	if not patch(f"zones/{zone["id"]}/url_normalization", {"scope": "incoming", "type": "rfc_3986"}):
		print("Can't do url_normalization")

def proxy_record(record, proxied):
	payload_as_json = {
		"proxied": proxied
	}
	if not patch(f"zones/{record["zone_id"]}/dns_records/{record["id"]}", payload_as_json):
		print("Can't do proxy")

def quote_if_weird(string):
	if contains_weird(string):
		return quote(string)
	return string

# ToDo: We gotta make this handle TTL eventually.
# Also this isn't really working how I want it to. Because SPF and Google verification records get match as the same thing and are both deleted...
def hard_ensure_record(type, name, content, proxied = PROXIED):
	ensured = False
	remove = []
	for record in records:
		# print(record["type"], record["name"], record["content"], record["proxied"])
		if record["type"] == type and record["name"] == name:
			if record["content"] == content and record["proxied"] == proxied:
				# It's the same so we can get outta here.
				ensured = True
			else:
				# The identity is the same, but not the values.
				remove.append(record)

	for record in remove:
		delete_record(record)

	if ensured:
		return ensured

	# Prioritize zone name given that @ = zone name.
	if name == zone["name"]:
		print("You should be using @ for the name!")

	payload_as_json = {
		"content": quote_if_weird(content),
		"name": name,
		"proxied": proxied,
		"ttl": AUTO,
		"type": type
	}

	if post(f"zones/{zone["id"]}/dns_records", payload_as_json):
		print(f"Create {zone["name"]}'s record [{type}, {name}, {content}]")
	else:
		print(f"Failed to ensure {zone["name"]}'s record [{type}, {name}, {content}]")

	return False

def ipv4_address(string):
	ipv4_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
	if not re.match(ipv4_regex, string):
		return False
	parts = string.split(".")
	return all(0 <= int(part) <= 255 for part in parts)

def ensure_record(name, content, proxied = PROXIED):
	if ipv4_address(content):
		hard_ensure_record(ADDRESS, name, content, proxied)
	elif contains_weird(content):
		hard_ensure_record(TEXT, name, content, UNPROXIED)
	else:
		hard_ensure_record(CNAME, name, content, proxied)

def ensure_fast_vps_records():
	print(f"Do fast VPS record {zone["name"]}")
	# if zone["name"] != "je.gy":
	# 	ensure_record(WWW, "pan.je.gy")
	# else:
		# ensure_record(ROOT, VPS) # Pan (Hetzner US)
	# ensure_record(WILD, VPS) # Pan (Hetzner US)
	# ensure_record(WILD, "fe46fb907541b3e9d66a6f721dc11258.serveo.net")
	# ensure_record(WILD, VPS)
	# ensure_record(WILD, f"{get_short_name(zone["name"])}.pages.dev") # Pages

def get_og(zone_name):
	parts = zone_name.split(".")
	og = parts[1] == "com" or parts[1] == "net" or parts[1] == "org"
	return og

def get_short_name(zone_name):
	og = get_og(zone_name)
	parts = zone_name.split(".")
	short_name = og and parts[0] or zone_name.replace(".", "")
	return short_name

def delete_web_record(record):
	if web(record):
		delete_record(record)

def web(record):
	return (record["type"] == CNAME or record["type"] == ADDRESS) and (record["name"] == ROOT or record["name"] == WWW)

def get_web_pair(zone_name):
	www = f"www.{zone_name}"
	root = zone_name
	if get_og(zone_name):
		return www, root
	else:
		return root, www

def ensure_cname_records():
	for record in records:
		# We gotta delete

		www = None
		root = None

		if not records:
			print(f"No DNS records for {zone["name"]}")
			return

		def _():
			if web(record):
				if record["type"] == WWW:
					www = record
					target = record["content"]
				elif record["type"] == ROOT:
					root = record
					target = record["content"]
		depend(_, "record")

		if not www and root:
			ensure_record(WWW, root["content"])
			# print(f"Created www subs record for {record["zone_name"]}")
		elif www and root and www["content"] != root["content"]:
			# print(f"Subs are pointing to different targets for {record["zone_name"]}")
			# delete_record(record, root)
			pass
		if not root and www:
			ensure_record(record["zone_name"], target)
			# print(f"{record["zone_name"]} is missing a root sub but has www")

		# if root:
		# 	delete_record(record, root)

def delete_dev_record(record):
	if record["name"] == "dev":
		delete_record(record)

def ensure_dev_records():
	for record in records:
		ensure_record("dev", VPS, PROXIED)

# def delete_a_and_cname_record(record):
# 		if record["type"] == ADDRESS or record["type"] == CNAME)):
# 			delete_record(record)

def delete_text_record(record):
	if record["type"] == TEXT:
		delete_record(record)

# def proxy_and_lint_record(record):
# 		if record["type"] == ADDRESS:
# 			if record["name"] == ROOT or record["name"] == WWW:
# 				# proxy_record(record, PROXIED)
# 				proxy_record(record, PROXIED) # We're gonna turn off proxying for now because it's faster.
# 			elif record["proxied"]:
# 				proxy_record(record, UNPROXIED)

# ToDo
def ensure_world_record_and_proxy_records():
	for record in records:
		if web(record):
			if record["type"] == ADDRESS:
				proxy_record(record, PROXIED)

def ensure_route(script, pattern):
	payload_as_json = {
		"pattern": pattern,
		"script": script
	}
	if post(f"zones/{zone["id"]}/workers/routes", payload_as_json):
		print(f"Add {zone["name"]}'s worker route {pattern}")
	else:
		print("Can't ensure route")

def get_route():
	return get(f"zones/{zone["id"]}/workers/routes")

def delete_route(route):
	if delete(f"zones/{zone["id"]}/workers/routes/{route["id"]}"):
		print(f"Delete {zone["name"]}'s worker route {route["pattern"]}")
	else:
		print("Can't delete route")

def delete_api_route():
	if route["pattern"] == f"api.{zone["name"]}/":
		delete_route(route)

def ensure_api_route():
	ensure_route(get_short_name(zone["name"]), f"api.{zone["name"]}/")

def delete_wildcard_record(record):
	if record["name"] == WILD:
		delete_record(record)

def delete_root_cname_record(record):
	if record["type"] == ROOT and record["type"] == CNAME:
		delete_record(record)

def delete_root_txt_record(record):
	if record["type"] == ROOT and record["type"] == TEXT:
		delete_record(record)

def delete_url_linter_route():
	if route["script"] == URL_LINTER_WORKER_NAME:
		delete_route(route)

def ensure_url_linter_route():
	# Forward should really be called lint URL or something different.
	if get_og(zone["name"]):
		ensure_route(URL_LINTER_WORKER_NAME, f"www.{zone["name"]}/*")
	else:
		ensure_route(URL_LINTER_WORKER_NAME, f"{zone["name"]}/*")

	# if zone["name"] == "leetforms.com":
	# 	ensure_route("leetforms", f"tattoocollectivereno.leetforms.com/")
	# ensure_route(URL_LINTER_WORKER_NAME, f"*{zone["name"]}/*")

def delete_api_record(record):
	if record["name"] == "api":
		delete_record(record)

def ensure_api_records():
	ensure_record("api", f"{get_short_name(zone["name"])}.jskinnerd.workers.dev")

def get_pages():
	global pages; pages = []
	page = 1
	while (data := get(f"accounts/{ACCOUNT_ID}/pages/projects?page={page}")):
		pages.extend(data)
		if len(data) < 10:
			break
		page += 1

def ensure_page_domain(domain):
	payload_as_json = {
		"domains": [f"https://{domain}/"]
	}
	if post(f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains", payload_as_json):
		print("Could ensure page domain")
	else:
		print("Can't ensure page domain")

def get_page_domains():
	global page_domains; page_domains = get(f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains")

def delete_page_domain():
	if delete(f"accounts/{ACCOUNT_ID}/pages/projects/{page["name"]}/domains/{page_domain["name"]}"):
		print("Could delete page domain")
	else:
		print("Can't delete page domain")

# Make a function to lint URLs (ensure trailing slashes) on Pages, Workers, etc.

def ensure_google_search_console_records():
	ensure_record(ROOT, GOOGLE_SITE_VERIFICATION)

def auto_record(record):
	if record["ttl"] != AUTO:
		payload_as_json = {
			"ttl": AUTO
		}
		if patch(f"zones/{record["zone_id"]}/dns_records/{record["id"]}", payload_as_json):
			print("Could auto")
		else:
			print("Can't auto")

def delete_dmarc_record(record):
	if record["name"] == "_dmarc":
		delete_record(record)

def ensure_dmarc_records():
	ensure_record("_dmarc", "v=DMARC1; p=quarantine;")

def delete_dkim_record(record):
	if record["name"] == "_domainkey":
		delete_record(record)

def flatten(flatten = FLATTEN):
	payload_as_json = {
		"flatten": flatten
	}
	if perform("patch", f"zones/{record["zone_id"]}/dns_records/{record["id"]}", payload_as_json):
		print("Could flatten")
	else:
		print("Can't flatten")

def flatten_record(record, flatten = FLATTEN):
		flatten()

def delete_smtp_server_record(record):
	if record["content"] == "smtp-server.jskinnerd.workers.dev":
		delete_record(record)

def quoted(string):
	return string[0] == '"' and string[-1] == '"'

def unquoted(string):
	return string[0] != '"' and string[-1] != '"'

def unquote(string):
	return quoted(string) and string[1:-1] or string

def quote(string):
	return unquoted(string) and f'"{string}"' or string

def contains_weird(string):
	return bool(re.search(r"[^\w.]", string))

def tainted():
	return record["type"] == TEXT and contains_weird(record["content"]) and unquoted(record["content"])

def delete_tainted_record(record):
	if tainted():
		delete_record(record)

def delete_mailchannels_record(record):
	if record["name"] == "_mailchannels":
		delete_record(record)

def ensure_mailchannels_records():
	ensure_record("_mailchannels", f"v=mc1 auth={MAILCHANNELS_ID}")

def ensure_dkim_records():
	for record in records:
		pass
	# ToDo

def ensure_mail_records():
	ensure_spf_records()
	ensure_dmarc_records()
	ensure_dkim_records()

def brr_derivative():
	return "rate" in zone["name"] and zone["name"] != "bestratereview.com"

def get_page_domain():
	domain_out = None
	domain_target = f"{get_short_name(zone["name"])}.pages.dev"
	def _():
		# check_page_domain()
		current_domain = page["subdomain"]
		if current_domain == domain_target:
			nonlocal domain_out; domain_out = current_domain
	depend(_, "page") # This is so fucking stupid.
	return domain_out

def check_page_domain():
	has_primary = None
	has_secondary = None
	closest_zone = get_closest_zone(page["name"])
	closest_primary, closest_secondary = get_web_pair(closest_zone["name"])
	def _():
		if page_domain["name"] == closest_primary:
			nonlocal has_primary; has_primary = True
		if page_domain["name"] == closest_secondary:
			nonlocal has_secondary; has_secondary = True
	depend(_, "page_domain")
	has_primary = has_primary or False
	has_secondary = has_secondary or False
	if not has_primary:
		print(f"Page {page["name"]} missing {closest_primary}")
	if not has_secondary:
		print(f"Page {page["name"]} missing {closest_secondary}")
	if len(page_domains) > 2:
		print(f"Page {page["name"]} too many domains")

# We should really just name the pages the same thing as the domain, that way we can look it up from the pages directly.
# On top of that, this will introduce error...
def get_closest_zone(name):
	return min(zones, key=lambda zone: Levenshtein.distance(name, zone["name"]), default=None)

# ToDo: This should anylitically check if they're forwarding to the correct email as opposed to "is forwarding on/off?"
def check_email_routing():
	# emails = get(f"accounts/{ACCOUNT_ID}/email/routing/addresses")
	routing_info = get(f"zones/{zone["id"]}/email/routing")
	if brr_derivative() and routing_info["enabled"] == False:
		print(f"Turn on email routing for {zone["name"]}!")

def depend(func, grab):
	exec(f"""get_{grab}s()
for _{grab} in {grab}s:
	global {grab}; {grab} = _{grab}
	func()""")

def ensure_the_important_brr_record():
	if zone["name"] == "bestratereview.com":
		ensure_record("@", "google-site-verification=1O4KHQCY_QaBmRlMHA_WUU3LGeqjmKr_4JN25L5_ybQ")

def print_rob_email_derivative():
	if brr_derivative():
		print(f"rob@{zone["name"]}")

if __name__ == "__main__":
	def _():
		def _():
			ensure_setting()
		depend(_, "setting")
		# Records
		get_records()
		ensure_web_records()
		ensure_mail_records()
		check_email_routing()
		# Just do this last so it's impossible to fuck up.
		ensure_the_important_brr_record()
		# Page rules
		get_page_rules()
		ensure_page_rules()
		print_rob_email_derivative()
	depend(_, "zone")