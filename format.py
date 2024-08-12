import requests
import json

api_token = "Nk4ut0AY4ARC0OhOlw4_y4CbFWrXVNX4kvJrBqbz"

headers = {
	"Authorization": f"Bearer {api_token}",
	"Content-Type": "application/json"
}

def get_zones():
	response = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers)
	return response.json()["result"]

def get_records(zone):
	response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/dns_records", headers=headers)
	return response.json()["result"]

def delete_record(record):
	print(f"Delete {record["zone_name"]}'s record {record["name"]}")
	response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{record["zone_id"]}/dns_records/{record["id"]}", headers=headers)

def get_settings(zone):
	response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/settings", headers=headers)
	return response.json()["result"]

def lint_spf_record(zone):
	url = f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/dns_records"
	payload = {
		"type": "TXT",
		"name": "@",
		"content": "v=spf1 include:_spf.mx.cloudflare.net ~all",
		"ttl": 86400 # https://community.cloudflare.com/t/adding-an-spf-record-to-our-dns/538913
	}
	response = requests.post(url, headers=headers, json=payload)

override_levels = {}

override_levels["0rtt"] = "on" # extra performance
override_levels["always_online"] = "off" # this is cool but bad for debugging
override_levels["always_use_https"] = "off" # never always do anything
override_levels["automatic_https_rewrites"] = "off"
override_levels["brotli"] = "on" # transparent
override_levels["browser_check"] = "off"
override_levels["development_mode"] = "off"
override_levels["early_hints"] = "off"
override_levels["email_obfuscation"] = "off" # stupid
override_levels["filter_logs_to_cloudflare"] = "off"
override_levels["hotlink_protection"] = "off" # stupid
override_levels["http3"] = "on" # support http3
override_levels["ip_geolocation"] = "on"
override_levels["ipv6"] = "on" # support ipv6
override_levels["log_to_cloudflare"] = "on"
override_levels["opportunistic_encryption"] = "off"
override_levels["opportunistic_onion"] = "off"
override_levels["orange_to_orange"] = "off"
override_levels["pq_keyex"] = "off"
override_levels["privacy_pass"] = "off"
override_levels["pseudo_ipv4"] = "off" # pseudo stuff isn't good
override_levels["replace_insecure_js"] = "off"
override_levels["rocket_loader"] = "off"
override_levels["server_side_exclude"] = "off"
override_levels["ssl"] = "flexible"
# override_levels["ssl"] = "full"
override_levels["tls_1_2_only"] = "off" # dont force stuff
override_levels["tls_1_3"] = "zrt" # more support (zrt = on + 0rtt)
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

override_levels["browser_cache_ttl"] = 0 # apparently 0 is the equivalent of "respect headers"
override_levels["challenge_ttl"] = 31536000 # 1 year
override_levels["edge_cache_ttl"] = 7200
override_levels["max_upload"] = 100

override_levels["minify"] = {"css": "off", "html": "off", "js": "off"}
override_levels["mobile_redirect"] = {"status": "off", "mobile_subdomain": None, "strip_uri": False}
override_levels["security_header"] = {"strict_transport_security": {"enabled": False, "max_age": 0, "include_subdomains": False, "preload": False, "nosniff": False}}

override_levels["ciphers"] = []

def add_redirect(zone, url0, url1):
	print(f"Add redirect {url0} -> {url1} to {zone["name"]}")
	data = {
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
		"priority": 1, # lmao
		"status": "active"
	}

	response = requests.post(
		f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/pagerules",
		headers=headers,
		json=data
	)
	return response.json()

def add_redirects(zone):
	url = zone["name"] + "/" # The URL you want to redirect from
	add_redirect(zone, f"https://{zone["name"]}/*", f"https://www.{zone["name"]}/$1") # this is better for if they do like blocksrey.com/asdasd
	if zone["name"] == "blocksrey.com":
		add_redirect(zone, f"https://www.{zone["name"]}/", f"https://www.{zone["name"]}/index.htm")
		add_redirect(zone, f"https://www.{zone["name"]}/?*", f"https://www.{zone["name"]}/index.htm")
	elif zone["name"] == "southtowntattoocollective.com":
		add_redirect(zone, f"https://*.{zone["name"]}/*", f"https://$1.{"tattoocollectivereno.com"}/$2")

def get_redirects(zone):
	url = f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/pagerules"
	headers = {
		"Authorization": f"Bearer {api_token}",
		"Content-Type": "application/json",
	}
	response = requests.get(url, headers=headers)
	return response.json()

def delete_redirect(zone, rule):
	print(f"Delete redirect {rule} from {zone["name"]}")
	url = f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/pagerules/{rule["id"]}"
	headers = {
		"Authorization": f"Bearer {api_token}",
		"Content-Type": "application/json",
	}
	response = requests.delete(url, headers=headers)
	return response.json()

def delete_redirects(zone):
	redirects = get_redirects(zone)
	rules = redirects["result"]

	for rule in rules:
		result = delete_redirect(zone, rule)

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
				# print(setting["id"], "=", setting["value"], "->", patch["value"])
				response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/settings/{setting["id"]}", headers=headers, json=patch)
		except:
			print(f"Missing override {setting["id"]} = {setting["value"]}")
	if True:
		response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/dnssec", headers=headers, json={"status": "disabled"})
		response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/settings/origin_max_http_version", headers=headers, json={"value": "1"})
		response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/url_normalization", headers=headers, json={"scope": "incoming", "type": "rfc_3986"})

def set_proxy(record, on):
	url = f"https://api.cloudflare.com/client/v4/zones/{record["zone_id"]}/dns_records/{record["id"]}"
	patch = {
		"type": record["type"],
		"name": record["name"],
		"content": record["content"],
		"proxied": on,
		"ttl": record["ttl"]
	}
	response = requests.post(url, headers=headers, json=patch)

def create_record(zone, type, name, content, proxied=False):
	print(f"Create {zone["name"]}'s record [{type}, {name}, {content}]")
	url = f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/dns_records"
	headers = {
		"Authorization": f"Bearer {api_token}",
		"Content-Type": "application/json"
	}
	data = {
		"type": type,
		"name": name,
		"content": content,
		"ttl": 0,
		"proxied": proxied
	}
	response = requests.post(url, headers=headers, json=data)

def do_the_fast_vps_record(zone):
	print("do_the_fast_vps_record", zone["name"])
	# if zone["name"] != "je.gy":
	# 	create_record(zone, "CNAME", "www", "pan.je.gy")
	# else:
		# create_record(zone, "A", "@", "5.78.96.29") # pan (hetzner us)
	# create_record(zone, "A", "*", "5.78.96.29") # pan (hetzner us)
	# create_record(zone, "CNAME", "*", "fe46fb907541b3e9d66a6f721dc11258.serveo.net")
	# create_record(zone, "A", "*", "138.68.79.95")
	# create_record(zone, "CNAME", "*", zone["name"].split(".")[0] + ".pages.dev") # pages

def get_is_special(zone):
	parts = zone["name"].split(".")
	is_special = parts[1] == "com" or parts[1] == "net" or parts[1] == "org"
	return is_special

def get_short_name(zone):
	is_special = get_is_special(zone)
	parts = zone["name"].split(".")
	short_name = is_special and parts[0] or zone["name"].replace(".", "")
	return short_name

def delete_page_records(zone):
	records = get_records(zone)
	for record in records:
		if record["content"].endswith(".pages.dev"):
			delete_record(record)

def do_page_records(zone):
	delete_page_records(zone)
	if get_is_special(zone):
		create_record(zone, "CNAME", "www", get_short_name(zone) + ".pages.dev", True)
	else:
		create_record(zone, "CNAME", "@", get_short_name(zone) + ".pages.dev", True)

def is_address(record):
	return record["type"] == "CNAME" or record["type"] == "A"

def is_www_record(record):
	return record["name"] == "www." + record["zone_name"]

def is_root_record(record):
	return record["name"] == record["zone_name"]

def lint_cname_records(zone):
	www = None
	root = None

	records = get_records(zone)

	if not records:
		print(f"No DNS records for {zone["name"]}")
		return

	for record in records:
		if is_address(record):
			if is_www_record(record):
				www = record
				target = record["content"]
			elif is_root_record(record):
				root = record
				target = record["content"]

	if not www and root:
		create_record(zone, "CNAME", "www", root["content"])
		delete_record(root)
		# print(f"Created www subs record for {record["zone_name"]}")
	elif www and root and www["content"] != root["content"]:
		# print(f"Subs are pointing to different targets for {record["zone_name"]}")
		delete_record(root)
	if not root and www:
		create_record(zone, "CNAME", record["zone_name"], target)
		# print(f"{record["zone_name"]} is missing a root sub but has www")
		pass

	# if root:
	# 	delete_record(root)

def delete_a_and_cname_records(records):
	print("delete_a_and_cname_records")
	for record in records:
		if record["type"] == "A" or record["type"] == "CNAME":
			delete_record(record)

def delete_text_records(records):
	print("delete_text_records")
	for record in records:
		if record["type"] == "TXT":
			delete_record(record)

def proxy_and_lint_records(records):
	# print("proxy_and_lint_records")
	for record in records:
		if is_address(record):
			if record["name"] == record["zone_name"] or record["name"] == f"www.{record["zone_name"]}":
				# set_proxy(record, True)
				set_proxy(record, True) # We're gonna turn off proxying for now because it's faster
			elif record["proxied"]:
				set_proxy(record, False)

def do_world_records_and_proxy(zone):
	records = get_records(zone)
	# print("do_world_records_and_proxy")
	for record in records:
		if is_address(record):
			if record["type"] == "A":
				set_proxy(record, True)

def add_worker_route(zone, script, pattern):
	print(f"Add {zone["name"]}'s worker route {pattern}")
	data = {
		"pattern": pattern,
		"script": script
	}
	response = requests.post(
		f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/workers/routes",
		headers=headers,
		json=data
	)
	return response.json()

def get_worker_routes(zone):
	response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/workers/routes", headers=headers)
	routes = response.json()
	return routes["result"]

def delete_worker_route(zone, route):
	print(f"Delete {zone["name"]}'s worker route {route["pattern"]}")
	response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/workers/routes/{route["id"]}", headers=headers)
	return response.json()

def delete_forward_routes(zone):
	routes = get_worker_routes(zone)
	for route in routes:
		if route["script"] == "forward":
			delete_worker_route(zone, route)

def delete_wildcards(records):
	for record in records:
		if record["name"] == "*." + record["zone_name"]:
			delete_record(record)

def delete_root_cname_records(records):
	for record in records:
		if is_root_record(record) and record["type"] == "CNAME":
			delete_record(record)

def delete_root_txt_records(records):
	for record in records:
		if is_root_record(record) and record["type"] == "TXT":
			delete_record(record)

def do_forward_routes(zone):
	delete_forward_routes(zone)
	# Forward should really be calledl lint url or something different.
	if zone["name"] == "blocksrey.com":
		add_worker_route(zone, "forward", f"www.{zone["name"]}/*") # Fuck Meta and Cloudflare for this
	elif get_is_special(zone):
		add_worker_route(zone, "forward", f"www.{zone["name"]}/")
	else:
		add_worker_route(zone, "forward", f"{zone["name"]}/")
	# if zone["name"] == "leetforms.com":
	# 	add_worker_route(zone, "leetforms", f"tattoocollectivereno.leetforms.com/")
	# add_worker_route(zone, "forward", f"*{zone["name"]}/*")

def delete_api_routes(zone):
	records = get_records(zone)
	for record in records:
		if record["name"] == "api." + zone["name"]:
			delete_record(record)

def do_api_routes(zone):
	delete_api_routes(zone)
	create_record(zone, "CNAME", "api", f"{get_short_name(zone)}.blocksrey.workers.dev", True)
	add_worker_route(zone, get_short_name(zone), f"api.{zone["name"]}/")

if __name__ == "__main__":
	zones = get_zones()
	for zone in zones:
		# records = get_records(zone)
		do_api_routes(zone)
		# do_settings(zone)