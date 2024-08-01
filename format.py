import requests
import json

api_token = "Nk4ut0AY4ARC0OhOlw4_y4CbFWrXVNX4kvJrBqbz"

headers = {
	"Authorization": f"Bearer {api_token}",
	"Content-Type": "application/json"
}

def get_zones():
	response = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers)
	# print(response)
	return response.json()["result"]

def get_dns_records(zone):
	response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/dns_records", headers=headers)
	# print(response)
	return response.json()["result"]

def delete_dns_record(dns_record):
	response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{dns_record["zone_id"]}/dns_records/{dns_record["id"]}", headers=headers)
	# print(response)

def get_settings(zone):
	response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/settings", headers=headers)
	# print(response)
	return response.json()["result"]

def lint_spf_dns_record(zone):
	url = f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/dns_records"
	payload = {
		"type": "TXT",
		"name": "@",
		"content": "v=spf1 include:_spf.mx.cloudflare.net ~all",
		"ttl": 3600
	}
	response = requests.post(url, headers=headers, json=payload)
	# print(response)

override_levels = {}

override_levels["0rtt"] = "off"
override_levels["always_online"] = "off"
override_levels["always_use_https"] = "off"
override_levels["automatic_https_rewrites"] = "off"
override_levels["brotli"] = "off"
override_levels["browser_check"] = "off"
override_levels["development_mode"] = "off"
override_levels["early_hints"] = "off"
override_levels["email_obfuscation"] = "off"
override_levels["filter_logs_to_cloudflare"] = "off"
override_levels["hotlink_protection"] = "off"
override_levels["http3"] = "on"
override_levels["ip_geolocation"] = "on"
override_levels["ipv6"] = "on"
override_levels["log_to_cloudflare"] = "off"
override_levels["opportunistic_encryption"] = "off"
override_levels["opportunistic_onion"] = "off"
override_levels["orange_to_orange"] = "off"
override_levels["pq_keyex"] = "off"
override_levels["privacy_pass"] = "off"
override_levels["pseudo_ipv4"] = "off"
override_levels["replace_insecure_js"] = "off"
override_levels["rocket_loader"] = "off"
override_levels["server_side_exclude"] = "off"
override_levels["ssl"] = "flexible"
override_levels["tls_1_2_only"] = "off"
override_levels["tls_1_3"] = "off"
override_levels["tls_client_auth"] = "off"
override_levels["waf"] = "off"
override_levels["websockets"] = "on"
override_levels["visitor_ip"] = "on"

override_levels["cache_level"] = "aggressive"
override_levels["cname_flattening"] = "flatten_at_root"
override_levels["min_tls_version"] = "1.0"
override_levels["security_level"] = "essentially_off"

override_levels["browser_cache_ttl"] = 14400
override_levels["challenge_ttl"] = 1800
override_levels["edge_cache_ttl"] = 7200
override_levels["max_upload"] = 100

override_levels["minify"] = {"css": "off", "html": "off", "js": "off"}
override_levels["mobile_redirect"] = {"status": "off", "mobile_subdomain": None, "strip_uri": False}
override_levels["security_header"] = {"strict_transport_security": {"enabled": False, "max_age": 0, "include_subdomains": False, "preload": False, "nosniff": False}}

override_levels["ciphers"] = []

def add_redirect(zone, url0, url1):
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
	# print(response)
	return response.json()

def add_redirects(zone):
	url = zone["name"] + "/" # The URL you want to redirect from
	add_redirect(zone, f"https://{zone["name"]}/", f"https://www.{zone["name"]}/")
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
	# print(response)
	return response.json()

def delete_redirect(zone, rule):
	url = f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/pagerules/{rule["id"]}"
	headers = {
		"Authorization": f"Bearer {api_token}",
		"Content-Type": "application/json",
	}
	response = requests.delete(url, headers=headers)
	# print(response)
	return response.json()

def delete_redirects(zone):
	redirects = get_redirects(zone)
	rules = redirects["result"]

	for rule in rules:
		result = delete_redirect(zone, rule)

def disable_settings(zone):
	settings = get_settings(zone)
	for setting in settings:
		setting_id = setting["id"]
		if not setting["editable"]:
			continue
		try:
			override_level = override_levels[setting_id]
			if override_level != setting["value"]:
				patch = {
					"value": override_level
				}
				print(setting_id, "=", setting["value"], "->", patch["value"])
				response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/settings/{setting_id}", headers=headers, json=patch)
				# print(response)
		except:
			print("missing override", setting_id, "=", setting["value"])

def set_proxy(dns_record, on):
	url = f"https://api.cloudflare.com/client/v4/zones/{dns_record["zone_id"]}/dns_records/{dns_record["id"]}"

	patch = {
		"type": dns_record["type"],
		"name": dns_record["name"],
		"content": dns_record["content"],
		"proxied": on,
		"ttl": dns_record["ttl"]
	}

	response = requests.put(url, headers=headers, json=patch)
	# print(response)

def create_cname_dns_record(zone_id, name, content):
	url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
	headers = {
		"Authorization": f"Bearer {api_token}",
		"Content-Type": "application/json"
	}
	data = {
		"type": "CNAME",
		"name": name,
		"content": content,
		"ttl": 3600
	}
	response = requests.post(url, headers=headers, json=data)
	# print(response)

# def add_www_cname_for_root():
def ensure_www_cname(dns_records):
	www_cname = None
	root_cname = None

	if not dns_records:
		print("No DNS records!")
		return

	for dns_record in dns_records:
		if dns_record["type"] == "CNAME":
			if dns_record["name"] == "www." + dns_record["zone_name"]:
				www_cname = dns_record
				target = dns_record["content"]
			elif dns_record["name"] == dns_record["zone_name"]:
				root_cname = dns_record
				target = dns_record["content"]

	if not www_cname and root_cname:
		create_cname_dns_record(dns_record["zone_id"], "www", root_cname["content"])
		print(f"Created www CNAME dns_record for {dns_record["zone_name"]}")
	elif www_cname and root_cname and www_cname["content"] != root_cname["content"]:
		print(f"CNAMEs are pointing to different targets for {dns_record["zone_name"]}")
	if not root_cname and www_cname:
		create_cname_dns_record(dns_record["zone_id"], dns_record["zone_name"], target)
		print(f"{dns_record["zone_name"]} is missing a root CNAME but has www")

def delete_text_records(dns_records):
	for dns_record in dns_records:
		if dns_record["type"] == "TXT":
			delete_dns_record(dns_record)
			pass

def proxy_and_lint_dns_records(dns_records):
	for dns_record in dns_records:
		if dns_record["name"] == dns_record["zone_name"] or dns_record["name"] == f"www.{dns_record["zone_name"]}":
			set_proxy(dns_record, True)
		elif dns_record["proxied"]:
			set_proxy(dns_record, False)

if __name__ == "__main__":
	zones = get_zones()
	for zone in zones:
		dns_records = get_dns_records(zone)
		ensure_www_cname(dns_records)
		proxy_and_lint_dns_records(dns_records)
		delete_text_records(dns_records)
		lint_spf_dns_record(zone)
		delete_redirects(zone)
		add_redirects(zone)
		response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/dnssec", headers=headers, json={"status": "disabled"})
		# print(response)
		response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/settings/origin_max_http_version", headers=headers, json={"value": "1"})
		# print(response)
		response = requests.patch(f"https://api.cloudflare.com/client/v4/zones/{zone["id"]}/url_normalization", headers=headers, json={"scope": "incoming", "type": "rfc_3986"})
		# print(response)
		disable_settings(zone)