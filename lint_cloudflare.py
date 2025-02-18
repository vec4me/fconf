# Cloudflare Linter by Jeffrey Skinner <jeff@je.gy> a.k.a. jaydeeskinner
# I should do patching instead of deleting everything and rewriting.

# TODO: We should first pull, then make changes to the local data, then have a push function where we actually start to send the requests. This would probably be faster because we can compile deltas.
# This would also make it very easy to find extraneous configurations in which we can easily remove. This'll be good.

# TODO: We need to actually check if email routing is enabled for the zone.

# TODO: Make a function to lint URLs (ensure trailing slashes) on Pages, Workers, etc.

class Table(dict):
	def __init__(self, data=None):
		super().__init__()
		self._counter = 0

		if data:
			if isinstance(data, dict):
				for key, value in data.items():
					self[key] = self._convert(value)
			elif isinstance(data, (list, tuple, set)): # Handle other iterables
				for value in data:
					self.insert(value)

		self._initialize_counter() # Set _counter to length of continuous numerical keys

	def __getattr__(self, key):
		try:
			return self[key]
		except KeyError:
			return None

	def __setattr__(self, key, value):
		if key == "_counter":
			super().__setattr__(key, value)
		else:
			self[key] = self._convert(value)

	def __delattr__(self, key):
		try:
			del self[key]
		except KeyError:
			raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{key}'")

	@classmethod
	def _convert(cls, value):
		if isinstance(value, dict):
			return cls(value)
		elif isinstance(value, list):
			return [cls._convert(item) for item in value]
		return value

	def insert(self, value):
		key = str(self._counter)
		self[key] = self._convert(value)
		self._counter += 1

	def _initialize_counter(self):
		numeric_keys = sorted(int(k) for k in self.keys() if k.isdigit())
		self._counter = 0

		for key in numeric_keys:
			if key == self._counter:
				self._counter += 1
			else:
				break # Stop at the first discontinuity

	def __eq__(self, other):
		if isinstance(other, Table):
			return dict(self) == dict(other) # Compare internal dictionaries
		return False

	def __hash__(self):
		# Create a consistent hash based on sorted key-value pairs
		# We sort the items to ensure that different insertion orders still yield the same hash.
		return hash(frozenset(self.items()))

import requests
import json
import re
import Levenshtein
import os
import copy
from collections.abc import Mapping, Sequence

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
MAIL = "MX"

VPS = os.getenv("VPS")

CLOUDFLARE_ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")

CLOUDFLARE_HEADERS = Table({
	"Authorization": f"Bearer {os.getenv("CLOUDFLARE_API_TOKEN")}",
	"Content-Type": "application/json"
})

def delete(url):
	return perform("delete", url)

def get(url):
	return perform("get", url)

def patch(url, data):
	return perform("patch", url, data)

def post(url, data):
	return perform("post", url, data)

types = Table()
types.delete = requests.delete
types.get = requests.get
types.patch = requests.patch
types.post = requests.post

def perform(type, url, json = None):
	response = types[type](f"https://api.cloudflare.com/client/v4/{url}", headers = CLOUDFLARE_HEADERS, json = json)
	if response.status_code == 200:
		return response.json()["result"]
	else:
		# print(response.json())
		return False

overrides = Table()
overrides["0rtt"] = "on" # Extra performance
overrides.always_online = "off" # This is cool, but bad for debugging.
overrides.always_use_https = "off" # Never always do anything.
overrides.automatic_https_rewrites = "off"
overrides.brotli = "on" # Transparent
overrides.browser_check = "off"
overrides.development_mode = "off"
overrides.early_hints = "off"
overrides.email_obfuscation = "off" # Stupid
overrides.filter_logs_to_cloudflare = "off"
overrides.hotlink_protection = "off" # Stupid
overrides.http3 = "on" # Support HTTP/3
overrides.ip_geolocation = "on"
overrides.ipv6 = "on" # Support IPv6
overrides.log_to_cloudflare = "on"
overrides.opportunistic_encryption = "off"
overrides.opportunistic_onion = "off"
overrides.pq_keyex = "off"
overrides.privacy_pass = "off"
overrides.pseudo_ipv4 = "off" # Pseudo-stuff isn't good.
overrides.replace_insecure_js = "off"
overrides.rocket_loader = "off"
overrides.server_side_exclude = "off"
overrides.ssl = "flexible"
overrides.tls_1_2_only = "off" # Don't force stuff.
overrides.tls_1_3 = "zrt" # More support (zrt = on + 0rtt)
overrides.tls_client_auth = "off"
overrides.visitor_ip = "on"
overrides.waf = "off"
overrides.websockets = "on"
overrides.ech = "off"
overrides.orange_to_orange = "off"

# overrides.universal_ssl = ""
# overrides.response_buffering = "off"
# overrides.mirage = "off"
# overrides.binary_ast = "off"
# overrides.webp = "on"

# Enterprise
# overrides.advanced_ddos = "off" # Is this good? I'm not sure.
# overrides.http2 = "on" # I like ths idea of more support.

overrides.cache_level = "aggressive"
overrides.cname_flattening = "flatten_at_root"
overrides.min_tls_version = "1.0" # This is supposed to be a string.
overrides.security_level = "essentially_off"

overrides.browser_cache_ttl = RESPECT_HEADERS
overrides.challenge_ttl = ONE_WEEK
overrides.edge_cache_ttl = TWO_HOURS
overrides.max_upload = 100 # This is supposed to be a number for some reason.

overrides.minify = Table({"css": "off", "html": "off", "js": "off"})
overrides.mobile_redirect = Table({"status": "off", "mobile_subdomain": None, "strip_uri": False})
overrides.security_header = Table({"strict_transport_security": {"enabled": False, "max_age": 0, "include_subdomains": False, "preload": False, "nosniff": False}})

overrides.ciphers = []

def make_setting(zone, id = None, value = None, cf_data = None):
	if cf_data:
		id = cf_data.id
		value = cf_data.value

	zone = zone or print(zone.name, "missing zone")
	value = value# or print(zone.name, "missing value")

	def location():
		return zone.name + str(id) + str(value)

	def push():
		data = {
			"id": id,
			"value": value
		}
		if not patch(f"zones/{zone.id}/settings/{id}", data):
			print(f"error {zone.name} setting {id} to {value}")
		# if False:
		# 	if not patch(f"zones/{zone_id}/dnssec", {"status": "disabled"}):
		# 		print("can't do dnssec")
		# 	if not patch(f"zones/{zone_id}/settings/origin_max_http_version", {"value": "1"}):
		# 		print("can't do origin_max_http_version")
		# 	if not patch(f"zones/{zone_id}/url_normalization", {"scope": "incoming", "type": "rfc_3986"}):
		# 		print("can't do url_normalization")

	def remove():
		pass
		# print("you can't remove a setting lol", self)

	self = Table()
	self.remove = remove
	self.id = id
	self.location = location
	self.push = push

	if cf_data:
		cf_items[location()] = self
	else:
		local[location()] = self

	return self

# TODO: We gotta make this handle TTL eventually.
# Also this isn't really working how I want it to. Because SPF and Google verification records get match as the same thing and are both removed...
def make_record(zone, name = None, content = None, type = None, proxied = PROXIED, priority = None, ttl = AUTO, id = None, cf_data = None):
	if cf_data:
		if 0 < len(cf_data.tags):
			title = cf_data.tags[0]
		if cf_data.name == zone.name:
			name = ROOT
		elif cf_data.name.endswith(f".{zone.name}"):
			name = cf_data.name[0:-(1 + len(zone.name))]
		if quoted(cf_data.content):
			content = unquote(cf_data.content)
		else:
			content = cf_data.content
		ttl = int(cf_data.ttl)
		proxied = cf_data.proxied
		type = cf_data.type
		priority = cf_data.priority
		id = cf_data.id
		# Sorry, did the API change or something? This used to be built in I thought.

	if type == None:
		if ipv4_address(content):
			type = ADDRESS
		elif weird(content):
			type = TEXT
		else:
			type = CNAME

	if type == TEXT:
		proxied = UNPROXIED
	elif type == MAIL:
		proxied = UNPROXIED
		priority = 1

	# Prioritize zone name given that @ = zone name.
	if name == zone.name:
		print(f"please use @ for the record name instead of {zone.name}")

	content = quote_if_weird(content)

	name = name or print(zone.name, "missing name")
	type = type or print(zone.name, "missing type")
	content = content or print(zone.name, "missing content")
	proxied = proxied# or print(zone.name, "missing proxied")
	ttl = ttl or print(zone.name, "missing ttl")
	priority = priority# or print(zone.name, "missing priority")
	zone = zone or print(zone.name, "missing zone")

	# TODO
	# def flatten(record, flatten = FLATTEN):
	# 	data = Table({
	# 		"flatten": flatten
	# 	})

	def proxy(on):
		proxied = on

	def location():
		return zone.name + name + type + content + str(proxied) + str(ttl) + str(priority)

	def is_web():
		return (type == CNAME or type == ADDRESS) and (record.name == ROOT or record.name == WWW)

	def push():
		data = {
			"content": quote_if_weird(content),
			"name": name,
			"proxied": proxied,
			"ttl": ttl,
			"priority": priority,
			"type": type
		}
		if not post(f"zones/{zone.id}/dns_records", data):
			print(f"error {zone.name} make record [{type}, {name}, {content}]")

	def remove():
		if not delete(f"zones/{zone.id}/dns_records/{id}"):
			# print(f"error {zone.name} remove record [{type}, {name}, {content}]")
			pass

	self = Table()
	self.remove = remove
	self.is_web = is_web
	self.location = location
	self.push = push

	if cf_data:
		cf_items[location()] = self
	else:
		local[location()] = self

	return self

def make_route(zone, origin = None, target = None, cf_data = None):
	if cf_data:
		origin = cf_data.pattern
		target = cf_data.script
		id = cf_data.id

	origin = origin or print(zone.name, "missing origin")
	target = target or print(zone.name, "missing target")

	def remove():
		if not delete(f"zones/{zone.id}/workers/routes/{id}"):
			print(f"error {zone.name} remove worker route {origin}")

	def push():
		data = {
			"pattern": origin,
			"target": target
		}
		if not post(f"zones/{zone.id}/workers/routes", data):
			print(f"error {zone.name} create worker route {origin}")

	def location():
		return zone.name + origin + target

	self = Table()
	self.remove = remove
	self.location = location
	self.push = push

	if cf_data:
		cf_items[location()] = self
	else:
		local[location()] = self

	return self

def make_rule(zone, target = None, enabled = True, cf_data = None):
	if cf_data:
		target = cf_data.actions[0].type != "drop" and cf_data.actions[0].value[0]
		enabled = cf_data.enabled # Make sure this is working
		id = cf_data.id

	target = target or print(zone.name, "missing target")

	def location():
		return zone.name + str(target) + str(enabled)

	def remove():
		if not delete(f"zones/{zone.id}/email/routing/rules/{id}"):
			print(f"error {zone.name} remove e-rule {target}")

	def push():
		data = {
			"matchers": [
				{
					"type": "all"
				}
			],
			"actions": [
				{
					"type": "forward" if "@" in (target or "") else "worker",
					"value": [target]
				}
			],
			"enabled": enabled
		}
		if not post(f"zones/{zone.id}/email/routing/rules", data):
			print(f"error {zone.name} make e-rule {target}")

	self = Table()
	self.remove = remove
	self.location = location
	self.push = push

	if cf_data:
		cf_items[location()] = self
	else:
		local[location()] = self

	return self

def make_pagerule(zone, origin = None, target = None, cf_data = None):
	if cf_data:
		origin = cf_data.targets[0].constraint.value
		target = cf_data.actions[0].value.url
		id = cf_data.id

	origin = origin or print(zone.name, "missing origin")
	target = target or print(zone.name, "missing target")
	zone = zone or print(zone.name, "missing zone")

	def push():
		data = {
			"targets": [
				{
					"target": "url",
					"constraint": {
						"operator": "matches",
						"value": origin
					}
				}
			],
			"actions": [
				{
					"id": "forwarding_url",
					"value": {
						"url": target,
						"status_code": 301
					}
				}
			],
			"priority": 1, # LMAO
			"status": "active"
		}
		if not post(f"zones/{zone.id}/pagerules", data):
			print(f"error {zone.name} make rule [{origin} -> {target}]")

	def location():
		return zone.name + origin + target

	def remove():
		if not delete(f"zones/{zone.id}/pagerules/{id}"):
			print(f"error {zone.name} remove rule [{origin} -> {target}]")

	self = Table()
	self.remove = remove
	self.location = location
	self.push = push

	if cf_data:
		cf_items[location()] = self
	else:
		local[location()] = self

	return self

def make_domain(page, name = None, cf_data = None):
	if cf_data:
		name = cf_data.name

	name = name or print(page.name, "missing name")

	def location():
		return page.name + name

	def remove():
		if not delete(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects/{page.name}/domains/{name}"):
			print(f"error {page.name} remove domain {name}")

	def push():
		data = {
			"name": name
		}
		if not post(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects/{page.name}/domains", data):
			print(f"error {page.name} make domain {name}")

	self = Table()
	self.remove = remove
	self.location = location
	self.push = push

	if cf_data:
		cf_items[location()] = self
	else:
		local[location()] = self

	return self

def fetch():
	global cf_items
	global local
	global pages
	global zones
	# global domains
	cf_items = Table()
	local = Table()
	pages = Table()
	zones = Table()
	page = 1
	while (data := get(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects?page={page}")):
		for thing in data:
			pages.insert(thing)
			if len(data) < 10:
				break
			page += 1
	for k in pages:
		page = pages[k]
		domains = Table(get(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects/{page.name}/domains"))
		page.domains = domains
		for k in domains:
			domains[k] = make_domain(page, cf_data = domains[k])
	page = 1
	while (data := get(f"zones?per_page=69&page={page}")):
		for thing in data:
			zones.insert(Table(thing))
		if len(data) < 69:
			break
		page += 1
	for k in zones:
		zone = zones[k]
		pagerules = Table(get(f"zones/{zone.id}/pagerules"))
		records = Table(get(f"zones/{zone.id}/dns_records"))
		routes = Table(get(f"zones/{zone.id}/workers/routes"))
		rules = Table(get(f"zones/{zone.id}/email/routing/rules"))
		settings = Table(get(f"zones/{zone.id}/settings"))
		zone.pagerules = pagerules
		zone.records = records
		zone.routes = routes
		zone.rules = rules
		zone.settings = settings
		for k in pagerules:
			pagerules[k] = make_pagerule(zone, cf_data = pagerules[k])
		for k in records:
			records[k] = make_record(zone, cf_data = records[k])
		for k in routes:
			routes[k] = make_route(zone, cf_data = routes[k])
		for k in rules:
			rules[k] = make_rule(zone, cf_data = rules[k])
		for k in settings:
			settings[k] = make_setting(zone, cf_data = settings[k])

def do_sendgrid_senders():
	for k in zones:
		zone = zones[k]
		if brr_child(zone):
			make_sendgrid_sender(f"{HOOK_DN}@{zone.name}")

def responding(address):
	try:
		requests.head(f"https://{address}/")
		return True
	except:
		return False

def do_web_records():
	for k in zones:
		zone = zones[k]
		# This is pretty bad.
		revert = None
		if zone.name == "southtowntattoocollective.com":
			revert = "southtowntattoocollective.com"
			zone.name = "tattoocollectivereno.com"

		address = get_domain_from_zone_if_exists(zone)
		if not address:
			if zone.name == "bestratereview.com":
				address = "35.192.114.80"
			else:
				address = VPS

		if standard(zone):
			make_record(zone, WWW, address)
			make_record(zone, ROOT, address)
		else:
			make_record(zone, ROOT, address)
			make_record(zone, WWW, address)

		# This is part of the pretty bad thing.
		if revert:
			zone.name = revert

def quote_if_weird(string):
	if weird(string):
		return quote(string)
	return string

def ipv4_address(string):
	ipv4_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
	if not re.match(ipv4_regex, string):
		return False
	parts = string.split(".")
	return all(0 <= int(part) <= 255 for part in parts)

def standard(zone):
	parts = zone.name.split(".")
	og = parts[1] == "com" or parts[1] == "net" or parts[1] == "org"
	return og

def short(zone):
	og = standard(zone)
	parts = zone.name.split(".")
	name = og and parts[0] or zone.name.replace(".", "")
	return name

def pair(zone):
	www = f"www.{zone.name}"
	root = zone.name
	if standard(zone):
		return www, root
	else:
		return root, www

# TODO
def do_world_record_and_proxys():
	for record in records:
		if record.is_web():
			if record.is_a(ADDRESS):
				record.proxy(PROXIED)

def do_google_search_console_records():
	for k in zones:
		zone = zones[k]
		make_record(zone, ROOT, os.getenv("GOOGLE_SITE_VERIFICATION"))

def quoted(string):
	return string[0] == '"' and string[-1] == '"'

def unquoted(string):
	return string[0] != '"' and string[-1] != '"'

def unquote(string):
	return quoted(string) and string[1:-1] or string

def quote(string):
	return unquoted(string) and f'"{string}"' or string

def weird(string):
	return bool(re.search(r"[^\w.]", string))

def brr_child(zone):
	return "rate" in zone.name and zone.name != "bestratereview.com"

def get_domain_from_zone_if_exists(zone):
	target = f"{short(zone)}.pages.dev"
	for k in pages:
		page = pages[k]
		domain = page.subdomain
		if domain == target:
			return domain

# We should really just name the pages the same thing as the domain, that way we can look it up from the pages directly.
# On top of that, this will introduce error...
def closest(page):
	return min(zones, k = lambda zone: Levenshtein.distance(page.name, zone.name), default = None)

# Brianna Flores is the persona we'll go with for now.
HOOK_NAME = "Brianna Flores"
HOOK_DN = HOOK_NAME.split(" ")[0].lower()

# SMARTLEAD_API_KEY = os.getenv("SMARTLEAD_API_KEY")

# def get_smartlead_entries():
# 	url = f"https://server.smartlead.ai/api/v1/email-accounts/?api_k={SMARTLEAD_API_KEY}&offset=0&limit=10"
# 	headers = Table({"Content-Type": "application/json"})
# 	response = requests.get(url, headers = headers)
# 	return response.json()

# smartlead_entries = get_smartlead_entries()

# def get_smartlead_entry_id_from_email(email):
# 	for smartlead_entry in smartlead_entries:
# 		if smartlead_entry.from_email == email:
# 			return smartlead_entry.id

# def make_smartlead_email(email):
# 	url = f"https://server.smartlead.ai/api/email-account/save-email-account"
# 	data = Table({
# 		"fromName": HOOK_NAME,
# 		"fromEmail": email,
# 		"username": "apik",
# 		"password": os.getenv("SENDGRID_API_KEY"),
# 		"host": "smtp.sendgrid.net",
# 		"port": 465,
# 		"portType": "SSL",
# 		"messagePerDay": 21,
# 		"imapHost": "imap.mail.me.com",
# 		"imapPort": 993,
# 		"imapPortType": "SSL",
# 		"isDifferentImapAccount": True,
# 		"signature": None,
# 		"bccEmail": None,
# 		"imapUsername": "jaydeeskinner@icloud.com",
# 		"imapPassword": os.getenv("ICLOUD_PASSWORD"),
# 		"differentReplyToAddress": email,
# 		"customTrackingDomain": "",
# 		"minTimeToWaitInMins": None,
# 	})
# 	id = get_smartlead_entry_id_from_email(email)
# 	if id != None:
# 		data.id = id
# 	# TODO: We need to automate getting the authorization header.
# 	headers = Table({
# 		"Content-Type": "application/json",
# 		"Authorization": f"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImVtYWlsIjoiamVmZkBqZS5neSIsImlkIjo3NjkwMSwibmFtZSI6IkplZmZyZXkgU2tpbm5lciIsInV1aWQiOiI2NGQ2MjMxZS1kNjg3LTRhYmQtYTljNi1jYzdkMGQwNmUzYWYiLCJyb2xlIjoiYWRtaW4iLCJwcm92aWRlciI6ImFwcCJ9LCJodHRwczovL2hhc3VyYS5pby9qd3QvY2xhaW1zIjp7IngtaGFzdXJhLWFsbG93ZWQtcm9sZXMiOlsidXNlcnMiXSwieC1oYXN1cmEtZGVmYXVsdC1yb2xlIjoidXNlcnMiLCJ4LWhhc3VyYS11c2VyLWlkIjoiNzY5MDEiLCJ4LWhhc3VyYS11c2VyLXV1aWQiOiI2NGQ2MjMxZS1kNjg3LTRhYmQtYTljNi1jYzdkMGQwNmUzYWYiLCJ4LWhhc3VyYS11c2VyLW5hbWUiOiJKZWZmcmV5IFNraW5uZXIiLCJ4LWhhc3VyYS11c2VyLXJvbGUiOiJhZG1pbiIsIngtaGFzdXJhLXVzZXItZW1haWwiOiJqZWZmQGplLmd5In0sImlhdCI6MTczMjQ2MzU4MH0.v0fN8-CGW0eqOIDW9y3fZ5EFne7PVQGjHNkQ7_XdMj0"
# 	})
# 	response = requests.post(url, headers = headers, data = json.dumps(data))
# 	print(response.json())

# Sendgrid stuff goes here

SENDGRID_HEADERS = Table({
	"Authorization": f"Bearer {os.getenv("SENDGRID_API_KEY")}",
	"Content-Type": "application/json"
})

def make_sendgrid_sender(email):
	data = Table({
		"address": "12575 Beatrice St",
		"city": "Los Angeles",
		"country": "USA",
		"from": {
			"email": email,
			"name": HOOK_NAME
		},
		"nickname": email,
		"reply_to": {
			"email": email,
			"name": HOOK_NAME
		},
		"state": "CA",
		"zip": "90066"
	})
	response = requests.post("https://api.sendgrid.com/v3/marketing/senders", json = data, headers = SENDGRID_HEADERS)
	if response.status_code != 201:
		print(f"error creating {email}:", response.json())
	if True:
		data = Table({
			"domain": zone.name,
			"subdomain": "mail",
			"automatic_security": True,
			"custom_spf": False
		})
		response = requests.post("https://api.sendgrid.com/v3/whitelabel/domains", json = data, headers = SENDGRID_HEADERS)
		if response.status_code == 201:
			dns = response.json().dns
			for i in dns:
				record_info = dns[i]
				make_record(zone, record_info.host.replace(f".{zone.name}", ""), record_info.data, title = "sendgrid", proxied = UNPROXIED)
		else:
			print(f"error {response.status_code}, {response.text}")

def run_deltas():
	for location in cf_items:
		if not local.get(location):
			cf_items[location].remove()
	for location in local:
		if not cf_items.get(location):
			local[location].push()

if __name__ == "__main__":
	fetch()
	do_web_records()
	# Email stuff
	for k in zones:
		zone = zones[k]

		# BRR unsubscribe configuration
		# if not brr_has_mail_record(zone):
		# 	print(zone, "is missing brr mail record")
		# if not zone.name in unsubscribe_worker.domains:
		# 	print(domain, "is missing from brr unsubscribe worker")

		# Records
		make_record(zone, "api", f"{short(zone)}.jaydeeskinner.workers.dev")
		if brr_child(zone):
			make_rule(zone, "brr")
		elif zone.name == "bestratereview.com":
			make_record(zone, ROOT, "google-site-verification=1O4KHQCY_QaBmRlMHA_WUU3LGeqjmKr_4JN25L5_ybQ")
			make_record(zone, ROOT, "smtp.google.com", MAIL, UNPROXIED, priority = 1)
		elif zone.name == "tattoocollectivereno.com" or zone.name == "southtowntattoocollective.com":
			make_rule(zone, target = "tattoocollectivereno@gmail.com")
		elif zone.name == "je.gy":
			make_rule(zone, target = "jaydeeskinner@icloud.com")
		else:
			make_rule(zone, target = "jeff@je.gy")

		# Mail stuff
		make_record(zone, ROOT, "v=spf1 include:icloud.com include:_spf.mx.cloudflare.net include:_spf.google.com include:sendgrid.net ~all")
		make_record(zone, "_dmarc", "v=DMARC1; p=quarantine;")
		# make_record(zone, "_mailchannels", f"v=mc1 auth={os.getenv("MAILCHANNELS_ID")}", title = "mailchannels")
		# TODO: We also need to make DKIM records.

		# Page rules (redirects)
		first, second = pair(zone)
		# This fixes the Instagram redirect thing.
		make_pagerule(zone, f"https://{first}/fbclid*", f"https://{first}/")
		if brr_child(zone):
			make_pagerule(zone, f"https://{first}/*", f"https://www.bestratereview.com/$1")
			make_pagerule(zone, f"https://{second}/*", f"https://www.bestratereview.com/$1")
		elif zone.name == "jaydeeskinner.com":
			make_pagerule(zone, f"https://{first}/", f"https://{first}/index.htm")
		elif zone.name == "southtowntattoocollective.com":
			make_pagerule(zone, f"https://*southtowntattoocollective.com/*", f"https://$1tattoocollectivereno.com/$2") # This works for now.
		else:
			make_pagerule(zone, f"https://{second}/*", f"https://{first}/$1")

		# Page domains
		name = short(zone)
		first, second = pair(zone)
		for k in pages:
			page = pages[k]
			if page.name == name:
				make_domain(page, first)
				make_domain(page, second)

		# Settings
		for j in zone.settings:
			setting = zone.settings[j]
			if setting.editable:
				make_setting(zone, setting.id, overrides[setting.id])

		# Routes
		# make_route(zone, f"api.{zone.name}/", short(zone)) # API routes
		# # Forward should really be called lint URL or something different.
		# # URL linter route
		# if standard(zone):
		# 	make_route(zone, f"www.{zone.name}/*", "forward")
		# else:
		# 	make_route(zone, f"{zone.name}/*", "forward")
		# # if zone.name == "leetforms.com":
		# # 	make_route("leetforms", f"tattoocollectivereno.leetforms.com/")
		# # make_route("forward", f"*{zone.name}/*")

	# do_sendgrid_senders()
	run_deltas()