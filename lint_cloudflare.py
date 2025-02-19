# Cloudflare Linter by Jeffrey Skinner <jeff@je.gy> a.k.a. jaydeeskinner
# I should do patching instead of deleting everything and rewriting.

# TODO: We should first pull, then make changes to the local data, then have a push function where we actually start to send the requests. This would probably be faster because we can compile deltas.
# This would also make it very easy to find extraneous configurations in which we can easily remove. This'll be good.

# TODO: We need to actually check if email routing is enabled for the zone.

# TODO: Make a function to lint URLs (ensure trailing slashes) on Pages, Workers, etc.

# TODO: We need to get the unsubscribe thing to work, we gotta allow the worker to accept the /unsubscribe connections.

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
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")

CLOUDFLARE_HEADERS = Table({
	"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
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

def make_setting(zone, id = None, value = None, cloudee = None):
	if cloudee:
		id = cloudee.id
		value = cloudee.value

	zone = zone or print(zone.name, "setting, missing zone")
	value = value# or print(zone.name, "setting, missing value")

	def identity():
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
	self.id = id
	self.identity = identity
	self.push = push
	self.remove = remove
	self.type = "setting"

	if cloudee:
		cloud[identity()] = self
	else:
		local[identity()] = self

	return self

# TODO: We gotta make this handle TTL eventually.
# Also this isn't really working how I want it to. Because SPF and Google verification records get match as the same thing and are both removed...
def make_record(zone, name = None, content = None, type = None, proxied = PROXIED, priority = None, ttl = AUTO, id = None, title = None, cloudee = None):
	if cloudee:
		if 0 < len(cloudee.tags):
			title = cloudee.tags[0]
		if cloudee.name == zone.name:
			name = ROOT
		elif cloudee.name.endswith(f".{zone.name}"):
			name = cloudee.name[0:-(1 + len(zone.name))]
		if quoted(cloudee.content):
			content = unquote(cloudee.content)
		else:
			content = cloudee.content
		ttl = int(cloudee.ttl)
		proxied = cloudee.proxied
		type = cloudee.type
		priority = cloudee.priority
		id = cloudee.id
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

	name = name or print(zone.name, "record, missing name")
	type = type or print(zone.name, "record, missing type")
	content = content or print(zone.name, "record, missing content")
	proxied = proxied# or print(zone.name, "record, missing proxied")
	ttl = ttl or print(zone.name, "record, missing ttl")
	priority = priority# or print(zone.name, "record, missing priority")
	zone = zone or print(zone.name, "record, missing zone")

	# TODO
	# def flatten(record, flatten = FLATTEN):
	# 	data = Table({
	# 		"flatten": flatten
	# 	})

	def proxy(on):
		proxied = on

	def identity():
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
			pass
			# print(f"error {zone.name} remove record [{type}, {name}, {content}]")

	self = Table()
	self.is_web = is_web
	self.identity = identity
	self.push = push
	self.remove = remove
	self.type = "record"

	if cloudee:
		cloud[identity()] = self
	else:
		local[identity()] = self

	return self

def make_route(zone, origin = None, target = None, cloudee = None):
	if cloudee:
		origin = cloudee.pattern
		target = cloudee.script
		id = cloudee.id

	origin = origin or print(zone.name, "route, missing origin")
	target = target or print(zone.name, "route, missing target")

	def remove():
		if not delete(f"zones/{zone.id}/workers/routes/{id}"):
			print(f"error {zone.name} remove worker route {origin}")

	def push():
		data = {
			"pattern": origin,
			"script": target
		}
		if not post(f"zones/{zone.id}/workers/routes", data):
			print(f"error {zone.name} create worker route {origin}")

	def identity():
		return zone.name + origin + str(target)

	self = Table()
	self.identity = identity
	self.push = push
	self.remove = remove
	self.type = "route"

	if cloudee:
		cloud[identity()] = self
	else:
		local[identity()] = self

	return self

def make_rule(zone, target = None, enabled = True, cloudee = None):
	if cloudee:
		target = cloudee.actions[0].type != "drop" and cloudee.actions[0].value[0]
		enabled = cloudee.enabled # Make sure this is working
		id = cloudee.id

	target = target or print(zone.name, "rule, missing target")

	def identity():
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
	self.identity = identity
	self.push = push
	self.remove = remove
	self.type = "rule"

	if cloudee:
		cloud[identity()] = self
	else:
		local[identity()] = self

	return self

cloud_pagerule_counts = Table()
local_pagerule_queues = Table()

def make_pagerule(zone, origin = None, target = None, position = None, cloudee = None):
	self = Table()

	if cloudee:
		origin = cloudee.targets[0].constraint.value
		target = cloudee.actions[0].value.url
		if cloud_pagerule_counts.get(zone.name) != None:
			cloud_pagerule_counts[zone.name] += 1
		else:
			cloud_pagerule_counts[zone.name] = 1
		position = cloud_pagerule_counts[zone.name]
		id = cloudee.id
	else:
		if local_pagerule_queues.get(zone.name) != None:
			local_pagerule_queues[zone.name].append(self)
		else:
			local_pagerule_queues[zone.name] = [self]
		position = len(local_pagerule_queues[zone.name])

	origin = origin or print(zone.name, "pagerule, missing origin")
	target = target or print(zone.name, "pagerule, missing target")
	zone = zone or print(zone.name, "pagerule, missing zone")

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
			# "priority": priority,
			"priority": 1, # Append
			"status": "active"
		}
		if not post(f"zones/{zone.id}/pagerules", data):
			print(f"error {zone.name} make pagerule [{origin} -> {target}]")

	def identity():
		return zone.name + origin + target + str(position)

	def remove():
		if not delete(f"zones/{zone.id}/pagerules/{id}"):
			print(f"error {zone.name} remove pagerule [{origin} -> {target}]")

	if cloudee:
		# print(zone.name, "cloud pagerule", position, origin, target)
		cloud[identity()] = self
	else:
		# print(zone.name, "local pagerule", position, origin, target)
		local[identity()] = self

	self.identity = identity
	self.push = push
	self.remove = remove
	self.type = "pagerule"

	return self

def make_domain(page, name = None, cloudee = None):
	if cloudee:
		name = cloudee.name

	name = name or print(page.name, "domain, missing name")

	def identity():
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
	self.identity = identity
	self.push = push
	self.remove = remove
	self.type = "domain"

	if cloudee:
		cloud[identity()] = self
	else:
		local[identity()] = self

	return self

# Thanks ChatGPT
def get_pages():
	url = f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects"
	headers = {"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}", "Content-Type": "application/json"}

	projects = []
	page = 1
	while True:
		response = requests.get(f"{url}?page={page}", headers=headers).json()
		if not response.get("success", False):
			print("Error fetching data:", response)
			break

		projects.extend(response.get("result", []))
		result_info = response.get("result_info", {})

		if result_info.get("page", 1) >= result_info.get("total_pages", 1):
			break
		page += 1

	return Table(projects)

def get_zones():
	zones = Table()
	page = 1
	while (data := get(f"zones?per_page=69&page={page}")):
		for thing in data:
			zones.insert(thing)
		if len(data) < 69:
			break
		page += 1
	return zones

def get_domains(pages):
	page = 1
	for k in pages:
		page = pages[k]
		domains = Table(get(f"accounts/{CLOUDFLARE_ACCOUNT_ID}/pages/projects/{page.name}/domains"))
		page.domains = domains
		for k in domains:
			domains[k] = make_domain(page, cloudee = domains[k])

def fetch():
	global cloud
	global local
	global pages
	global zones
	# global domains
	cloud = Table()
	local = Table()
	pages = get_pages()
	zones = get_zones()
	get_domains(pages)
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
			pagerules[k] = make_pagerule(zone, cloudee = pagerules[k])
		for k in records:
			records[k] = make_record(zone, cloudee = records[k])
		for k in routes:
			routes[k] = make_route(zone, cloudee = routes[k])
		for k in rules:
			rules[k] = make_rule(zone, cloudee = rules[k])
		for k in settings:
			settings[k] = make_setting(zone, cloudee = settings[k])

def do_sendgrid_senders():
	global zones
	for k in zones:
		zone = zones[k]
		if brr_child(zone):
			make_sendgrid_sender(zone, f"{HOOK_DN}@{zone.name}")
	response = requests.get("https://api.sendgrid.com/v3/whitelabel/domains?limit=1337", headers = SENDGRID_HEADERS)
	if response.status_code == 200:
		for item in response.json():
			for i in item["dns"]:
				record = item["dns"][i]
				zone_name = domain(record["host"])
				for j in zones:
					zone = zones[j]
					if zone.name == zone_name:
						make_record(zone, record["host"].replace(f".{zone.name}", ""), record["data"], title = "sendgrid", proxied = UNPROXIED)
	else:
		print("error getting the Sendgrid domains")

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

def domain(address):
	parts = address.split(".")
	if len(parts) < 2:
		return address # Return as-is if not a valid subdomain structure
	return ".".join(parts[-2:])

def brr_child(zone):
	return "rate" in zone.name and zone.name != "bestratereview.com"

def zone_page(zone):
	look = short(zone)
	if zone.name == "southtowntattoocollective.com":
		look = "tattoocollectivereno"
	target = f"{look}.pages.dev"
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

def make_sendgrid_sender(zone, email):
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
	data = Table({
		"domain": zone.name,
		"subdomain": "sendgrid",
		"automatic_security": True,
		"custom_spf": False
	})
	response = requests.post("https://api.sendgrid.com/v3/whitelabel/domains", json = data, headers = SENDGRID_HEADERS)
	if response.status_code != 201:
		print(f"error {response.status_code}, {response.text}")

def run_deltas():
	for identity in cloud:
		if not local.get(identity):
			cloud[identity].remove()
	for identity in local:
		if not cloud.get(identity):
			item = local[identity]
			if item.type != "pagerule":
				item.push()
	for zone_name in local_pagerule_queues:
		queue = local_pagerule_queues[zone_name]
		for item in queue:
			if not cloud.get(item.identity()):
				item.push()

if __name__ == "__main__":
	fetch()

	do_sendgrid_senders()

	for k in zones:
		zone = zones[k]
		first, second = pair(zone)

		# Records
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

		address = zone_page(zone)

		if not address:
			if "rate" in zone.name:
				address = "35.192.114.80"
			else:
				address = VPS

		if standard(zone):
			make_record(zone, WWW, address)
			make_record(zone, ROOT, address)
		else:
			make_record(zone, ROOT, address)
			make_record(zone, WWW, address)

		# Mail stuff
		make_record(zone, ROOT, "v=spf1 include:icloud.com include:_spf.mx.cloudflare.net include:_spf.google.com include:sendgrid.net ~all")
		make_record(zone, "_dmarc", "v=DMARC1; p=quarantine;")
		# make_record(zone, "_mailchannels", f"v=mc1 auth={os.getenv("MAILCHANNELS_ID")}", title = "mailchannels")
		# TODO: We also need to make DKIM records.

		# Mail tracking (unsubscribes, etc.)
		make_record(zone, "mail", "mail.jaydeeskinner.workers.dev")
		make_route(zone, f"mail.{zone.name}/unsubscribe*", "mail")

		# Page rules (redirects)
		make_pagerule(zone, f"http://{second}/*", f"http://{first}/$1")
		make_pagerule(zone, f"http://{first}/fbclid*", f"http://{first}/") # This fixes the Instagram redirect thing.
		if zone.name == "jaydeeskinner.com":
			make_pagerule(zone, f"http://{first}/", f"http://{first}/index.htm")
		elif brr_child(zone):
			make_pagerule(zone, f"http://*{domain(first)}/*", f"http://$1bestratereview.com/$2")
		elif zone.name == "southtowntattoocollective.com":
			make_pagerule(zone, f"http://*southtowntattoocollective.com/*", f"http://$1tattoocollectivereno.com/$2") # This works for now.
		else:
			pass

		# Page domains
		name = short(zone)
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

		# API
		make_record(zone, "api", f"{short(zone)}.jaydeeskinner.workers.dev") # TODO: We should have a function to check if the worker domain exists in the first place.
		make_route(zone, f"api.{zone.name}/*", short(zone)) # API routes, also we might need to change to /* instead of /.

		# Forward should really be called lint URL or something different.
		# URL linter route
		make_route(zone, f"{first}/*", "forward")

	run_deltas()