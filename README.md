# Functional Configurator
Declarative infrastructure configuration for Cloudflare, Telnyx, and Regery. Example configuration and zone files live under `examples/`; the implementation lives under `src/`.

## Environment Variables
| Variable | Required | Where to get it |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | Yes | [Cloudflare dashboard](https://dash.cloudflare.com/profile/api-tokens) > Create Token. Needs edit permissions for DNS, Zone Settings, Zone Rulesets, Workers Routes, and Email Routing, plus the existing Workers and Pages access. |
| `CLOUDFLARE_ACCOUNT_ID` | Yes | Cloudflare dashboard > any domain > Overview sidebar > Account ID. |
| `TELNYX_API_KEY` | Yes | [Telnyx portal](https://portal.telnyx.com/) > API Keys. |
| `SIP_PASSWORD` | Yes | Password for Telnyx SIP credential connections. |
| `REGERY_API_KEY` | Yes | [Regery dashboard](https://regery.com/) > API settings. |
| `REGERY_API_SECRET` | Yes | [Regery dashboard](https://regery.com/) > API settings. Paired with `REGERY_API_KEY`. |
| `REGERY_CONTACT_ID` | Yes | Contact ID for domain registration contacts (registrant, admin, tech, billing). |

Select the exact provider scope for a plan or application:

```sh
./fconf --do cloudflare
./fconf --do telnyx
./fconf --do regery
./fconf --do cloudflare --do regery
./fconf --do all
./fconf --do cloudflare --apply
./fconf --check
./fconf --do cloudflare --plan=json
```

Each selected provider prints its plan without mutating remote state. Add `--apply` to perform every planned mutation for the selected providers. Use `--check` to validate all local files without credentials or network access. Regery consumes Cloudflare's authoritative nameserver observations but does not reconcile Cloudflare configuration. Telnyx and Regery declarations live in `examples/telnyx.json` and `examples/regery.json`; Cloudflare relationships are declared directly in zone files. Undeclared remote resources are left untouched.

Plans contain plain `push`, `remove`, `replace`, and non-mutating `unknown` operations. `unknown` means observation failed for that boundary, so no resource beneath it can be changed. Plan operations have stable identifiers and explicit dependencies; for example, an Email Routing destination is pushed before a forwarding rule that requires it. Use `--plan=json` for the machine-readable representation.

Application reports every operation as completed, failed, or skipped; a failed prerequisite skips its dependents. Every provider is re-observed after application, and success requires the verification plan to be empty.

## Email Routing
Use `; cloudflare email-forward source@example.com=destination@example.net` to declare one mailbox mapping or `; cloudflare email-forward *=destination@example.net` to declare a catch-all. Cloudflare owns the required Email Routing DNS records. Google-hosted domains declare their ordinary MX, SPF, and verification records directly in their zone files.

## Zone Files
Each `examples/example.com.zone` file is a standard BIND-style zone file. Ordinary DNS tools ignore the whole-line Cloudflare annotations, while the configurator uses them for provider relationships:

```dns
; cloudflare page-domain example-website:example.com
$INCLUDE _defaults.zone
; cloudflare page-domain example-website:www.example.com
; cloudflare email-forward inbox@example.com=mailbox@example.net
; cloudflare setting ssl=full
; cloudflare route api.example.com/*=example-api
; cloudflare redirect 301 '(http.host eq "example.com")' 'concat("https://www.example.com", http.request.uri.path)'

origin.example.com. 1 IN CNAME origin.example.net. ; cloudflare proxied
_dmarc.example.com. 1 IN TXT   "v=DMARC1; p=quarantine;"
```

Global Cloudflare settings and DNSSEC policy live in `examples/_defaults.zone`. A zone inherits them only when it explicitly contains `$INCLUDE _defaults.zone`; included annotations are parsed in place and later local settings override included settings. Every record uses an absolute owner name and explicitly declares its TTL and `IN` class, so no record depends on `$ORIGIN`, `$TTL`, or the preceding record. Supported whole-line annotations are `worker-domain`, `page-domain`, `email-forward`, `redirect`, `route`, `dnssec`, and `setting`. Add `; cloudflare proxied` at the aligned end of an individual DNS record to proxy that exact record. DNS proxying is disabled when the inline annotation is absent.
