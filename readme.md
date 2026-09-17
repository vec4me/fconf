# Functional Configurator
Declarative infrastructure configuration for Cloudflare, Telnyx, and Regery.

## Environment Variables
| Variable | Required | Where to get it |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | Yes | [Cloudflare dashboard](https://dash.cloudflare.com/profile/api-tokens) > Create Token. Needs edit permissions for DNS, Zone Settings, Zone Rulesets, Workers Routes, Email Routing, and Email Sending, plus the existing Workers and Pages access. |
| `CLOUDFLARE_ACCOUNT_ID` | Yes | Cloudflare dashboard > any domain > Overview sidebar > Account ID. |
| `VPS` | No | IP address of your default VPS. Used as the A record for domains without a specific address configured. |
| `TELNYX_API_KEY` | Yes | [Telnyx portal](https://portal.telnyx.com/) > API Keys. |
| `SIP_PASSWORD` | No | Password for Telnyx SIP credential connections. Defaults to empty string. |
| `REGERY_API_KEY` | Yes | [Regery dashboard](https://regery.com/) > API settings. |
| `REGERY_API_SECRET` | Yes | [Regery dashboard](https://regery.com/) > API settings. Paired with `REGERY_API_KEY`. |
| `REGERY_CONTACT_ID` | Yes | Contact ID for domain registration contacts (registrant, admin, tech, billing). |

Run `python config.py`. The tool fetches current state from all providers, computes a diff against the desired configuration, and prompts before applying changes.

## Outbound Email
The configurator onboards every Cloudflare Email Routing domain with Cloudflare Email Sending. Existing SMTP applications can submit through `smtp.mx.cloudflare.net` on port `465` with implicit TLS, the username `api_token`, and a Cloudflare API token with `Email Sending: Edit` as the password. Applications can alternatively use the Cloudflare Email Sending REST API or a Worker email binding.
