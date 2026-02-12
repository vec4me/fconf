# Functional Configurator

Declarative infrastructure configuration for Cloudflare, AWS SES, and Telnyx.

## Environment Variables

| Variable | Required | Where to get it |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | Yes | [Cloudflare dashboard](https://dash.cloudflare.com/profile/api-tokens) > Create Token. Needs permissions for Zone (DNS, Settings), Account (Workers, Pages), and Zone Rulesets. |
| `CLOUDFLARE_ACCOUNT_ID` | Yes | Cloudflare dashboard > any domain > Overview sidebar > Account ID. |
| `AWS_ACCESS_KEY_ID` | Yes (if SES domains configured) | AWS IAM access key. Needs permissions for SES, S3, IAM, and Lambda. Can also be configured via `~/.aws/credentials`. |
| `AWS_SECRET_ACCESS_KEY` | Yes (if SES domains configured) | AWS IAM secret key. Paired with `AWS_ACCESS_KEY_ID`. |
| `AWS_REGION` | Yes (if SES domains configured) | The AWS region your SES is set up in, e.g. `us-east-1`. Must be a region where SES is available. |
| `VPS` | No | IP address of your default VPS. Used as the A record for domains without a specific address configured. |
| `TELNYX_API_KEY` | Yes | [Telnyx portal](https://portal.telnyx.com/) > API Keys. |
| `SIP_PASSWORD` | No | Password for Telnyx SIP credential connections. Defaults to empty string. |
| `REGERY_API_KEY` | Yes | [Regery dashboard](https://regery.com/) > API settings. |
| `REGERY_API_SECRET` | Yes | [Regery dashboard](https://regery.com/) > API settings. Paired with `REGERY_API_KEY`. |
| `REGERY_CONTACT_ID` | Yes | Contact ID for domain registration contacts (registrant, admin, tech, billing). |

Run `python config.py`. The tool fetches current state from all providers, computes a diff against the desired configuration, and prompts before applying changes.
