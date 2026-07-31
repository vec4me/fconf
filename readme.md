# Functional Configurator

Functional Configurator makes cloud state match a declarative JSON document. Provider sections intentionally follow their APIs instead of exposing a second policy language.

## Usage

Build the CLI, then plan or apply the repository's JavaScript configuration:

```sh
sh tools/build-cli.sh
node config.js
node config.js --wet-run
```

`config.js` contains one plain object per provider and passes each one independently to `fconf`. A dry run prints creates, updates, and removals; `--wet-run` applies them.

The provider-scoped CLI is `fconf <provider> <configuration-file|-> [--wet-run]`. Cloudflare zones are keyed by their exact zone name. Resource collections within a zone are keyed only to give each desired resource stable identity; their values are request bodies shaped like the corresponding provider API.

Cloudflare `workers` is keyed by script name. Each Worker contains a `script-settings` subresource whose value is a declared subset of that API's JSON body (`logpush`, `observability`, `tags`, or `tail_consumers`). An empty `script-settings` object verifies that the Worker exists without managing any settings. Worker source uploads are not inferred from this collection.

Cloudflare hierarchy follows API ownership:

```json
{
    "workers": { "script-name": { "script-settings": {} } },
    "worker_domains": { "app.example.com": { "hostname": "app.example.com", "service": "script-name", "environment": "production" } },
    "pages": { "projects": { "project-name": { "domains": { "app.example.com": { "name": "app.example.com" } } } } },
    "zones": { "example.com": { "settings": {}, "dns_records": {}, "worker_routes": {}, "redirect_rules": {} } }
}
```

Telnyx collections likewise use endpoint names: `messaging_profiles`, `outbound_voice_profiles`, `credential_connections`, and `phone_numbers`. A phone-number entry can contain the native `voice` and `messaging` subresource bodies plus `phone_number` for the base `PATCH /phone_numbers/{id}` body.

See [examples](examples/) and [config.js](config.js) for complete documents.

Telnyx request bodies may contain `$ref:collection/key` to refer to an object declared elsewhere in the Telnyx section and `$env:NAME` to read a secret at apply time.

## Environment

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `TELNYX_API_KEY` when a `telnyx` section is present
- `REGERY_API_KEY` and `REGERY_API_SECRET` when a `regery.domains` section is present

Credentials come from environment variables and do not appear in desired-state objects.

## Dependencies

- libc
- libcurl
- libyyjson
