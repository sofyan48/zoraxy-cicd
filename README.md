# Zoraxy CI/CD Integrator

A Go plugin for creating, updating upstreams, and deleting Zoraxy **host-based HTTP reverse proxies** from CI/CD pipelines. It implements the `-introspect` / `-configure` contract from the [Zoraxy Plugin API](https://zoraxy.aroz.org/plugins/html/zoraxy_plugin%20API.html) and uses the Zoraxy management API. It does not automatically provision certificates, configure DNS, or deploy applications.

> **Warning:** Zoraxy's bearer-token plugin API does not support creating or deleting proxy rules. This plugin signs in to the **management API** using administrator credentials and CSRF protection for those operations. Store credentials and tokens securely; never expose the CI/CD endpoint to the internet without HTTPS. Keep the Zoraxy management port private.

## Installation and Configuration

Requires Go 1.22+. Build for the **Zoraxy server's operating system and architecture** (Linux amd64 in this example):

```sh
GOOS=linux GOARCH=amd64 go build -o dist/zoraxy-integrator .
```

Create a directory named `zoraxy-integrator` inside Zoraxy's plugin directory. Place the `zoraxy-integrator` executable and `integrator.json` inside it, and grant execute permission to the binary. Zoraxy discovers an executable with the same name as its parent directory and runs it with `-introspect` and `-configure`. Enable the plugin in Zoraxy's plugin manager. To inspect its metadata manually, run `./dist/zoraxy-integrator -introspect`.

Create `integrator.json` from `integrator.example.json` and replace all example values. `allowed_domains` is required; a hostname must match a listed domain or one of its subdomains. Generate a random token of **at least 32 characters**, for example with `openssl rand -hex 32`. Restrict access to the configuration file (for example, `chmod 600 integrator.json`) and never commit secrets. You can also configure the plugin using `ZORAXY_URL`, `ZORAXY_USERNAME`, `ZORAXY_PASSWORD`, `INTEGRATOR_TOKEN`, and `INTEGRATOR_ALLOWED_DOMAINS` (a comma-separated list). Environment variables override file settings. The default Zoraxy management URL is `http://127.0.0.1:8000` and must be reachable from the plugin process; use HTTPS when crossing an untrusted network. The Zoraxy account must support session-based login; do not rely on `-noauth` mode.

To test without the Zoraxy plugin manager, run `go run . -listen 127.0.0.1:9080 -config integrator.json`. The endpoint is then available directly at that address. When installed as a plugin, the same endpoint is forwarded through a **proxy rule with the plugin enabled**, under the `/_zoraxy-integrator/v1/` prefix. Do not enable the plugin on untrusted public proxy rules: the hostname allowlist limits the targets that can be modified, not who can attempt to access the endpoint. Use a dedicated hostname protected by HTTPS and access controls, or call the local listener from a CI job on the same machine. Never leak tokens into pipeline logs or artifacts. `UIPath` only displays instructions; it does not store secrets.

### Allowing All Domains

Use an explicit wildcard in `integrator.json`:

```json
"allowed_domains": ["*"]
```

Alternatively, set `INTEGRATOR_ALLOWED_DOMAINS='*'`. Restart the plugin after changing its configuration. This wildcard allows all valid DNS hostnames; it does not enable wildcard hostnames in deployment payloads. Empty allowlists are still rejected. Bearer authentication remains mandatory, and updates/deletions remain restricted to rules tagged `zoraxy-integrator`.

**Risk:** anyone holding the token can create proxies for any domain. Use this setting only with trusted pipelines, and protect the endpoint with HTTPS and network restrictions. It does not automatically configure DNS or domain certificates.

## CI/CD API

All requests require `Authorization: Bearer <token>`. `PUT` and `DELETE` require `Content-Type: application/json` and a single JSON body. Use a plugin address reachable from your pipeline:

```sh
curl -fsS -X PUT https://integrator.example.com/_zoraxy-integrator/v1/proxies \
  -H 'Authorization: Bearer YOUR_TOKEN' -H 'Content-Type: application/json' \
  -d '{"hostname":"app.apps.example.com","upstream":"http://10.0.0.5:8080"}'

curl -fsS -X DELETE https://integrator.example.com/_zoraxy-integrator/v1/proxies \
  -H 'Authorization: Bearer YOUR_TOKEN' -H 'Content-Type: application/json' \
  -d '{"hostname":"app.apps.example.com"}'
```

`upstream` must use `http://host:port` or `https://host:port`, without a path, query string, or user information. The scheme determines TLS **to the upstream**; public/client-facing TLS is configured separately in Zoraxy. JSON responses use `{"action":"created|updated|unchanged|deleted","hostname":"...","upstream":"..."}`. `GET /_zoraxy-integrator/v1/health` also requires a token and returns `{"status":"ok"}`.

The plugin creates rules tagged `zoraxy-integrator` and only updates or deletes rules carrying that tag. If a hostname already exists but is not owned by the plugin, the request fails instead of overwriting it. Upstream changes support enabled rules with **exactly one active upstream and no inactive upstreams**, while preserving other rule settings. Deleting a nonexistent hostname returns `unchanged`. Mutations are followed by read-back verification; failures return HTTP 502. After a 502 response, inspect the rule in Zoraxy before retrying: the Zoraxy API is not transactional. Separate processes or concurrent CI jobs do not share a cross-process lock; serialize deployments for each hostname.

### Access Rules and Exploit Prevention (v0.2.0)

A `PUT` payload can include two additional options:

```json
{
  "hostname": "app.example.com",
  "upstream": "http://10.0.0.5:8080",
  "access_rule": "default",
  "exploit_prevention": true
}
```

- `access_rule`: the **ID** of an existing Zoraxy access rule, not its display name. Find the ID in the management API response from `/api/access/list` using an administrator session, or inspect access-rule selection requests in your browser's developer tools. The plugin does not create access rules. IDs are checked before proxy mutations; an unknown ID causes the operation to fail.
- `exploit_prevention`: controls **Block Common Exploits** (SQL injection, XSS, etc.). Set `true` to enable it or `false` to disable it. It does not change existing AI crawler blocking or mitigation actions. New rules use Zoraxy's default mitigation action (`0`, an HTTP 404 response).
- When creating a rule, omitted options default to `access_rule: "default"` and `exploit_prevention: false`.
- When updating a rule, omitted options (or `null`) preserve the existing values. Changing only these settings while keeping the same upstream returns `updated`; submitting the same configuration again returns `unchanged`. `upstream` is still required.
- `DELETE` accepts only a hostname, not these options.

Changing Exploit Prevention on an existing rule requires `/api/proxy/edit`, which can reset settings if parameters are incomplete. The integrator reads the rule details first and preserves other settings, including authentication, tags, rate limits, and security settings. If your Zoraxy version returns unknown or incomplete fields, or CAPTCHA settings that cannot be preserved (such as exception rules), the plugin **rejects the operation before mutation**. This support is based on the Zoraxy source contract at commit `310b0cc343a3c2af6d040a5300f7047d61ec0aeb`; test your version in staging. Upstream, exploit prevention, and access-rule changes use separate requests, not a transaction; inspect the current state if an error occurs after some requests have succeeded.

After upgrading, stop the plugin, replace the binary with the build for your operating system and architecture, and start it again. The UI and version header should show `0.2.0`.

## GitHub Actions Example

Add the following step **after the application deployment succeeds**. Store `INTEGRATOR_URL` (for example, `https://integrator.example.com`) and `INTEGRATOR_TOKEN` as repository secrets, and configure the repository variables `APP_HOSTNAME` and `APP_UPSTREAM`. The runner must be able to reach the integrator, and Zoraxy must be able to reach the upstream. This example uses `jq`, which is available on GitHub-hosted Ubuntu runners.

```yaml
concurrency:
  group: production-proxy
  cancel-in-progress: false

jobs:
  proxy:
    runs-on: ubuntu-latest
    steps:
      - name: Apply Zoraxy proxy
        env:
          INTEGRATOR_URL: ${{ secrets.INTEGRATOR_URL }}
          INTEGRATOR_TOKEN: ${{ secrets.INTEGRATOR_TOKEN }}
          APP_HOSTNAME: ${{ vars.APP_HOSTNAME }}
          APP_UPSTREAM: ${{ vars.APP_UPSTREAM }}
        run: |
          set -eu
          jq -n --arg hostname "$APP_HOSTNAME" --arg upstream "$APP_UPSTREAM" \
            '{hostname: $hostname, upstream: $upstream}' > payload.json
          curl --fail-with-body --silent --show-error --max-time 60 \
            -X PUT "${INTEGRATOR_URL}/_zoraxy-integrator/v1/proxies" \
            -H "Authorization: Bearer ${INTEGRATOR_TOKEN}" \
            -H 'Content-Type: application/json' \
            --data-binary @payload.json
```

`curl` exits with a nonzero status on 4xx/5xx responses, causing the job to fail. Do not add automatic retries for mutations without checking the current state after an error.

## Validation

```sh
go test -race ./...
go vet ./...
```

Zoraxy CRUD contract references: [proxy handlers](https://github.com/tobychui/zoraxy/blob/main/src/reverseproxy.go) and [upstream handlers](https://github.com/tobychui/zoraxy/blob/main/src/upstreams.go). The Zoraxy management API is not guaranteed to remain stable across versions; test in staging before using it in production.
