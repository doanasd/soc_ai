# Known Benign Patterns

## Internet Background Noise

- Single internet SYN to SSH, Redis, MySQL, PostgreSQL, MongoDB, or Elasticsearch.
- One-off probes from random public IPs.
- Port scans with `packets <= 1`.
- Low-byte internet noise with no repetition in the same window.
- Small-packet or low-byte accepted TCP probes to management ports such as `22` or `23` when the evidence still fits handshake-only or banner-grab behavior.
- Recurrent low-volume SSH probes from `147.185.132.40` to `10.141.1.64:22` when there is no host-level session or auth evidence.

## WAF Benign Patterns

- Single or low-rate `allow` requests to `/login`, `/payment`, `/api/*`, and other public app paths.
- Normal customer traffic to payment and auth endpoints without attack indicators.
- Default allow or whitelisted traffic.
- Single blocked exploit probe.
- Routine blocked WAF traffic at baseline volume.
- Temporary blocked-volume increase after rule tuning or managed rule updates when service impact is absent.

## Internal East-West Benign Patterns

- Application tier hosts connecting to a shared internal PostgreSQL host.
- Multiple internal hosts reaching one DB or cache backend on expected ports.
- Normal service connectivity to `5432`, `3306`, `6379`, `27017`, or `9200` when ownership and architecture align.
- High-count or sustained internal DB sessions that match expected application behavior.
- Internal clients reaching `10.141.19.244:5432` for normal PostgreSQL usage.
- Internal clients reaching `10.141.158.148:5432` for normal PostgreSQL usage.
- Multiple internal clients reaching `10.141.158.148:5432` in one window when it behaves as a shared production PostgreSQL backend.
- Internal admin users or approved internal paths reaching `10.141.10.250:443`.
- Traffic involving `10.141.1.64` that matches documented `NON-CDK-GW3-LIVE` gateway-host behavior.
- Low-volume or short-lived traffic to `10.141.1.64` is not enough to infer unauthorized exposure without confirmed role mismatch.
- Low-volume accepted traffic to `10.141.1.64` on `22` or `23` should be treated as scan or reconnaissance noise when packet and byte evidence remains small and there is no host-level corroboration.
- Recurrent low-volume SSH probes to `10.141.1.64:22` from `147.185.132.40` should be treated as scanner noise or low-signal reconnaissance unless the pattern broadens or host/auth telemetry confirms a real session.

## Authorized Source Benign Patterns

- `ATOME-Production` source IPs `13.228.154.28/32`, `18.138.71.183/32`, `18.141.241.219/32`, and `165.173.9.115/32` reaching approved production services on expected ports.
- `ATOME-Staging` source IP `52.74.202.90/32` only when the destination and environment match the approved staging use case.
- Authorized source traffic that stays low-rate, targets the expected service, and does not show scanning, spread, or abusive automation.

## Platform Noise

- Monitoring, backup, package update, and agent traffic.
- Internal Linux management from approved admin ranges.
- Service-mesh or orchestration chatter.

## Suppression Rule

- If the batch matches one of these patterns and there is no contradictory evidence, prefer `should_alert=false`.
