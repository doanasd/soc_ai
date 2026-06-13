# Detection Policy

## Global Rules

- Alert only on correlated, anomalous, or unauthorized behavior.
- Use evidence from the full window, not worst-case speculation.
- `ACCEPT` in VPC Flow Logs does not prove successful connection or successful authentication.
- For VPC flows, use `packets` and `bytes` as primary session-strength indicators before calling activity an exposure or compromise.
- Small packet and byte volume should usually be treated as scan, probe, or low-signal reconnaissance even when the destination port is sensitive.
- If the summarized VPC evidence does not include packet or byte counts, do not infer a real session from accepted flow count alone.
- Critical asset context increases review priority but never creates an alert by itself.
- Destination port matters more than source port.
- Use known asset-role context:
  - `10.141.1.64` is a documented production gateway host named `NON-CDK-GW3-LIVE`
  - do not assume `10.141.1.64` is a managed NAT gateway or an outbound-only `443/TCP` asset unless separately confirmed
  - `10.141.10.250` is a production Admin Portal app server using `443/TCP`
  - `10.141.19.244` is a production PostgreSQL server using `5432/TCP`
  - `10.141.158.148` is a production PostgreSQL server using `5432/TCP`
  - do not describe `10.141.158.148` as an unknown host when the observed traffic matches internal app-to-DB behavior
- Use known authorized source context:
  - `13.228.154.28/32`, `18.138.71.183/32`, `18.141.241.219/32`, `165.173.9.115/32` are `ATOME-Production`
  - `52.74.202.90/32` is `ATOME-Staging`
  - authorized source status lowers suspicion only when destination, port, direction, and environment match the expected use case
- Required telemetry health matters:
  - AWS VPC Flow Logs and AWS WAF logs are both expected inputs
  - if either required log type is absent for a full reporting interval, treat it as `telemetry_gap`
  - telemetry loss is an operational alert, not a no-alert status

## Ignore

- Single WAF `allow` to public endpoints such as `/login`, `/payment`, and `/api/*` with no attack indicators.
- Low-rate WAF `allow` traffic to public endpoints that matches routine user behavior.
- Single blocked WAF request or small blocked probe set with no volume anomaly.
- Internet scans, random IP probing, or one-off SSH/Redis/DB hits with only one packet or trivial bytes.
- VPC flows with `packets <= 1`.
- External-to-private VPC flows with low packet and byte volume that look consistent with handshake-only or banner-grab probing.
- Single external-to-private flow with no repetition and no evidence of a real session.
- Internal-to-internal DB or cache access that matches app-to-DB or service-to-service patterns.
- Multiple internal hosts connecting to one internal PostgreSQL or similar backend when there is no other anomaly.
- Internal-to-`10.141.19.244:5432` traffic that matches expected application or admin workflows.
- Internal-to-`10.141.158.148:5432` traffic that matches expected application or admin workflows.
- Multiple internal clients connecting to `10.141.158.148:5432` in the same window can be normal shared PostgreSQL usage.
- Internal-to-`10.141.10.250:443` traffic that matches expected Admin Portal access.
- Traffic from authorized ATOME production IPs to approved production services on expected ports, when volume and behavior remain normal.

## Low Signal

- Repeated blocked WAF traffic that remains blocked and stays near normal baseline.
- Small VPC probes to sensitive ports where `packets <= 10` and byte volume is low.
- A few accepted TCP flows to management ports such as `22` or `23` where packet and byte volume remain small.
- Single accepted flow to a sensitive port without repetition, session evidence, or corroborating logs.
- Internal DB access that is important to note but still consistent with expected east-west service behavior.
- Unexpected but low-volume internal access to `10.141.10.250:443` from a source with unknown ownership.
- Short-lived or low-count flows involving `10.141.1.64` without repetition, session evidence, or a confirmed port-role mismatch.
- Low-volume Telnet or SSH probing to `10.141.1.64` where accepted flow evidence exists but packet and byte counts remain too small to support a real-session conclusion.
- Low-volume traffic from an authorized source that targets an unusual asset or mismatched environment, but lacks repetition or session evidence.
- Low-volume external SSH probes from recurrent scanner IPs such as `147.185.132.40` to `10.141.1.64:22` when there is no host-level session evidence, no auth evidence, and no broader spread.

## WAF Alert Conditions

- `auth_abuse`
  - repeated login attempts beyond normal user rate
  - concentrated abuse against the same account, auth path, or token flow
- `web_attack`
  - repeated exploit payloads
  - attack payloads that are allowed, partially allowed, or mixed allowed/blocked
- `business_abuse`
  - abnormal automation or request rate against payment, account, checkout, or admin workflows
- `waf_block_rate_anomaly`
  - blocked volume is `>= 3x` normal baseline
  - blocked count also exceeds a meaningful absolute floor
  - service impact or flood evidence is not yet confirmed
- `possible_ddos`
  - blocked anomaly persists across multiple windows
  - and at least one is true:
    - many source IPs are involved
    - request distribution is broad
    - one or more critical endpoints are heavily targeted
    - service degradation is observed

## WAF Severity Guidance

- Single blocked-WAF anomaly in one 5-minute window with no matching recurrence in the last hour should usually be `low` severity or no-alert.
- Repeated matching blocked-WAF anomalies across 2 to 5 windows in the last hour can be `medium` when the endpoint, rule, or request pattern is clearly recurring.
- Matching blocked-WAF anomalies that continue for roughly 30 minutes or more, or that recur across most of the last hour, can be `high`.
- Use `critical` for WAF or DDoS only when there is confirmed service degradation, business impact, or clear evidence that the blocking controls are failing.
- Prefer `waf_block_rate_anomaly` over `possible_ddos` for isolated or short-lived spikes.

## Telemetry Health Alert Conditions

- `telemetry_gap`
  - AWS VPC Flow Logs are absent for the full reporting interval
  - or AWS WAF logs are absent for the full reporting interval
  - or both are absent for the full reporting interval
- Do not suppress telemetry loss as a normal no-activity condition.
- A telemetry gap is valid even when attack evidence is absent, because monitoring visibility is degraded.

## VPC Alert Conditions
### 1. Explicit Benign Patterns (DO NOT ALERT)
Do NOT alert when:
- single-packet traffic (packets <= 1) → internet scan
- internal-to-internal database traffic where:
  - source_port is a known DB port (5432, 3306, 6379)
  - destination_port is ephemeral (>1024)
  - indicates server response traffic
- multiple internal hosts connecting to the same database service
- sustained east-west traffic between known application and database tiers
- internal application traffic to `10.141.19.244:5432` from known internal sources
- internal application traffic to `10.141.158.148:5432` from known internal sources
- internal east-west traffic where `10.141.158.148:5432` acts as a shared PostgreSQL backend for multiple application hosts
- internal admin access to `10.141.10.250:443` from approved internal ranges or expected internal paths
- access from `ATOME-Production` source IPs to approved production services when it matches the approved port and expected access pattern
Classify as:
- `internal_db_access_pattern`
- `normal_east_west_app_db_traffic`
- `expected_internal_service_connectivity`

### 2. Exposed Service
Classify as `exposed_service` only when:
- external-to-private traffic targets management or data-store ports
AND
- traffic indicates a real session (packets > 10 or meaningful bytes)
AND
- NOT part of expected public service behavior
- or traffic targets a known internal-only asset in a way that conflicts with its role:
  - `10.141.1.64` receiving externally sourced traffic that conflicts with the documented role of `NON-CDK-GW3-LIVE` and shows real-session evidence
  - `10.141.19.244` receiving non-internal or non-DB access
  - `10.141.158.148` receiving non-internal or non-DB access
  - `10.141.10.250` receiving unauthorized external access when the service is intended for internal admin use

Prefer `reconnaissance` or no-alert instead of `exposed_service` when:
- the destination port is sensitive but packet and byte volume stay small
- accepted flows could still be explained by handshake-only probing or banner grabbing
- only a few accepted records are present and there is no corroborating host, auth, or application evidence
- the conclusion depends mainly on destination port without strong session-strength evidence

Do NOT alert if:
- service is intentionally public (API, web, payment endpoints)
- traffic matches normal baseline patterns
- source is authorized and behavior matches the approved service, environment, and port profile
- destination is `10.141.158.148:5432` and the observed traffic is internal application-to-database connectivity without external exposure evidence
- destination is `10.141.1.64` and the alert logic depends only on the outdated assumption that this host should accept outbound `443/TCP` only
- destination is `10.141.1.64:22`, the source is a known recurrent scanner such as `147.185.132.40`, and the observed evidence stays low-volume without host/auth corroboration
- destination is `10.141.1.64:23` or another management port, but packet and byte volume remain small enough that the evidence still fits scan or probe behavior rather than a real session

### 3. Lateral Movement
Classify as `lateral_movement` only when:
- internal source is unauthorized or outside expected role
AND at least one:
- one source touches many unrelated internal hosts
- one source scans many ports
- auth failures are observed
- host compromise indicators are present
- rapid spread from one source to multiple destinations
- clear deviation from baseline behavior

Do NOT classify as lateral movement based only on:
- multiple internal clients accessing a database
- sustained traffic volume
- access to a critical port

### 4. Baseline Rule
Baseline must consider:
- known application tiers
- expected client-to-service relationships
- typical number of clients per service
- normal traffic volume
- known inventory:
  - `10.141.1.64` -> documented gateway host role `NON-CDK-GW3-LIVE`, not NAT-only by default
  - `10.141.10.250` -> Admin Portal app role
  - `10.141.19.244` -> PostgreSQL role
  - `10.141.158.148` -> PostgreSQL role
  - authorized sources:
    - `13.228.154.28/32` -> `ATOME-Production`
    - `18.138.71.183/32` -> `ATOME-Production`
    - `18.141.241.219/32` -> `ATOME-Production`
    - `165.173.9.115/32` -> `ATOME-Production`
    - `52.74.202.90/32` -> `ATOME-Staging`


## Hard Corrections

- Do not classify normal internal app-to-DB traffic as `lateral_movement` without clear deviation or unauthorized behavior.
- Do not classify internal traffic to `10.141.158.148:5432` as `unknown host`, `exposed_service`, or `lateral_movement` when it matches expected PostgreSQL client behavior.
- Do not classify traffic to `10.141.1.64` as `exposed_service` based only on a NAT-gateway assumption. Require confirmed role mismatch or unauthorized exposure evidence.
- Do not classify accepted VPC traffic as `exposed_service` based only on sensitive destination port and a few accepted records; require meaningful packet or byte volume, or corroborating host/auth evidence.
- Do not auto-alert on ports `22`, `6379`, `3306`, `5432`, `27017`, or `9200`.
- Do not auto-alert on port `23` when the evidence is limited to small packet and byte volume consistent with probing.
- Do not auto-alert on blocked WAF traffic unless both baseline anomaly and absolute floor conditions are met.
- Consider WAF rule changes, signature updates, tuning changes, and logging changes before escalating blocked-volume spikes.
- Do not treat an authorized IP as a blanket bypass. If an authorized source hits the wrong asset, wrong environment, wrong port, or shows anomalous rate, evaluate it normally.
- Treat recurrent low-volume SSH probes from `147.185.132.40` to `10.141.1.64` as `reconnaissance` or no-alert noise unless packet count, byte count, spread, or corroborating telemetry shows real-session behavior.
