# Environment

## Platform

- Production workloads run on AWS.
- Internet-facing web traffic is fronted by AWS WAF through ALB or API Gateway.
- East-west and ingress/egress network telemetry comes from AWS VPC Flow Logs at ENI level.
- Backend application and database workloads run on Linux systems in private subnets.
- Continuous visibility is expected from both AWS WAF logs and AWS VPC Flow Logs.
- Missing WAF or VPC telemetry for a full monitoring interval is an operationally significant blind spot.

## Known Production Assets

- `10.141.1.64`
  - role: gateway host
  - service: `NON-CDK-GW3-LIVE`
  - environment: production
  - expected traffic: gateway and service connectivity based on documented host ownership
  - expected port/protocol: not limited to `443/TCP` unless separately confirmed
  - expected direction: evaluate by documented service role, not by NAT-only assumption
- `10.141.10.250`
  - role: application server
  - service: Admin Portal
  - stack: NodeJS
  - environment: production
  - expected traffic: internal admin access
  - expected port/protocol: `443/TCP`
  - expected direction: inbound from approved internal paths and internal east-west traffic
- `10.141.19.244`
  - role: database server
  - service: PostgreSQL
  - stack: PostgreSQL
  - environment: production
  - expected traffic: database traffic only
  - expected port/protocol: `5432/TCP`
  - expected direction: internal
- `10.141.158.148`
  - role: database server
  - service: PostgreSQL
  - stack: PostgreSQL
  - environment: production
  - expected traffic: database traffic only
  - expected port/protocol: `5432/TCP`
  - expected direction: internal
  - architecture note: valid internal PostgreSQL asset for application-to-database connectivity

## Authorized Source IPs

- `13.228.154.28/32`
  - label: `ATOME-Production`
  - trust note: authorized source when traffic matches approved production role
- `18.138.71.183/32`
  - label: `ATOME-Production`
  - trust note: authorized source when traffic matches approved production role
- `18.141.241.219/32`
  - label: `ATOME-Production`
  - trust note: authorized source when traffic matches approved production role
- `165.173.9.115/32`
  - label: `ATOME-Production`
  - trust note: authorized source when traffic matches approved production role
- `52.74.202.90/32`
  - label: `ATOME-Staging`
  - trust note: authorized staging source, but production access still requires expected path and service alignment

## Normal Baseline

- Public endpoints such as `/login`, `/payment`, and `/api/*` receive normal internet traffic and normal `allow` decisions.
- Blocked WAF traffic is expected on internet-facing services.
- Internet scans, one-off probes, and random IP noise are routine baseline.
- Internal application-to-database and service-to-service traffic is common.
- Multiple internal application hosts connecting to one internal PostgreSQL, MySQL, Redis, MongoDB, or Elasticsearch service can be normal.
- Internal access to `10.141.10.250:443` can be normal when it matches the Admin Portal access path.
- Internal access to `10.141.19.244:5432` can be normal when it matches application-to-database behavior.
- Internal access to `10.141.158.148:5432` can be normal when it matches application-to-database behavior.
- Multiple internal application hosts connecting to `10.141.158.148:5432` within the same window can be normal shared-database behavior.
- `10.141.1.64` is a documented gateway host, not an unknown private IP. Do not assume it is a managed NAT gateway or outbound-only asset unless separately confirmed.
- Inbound traffic to `10.141.1.64` is not automatically suspicious solely because the destination port is not `443/TCP`; judge it against the host's actual service ownership, exposure intent, repetition, and session evidence.
- Traffic from authorized ATOME source IPs can be normal when it targets the correct service, environment, and port.
- Authorized source status reduces suspicion only for expected access. It does not override anomalous rate, anomalous destination, or off-role behavior.

## Traffic Assumptions

- `ACCEPT` in VPC Flow Logs means the network path allowed the flow. It does not prove TCP session success, authentication success, or exploit success.
- A single packet or trivial byte count is usually scan noise, not a real session.
- For VPC triage, `packets` and `bytes` are primary evidence of whether traffic was only a probe or a likely real session.
- Small packet and byte volume, even to sensitive ports such as `22` or `23`, usually indicates probing, banner grabbing, or handshake-only scan activity rather than meaningful access.
- Larger packet and byte volume materially above handshake-only traffic increases confidence that a real interactive or application session may have occurred.
- If packet or byte evidence is missing from the current batch summary, do not assume a real session from accepted flow records alone; stay conservative unless repetition or corroborating telemetry exists.
- Sensitive ports increase review priority, not alert certainty.
- Critical destination alone does not make traffic malicious.
- Traffic to known assets must be judged against their expected role:
  - `10.141.1.64`: documented gateway host behavior for `NON-CDK-GW3-LIVE`; do not assume outbound-only NAT behavior
  - `10.141.10.250`: internal/admin `443/TCP`
  - `10.141.19.244`: internal PostgreSQL `5432/TCP`
  - `10.141.158.148`: internal PostgreSQL `5432/TCP` shared backend behavior
- Traffic from known authorized sources must also be judged against environment fit:
  - production-authorized sources are more trusted for production-aligned access
  - staging-authorized sources are not automatically normal on production assets

## Triage Mode

- Evaluate activity by evidence in the batch window.
- Prefer false-negative tolerance for isolated internet noise over noisy false positives.
- Require threshold, repetition, deviation from baseline, or corroborating signals before escalation.
- Treat missing required telemetry as an operational alert even when no malicious event is visible.
