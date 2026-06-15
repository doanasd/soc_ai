# Response Playbooks

## WAF Auth Abuse

- Confirm auth-path concentration and request volume.
- Check application auth logs for failure bursts or account targeting.
- Apply WAF rate or IP controls only when abuse is confirmed.

## WAF Block Volume Anomaly

- Compare blocked volume to the normal baseline for the same service.
- Confirm both:
  - `>= 3x` baseline
  - above a meaningful absolute floor
- Check false-positive explanations first:
  - rule changes
  - tuning changes
  - managed rule updates
  - parsing or logging changes
- Use proportional action until service impact is confirmed.

## Telemetry Gap

- Treat missing AWS VPC Flow Logs or AWS WAF logs for a full reporting interval as a monitoring alert.
- Confirm which required log type is missing:
  - `vpc`
  - `waf`
  - or both
- Check pipeline health in order:
  - upstream AWS log delivery
  - collector or agent process health
  - file creation and file rotation
  - forwarding and local disk availability
- Escalate as telemetry outage if the gap persists into the next interval.

## Internal DB Traffic Review

- Map source IPs to application tiers or known service owners.
- Confirm whether the destination DB or cache host is an expected shared backend.
- Treat `10.141.19.244:5432` as a known production PostgreSQL asset and validate whether sources belong to expected app or admin tiers.
- Treat `10.141.158.148:5432` as a known production PostgreSQL asset and validate whether sources belong to expected app or admin tiers.
- If the destination is `10.141.158.148:5432`, start from the assumption that it is a documented internal PostgreSQL host, not an unknown service.
- Treat only the confirmed inventory as expected:
  - `10.141.1.64` -> documented gateway host `NON-CDK-GW3-LIVE`; do not assume NAT-only `443/TCP`
  - `10.141.10.250` -> Admin Portal on `443/TCP`
  - `10.141.19.244` -> PostgreSQL on `5432/TCP`
  - `10.141.158.148` -> PostgreSQL on `5432/TCP`
- Use authorized source context during validation:
  - `13.228.154.28/32`, `18.138.71.183/32`, `18.141.241.219/32`, `165.173.9.115/32` -> `ATOME-Production`
  - `52.74.202.90/32` -> `ATOME-Staging`
- Compare the pattern to expected east-west architecture before escalating.
- Do not recommend isolation, blocking, or credential rotation unless malicious evidence exists.

## VPC External Exposure

- Verify whether the destination host and destination port are intended to be internet reachable.
- Check `packets` and `bytes` first to decide whether the flow looks like a real session or only low-volume probing.
- If packet and byte volume stay small, treat the activity as scan or reconnaissance unless host, auth, or service logs show stronger evidence.
- Review security groups, NACLs, and route exposure.
- Pull host and service logs to determine whether a real session occurred.
- Use known inventory during triage:
  - `10.141.1.64` is a documented gateway host `NON-CDK-GW3-LIVE`; verify actual listening services and intended exposure before calling it an exposed service
  - `10.141.10.250` should support internal/admin `443/TCP`
  - `10.141.19.244` should support internal PostgreSQL `5432/TCP`
  - `10.141.158.148` should support internal PostgreSQL `5432/TCP`
- For `10.141.1.64`, require confirmation of unauthorized service exposure before recommending blocking based only on destination port.
- For accepted Telnet or SSH traffic to `10.141.1.64`, do not recommend blocking or containment based only on a few low-volume flows; confirm session strength and host evidence first.
- Validate whether the source is one of the approved authorized IPs before escalating:
  - `13.228.154.28/32`
  - `18.138.71.183/32`
  - `18.141.241.219/32`
  - `165.173.9.115/32`
  - `52.74.202.90/32`
- Block or contain only when the exposure is unauthorized or clearly abusive.

## Lateral Movement

- Confirm source ownership and subnet legitimacy.
- Check for broad host touch, broad port touch, auth failures, compromise indicators, or rapid spread.
- Escalate only when evidence supports unauthorized internal movement.
## Known Malicious IP Response

- When `malicious_src.confidence_score >= 75`:
  1. Block source IP at WAF or security group immediately if traffic is ongoing.
  2. Review all events from this IP in the last 24 hours across all log types.
  3. Check for any successful authentication or accepted sessions from this IP.
  4. If `is_tor = true`: assume deliberate attack, escalate to senior analyst.
  5. If `categories` includes `SSH_Brute_Force`: audit all SSH access logs on targeted hosts.
  6. If `categories` includes `Web_App_Attack`: review WAF logs for any allowed requests from this IP.
  7. Document IP, score, categories, and timeline in incident record.

## Tor Exit Node Response

- Treat any accepted connection from a Tor exit node as high priority.
- Verify no successful authentication occurred.
- Check for data exfiltration indicators: large outbound bytes, unusual destinations.
- Consider blocking entire Tor exit node list at perimeter if volume is sustained.
