# Detection Policy

## Global Rules
- Alert only on correlated, anomalous, or unauthorized behavior. Use full-window evidence.
- `ACCEPT` in VPC Flow Logs does not prove successful connection or authentication.
- For VPC: use `packets` and `bytes` as session-strength indicators. `packets<=1` = scan/probe, not a session.
- Destination port matters more than source port.
- Critical asset context increases review priority but never creates an alert by itself.
- Required telemetry: AWS VPC Flow Logs + AWS WAF logs. Absence = `telemetry_gap` alert.

## Asset Inventory
| IP | Role | Port |
|---|---|---|
| 10.141.1.64 | Production gateway NON-CDK-GW3-LIVE | varies |
| 10.141.10.250 | Admin Portal app server | 443/TCP |
| 10.141.19.244 | Production PostgreSQL | 5432/TCP |
| 10.141.158.148 | Production PostgreSQL | 5432/TCP |

## Authorized Sources
| CIDR | Environment |
|---|---|
| 13.228.154.28/32, 18.138.71.183/32, 18.141.241.219/32, 165.173.9.115/32 | ATOME-Production |
| 52.74.202.90/32 | ATOME-Staging |
Authorized source lowers suspicion only when destination, port, direction, and environment all match expected use.

## Ignore (no-alert)
- Single WAF allow/block with no volume anomaly or attack indicators.
- VPC flows with `packets<=1` or small bytes consistent with scan/probe/handshake.
- Internal-to-internal DB/cache traffic matching app-to-DB patterns (10.141.19.244:5432, 10.141.158.148:5432).
- Internal access to Admin Portal 10.141.10.250:443 from expected internal ranges.
- Traffic from authorized ATOME IPs to approved services on expected ports with normal volume.
- Recurrent low-volume SSH probes from 147.185.132.40 to 10.141.1.64 without session evidence.
- Multiple internal clients to same PostgreSQL backend = normal shared usage.

## Low Signal (low severity only)
- Repeated blocked WAF at normal baseline. Small VPC probes to sensitive ports (packets<=10).
- A few accepted TCP flows to port 22/23 with small packet/byte volume.
- Single accepted flow to sensitive port with no repetition or session evidence.

## WAF Alert Conditions
- `auth_abuse`: repeated login attempts beyond normal rate, concentrated against same account/auth path.
- `web_attack`: repeated exploit payloads, especially if allowed or mixed allow/block.
- `business_abuse`: abnormal automation against payment/checkout/admin workflows.
- `waf_block_rate_anomaly`: blocked volume >=3x baseline AND above meaningful absolute floor.
- `possible_ddos`: block anomaly persists across multiple windows WITH broad source IPs or endpoint targeting.

## WAF Severity
- Single blocked anomaly in 1 window → `low` or no-alert.
- Recurring across 2-5 windows in last hour → `medium`.
- Persists ~30min or most of last hour → `high`.
- `critical` only for confirmed service degradation or failing controls.

## VPC Alert Conditions
- `exposed_service`: external-to-private to management/data-store port AND packets>10 AND not authorized/public.
- `lateral_movement`: internal unauthorized source touching many hosts/ports, auth failures, or compromise indicators. NOT just multiple clients to same DB.
- `reconnaissance`: external low-volume probing to sensitive ports without session evidence.

## Hard Corrections
- Do NOT classify internal app-to-DB traffic as `lateral_movement` without clear deviation.
- Do NOT classify traffic to 10.141.158.148:5432 as unknown host or exposed_service when it matches PostgreSQL client behavior.
- Do NOT classify traffic to 10.141.1.64 as `exposed_service` based only on NAT-gateway assumption.
- Do NOT auto-alert on ports 22, 23, 6379, 3306, 5432, 27017, 9200 without session evidence.
- Do NOT treat blocked WAF traffic as alert unless both baseline anomaly AND absolute floor conditions are met.

## Threat Intelligence Rules
- `confidence_score >= 75`: confirmed malicious actor. Upgrade severity 1 level. NOT background noise regardless of packet count.
- `confidence_score >= 90`: minimum `medium`. Combined with SSH failure/WAF block/sensitive port → minimum `high`.
- `is_tor = true`: deliberate anonymized attack. Upgrade severity 1 additional level.
- `categories` includes `SSH_Brute_Force` + `ssh_login_failed` → `brute_force`, minimum `medium`.
- `categories` includes `Web_App_Attack` + WAF block → `web_attack`, minimum `medium`.
- `categories` includes `Port_Scan` + multiple VPC ports → `reconnaissance`, minimum `medium`.
- `critical` still requires confirmed service impact or successful unauthorized access even with threat intel.

## CloudTrail Alert Conditions
- Ignore: AWS service calls (invokedBy set, sourceIPAddress is *.amazonaws.com), Config/Health/Support read-only calls.
- Alert: Human IAM actions with AccessDenied repeated (>=3 in window) from same user/IP.
- Alert: High-risk write actions (CreateUser, AttachUserPolicy, CreateAccessKey, DeleteTrail, StopLogging).
- Alert: Root ConsoleLogin especially with MFAUsed=No.
- Alert: ResourceNotFoundException from human principals on sensitive resources.
- `isAwsService=true` → baseline, not alert-worthy unless combined with anomaly.
