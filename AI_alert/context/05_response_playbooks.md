# Response Playbooks

## Known Malicious IP (confidence_score >= 75)
1. Block source IP at WAF/security group if traffic is ongoing.
2. Review all events from this IP in last 24h across all log types.
3. Check for successful authentication or accepted sessions.
4. If `is_tor=true`: escalate to senior analyst immediately.
5. If `SSH_Brute_Force`: audit SSH access logs on targeted hosts.
6. If `Web_App_Attack`: review WAF logs for any allowed requests.

## WAF Auth Abuse
- Confirm auth-path concentration and request volume.
- Apply WAF rate/IP controls only when abuse is confirmed.

## WAF Block Volume Anomaly
- Verify >=3x baseline AND above absolute floor.
- Rule out false positives: rule changes, tuning, managed rule updates.

## VPC External Exposure
- Check `packets` and `bytes` first — small volume = scan, not session.
- Review security groups, NACLs, route exposure.
- Block only when exposure is unauthorized or clearly abusive.

## Lateral Movement
- Confirm source ownership. Check broad host/port touch, auth failures, spread.
- Escalate only with confirmed unauthorized internal movement.

## Telemetry Gap
- Confirm which log type is missing (vpc/waf/both).
- Check pipeline health: AWS delivery → collector → file creation → forwarding.
- Escalate if gap persists into next interval.

## CloudTrail High-Risk Actions
- CreateUser/AttachUserPolicy/CreateAccessKey: verify if authorized change, check who initiated.
- Root login: verify MFA status, review session activity.
- StopLogging/DeleteTrail: treat as potential incident, escalate immediately.
- Repeated AccessDenied: check if reconnaissance or misconfigured permission.
