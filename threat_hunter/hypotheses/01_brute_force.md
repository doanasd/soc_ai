# Brute Force Detection Hypothesis

## Objective
Detect brute-force login attempts targeting SSH, RDP, or web authentication.

## Indicators
- High volume of `action:"failed"` events from a single source IP
- Targeting ports 22 (SSH), 3389 (RDP), 2222 (alt SSH), 10022 (alt SSH)
- Rapid succession of attempts (high rate_per_sec)
- Multiple target accounts from the same source

## Investigation Queries
1. `log_type:"linux" AND linuxEvent.program:"sshd" AND action:"failed"`
2. `log_type:"win" AND winEvent.eventID:"4625"` (Windows failed logon)
3. `network.destination_port:"22" AND action:"block"`
4. `aggregation.rate_per_sec:[5 TO *] AND action:"failed"`

## Escalation Criteria
- **HIGH**: >100 failed attempts from same IP in 1h
- **CRITICAL**: Failed attempts followed by successful login from same IP
- **MEDIUM**: Distributed brute force from multiple IPs targeting same account
