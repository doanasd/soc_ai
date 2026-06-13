# Port Scanning & Reconnaissance Hypothesis

## Objective
Detect network reconnaissance activities including port scanning and service enumeration.

## Indicators
- Single source IP connecting to many destination ports
- Single source IP connecting to many destination IPs
- VPC flow logs showing short-lived connections to multiple ports
- Low packet/byte counts per connection (SYN scans)

## Investigation Queries
1. `log_type:"vpc" AND network.source_ip:"<suspect_ip>"`
2. `log_type:"vpc" AND flow.packets:[1 TO 3]` (SYN scan indicator)
3. `action:"block" AND network.destination_port:[1 TO 1024]`
4. `log_type:"waf" AND waf.uri:("/.env" OR "/wp-admin" OR "/actuator" OR "/.git")`

## Escalation Criteria
- **HIGH**: Scanning from internal IP (potential compromised host)
- **MEDIUM**: External IP scanning multiple sensitive ports
- **LOW**: Single port check from known scanner IP
