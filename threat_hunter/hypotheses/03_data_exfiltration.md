# Data Exfiltration Hypothesis

## Objective
Detect potential data exfiltration through unusual outbound traffic patterns.

## Indicators
- Unusually high outbound byte counts from internal IPs
- Traffic to rare/unusual destination IPs
- Large data transfers during off-hours
- DNS tunneling indicators (high volume of DNS queries)

## Investigation Queries
1. `log_type:"vpc" AND action:"allow" AND flow.bytes:[1000000 TO *]`
2. `log_type:"vpc" AND network.source_ip:"10.0.0.0/8" AND action:"allow"`
3. `log_type:"vpc" AND network.destination_port:("53" OR "443" OR "8443")`

## Escalation Criteria
- **CRITICAL**: Large data transfer to known-bad IP
- **HIGH**: Unusual volume from server that normally doesn't generate outbound traffic
- **MEDIUM**: Off-hours data transfer from workstation
