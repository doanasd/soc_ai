# Web Application Attack Hypothesis

## Objective
Detect web application attacks including SQL injection, XSS, path traversal, and API abuse.

## Indicators
- WAF rules triggered repeatedly from same source
- Suspicious URI patterns (SQLi, XSS, path traversal)
- High volume of blocked requests targeting same endpoint
- Unusual HTTP methods (PUT, DELETE, PATCH on public endpoints)

## Investigation Queries
1. `log_type:"waf" AND action:"block" AND waf.uri:("select" OR "union" OR "drop")`
2. `log_type:"waf" AND action:"block" AND waf.uri:("../" OR "/etc/passwd" OR "%00")`
3. `log_type:"waf" AND action:"allow" AND aggregation.rate_per_sec:[10 TO *]`
4. `log_type:"waf" AND network.method:("PUT" OR "DELETE" OR "PATCH")`

## Escalation Criteria
- **CRITICAL**: Successful SQLi/RCE (block bypassed)
- **HIGH**: Persistent attack from single IP across multiple URIs
- **MEDIUM**: Automated scanner hitting WAF rules
- **LOW**: Single blocked request with common attack pattern
