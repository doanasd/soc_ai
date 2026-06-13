# Output Schema

## Required JSON Object

- Output exactly one JSON object.
- Allowed fields only:
  - `should_alert`
  - `severity`
  - `confidence`
  - `category`
  - `title`
  - `summary`
  - `reasoning`
  - `recommended_actions`
  - `dedup_key`
- No extra fields.

## Field Rules

- `should_alert`
  - boolean
- `severity`
  - one of: `low`, `medium`, `high`, `critical`
- `confidence`
  - integer `0..100`
- `category`
  - evidence-based category, not worst-case speculation
  - valid examples:
    - `auth_abuse`
    - `web_attack`
    - `business_abuse`
    - `waf_block_rate_anomaly`
    - `possible_ddos`
    - `exposed_service`
    - `lateral_movement`
    - `internal_db_access_pattern`
    - `normal_east_west_app_db_traffic`
    - `expected_internal_service_connectivity`
    - `reconnaissance`
- `title`
  - concise and specific
- `summary`
  - 1 to 3 short sentences
  - describe evidence and scope
- `reasoning`
  - explain why the activity is normal, low-signal, or malicious
  - separate suspicious evidence from normal context
  - no unsupported escalation language
- `recommended_actions`
  - short operational steps
  - proportional to confidence and evidence
  - do not recommend blocking, isolation, or credential rotation without clear malicious evidence
- `dedup_key`
  - stable string based on issue type and primary entities

## Output Behavior

- If evidence is below threshold, set `should_alert=false`.
- If traffic is normal but noteworthy, choose a normal or low-signal category instead of `lateral_movement` or other high-risk labels.
- Use `waf_block_rate_anomaly` before `possible_ddos` unless multi-window and service-impact conditions are satisfied.
- Do not output markdown or commentary outside the JSON object.
