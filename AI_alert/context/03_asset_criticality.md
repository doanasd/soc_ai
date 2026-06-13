# Asset Criticality

## Rule

- Criticality increases review priority.
- Criticality alone must never create an alert.
- A critical asset with normal behavior remains normal.

## Web and API Assets

- Authentication paths:
  - `/login`
  - `/oauth`
  - token and SSO endpoints
- Financial paths:
  - `/payment`
  - checkout APIs
  - transaction APIs
- Administrative paths:
  - `/admin`
  - privileged management APIs

## Network Assets

- Management access:
  - `22`
  - `2222`
  - `10022`
- Data-store access:
  - `3306`
  - `5432`
  - `6379`
  - `27017`
  - `9200`
- Private services that are not intended for direct internet exposure.

## Known Asset Inventory

- `10.141.1.64`
  - production gateway host
  - service: `NON-CDK-GW3-LIVE`
  - expected use: gateway or shared service behavior based on actual host ownership
  - expected port: not limited to `443/TCP` unless separately validated
  - criticality note: unusual inbound traffic raises review priority, but alerting still requires confirmed role mismatch, exposure evidence, or corroborating signals
- `10.141.10.250`
  - production application server
  - service: Admin Portal
  - expected port: `443/TCP`
  - expected direction: internal/admin access
  - criticality note: unauthorized external exposure matters; expected internal admin use does not
- `10.141.19.244`
  - production PostgreSQL database
  - expected port: `5432/TCP`
  - expected direction: internal only
  - criticality note: app-to-DB connectivity can be normal even from multiple internal clients
- `10.141.158.148`
  - production PostgreSQL database
  - expected port: `5432/TCP`
  - expected direction: internal only
  - criticality note: app-to-DB connectivity can be normal even from multiple internal clients
  - inventory note: valid known database asset, not an unknown host

## Authorized Sources

- `13.228.154.28/32`
  - `ATOME-Production`
  - trusted for production-aligned access only
- `18.138.71.183/32`
  - `ATOME-Production`
  - trusted for production-aligned access only
- `18.141.241.219/32`
  - `ATOME-Production`
  - trusted for production-aligned access only
- `165.173.9.115/32`
  - `ATOME-Production`
  - trusted for production-aligned access only
- `52.74.202.90/32`
  - `ATOME-Staging`
  - not automatically normal on production assets

## Internal DB Clarification

- Internal access to PostgreSQL, MySQL, Redis, MongoDB, or Elasticsearch is not automatically suspicious.
- Multiple internal sources talking to one database host can be normal application architecture.
- Sustained or high-count DB sessions are not proof of compromise without baseline deviation or corroborating evidence.
