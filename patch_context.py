#!/usr/bin/env python3
"""
Patch context SOC files: thêm CloudTrail, Cisco IOS, Linux journald/systemd
Chạy trên EC2: python3 patch_context.py
"""

import os

CONTEXT_DIR = "/home/ubuntu/soc_ai/AI_alert/context"

# ── 01_environment.md: thêm CloudTrail + Cisco assets ────────────────────
ENV_APPEND = """
## Additional Log Sources

### AWS CloudTrail
- Captures all AWS API calls across all services and regions.
- Source accounts: `041550429462` (production), `130759357100` (staging/ops), `051648402040` (management)
- Key services monitored: IAM, EC2, S3, Config, ACM, access-analyzer
- AWS internal service calls (invokedBy: config.amazonaws.com etc.) are expected baseline.
- Human console logins come from SSO sessions via `AWSReservedSSO_*` roles.
- `errorCode: AccessDenied` from service accounts is often expected (Config probing).
- `errorCode: AccessDenied` from human users (SSO sessions) may indicate privilege issues.

### Cisco IOS Switches
- Devices: `10.6.88.250`, `10.6.88.252` (internal network switches)
- Log format: `%FACILITY-SEV-MNEMONIC: description`
- Expected baseline: interface UPDOWN events during maintenance windows or device restarts.
- `GigabitEthernet0/24` flapping (up→down→up within seconds) indicates link instability.
- `GigabitEthernet0/43` state changes are expected during normal operations.

### Linux journald / systemd (extended)
- Additional hosts: `evvolabs-prod` (production), `server4` (utility server)
- Expected processes: CRON, sshd, snapd, fwupd, fwupdmgr, systemd, systemd-logind
- OpenVPN failures on `server4`: recurring `Failed to query password` is a known config issue.
- `apt-helper` / `systemd-networkd-wait-online` timeout on `server4` is expected.
- `smartd` SMART attribute changes on `server4` are routine health monitoring.
- `opensearch-dashboards` index creation messages are expected Wazuh/SIEM operational logs.
- `python[...]` logs showing Groq API calls are from the SOC AI pipeline itself.
"""

# ── 02_detection_policy.md: thêm CloudTrail + Cisco policies ────────────
POLICY_APPEND = """
## CloudTrail Detection Policy

### Ignore (Expected Baseline)
- ReadOnly API calls (`readOnly: true`) from AWS service principals (Config, CloudTrail).
- `ListAnalyzers`, `ListCertificateAuthorities`, `DescribeCertificate` from Config service role.
- `GetAccountInformation` from SSO sessions to console.
- `ResourceNotFoundException` errors from Config scanning for optional contacts.
- Any call with `invokedBy: config.amazonaws.com` or `cloudtrail.amazonaws.com`.

### Alert Conditions

**`cloudtrail_privilege_escalation`** — HIGH/CRITICAL
- `CreateUser`, `AttachUserPolicy`, `PutUserPolicy`, `DetachUserPolicy` from non-admin
- `CreateAccessKey` for existing high-privilege users
- `CreateRole` + `AttachRolePolicy` in rapid succession

**`cloudtrail_access_denied_anomaly`** — MEDIUM
- Multiple `AccessDenied` errors from the same human SSO identity within 5 minutes
- `AccessDenied` on sensitive actions (IAM, S3 bucket policy, EC2 security groups)
- `AccessDenied` from IP not matching known VPN/office ranges

**`cloudtrail_infrastructure_change`** — MEDIUM/HIGH
- Security group rule changes (`AuthorizeSecurityGroupIngress`)
- S3 bucket policy changes (`PutBucketPolicy`, `DeleteBucketPolicy`)
- EC2 instance launch/termination outside business hours

**`cloudtrail_console_login`** — LOW/MEDIUM
- Console logins from unknown IPs → LOW
- Console login failure → MEDIUM if repeated

### Hard Rules CloudTrail
- Do NOT alert on AWS service-to-service API calls (Config, CloudTrail internal).
- Do NOT alert on `readOnly: true` calls from known service roles.
- `AccessDenied` on `GetAlternateContact` from Config is normal — it's probing for optional config.

## Cisco IOS Detection Policy

### Ignore (Expected Baseline)
- Single interface UPDOWN event without rapid flapping.
- Scheduled maintenance interface changes.
- `LINEPROTO-5-UPDOWN` + `LINK-3-UPDOWN` in immediate succession (normal link up sequence).

### Alert Conditions

**`cisco_link_flapping`** — MEDIUM
- Same interface cycling up→down→up within 60 seconds (indicates physical issue or attack).
- Multiple interfaces going down simultaneously (possible switch failure or network attack).

**`cisco_auth_failure`** — HIGH
- Failed SSH/console login attempts to network device.

### Hard Rules Cisco
- Do NOT alert on single interface state change (expected during normal ops).
- Interface `GigabitEthernet0/24` rapid flap (within 30s) is suspicious — may indicate STP issue or cable problem.

## Linux journald / systemd Detection Policy

### Ignore (Expected Baseline)
- CRON job execution for root (sysstat, dpkg-db-backup, logrotate).
- `fwupd`/`fwupdmgr` metadata refresh.
- `snapd` profile reload.
- `fstrim` disk trim operations.
- `smartd` SMART attribute monitoring (unless pre-failure severity).
- `systemd-networkd-wait-online` timeout on `server4` — known config issue.
- `openvpn`/`ovpn-client` password failures on `server4` — known config issue.
- `opensearch-dashboards` index creation — expected Wazuh/SIEM operations.
- `python[...]` Groq API calls — SOC AI pipeline internal logs.

### Alert Conditions

**`linux_new_root_session`** — MEDIUM
- `systemd-logind` new session for root outside maintenance window.
- `systemd-logind` new session from unexpected IP.

**`linux_service_failure`** — LOW/MEDIUM
- Critical system service crash (not expected noise services like openvpn on server4).

**`linux_package_install`** — LOW
- `apt`/`dpkg` package installation during off-hours.
"""

# ── 04_known_benign_patterns.md: thêm patterns mới ───────────────────────
BENIGN_APPEND = """
## AWS CloudTrail Benign Patterns

- Any `readOnly: true` API call from `invokedBy: config.amazonaws.com` — routine Config compliance scanning.
- `ListAnalyzers` from `AWSServiceRoleForConfig` — routine.
- `GetAccountInformation` from SSO sessions — console access tracking, expected.
- `ListCertificateAuthorities` + `DescribeCertificate` from Config — ACM scanning.
- `GetAlternateContact` returning `ResourceNotFoundException` — Config probing optional fields.
- `AccessDenied` on `GetAlternateContact` from Config service role — expected (contact not configured).
- Repeated identical CloudTrail API calls from same service role within same minute — Config polling.

## Cisco IOS Benign Patterns

- `%LINK-3-UPDOWN` followed immediately by `%LINEPROTO-5-UPDOWN` for same interface — normal link up.
- Single interface state change (`up` or `down`) without flapping.
- Interface `GigabitEthernet0/43` state change on `10.6.88.250` — expected.

## Linux journald / systemd Benign Patterns

- `50-motd-news` executing on login — normal MOTD update.
- CRON executing `debian-sa1` — sysstat data collection, runs every 5 minutes.
- `dbus-daemon` activating `org.freedesktop.fwupd` — firmware update check.
- `snapd` reloading `snap-confine` profiles — snap daemon maintenance.
- `kernel` AppArmor profile replace with "same as current profile, skipping" — normal snapd update.
- `loop0` capacity change (0 to 8) — snap package mount, expected.
- `smartd` SMART Usage Attribute changes — normal disk health tracking.
- `systemd-resolved` switching between UDP/TCP for DNS — normal DNS fallback behavior.
- `opensearch-dashboards` creating Wazuh statistics/monitoring indexes — expected weekly.
- `python[...]` logging Groq API 401 errors — SOC pipeline API key rotation events.
- `python3[...]` S3 bucket polling for new WAF/VPC flow log files — log ingestion pipeline.
"""

# ── 03_asset_criticality.md: thêm CloudTrail + Cisco assets ─────────────
CRITICALITY_APPEND = """
## AWS CloudTrail Asset Criticality

- Account `041550429462`: Production AWS account — HIGH criticality for any write actions.
- Account `130759357100`: Operations/staging account — MEDIUM criticality.
- Account `051648402040`: Management/control tower account — CRITICAL for IAM changes.
- IAM actions (user/role/policy create/delete/modify) in any account → CRITICAL review priority.
- S3 bucket policy changes → HIGH review priority.
- Security group changes → HIGH review priority.
- Console logins from unknown IPs → MEDIUM review priority.

## Cisco Network Device Criticality

- `10.6.88.250`, `10.6.88.252`: Core network switches — CRITICAL infrastructure.
- Interface flapping on these devices affects network availability for all connected hosts.
- Any authenticated access (SSH/console) to these devices → HIGH review priority.
"""

# ── 06_output_schema.md: thêm CloudTrail + Cisco categories ─────────────
SCHEMA_APPEND = """
## Additional Log Type Categories

### CloudTrail Categories
- `cloudtrail_privilege_escalation` — IAM user/role/policy changes
- `cloudtrail_access_denied_anomaly` — repeated AccessDenied from human identity
- `cloudtrail_infrastructure_change` — SG rules, S3 policy, EC2 changes
- `cloudtrail_console_login` — human console login events
- `cloudtrail_readonly_baseline` — expected service-to-service API calls (no alert)

### Cisco IOS Categories
- `cisco_link_flapping` — interface cycling up/down rapidly
- `cisco_auth_failure` — failed device login
- `cisco_link_state_change` — single interface state change (usually no alert)

### Linux journald / systemd Categories
- `linux_new_root_session` — unexpected root login via systemd-logind
- `linux_service_failure` — critical service crash
- `linux_cron_anomaly` — unexpected cron execution
"""


def append_to_file(filepath: str, content: str, marker: str = None):
    """Append content to file if not already present."""
    if not os.path.exists(filepath):
        print(f"⚠️  File not found: {filepath}")
        return

    with open(filepath) as f:
        existing = f.read()

    # Check nếu đã append rồi (dùng dòng đầu tiên của content làm marker)
    check = content.strip().split("\n")[1].strip()
    if check in existing:
        print(f"⏭️  Already applied: {os.path.basename(filepath)}")
        return

    with open(filepath, "a") as f:
        f.write("\n" + content)
    print(f"✅ Updated: {os.path.basename(filepath)}")


def apply_patches():
    patches = [
        ("01_environment.md",       ENV_APPEND),
        ("02_detection_policy.md",  POLICY_APPEND),
        ("03_asset_criticality.md", CRITICALITY_APPEND),
        ("04_known_benign_patterns.md", BENIGN_APPEND),
        ("06_output_schema.md",     SCHEMA_APPEND),
    ]

    for filename, content in patches:
        filepath = os.path.join(CONTEXT_DIR, filename)
        append_to_file(filepath, content)

    print("\n✅ All context patches applied")
    print("Note: Context files are auto-reloaded by AI Alert on next batch")


if __name__ == "__main__":
    apply_patches()
