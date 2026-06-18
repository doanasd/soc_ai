#!/usr/bin/env python3
"""
Patch script: thêm CloudTrail và Cisco IOS normalizer vào normalize-service.py
Chạy trên EC2: python3 patch_normalize.py
"""
import re
 
PATH = "/home/ubuntu/soc_ai/normalize-service.py"
 
# ── 1. Thêm location prefixes mới ─────────────────────────────────────────
OLD_PREFIXES = '''WAF_LOCATION_PREFIX      = "/tmp/aws-waf/waf/"
VPC_LOCATION_PREFIX      = "/tmp/aws-waf/vpc/"
FORTINET_LOCATION_PREFIX = "/tmp/fortinet/"'''
 
NEW_PREFIXES = '''WAF_LOCATION_PREFIX        = "/tmp/aws-waf/waf/"
VPC_LOCATION_PREFIX        = "/tmp/aws-waf/vpc/"
FORTINET_LOCATION_PREFIX   = "/tmp/fortinet/"
CISCO_LOCATION_PREFIX      = "/tmp/cisco/"'''
 
# ── 2. Thêm 2 normalizer functions trước hàm _is_linux_event ──────────────
INSERT_BEFORE = "def _is_linux_event(archive_evt: dict) -> bool:"
 
NEW_NORMALIZERS = '''
# ── AWS CloudTrail ────────────────────────────────────────────────────────────
# Format: Wazuh wraps CloudTrail JSON trong field aws.* hoặc integration="aws"
 
CLOUDTRAIL_READONLY_EVENTS = {
    "ListAnalyzers", "DescribeCertificate", "ListCertificateAuthorities",
    "GetAccountInformation", "GetAlternateContact", "DescribeInstances",
    "ListBuckets", "GetBucketPolicy", "ListUsers", "GetUser",
    "DescribeSecurityGroups", "DescribeVpcs", "GetCallerIdentity",
    "ListRoles", "GetRole", "DescribeTable",
}
 
CLOUDTRAIL_HIGH_RISK_EVENTS = {
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "CreateAccessKey", "DeleteAccessKey", "PutUserPolicy",
    "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
    "PutRolePolicy", "CreatePolicy", "DeletePolicy",
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress", "DeleteSecurityGroup",
    "ModifyInstanceAttribute", "RunInstances", "TerminateInstances",
    "CreateVpc", "DeleteVpc", "CreateSubnet", "DeleteSubnet",
    "CreateInternetGateway", "AttachInternetGateway",
    "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
    "DeleteBucket", "CreateBucket",
    "ConsoleLogin", "SwitchRole",
    "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance",
    "StopInstances", "StartInstances",
}
 
def outcome_from_cloudtrail(event_name: str, error_code: str) -> str:
    if error_code:
        return "failure"
    return "success"
 
def severity_from_cloudtrail(event_name: str, error_code: str, readonly: bool) -> str:
    if event_name in CLOUDTRAIL_HIGH_RISK_EVENTS and not error_code:
        return "high"
    if event_name in CLOUDTRAIL_HIGH_RISK_EVENTS and error_code:
        return "medium"
    if error_code in ("AccessDenied", "UnauthorizedAccess"):
        return "medium"
    if readonly:
        return "info"
    return "low"
 
def normalize_cloudtrail_event(archive_evt: dict) -> Optional[dict]:
    """
    Normalize AWS CloudTrail event.
    Input format: {"integration":"aws","aws":{...CloudTrail fields...}}
    hoặc Wazuh wrapper có field "aws" chứa CloudTrail data
    """
    aws = archive_evt.get("aws") or {}
    if not isinstance(aws, dict):
        return None
 
    # Nhận diện: phải có eventName và eventSource
    event_name   = aws.get("eventName") or aws.get("eventName", "")
    event_source = aws.get("eventSource") or ""
    event_time   = aws.get("eventTime") or archive_evt.get("timestamp", "")
 
    if not event_name:
        return None
 
    # User identity
    user_identity = aws.get("userIdentity") or {}
    principal_id  = user_identity.get("principalId", "")
    user_arn      = user_identity.get("arn", "")
    user_type     = user_identity.get("type", "")
    account_id    = aws.get("aws_account_id") or aws.get("recipientAccountId", "")
 
    # Session context → username
    session_ctx   = user_identity.get("sessionContext") or {}
    session_issuer = session_ctx.get("sessionIssuer") or {}
    username      = session_issuer.get("userName") or user_identity.get("userName") or ""
 
    # Extract email từ principalId (format: ROLE:email@domain.com)
    if ":" in principal_id:
        username = username or principal_id.split(":")[-1]
 
    src_ip        = aws.get("sourceIPAddress") or aws.get("source_ip_address") or ""
    user_agent    = aws.get("userAgent") or ""
    region        = aws.get("awsRegion") or ""
    request_id    = aws.get("requestID") or aws.get("eventID") or ""
    error_code    = aws.get("errorCode") or ""
    readonly      = bool(aws.get("readOnly", False))
    event_type    = aws.get("eventType") or ""
    event_category = aws.get("eventCategory") or ""
    invoked_by    = user_identity.get("invokedBy") or ""
 
    outcome  = outcome_from_cloudtrail(event_name, error_code)
    severity = severity_from_cloudtrail(event_name, error_code, readonly)
 
    # Action classification
    if event_name == "ConsoleLogin":
        action = "console_login_success" if not error_code else "console_login_failed"
    elif error_code == "AccessDenied":
        action = "access_denied"
    elif event_name in CLOUDTRAIL_HIGH_RISK_EVENTS:
        action = f"cloudtrail_{event_name.lower()}"
    elif readonly:
        action = "cloudtrail_readonly"
    else:
        action = f"cloudtrail_{event_name.lower()}"
 
    # Bỏ qua event từ AWS internal services nếu là readonly thông thường
    # Nhưng vẫn giữ để enricher xử lý
    is_aws_service = src_ip in (
        "config.amazonaws.com", "cloudtrail.amazonaws.com",
        "s3.amazonaws.com", "lambda.amazonaws.com",
    ) or invoked_by in (
        "config.amazonaws.com", "cloudtrail.amazonaws.com",
    )
 
    message = f"CloudTrail {event_name} by {username or user_type} from {src_ip}"
    if error_code:
        message += f" [ERROR: {error_code}]"
 
    return {
        "time":           event_time,
        "log_type":       "cloudtrail",
        "vendor":         "aws",
        "action":         action,
        "outcome":        outcome,
        "asset_host":     account_id,
        "correlation_id": request_id,
        "network": {
            "source_ip":        src_ip if not is_aws_service else "",
            "source_port":      None,
            "country":          "",
            "destination_ip":   "",
            "destination_port": None,
            "protocol":         "HTTPS",
            "method":           "POST",
        },
        "message":     message,
        "maliciousIP": None,
        "waf":         "",
        "flow":        "",
        "winEvent":    "",
        "linuxEvent":  "",
        "fortinet":    "",
        "cloudtrail": {
            "eventName":      event_name,
            "eventSource":    event_source,
            "eventType":      event_type,
            "eventCategory":  event_category,
            "awsRegion":      region,
            "readOnly":       readonly,
            "errorCode":      error_code,
            "userAgent":      user_agent,
            "userType":       user_type,
            "userArn":        user_arn,
            "username":       username,
            "accountId":      account_id,
            "invokedBy":      invoked_by,
            "isAwsService":   is_aws_service,
            "severity":       severity,
            "requestParameters": aws.get("requestParameters") or {},
        },
    }
 
 
# ── Cisco IOS ─────────────────────────────────────────────────────────────────
# Format: syslog %FACILITY-SEVERITY-MNEMONIC: description
 
CISCO_SEVERITY_MAP = {
    "0": "emergency", "1": "alert", "2": "critical", "3": "error",
    "4": "warning",   "5": "notice", "6": "informational", "7": "debug",
    "EMERG": "emergency", "ALERT": "alert", "CRIT": "critical",
    "ERR": "error", "WARNING": "warning", "NOTICE": "notice",
    "INFO": "informational", "DEBUG": "debug",
}
 
CISCO_OUTCOME_MAP = {
    "up":   "allowed",
    "down": "blocked",
    "err-disabled": "blocked",
    "connected": "allowed",
    "notconnect": "blocked",
}
 
def parse_cisco_syslog(raw_line: str) -> dict:
    """
    Parse Cisco IOS syslog: %FACILITY-SEV-MNEMONIC: description
    Ví dụ: %LINK-3-UPDOWN: Interface GigabitEthernet0/43, changed state to up
    """
    result = {}
    # Pattern: %FACILITY-SEV-MNEMONIC: message
    m = re.search(r'%([A-Z0-9_]+)-(\d+|[A-Z]+)-([A-Z0-9_]+):\s*(.*)', raw_line)
    if m:
        result["facility"]  = m.group(1)
        result["severity"]  = CISCO_SEVERITY_MAP.get(m.group(2), m.group(2))
        result["mnemonic"]  = m.group(3)
        result["description"] = m.group(4).strip()
    # Extract interface nếu có
    iface = re.search(r'Interface\s+(\S+)', raw_line, re.IGNORECASE)
    if iface:
        result["interface"] = iface.group(1).rstrip(",")
    # Extract state changed
    state = re.search(r'changed state to\s+(\S+)', raw_line, re.IGNORECASE)
    if state:
        result["state"] = state.group(1)
    return result
 
def normalize_cisco_event(archive_evt: dict) -> Optional[dict]:
    """
    Normalize Cisco IOS syslog event.
    """
    full_log_raw = archive_evt.get("full_log", "")
    if not full_log_raw or not isinstance(full_log_raw, str):
        return None
 
    # Phải chứa Cisco syslog pattern
    if "%" not in full_log_raw or "-" not in full_log_raw:
        return None
 
    # Extract device IP từ syslog header (format: "Jun 15 02:14:19 10.6.88.250 31918: ...")
    device_ip = ""
    ip_m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', full_log_raw[:60])
    if ip_m:
        device_ip = ip_m.group(1)
 
    # Parse Cisco-specific fields
    kv = parse_cisco_syslog(full_log_raw)
    if not kv.get("mnemonic"):
        return None
 
    mnemonic  = kv.get("mnemonic", "")
    facility  = kv.get("facility", "")
    sev       = kv.get("severity", "informational")
    desc      = kv.get("description", "")
    interface = kv.get("interface", "")
    state     = kv.get("state", "")
 
    # Action classification
    if mnemonic in ("UPDOWN", "LINK_UP", "CONNECTED"):
        action = f"interface_{state.lower()}" if state else "interface_state_change"
    elif mnemonic in ("LINEPROTO-5-UPDOWN",):
        action = f"lineproto_{state.lower()}" if state else "lineproto_change"
    elif "UPDOWN" in mnemonic:
        action = f"link_{state.lower()}" if state else "link_change"
    elif "ERR" in mnemonic or "FAIL" in mnemonic:
        action = "cisco_error"
    elif "AUTH" in mnemonic or "LOGIN" in mnemonic:
        action = "cisco_auth_event"
    else:
        action = f"cisco_{mnemonic.lower()}"
 
    outcome = CISCO_OUTCOME_MAP.get(state.lower(), "unknown") if state else "unknown"
 
    # Severity → outcome mapping
    if sev in ("emergency", "alert", "critical", "error"):
        outcome = "failure"
    elif sev in ("informational", "notice") and state == "up":
        outcome = "allowed"
 
    message = f"Cisco {facility}-{mnemonic}: {desc}"
 
    # Timestamp từ Wazuh event
    event_time = archive_evt.get("timestamp") or ""
 
    return {
        "time":           event_time,
        "log_type":       "cisco",
        "vendor":         "Cisco",
        "action":         action,
        "outcome":        outcome,
        "asset_host":     device_ip,
        "correlation_id": "",
        "network": {
            "source_ip":        "",
            "source_port":      None,
            "country":          "",
            "destination_ip":   "",
            "destination_port": None,
            "protocol":         "",
            "method":           None,
        },
        "message":     message,
        "maliciousIP": None,
        "waf":         "",
        "flow":        "",
        "winEvent":    "",
        "linuxEvent":  "",
        "fortinet":    "",
        "cisco": {
            "facility":    facility,
            "mnemonic":    mnemonic,
            "severity":    sev,
            "description": desc,
            "interface":   interface,
            "state":       state,
            "device_ip":   device_ip,
            "raw":         full_log_raw[-300:],
        },
    }
 
 
def _is_linux_event(archive_evt: dict) -> bool:
'''
 
# ── 3. Thêm routing vào normalize_event() ──────────────────────────────────
OLD_ROUTING_FORTINET = '''    if isinstance(full_log_raw, str) and "devname=" in full_log_raw:
        return normalize_fortinet_event(archive_evt)
 
    if _is_linux_event(archive_evt):
        return normalize_linux_event(archive_evt)
 
    return None'''
 
NEW_ROUTING_FORTINET = '''    if isinstance(full_log_raw, str) and "devname=" in full_log_raw:
        return normalize_fortinet_event(archive_evt)
 
    # CloudTrail: có field "aws" với eventName
    if isinstance(archive_evt.get("aws"), dict) and archive_evt["aws"].get("eventName"):
        return normalize_cloudtrail_event(archive_evt)
    if archive_evt.get("integration") == "aws" and isinstance(archive_evt.get("aws"), dict):
        return normalize_cloudtrail_event(archive_evt)
 
    # Cisco IOS: chứa %FACILITY-SEV-MNEMONIC pattern
    if isinstance(full_log_raw, str) and "%" in full_log_raw:
        m = __import__("re").search(r"%[A-Z0-9_]+-\\d+-[A-Z0-9_]+:", full_log_raw)
        if m:
            return normalize_cisco_event(archive_evt)
 
    if _is_linux_event(archive_evt):
        return normalize_linux_event(archive_evt)
 
    return None'''
 
# ── 4. Cập nhật TYPE_MAP trong main() ─────────────────────────────────────
OLD_TYPE_MAP = '''    TYPE_MAP = {"waf":"waf","vpc":"vpc","win":"windows","linux":"linux","fortinet":"fortinet"}'''
NEW_TYPE_MAP = '''    TYPE_MAP = {"waf":"waf","vpc":"vpc","win":"windows","linux":"linux","fortinet":"fortinet","cloudtrail":"cloudtrail","cisco":"cisco"}'''
 
# ── 5. Cập nhật stats dict trong main() ────────────────────────────────────
OLD_STATS = '''    stats = {"waf":0,"vpc":0,"windows":0,"linux":0,"fortinet":0,"skipped":0,"errors":0}'''
NEW_STATS = '''    stats = {"waf":0,"vpc":0,"windows":0,"linux":0,"fortinet":0,"cloudtrail":0,"cisco":0,"skipped":0,"errors":0}'''
 
# ── 6. Cập nhật print trong main() ─────────────────────────────────────────
OLD_PRINT = '''                print(
                    f"[normalize] +1 {log_type:10s} | "
                    f"WAF={stats['waf']} VPC={stats['vpc']} "
                    f"WIN={stats['windows']} LNX={stats['linux']} "
                    f"FTN={stats['fortinet']} | total={total}"
                )'''
NEW_PRINT = '''                print(
                    f"[normalize] +1 {log_type:10s} | "
                    f"WAF={stats['waf']} VPC={stats['vpc']} "
                    f"WIN={stats['windows']} LNX={stats['linux']} "
                    f"FTN={stats['fortinet']} CT={stats['cloudtrail']} "
                    f"CS={stats['cisco']} | total={total}"
                )'''
 
 
def apply_patch():
    with open(PATH) as f:
        content = f.read()
 
    errors = []
 
    # Patch 1: location prefixes
    if OLD_PREFIXES in content:
        content = content.replace(OLD_PREFIXES, NEW_PREFIXES)
        print("✅ Patch 1: location prefixes updated")
    else:
        errors.append("Patch 1: OLD_PREFIXES not found")
 
    # Patch 2: insert normalizer functions
    if INSERT_BEFORE in content and "normalize_cloudtrail_event" not in content:
        content = content.replace(INSERT_BEFORE, NEW_NORMALIZERS)
        print("✅ Patch 2: CloudTrail + Cisco normalizers inserted")
    elif "normalize_cloudtrail_event" in content:
        print("⏭️  Patch 2: already applied")
    else:
        errors.append("Patch 2: INSERT_BEFORE not found")
 
    # Patch 3: routing
    if OLD_ROUTING_FORTINET in content:
        content = content.replace(OLD_ROUTING_FORTINET, NEW_ROUTING_FORTINET)
        print("✅ Patch 3: routing updated")
    else:
        errors.append("Patch 3: routing pattern not found")
 
    # Patch 4: TYPE_MAP
    if OLD_TYPE_MAP in content:
        content = content.replace(OLD_TYPE_MAP, NEW_TYPE_MAP)
        print("✅ Patch 4: TYPE_MAP updated")
    else:
        errors.append("Patch 4: TYPE_MAP not found")
 
    # Patch 5: stats
    if OLD_STATS in content:
        content = content.replace(OLD_STATS, NEW_STATS)
        print("✅ Patch 5: stats dict updated")
    else:
        errors.append("Patch 5: stats dict not found")
 
    # Patch 6: print
    if OLD_PRINT in content:
        content = content.replace(OLD_PRINT, NEW_PRINT)
        print("✅ Patch 6: print updated")
    else:
        errors.append("Patch 6: print not found")
 
    if errors:
        print("\n⚠️  Warnings (manual check needed):")
        for e in errors:
            print(f"  - {e}")
 
    with open(PATH, "w") as f:
        f.write(content)
 
    # Verify syntax
    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    if r.returncode == 0:
        print("\n✅ Syntax check PASSED")
    else:
        print(f"\n❌ Syntax error:\n{r.stderr}")
 
    # Count new log types
    print(f"\nVerify - cloudtrail in file: {'normalize_cloudtrail_event' in content}")
    print(f"Verify - cisco in file: {'normalize_cisco_event' in content}")
    print(f"Verify - no OUTPUT_PATH: {'OUTPUT_PATH' not in content or content.count('OUTPUT_PATH') == 0}")
 
 
if __name__ == "__main__":
    apply_patch()
