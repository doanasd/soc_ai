#!/usr/bin/env python3
"""
Patch pre-processor.py và normalize-service.py để support Cisco IOS và CloudTrail.
Chạy: ~/soc_ai/venv/bin/python3 patch_pipeline.py
"""
import re, sys

# ─────────────────────────────────────────────────────────────────
# PATCH 1: pre-processor.py — fix Cisco regex
# ─────────────────────────────────────────────────────────────────
PRE_FILE = "/home/ubuntu/soc_ai/pre-processor.py"

with open(PRE_FILE) as f:
    pre = f.read()

OLD_CISCO_RE = '''CISCO_RE = re.compile(
    r\'^(?P<seq>\\\\d+):\\\\s+\'     # timestamp prefix
    r\'(?P<seq>\\\\d+):\\\\s+\'
    r\'\\\\S+\\\\s+\\\\S+:\\\\s+\'                # inner timestamp
    r\'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\\\\d)-(?P<mnemonic>[A-Z0-9_]+):\\\\s*\'
    r\'(?P<message>.*)$\'
)'''

# Tìm đoạn CISCO_RE thực tế trong file
cisco_start = pre.find("CISCO_RE = re.compile(")
cisco_end   = pre.find(")", cisco_start) + 1
# Tìm dấu ) cuối cùng của block
depth = 0
for i, c in enumerate(pre[cisco_start:]):
    if c == '(': depth += 1
    if c == ')':
        depth -= 1
        if depth == 0:
            cisco_end = cisco_start + i + 1
            break

old_cisco_block = pre[cisco_start:cisco_end]
new_cisco_block = '''CISCO_RE = re.compile(
    r\'^(?:\\\\w+\\\\s+\\\\d+\\\\s+\\\\S+\\\\s+)?\'       # optional outer timestamp: Jun 15 02:14:19
    r\'(?:\\\\S+\\\\s+)?\'                                  # optional host: 10.6.88.250
    r\'(?:\\\\d+:\\\\s+)?\'                                  # optional seq: 31918:
    r\'(?:\\\\w+\\\\s+\\\\d+\\\\s+\\\\S+:\\\\s+)?\'        # optional inner timestamp
    r\'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\\\\d)-(?P<mnemonic>[A-Z0-9_]+):\\\\s*\'
    r\'(?P<message>.*)$\'
)'''

if old_cisco_block in pre:
    pre = pre.replace(old_cisco_block, new_cisco_block)
    print("✅ PATCH 1a: Cisco regex replaced")
else:
    # Replace trực tiếp bằng sed-style
    pre = pre[:cisco_start] + new_cisco_block + pre[cisco_end:]
    print("✅ PATCH 1a: Cisco regex replaced (fallback)")

# Fix wrap_cisco: extract src_host từ đầu dòng đúng hơn
OLD_WRAP_CISCO_SRC = '''    # Extract source IP from syslog header
    src_match = re.match(r\'^(\\\\S+)\\\\s+\', line)
    src_host  = src_match.group(1) if src_match else "cisco"'''

NEW_WRAP_CISCO_SRC = '''    # Extract source IP/host từ syslog header (position 3: after "Mon DD HH:MM:SS")
    parts = line.strip().split()
    src_host = "cisco"
    for part in parts:
        if re.match(r\'\\\\d+\\.\\\\d+\\.\\\\d+\\.\\\\d+\', part):
            src_host = part
            break'''

if OLD_WRAP_CISCO_SRC in pre:
    pre = pre.replace(OLD_WRAP_CISCO_SRC, NEW_WRAP_CISCO_SRC)
    print("✅ PATCH 1b: wrap_cisco src_host extraction fixed")
else:
    print("⚠️  PATCH 1b: wrap_cisco src_host not found - skipping")

# Fix detect Cisco: check % pattern trước khi check syslog
OLD_DETECT = '''    # Cisco IOS syslog
    if re.search(r\'%[A-Z0-9_]+-\\\\d-[A-Z0-9_]+:\', line):
        return wrap_cisco(line)

    # Standard syslog text
    if SYSLOG_RE.match(line):
        return wrap_syslog(line)'''

NEW_DETECT = '''    # Cisco IOS syslog — check trước syslog vì có thể match cả 2
    if \'%\' in line and re.search(r\'%[A-Z0-9_]+-\\\\d-[A-Z0-9_]+:\', line):
        result = wrap_cisco(line)
        if result:
            return result

    # Standard syslog text
    if SYSLOG_RE.match(line):
        return wrap_syslog(line)'''

if OLD_DETECT in pre:
    pre = pre.replace(OLD_DETECT, NEW_DETECT)
    print("✅ PATCH 1c: Cisco detection order fixed")
else:
    print("⚠️  PATCH 1c: detection block not found - checking alternative")
    # Try without the blank line
    alt_old = "    # Cisco IOS syslog\n    if re.search(r'%[A-Z0-9_]+-\\d-[A-Z0-9_]+:', line):\n        return wrap_cisco(line)\n\n    # Standard syslog text\n    if SYSLOG_RE.match(line):\n        return wrap_syslog(line)"
    if alt_old in pre:
        pre = pre.replace(alt_old, NEW_DETECT)
        print("✅ PATCH 1c: fixed via alternative")

with open(PRE_FILE, "w") as f:
    f.write(pre)
print("✅ pre-processor.py saved\n")

# ─────────────────────────────────────────────────────────────────
# PATCH 2: normalize-service.py — thêm CloudTrail + Cisco handler
# ─────────────────────────────────────────────────────────────────
NORM_FILE = "/home/ubuntu/soc_ai/normalize-service.py"

with open(NORM_FILE) as f:
    norm = f.read()

# 2a: Thêm 2 hàm normalize mới TRƯỚC def normalize_event
NEW_FUNCTIONS = '''
def normalize_cloudtrail_event(archive_evt: dict) -> Optional[dict]:
    """CloudTrail event đã qua pre-processor → normalize về schema chuẩn."""
    data      = archive_evt.get("data", {}) or {}
    rule      = archive_evt.get("rule", {}) or {}
    agent     = archive_evt.get("agent", {}) or {}
    predecoder = archive_evt.get("predecoder", {}) or {}
    cloudtrail = archive_evt.get("cloudtrail", {}) or {}

    aws_event   = data.get("aws_event", "")
    aws_source  = data.get("aws_source", "")
    aws_region  = data.get("aws_region", "")
    aws_account = data.get("aws_account", "")
    src_ip      = data.get("srcip", "")
    user_name   = data.get("dstuser", "")
    user_arn    = data.get("user_arn", "")
    user_type   = data.get("user_type", "")
    read_only   = data.get("read_only", "True")
    error_code  = data.get("error_code", "")

    # Classify action
    if error_code:
        action = "api_error"
    elif read_only in ("True", "true", True):
        action = "api_read"
    else:
        action = "api_write"

    # Source IP — AWS service calls dùng service name, không phải IP
    network_src_ip = src_ip if re.match(r\'\\d+\\.\\d+\\.\\d+\\.\\d+\', src_ip) else ""
    network_src_host = src_ip if not network_src_ip else ""

    rule_level = rule.get("level", 3)
    outcome = "unknown"
    if rule_level >= 10: outcome = "critical"
    elif rule_level >= 8: outcome = "failure"
    elif rule_level >= 5: outcome = "warning"
    elif rule_level >= 3: outcome = "success"

    message = rule.get("description", f"CloudTrail: {aws_event}")
    if error_code:
        message += f" [ERROR: {error_code}: {data.get(\'error_message\', \'\')}]"

    return {
        "time":           archive_evt.get("timestamp"),
        "log_type":       "cloudtrail",
        "vendor":         "aws",
        "action":         action,
        "outcome":        outcome,
        "asset_host":     f"aws-{aws_account}" if aws_account else agent.get("name", ""),
        "correlation_id": data.get("request_id", ""),
        "network": {
            "source_ip":        network_src_ip,
            "source_port":      None,
            "country":          "",
            "destination_ip":   "",
            "destination_port": None,
            "protocol":         "HTTPS",
            "method":           "POST",
        },
        "message": message,
        "maliciousIP": None,
        "waf": "", "flow": "", "winEvent": "", "fortinet": "", "linuxEvent": "",
        "cloudtrailEvent": {
            "eventName":    aws_event,
            "eventSource":  aws_source,
            "awsRegion":    aws_region,
            "accountId":    aws_account,
            "userType":     user_type,
            "userName":     user_name,
            "userArn":      user_arn,
            "sourceIP":     src_ip,
            "readOnly":     read_only,
            "errorCode":    error_code,
            "ruleLevel":    rule_level,
            "ruleGroups":   rule.get("groups", []),
            "ruleId":       rule.get("id", ""),
        },
    }


def normalize_cisco_event(archive_evt: dict) -> Optional[dict]:
    """Cisco IOS syslog đã qua pre-processor → normalize về schema chuẩn."""
    data      = archive_evt.get("data", {}) or {}
    rule      = archive_evt.get("rule", {}) or {}
    agent     = archive_evt.get("agent", {}) or {}
    predecoder = archive_evt.get("predecoder", {}) or {}

    facility = data.get("facility", "")
    severity = int(data.get("severity", "5"))
    mnemonic = data.get("mnemonic", "")
    message  = data.get("message", archive_evt.get("full_log", "")[:200])
    src_host = agent.get("ip") or agent.get("name") or predecoder.get("hostname", "")

    # Map Cisco severity → action
    action_map = {
        0: "emergency", 1: "alert", 2: "critical",
        3: "error", 4: "warning", 5: "notice", 6: "info", 7: "debug"
    }
    action = action_map.get(severity, "notice")

    outcome_map = {
        0: "critical", 1: "critical", 2: "critical",
        3: "failure", 4: "warning", 5: "success", 6: "success", 7: "success"
    }
    outcome = outcome_map.get(severity, "unknown")

    # Extract interface if present
    iface_match = re.search(r\'Interface (\\S+)\', message)
    interface = iface_match.group(1) if iface_match else ""

    return {
        "time":           archive_evt.get("timestamp"),
        "log_type":       "cisco",
        "vendor":         "Cisco",
        "action":         action,
        "outcome":        outcome,
        "asset_host":     src_host,
        "correlation_id": "",
        "network": {
            "source_ip":        src_host if re.match(r\'\\d+\\.\\d+\\.\\d+\\.\\d+\', src_host) else "",
            "source_port":      None,
            "country":          "",
            "destination_ip":   "",
            "destination_port": None,
            "protocol":         "",
            "method":           "",
        },
        "message": f"Cisco {facility}-{severity}-{mnemonic}: {message[:200]}",
        "maliciousIP": None,
        "waf": "", "flow": "", "winEvent": "", "fortinet": "", "linuxEvent": "",
        "ciscoEvent": {
            "facility":  facility,
            "severity":  severity,
            "mnemonic":  mnemonic,
            "interface": interface,
            "message":   message,
            "ruleLevel": rule.get("level", 3),
            "ruleId":    rule.get("id", ""),
            "ruleGroups": rule.get("groups", []),
        },
    }

'''

# Insert trước def normalize_event
INSERT_BEFORE = "def normalize_event(archive_evt: dict) -> Optional[dict]:"
if INSERT_BEFORE in norm:
    norm = norm.replace(INSERT_BEFORE, NEW_FUNCTIONS + INSERT_BEFORE)
    print("✅ PATCH 2a: normalize_cloudtrail_event + normalize_cisco_event added")
else:
    print("❌ PATCH 2a: Could not find insertion point")
    sys.exit(1)

# 2b: Thêm branch trong normalize_event để route cloudtrail và cisco
OLD_NORMALIZE_END = '''    if _is_linux_event(archive_evt):
        return normalize_linux_event(archive_evt)

    return None'''

NEW_NORMALIZE_END = '''    if _is_linux_event(archive_evt):
        return normalize_linux_event(archive_evt)

    # CloudTrail — đã qua pre-processor
    if loc.startswith("/aws/cloudtrail/") or decoder_name == "cloudtrail":
        return normalize_cloudtrail_event(archive_evt)

    # Cisco IOS — đã qua pre-processor
    if loc.startswith("/cisco/") or decoder_name == "cisco-ios":
        return normalize_cisco_event(archive_evt)

    return None'''

if OLD_NORMALIZE_END in norm:
    norm = norm.replace(OLD_NORMALIZE_END, NEW_NORMALIZE_END)
    print("✅ PATCH 2b: cloudtrail + cisco routing added to normalize_event")
else:
    print("⚠️  PATCH 2b: exact string not found, trying flexible match")
    # Flexible approach
    pattern = r'(    if _is_linux_event\(archive_evt\):\s+return normalize_linux_event\(archive_evt\)\s+return None)'
    replacement = '''    if _is_linux_event(archive_evt):
        return normalize_linux_event(archive_evt)

    # CloudTrail — đã qua pre-processor
    if loc.startswith("/aws/cloudtrail/") or decoder_name == "cloudtrail":
        return normalize_cloudtrail_event(archive_evt)

    # Cisco IOS — đã qua pre-processor
    if loc.startswith("/cisco/") or decoder_name == "cisco-ios":
        return normalize_cisco_event(archive_evt)

    return None'''
    norm_new = re.sub(pattern, replacement, norm)
    if norm_new != norm:
        norm = norm_new
        print("✅ PATCH 2b: applied via regex")
    else:
        print("❌ PATCH 2b: failed")
        sys.exit(1)

# 2c: Thêm "decoder_name" extraction vào normalize_event nếu chưa có
if 'decoder_name = ' not in norm[norm.find("def normalize_event"):norm.find("def normalize_event")+500]:
    OLD_NORM_EVT_BODY = '''def normalize_event(archive_evt: dict) -> Optional[dict]:
    location     = archive_evt.get("location", "")
    data         = archive_evt.get("data", {})
    full_log_raw = archive_evt.get("full_log", "")
    parsed_full  = parse_json_safe(full_log_raw)

    if isinstance(location, str):'''

    NEW_NORM_EVT_BODY = '''def normalize_event(archive_evt: dict) -> Optional[dict]:
    location     = archive_evt.get("location", "")
    data         = archive_evt.get("data", {})
    full_log_raw = archive_evt.get("full_log", "")
    parsed_full  = parse_json_safe(full_log_raw)
    loc          = str(location) if location else ""
    decoder_name = str((archive_evt.get("decoder") or {}).get("name", ""))

    if isinstance(location, str):'''

    if OLD_NORM_EVT_BODY in norm:
        norm = norm.replace(OLD_NORM_EVT_BODY, NEW_NORM_EVT_BODY)
        print("✅ PATCH 2c: decoder_name extraction added")
    else:
        print("⚠️  PATCH 2c: skipped - may already exist")
else:
    print("✅ PATCH 2c: decoder_name already present")

# 2d: Fix loc variable trong routing — đảm bảo dùng loc thay vì location
norm = norm.replace(
    'if loc.startswith("/aws/cloudtrail/") or decoder_name == "cloudtrail"',
    'if (isinstance(location, str) and location.startswith("/aws/cloudtrail/")) or decoder_name == "cloudtrail"'
)
norm = norm.replace(
    'if loc.startswith("/cisco/") or decoder_name == "cisco-ios"',
    'if (isinstance(location, str) and location.startswith("/cisco/")) or decoder_name == "cisco-ios"'
)

# 2e: Thêm cloudtrail vào stats counter và TYPE_MAP
OLD_STATS = '    stats = {"waf":0,"vpc":0,"windows":0,"linux":0,"fortinet":0,"skipped":0,"errors":0}'
NEW_STATS = '    stats = {"waf":0,"vpc":0,"windows":0,"linux":0,"fortinet":0,"cloudtrail":0,"cisco":0,"skipped":0,"errors":0}'
if OLD_STATS in norm:
    norm = norm.replace(OLD_STATS, NEW_STATS)
    print("✅ PATCH 2e: stats counter updated")

OLD_TYPEMAP = '    TYPE_MAP = {"waf":"waf","vpc":"vpc","win":"windows","linux":"linux","fortinet":"fortinet"}'
NEW_TYPEMAP = '    TYPE_MAP = {"waf":"waf","vpc":"vpc","win":"windows","linux":"linux","fortinet":"fortinet","cloudtrail":"cloudtrail","cisco":"cisco"}'
if OLD_TYPEMAP in norm:
    norm = norm.replace(OLD_TYPEMAP, NEW_TYPEMAP)
    print("✅ PATCH 2e: TYPE_MAP updated")

OLD_TOTAL = '        total = sum(stats[k] for k in ("waf","vpc","windows","linux","fortinet"))'
NEW_TOTAL = '        total = sum(stats[k] for k in ("waf","vpc","windows","linux","fortinet","cloudtrail","cisco"))'
if OLD_TOTAL in norm:
    norm = norm.replace(OLD_TOTAL, NEW_TOTAL)
    print("✅ PATCH 2e: total counter updated")

with open(NORM_FILE, "w") as f:
    f.write(norm)
print("✅ normalize-service.py saved\n")

print("=" * 50)
print("ALL PATCHES APPLIED")
print("Run: bash ~/soc_ai/stop.sh && bash ~/soc_ai/start.sh")
