#!/usr/bin/env python3
"""
Patch pre-processor.py: thêm parser cho MSWinEventLog (syslog-forwarded Windows Event Log)
Chạy trên EC2: python3 patch_preprocessor.py
"""
 
PATH = "/home/ubuntu/soc_ai/pre-processor.py"
 
# ── 1. Thêm regex pattern cho MSWinEventLog ────────────────────────────────
OLD_PATTERNS = '''CISCO_RE = re.compile(r'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\\d)-(?P<mnemonic>[A-Z0-9_]+):\\s*(?P<message>.*)')'''
 
NEW_PATTERNS = '''CISCO_RE = re.compile(r'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\\d)-(?P<mnemonic>[A-Z0-9_]+):\\s*(?P<message>.*)')
 
# MSWinEventLog: syslog-forwarded Windows Event Log (PRI header + MSWinEventLog marker)
# Format: <PRI>MMM DD HH:MM:SS hostname MSWinEventLog\\tTYPE\\tLOGNAME\\tRECID\\tTIMEGEN\\tSOURCE\\t...\\tCATEGORY\\tHOSTNAME\\tEVENTID/SRC\\tMESSAGE\\tRECID2
MSWINEVENTLOG_RE = re.compile(
    r'^(?:<\\d+>)?'                                    # optional PRI <14>
    r'(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+'
    r'(?P<day>\\d+)\\s+(?P<time>\\d{2}:\\d{2}:\\d{2})\\s+'
    r'(?P<host>\\S+)\\s+'
    r'MSWinEventLog\\s+(?P<rest>.*)$'
)'''
 
# ── 2. Thêm classifier + wrapper function trước hàm wrap_cloudtrail ────────
INSERT_BEFORE = "def wrap_cloudtrail(evt: dict) -> Optional[dict]:"
 
NEW_WRAPPER = '''def classify_mswineventlog(fields: list, full_line: str):
    """
    Phân loại MSWinEventLog field list (tab-separated).
    Trả về (rule_id, rule_level, rule_desc, groups, event_id_guess, src_ip, target_user, outcome)
    """
    # fields ví dụ:
    # ['1','Security','1863469','Mon Jun 15 01:34:23 20264625',
    #  'Microsoft-Windows-Security-Auditing','N/A','N/A','Failure Audit',
    #  'OST-DC01.onesystems.local','Logon',
    #  'An account failed to log on. Source Network Address: 185.220.101.47','18951847']
 
    log_name      = fields[1] if len(fields) > 1 else ""
    source_name   = fields[4] if len(fields) > 4 else ""
    event_outcome = fields[7] if len(fields) > 7 else ""   # "Failure Audit" / "Success Audit" / "Information"
    category      = fields[9] if len(fields) > 9 else ""   # "Logon", etc.
    message       = fields[10] if len(fields) > 10 else " ".join(fields[8:]) if len(fields) > 8 else full_line
 
    # Extract source IP từ message nếu có
    src_ip = None
    ip_m = re.search(r'(?:Source Network Address|IP Address|Network Address):\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)', message, re.I)
    if ip_m:
        src_ip = ip_m.group(1)
    else:
        ip_m2 = re.search(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b', message)
        if ip_m2:
            src_ip = ip_m2.group(1)
 
    # Extract target user nếu có
    target_user = None
    user_m = re.search(r'(?:Account Name|Logon Account|User):\\s*(\\S+)', message, re.I)
    if user_m:
        target_user = user_m.group(1)
 
    outcome_lower = event_outcome.lower()
 
    # Logon category
    if "logon" in category.lower():
        if "failure" in outcome_lower:
            return ("60106", 8, "Windows logon failure (forwarded syslog)",
                    ["win","authentication_failed"], "4625", src_ip, target_user, "failure")
        if "success" in outcome_lower:
            return ("60103", 3, "Windows logon success (forwarded syslog)",
                    ["win","authentication_success"], "4624", src_ip, target_user, "success")
 
    # Account management
    if "account" in category.lower() and ("created" in message.lower() or "added" in message.lower()):
        return ("60137", 10, "Windows account created (forwarded syslog)",
                ["win","account_changed"], "4720", src_ip, target_user, "success")
 
    # Directory sync / informational
    if "directory synchronization" in source_name.lower() or "information" in outcome_lower:
        return ("60100", 2, f"Windows informational: {message[:80]}",
                ["win","informational"], "0", src_ip, target_user, "info")
 
    # Default fallback
    rule_level = 8 if "failure" in outcome_lower else 3
    return ("60100", rule_level, f"Windows event: {category} - {message[:80]}",
            ["win","syslog_forwarded"], "0", src_ip, target_user,
            "failure" if "failure" in outcome_lower else "success")
 
 
def wrap_mswineventlog(line: str) -> Optional[dict]:
    """
    Wrap MSWinEventLog (syslog-forwarded Windows Event) thành Wazuh-like archive
    với cấu trúc win.system.eventID để normalize-service.py nhận diện đúng.
    """
    m = MSWINEVENTLOG_RE.match(line.strip())
    if not m:
        return None
 
    host = m.group("host")
    rest = m.group("rest")
    # Tab-separated fields sau "MSWinEventLog"
    fields = [f.strip() for f in rest.split("\\t") if f.strip() != ""]
    if not fields:
        # Thử split bằng nhiều space liên tiếp nếu không có tab
        fields = [f.strip() for f in re.split(r'\\s{2,}', rest) if f.strip() != ""]
 
    if len(fields) < 3:
        return None
 
    rule_id, rule_level, rule_desc, groups, event_id, src_ip, target_user, outcome = \\
        classify_mswineventlog(fields, line)
 
    ts = parse_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"))
    message_text = fields[10] if len(fields) > 10 else " ".join(fields)
 
    # Build cấu trúc "win" giống Windows Event JSON để normalize-service.py xử lý qua normalize_windows_event()
    win_payload = {
        "win": {
            "system": {
                "providerName": fields[4] if len(fields) > 4 else "MSWinEventLog",
                "eventID":      event_id,
                "systemTime":   ts,
                "computer":     host,
                "channel":      fields[1] if len(fields) > 1 else "Security",
                "message":      message_text,
            },
            "eventdata": {
                "ipAddress":        src_ip or "",
                "targetUserName":   target_user or "",
                "subjectUserName":  "",
                "workstationName":  "",
            },
        }
    }
 
    return {
        "timestamp": ts,
        "location":  "EventChannel",
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule_desc,
            "groups": groups,
        },
        "agent": {"name": host, "ip": ""},
        "decoder": {"name": "windows_eventchannel"},
        "predecoder": {"hostname": host, "program_name": "MSWinEventLog"},
        "data": win_payload,
        "full_log": json.dumps(win_payload, ensure_ascii=False),
        "_pre_processed": True,
        "_source_format": "mswineventlog",
    }
 
 
def wrap_cloudtrail(evt: dict) -> Optional[dict]:'''
 
# ── 3. Thêm routing trong preprocess_line() ─────────────────────────────────
OLD_ROUTING = '''    # Cisco IOS syslog — '%' phải có trong line
    if '%' in line and re.search(r'%[A-Z0-9_]+-\\d-[A-Z0-9_]+:', line):
        result = wrap_cisco(line)
        if result:
            return result
 
    # Standard syslog text
    if SYSLOG_RE.match(line):
        return wrap_syslog(line)
 
    return None'''
 
NEW_ROUTING = '''    # Cisco IOS syslog — '%' phải có trong line
    if '%' in line and re.search(r'%[A-Z0-9_]+-\\d-[A-Z0-9_]+:', line):
        result = wrap_cisco(line)
        if result:
            return result
 
    # MSWinEventLog — syslog-forwarded Windows Event Log
    if "MSWinEventLog" in line:
        result = wrap_mswineventlog(line)
        if result:
            return result
 
    # Standard syslog text
    if SYSLOG_RE.match(line):
        return wrap_syslog(line)
 
    return None'''
 
# ── 4. Cập nhật stats dict ────────────────────────────────────────────────
OLD_STATS = '''    stats = {"passthrough":0, "syslog":0, "cisco":0, "cloudtrail":0, "skipped":0, "errors":0}'''
NEW_STATS = '''    stats = {"passthrough":0, "syslog":0, "cisco":0, "cloudtrail":0, "mswineventlog":0, "skipped":0, "errors":0}'''
 
# ── 5. Cập nhật print total ──────────────────────────────────────────────
OLD_TOTAL = '''            total = sum(stats[k] for k in ("passthrough","syslog","cisco","cloudtrail"))
            print(
                f"[pre-processor] +1 {src:12s} | "
                f"total={total} pass={stats['passthrough']} "
                f"syslog={stats['syslog']} cisco={stats['cisco']} "
                f"cloudtrail={stats['cloudtrail']} skip={stats['skipped']}"
            )'''
 
NEW_TOTAL = '''            total = sum(stats[k] for k in ("passthrough","syslog","cisco","cloudtrail","mswineventlog"))
            print(
                f"[pre-processor] +1 {src:14s} | "
                f"total={total} pass={stats['passthrough']} "
                f"syslog={stats['syslog']} cisco={stats['cisco']} "
                f"cloudtrail={stats['cloudtrail']} win={stats['mswineventlog']} "
                f"skip={stats['skipped']}"
            )'''
 
 
def apply_patch():
    with open(PATH) as f:
        content = f.read()
 
    checks = [
        ("Patch 1 (patterns)", OLD_PATTERNS, NEW_PATTERNS),
        ("Patch 2 (wrapper)",  INSERT_BEFORE, NEW_WRAPPER),
        ("Patch 3 (routing)",  OLD_ROUTING, NEW_ROUTING),
        ("Patch 4 (stats)",    OLD_STATS, NEW_STATS),
        ("Patch 5 (total)",    OLD_TOTAL, NEW_TOTAL),
    ]
 
    already_applied = "wrap_mswineventlog" in content
 
    if already_applied:
        print("⏭️  Patch already applied (wrap_mswineventlog found)")
        return
 
    for name, old, new in checks:
        if old in content:
            content = content.replace(old, new)
            print(f"✅ {name}: applied")
        else:
            print(f"⚠️  {name}: pattern NOT FOUND — manual check needed")
 
    with open(PATH, "w") as f:
        f.write(content)
 
    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    if r.returncode == 0:
        print("\n✅ Syntax check PASSED")
    else:
        print(f"\n❌ Syntax error:\n{r.stderr}")
 
    print(f"\nVerify - wrap_mswineventlog in file: {'wrap_mswineventlog' in content}")
    print(f"Verify - MSWINEVENTLOG_RE in file: {'MSWINEVENTLOG_RE' in content}")
 
 
if __name__ == "__main__":
    apply_patch()
