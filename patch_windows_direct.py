#!/usr/bin/env python3
"""
Patch normalize-service.py: thêm Windows MSWinEventLog tab-based parser
nhận TRỰC TIẾP raw syslog-forwarded Windows Event (không qua pre-processor).

Format thật (xác nhận từ file gốc 02_windows_eventlog.txt):
<14>Jun 15 00:34:05 HOST MSWinEventLog\t1\tApplication\t1861940\t"Mon Jun 15 00:34:05 2026"\t0\tSourceName\tN/A\tN/A\tInformation\tComputerName\tN/A\t\tMessage text\t18951494

Field index sau "MSWinEventLog" (tab-separated):
[0]=EventType(1)  [1]=LogName  [2]=RecordNumber  [3]=TimeGenerated(text)
[4]=EventID  [5]=SourceName  [6]=N/A  [7]=N/A  [8]=EventType readable
[9]=ComputerName  [10]=Category  [11]=(empty/SID)  [12]=Message  [13]=RecordID2

Chạy trên EC2: python3 patch_windows_direct.py
"""

PATH = "/home/ubuntu/soc_ai/normalize-service.py"

# ── 1. Thêm regex pattern cho MSWinEventLog raw (PRI + tab) ────────────────
PATTERN_INSERT_MARKER = "WAF_LOCATION_PREFIX"

NEW_WIN_PATTERN = '''import re as _re_mod  # ensure re already imported above; placeholder no-op

# MSWinEventLog raw direct format (PRI header + tab-separated fields)
MSWINEVENTLOG_DIRECT_RE = re.compile(
    r'^(?:<\\d+>)?'
    r'(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+'
    r'(?P<day>\\d+)\\s+(?P<time>\\d{2}:\\d{2}:\\d{2})\\s+'
    r'(?P<host>\\S+)\\s+'
    r'MSWinEventLog\\t(?P<rest>.*)$'
)

WAF_LOCATION_PREFIX'''

# ── 2. Thêm Windows EventID severity/outcome mapping + classifier + normalizer ──
INSERT_BEFORE_LINUX = "def _is_linux_event(archive_evt: dict) -> bool:"

NEW_WIN_NORMALIZER = '''
# ── Windows MSWinEventLog (direct raw, syslog-forwarded) ──────────────────────

WIN_EVENTID_OUTCOME_MAP = {
    "4624": "success", "4625": "failure", "4634": "success",
    "4720": "success", "4722": "success", "4725": "success",
    "4726": "success", "4688": "success", "4740": "success",
    "4672": "success",  # special privileges assigned
}
WIN_EVENTID_SEVERITY_MAP = {
    "4625": 8,   # logon failure
    "4720": 10,  # user created
    "4726": 8,   # user deleted
    "4672": 8,   # special privileges (admin logon)
    "4740": 8,   # account lockout
    "4688": 3,   # process creation
    "4624": 3,   # logon success
}

MONTH_MAP_WIN = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12
}

def _parse_win_syslog_timestamp(month: str, day: str, time_str: str) -> str:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    try:
        m = MONTH_MAP_WIN.get(month, 1)
        d = int(day)
        h, mi, s = map(int, time_str.split(":"))
        year = now.year if m <= now.month else now.year - 1
        dt = datetime(year, m, d, h, mi, s, tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return now.isoformat().replace("+00:00", "Z")


def extract_win_ip_from_message(message: str) -> str:
    """Tìm IP trong message text — thường ở dạng 'Source Network Address: x.x.x.x'."""
    m = re.search(
        r'(?:Source Network Address|IP Address|Network Address|Caller Computer Name):\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})',
        message, re.I
    )
    if m:
        return m.group(1)
    m2 = re.search(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b', message)
    return m2.group(1) if m2 else ""


def extract_win_user_from_message(message: str) -> str:
    m = re.search(r'(?:Account Name|Logon Account|Target Account Name|New Account Name):\\s*(\\S+)', message, re.I)
    return m.group(1) if m else ""


def normalize_windows_eventlog_direct(line: str) -> Optional[dict]:
    """
    Normalize raw MSWinEventLog syslog-forwarded line trực tiếp (KHÔNG qua pre-processor).
    Output đúng schema "win" thống nhất với normalize_windows_event().
    """
    m = MSWINEVENTLOG_DIRECT_RE.match(line.strip())
    if not m:
        return None

    host = m.group("host")
    rest = m.group("rest")
    fields = rest.split("\\t")
    # Loại bỏ phần tử rỗng ở cuối do trailing tab, nhưng GIỮ index gốc
    # (không strip toàn bộ vì sẽ làm lệch index các field rỗng ở giữa)

    if len(fields) < 8:
        return None

    def fget(idx, default=""):
        return fields[idx].strip() if idx < len(fields) and fields[idx] is not None else default

    log_name      = fget(1)            # Application / Security / System
    event_id      = fget(4)            # EventID thật nằm ở index 4
    source_name   = fget(5)            # ProviderName
    event_outcome = fget(8)            # "Information" / "Failure Audit" / "Success Audit"
    computer      = fget(9) or host
    category      = fget(10)           # "Logon" / "N/A" / ...
    message       = fget(12)
    if not message and len(fields) > 13:
        # Một số dòng message rỗng do double-tab, lấy field kế tiếp có nội dung
        message = fget(13)

    src_ip      = extract_win_ip_from_message(message)
    target_user = extract_win_user_from_message(message)
    ts          = _parse_win_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"))

    outcome_lower = event_outcome.lower()
    if "failure" in outcome_lower:
        outcome = "failure"
    elif "success" in outcome_lower:
        outcome = "success"
    elif "information" in outcome_lower:
        outcome = WIN_EVENTID_OUTCOME_MAP.get(event_id, "info")
    else:
        outcome = WIN_EVENTID_OUTCOME_MAP.get(event_id, "unknown")

    rule_level = WIN_EVENTID_SEVERITY_MAP.get(event_id, 3 if outcome == "info" else 5)

    def first_line(msg, limit=200):
        if not msg:
            return ""
        for sep in [".\\r\\n", ".\\n", ". "]:
            if sep in msg:
                return msg.split(sep)[0].strip()[:limit] + "."
        return msg.strip()[:limit]

    return {
        "time":           ts,
        "log_type":       "win",
        "vendor":         "Microsoft",
        "action":         event_id or "0",
        "outcome":        outcome,
        "asset_host":     computer,
        "correlation_id": "",
        "network": {
            "source_ip":        src_ip,
            "source_port":      "",
            "country":          "",
            "destination_ip":   "",
            "destination_port": "",
            "protocol":         "",
            "method":           "",
        },
        "message":     first_line(message) or f"{log_name}: {source_name}",
        "maliciousIP": None,
        "waf": "", "flow": "", "linuxEvent": "", "fortinet": "",
        "winEvent": {
            "providerName":              source_name,
            "channel":                   log_name,
            "eventID":                   event_id,
            "logonType":                 "",
            "processName":               "",
            "subjectUserName":           "",
            "subjectDomainName":         "",
            "targetUserName":            target_user,
            "targetDomainName":          "",
            "authenticationPackageName": "",
            "workstationName":           "",
            "ipAddress":                 src_ip,
            "category":                  category,
            "eventOutcomeRaw":           event_outcome,
        },
    }


def _is_linux_event(archive_evt: dict) -> bool:'''

# ── 3. Thêm routing trong normalize_event() (xử lý cả dict đã wrap VÀ raw line) ──
# Vì normalize_event() nhận dict, còn MSWinEventLog raw là string, cần xử lý ở
# tầng main() trước khi gọi json.loads — patch riêng main()

OLD_MAIN_LOOP = '''    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        for line in follow_file(RAW_LOG_PATH, start_from_beginning=start_beginning):
            if not line.strip():
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                stats["errors"] += 1
                continue
            norm = normalize_event(evt)
            if not norm:
                stats["skipped"] += 1
                continue'''

NEW_MAIN_LOOP = '''    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        for line in follow_file(RAW_LOG_PATH, start_from_beginning=start_beginning):
            if not line.strip():
                continue

            # MSWinEventLog raw (syslog-forwarded, không phải JSON) — xử lý trước JSON parse
            if "MSWinEventLog" in line and "\\t" in line:
                norm = normalize_windows_eventlog_direct(line)
                if norm:
                    out.write(json.dumps(norm, ensure_ascii=False) + "\\n")
                    out.flush()
                    log_type = norm.get("log_type")
                    mapped = TYPE_MAP.get(log_type)
                    if mapped:
                        stats[mapped] += 1
                        total = sum(stats[k] for k in ("waf","vpc","windows","linux","fortinet","cloudtrail","cisco"))
                        print(f"[normalize] +1 {log_type:10s} | total={total} (direct MSWinEventLog)")
                    continue
                else:
                    stats["skipped"] += 1
                    continue

            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                stats["errors"] += 1
                continue
            norm = normalize_event(evt)
            if not norm:
                stats["skipped"] += 1
                continue'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "MSWINEVENTLOG_DIRECT_RE" in content:
        print("⏭️  Already applied")
        return

    patches = [
        ("Pattern insert",      PATTERN_INSERT_MARKER, NEW_WIN_PATTERN),
        ("Normalizer insert",   INSERT_BEFORE_LINUX, NEW_WIN_NORMALIZER),
        ("Main loop routing",   OLD_MAIN_LOOP, NEW_MAIN_LOOP),
    ]

    for name, old, new in patches:
        count = content.count(old)
        if count == 1:
            content = content.replace(old, new)
            print(f"✅ {name}: applied")
        elif count == 0:
            print(f"⚠️  {name}: pattern NOT FOUND")
        else:
            print(f"⚠️  {name}: pattern found {count} times (ambiguous) — manual check needed")

    with open(PATH, "w") as f:
        f.write(content)

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    if r.returncode == 0:
        print("\\n✅ Syntax check PASSED")
    else:
        print(f"\\n❌ Syntax error:\\n{r.stderr}")

    print(f"\\nVerify - MSWINEVENTLOG_DIRECT_RE: {'MSWINEVENTLOG_DIRECT_RE' in content}")
    print(f"Verify - normalize_windows_eventlog_direct: {'normalize_windows_eventlog_direct' in content}")


if __name__ == "__main__":
    apply_patch()
