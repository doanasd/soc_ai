#!/usr/bin/env python3
"""
Patch normalize-service.py: fix normalize_windows_eventlog_direct()
1. Xác nhận field index đúng (EventID tại [4], SourceName tại [5])
2. Thêm EventID → action name mapping có ý nghĩa
3. Fix outcome từ EventType readable field [8]
"""

PATH = "/home/ubuntu/soc_ai/normalize-service.py"

OLD_WIN_FUNC = '''def normalize_windows_eventlog_direct(line: str) -> Optional[dict]:
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
    }'''

NEW_WIN_FUNC = '''# EventID → action name mapping (Security + System + Application events)
WIN_EVENTID_ACTION_MAP = {
    # ── Security: Logon/Logoff ──────────────────────────────────────────────
    "4624": "logon_success",
    "4625": "logon_failure",
    "4634": "logoff",
    "4647": "user_initiated_logoff",
    "4648": "logon_explicit_credentials",
    "4672": "special_privileges_assigned",
    "4673": "privileged_service_called",
    "4674": "privileged_object_operation",
    "4675": "sid_filtered",
    # ── Security: Account Management ────────────────────────────────────────
    "4720": "user_account_created",
    "4722": "user_account_enabled",
    "4723": "password_change_attempt",
    "4724": "password_reset_attempt",
    "4725": "user_account_disabled",
    "4726": "user_account_deleted",
    "4727": "security_group_created",
    "4728": "member_added_to_group",
    "4729": "member_removed_from_group",
    "4730": "security_group_deleted",
    "4740": "account_locked_out",
    "4767": "account_unlocked",
    "4781": "account_name_changed",
    # ── Security: Process ───────────────────────────────────────────────────
    "4688": "process_created",
    "4689": "process_exited",
    # ── Security: Policy / Audit ─────────────────────────────────────────────
    "4719": "audit_policy_changed",
    "4902": "per_user_audit_policy_created",
    # ── Security: Object Access ─────────────────────────────────────────────
    "4656": "object_handle_requested",
    "4660": "object_deleted",
    "4663": "object_access_attempt",
    "4698": "scheduled_task_created",
    "4702": "scheduled_task_updated",
    # ── Security: Network ───────────────────────────────────────────────────
    "5140": "network_share_accessed",
    "5145": "network_share_object_checked",
    "5152": "packet_blocked",
    "5156": "connection_allowed",
    "5158": "bind_allowed",
    # ── Security: System ────────────────────────────────────────────────────
    "4608": "windows_starting",
    "4609": "windows_shutting_down",
    "4616": "system_time_changed",
    "4621": "crash_dump_initialized",
    "1102": "audit_log_cleared",
    "1100": "event_logging_stopped",
    # ── System log events ───────────────────────────────────────────────────
    "6005": "event_log_started",
    "6006": "event_log_stopped",
    "6008": "unexpected_shutdown",
    "6013": "system_uptime",
    "7034": "service_crashed",
    "7035": "service_control_sent",
    "7036": "service_state_changed",
    "7040": "service_start_type_changed",
    "7045": "service_installed",
    # ── Application log events (thường dùng EventID nhỏ/tùy ý) ─────────────
    "0":    "app_event",          # Generic application event
}

# EventID → severity level
WIN_EVENTID_SEVERITY_EXT = {
    "4625": 8, "4740": 8, "4648": 7, "4674": 5, "4673": 5,
    "4720": 10, "4726": 8, "4728": 7, "4729": 5,
    "1102": 10, "6008": 7, "7034": 6, "7045": 8,
    "4688": 3, "4624": 3, "4634": 2, "5156": 2,
    "4608": 2, "4609": 3, "6005": 2, "6006": 3,
}


def _win_action_from_eventid(event_id: str, source_name: str, log_name: str) -> str:
    """
    Tạo action name có ý nghĩa từ EventID.
    Ưu tiên: mapping cố định → source_name → log_name fallback.
    """
    if event_id in WIN_EVENTID_ACTION_MAP:
        return WIN_EVENTID_ACTION_MAP[event_id]

    # Với EventID lớn từ Application log — dùng source_name để tạo action
    if source_name and source_name not in ("N/A", ""):
        src_clean = re.sub(r"[^a-zA-Z0-9]", "_", source_name.lower()).strip("_")
        return f"app_{src_clean}_event"

    # Fallback: dùng channel + eventid
    channel = log_name.lower().replace(" ", "_") if log_name else "win"
    return f"{channel}_event_{event_id}" if event_id and event_id != "0" else "win_event"


def normalize_windows_eventlog_direct(line: str) -> Optional[dict]:
    """
    Normalize raw MSWinEventLog syslog-forwarded line trực tiếp (KHÔNG qua pre-processor).

    Format (tab-separated sau "MSWinEventLog"):
    [0]=EventType_num [1]=LogName [2]=RecordNum [3]=TimeGenerated
    [4]=EventID [5]=SourceName [6]=N/A [7]=N/A [8]=EventType_readable
    [9]=ComputerName [10]=Category [11]=SID/empty [12]=Message [13]=RecordID2
    """
    m = MSWINEVENTLOG_DIRECT_RE.match(line.strip())
    if not m:
        return None

    host = m.group("host")
    rest = m.group("rest")
    fields = rest.split("\\t")

    if len(fields) < 8:
        return None

    def fget(idx, default=""):
        if idx < len(fields) and fields[idx] is not None:
            return fields[idx].strip()
        return default

    log_name       = fget(1)   # Application / Security / System
    event_id       = fget(4)   # EventID thật
    source_name    = fget(5)   # ProviderName / SourceName
    event_type_raw = fget(8)   # "Information" / "Warning" / "Error" /
                               # "Failure Audit" / "Success Audit"
    computer       = fget(9) or host
    category       = fget(10)
    message        = fget(12)

    # Một số dòng có message ở index 13 do field 11 rỗng tạo double-tab
    if not message:
        message = fget(13)

    src_ip      = extract_win_ip_from_message(message)
    target_user = extract_win_user_from_message(message)
    ts          = _parse_win_syslog_timestamp(
        m.group("month"), m.group("day"), m.group("time")
    )

    # Outcome từ EventType readable field
    et_lower = event_type_raw.lower()
    if "failure" in et_lower:
        outcome = "failure"
    elif "success audit" in et_lower or "success" in et_lower:
        outcome = "success"
    elif "error" in et_lower:
        outcome = "failure"
    elif "warning" in et_lower:
        outcome = "warning"
    else:
        outcome = WIN_EVENTID_OUTCOME_MAP.get(event_id, "info")

    # Severity
    rule_level = (
        WIN_EVENTID_SEVERITY_EXT.get(event_id)
        or WIN_EVENTID_SEVERITY_MAP.get(event_id)
        or (5 if outcome in ("failure", "warning") else 3)
    )

    # Action có ý nghĩa
    action = _win_action_from_eventid(event_id, source_name, log_name)

    def first_line(msg, limit=200):
        if not msg:
            return ""
        for sep in [".\\r\\n", ".\\n", ". "]:
            if sep in msg:
                return msg.split(sep)[0].strip()[:limit] + "."
        return msg.strip()[:limit]

    summary = first_line(message) or f"{log_name}: {source_name} (EventID {event_id})"

    return {
        "time":           ts,
        "log_type":       "win",
        "vendor":         "Microsoft",
        "action":         action,
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
        "message":     summary,
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
            "eventOutcomeRaw":           event_type_raw,
        },
    }'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "_win_action_from_eventid" in content:
        print("⏭️  Already applied")
        return

    if OLD_WIN_FUNC not in content:
        print("⚠️  Pattern NOT FOUND")
        idx = content.find("def normalize_windows_eventlog_direct")
        print(f"   Function at char: {idx}")
        return

    content = content.replace(OLD_WIN_FUNC, NEW_WIN_FUNC)
    print("✅ normalize_windows_eventlog_direct() rewritten with action mapping")

    with open(PATH, "w") as f:
        f.write(content)

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")


if __name__ == "__main__":
    apply_patch()
