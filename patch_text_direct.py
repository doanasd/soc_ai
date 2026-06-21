#!/usr/bin/env python3
"""
Patch normalize-service.py: thêm khả năng nhận diện và parse TRỰC TIẾP
3 loại raw text (không qua pre-processor):
  - Cisco IOS syslog: %FACILITY-SEV-MNEMONIC: message
  - FortiGate syslog: date=... devname="..." key=value...
  - Linux syslog: MMM DD HH:MM:SS host program[pid]: message

Logic: viết lại normalize_linux_event() và normalize_cisco_event() để tự
classify trực tiếp từ full_log text thay vì đọc rule/data đã pre-processed.
Thêm hàm route_text_line() dùng trong main() loop.

Chạy trên EC2: python3 patch_text_direct.py
"""

PATH = "/home/ubuntu/soc_ai/normalize-service.py"

# ── 1. Viết lại normalize_linux_event() để tự classify từ raw text ─────────
OLD_LINUX_FUNC_START = '''def normalize_linux_event(archive_evt: dict) -> Optional[dict]:
    full_log_raw = archive_evt.get("full_log", "")
    data         = archive_evt.get("data", {}) or {}
    rule         = archive_evt.get("rule", {}) or {}
    agent        = archive_evt.get("agent", {}) or {}
    decoder      = archive_evt.get("decoder", {}) or {}
    predecoder   = archive_evt.get("predecoder", {}) or {}
    rule_id          = rule.get("id", "")
    rule_level       = rule.get("level", 0)
    rule_description = rule.get("description", "")
    decoder_name     = decoder.get("name", "")
    action   = classify_linux_action(rule_id, full_log_raw, decoder_name)
    outcome  = outcome_from_wazuh_level(rule_level)
    src_ip   = extract_linux_source_ip(full_log_raw, data)
    user     = extract_linux_user(full_log_raw, data)
    hostname = predecoder.get("hostname") or agent.get("name") or agent.get("ip") or ""'''

NEW_LINUX_FUNC_START = '''# Standard Linux syslog format: MMM DD HH:MM:SS host program[pid]: message
LINUX_SYSLOG_RE = re.compile(
    r'^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+'
    r'(?P<day>\\d+)\\s+(?P<time>\\d{2}:\\d{2}:\\d{2})\\s+'
    r'(?P<host>\\S+)\\s+'
    r'(?P<program>[^\\[:]+?)(?:\\[(?P<pid>\\d+)\\])?:\\s*'
    r'(?P<message>.*)$',
    re.DOTALL
)
MONTH_MAP_LINUX = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12
}

def _parse_linux_syslog_ts(month: str, day: str, time_str: str) -> str:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    try:
        m = MONTH_MAP_LINUX.get(month, 1)
        d = int(day)
        h, mi, s = map(int, time_str.split(":"))
        year = now.year if m <= now.month else now.year - 1
        dt = datetime(year, m, d, h, mi, s, tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return now.isoformat().replace("+00:00", "Z")


def classify_linux_program(program: str, message: str):
    """
    Tự classify Linux syslog program/message trực tiếp từ raw text
    (thay thế việc pre-processor từng làm).
    Trả về (rule_id, rule_level, rule_description, groups, decoder_name)
    """
    prog = program.strip().lower()
    msg  = message.strip()

    if prog == "sshd":
        if re.search(r'(?:Failed password|Invalid user|authentication failure)', msg, re.I):
            return ("5710", 10, "sshd: Attempt to login using a non-existent or invalid user",
                    ["syslog","sshd","authentication_failed"], "sshd")
        if re.search(r'Accepted (?:password|publickey)', msg, re.I):
            return ("5715", 3, "sshd: authentication success",
                    ["syslog","sshd","authentication_success"], "sshd")
        if "connection closed" in msg.lower():
            return ("5710", 5, "sshd: connection closed",
                    ["syslog","sshd"], "sshd")
        return ("5700", 5, f"sshd: {msg[:80]}", ["syslog","sshd"], "sshd")

    if prog == "sudo":
        if re.search(r'COMMAND=', msg):
            return ("5402", 3, f"sudo: {msg[:80]}", ["syslog","sudo"], "sudo")
        return ("5400", 3, f"sudo: {msg[:80]}", ["syslog","sudo"], "sudo")

    if prog in ("cron",) or prog == "cron":
        if "session opened" in msg.lower():
            return ("2830", 3, f"CRON: {msg[:80]}", ["syslog","cron","authentication_success"], "cron")
        return ("2830", 3, f"CRON: {msg[:80]}", ["syslog","cron"], "cron")

    if "pam_unix" in msg.lower() or "pam" in prog:
        if "session opened" in msg.lower():
            return ("5501", 3, f"PAM: {msg[:80]}", ["syslog","pam","authentication_success"], "pam")
        if "session closed" in msg.lower():
            return ("5502", 3, f"PAM: {msg[:80]}", ["syslog","pam"], "pam")
        if "authentication failure" in msg.lower():
            return ("5503", 5, f"PAM: {msg[:80]}", ["syslog","pam","authentication_failed"], "pam")
        return ("5500", 3, f"PAM: {msg[:80]}", ["syslog","pam"], "pam")

    if "systemd-logind" in prog:
        if "new session" in msg.lower():
            return ("5501", 5, f"systemd-logind: {msg[:80]}",
                    ["syslog","systemd","authentication_success"], "systemd")
        return ("1002", 3, f"systemd-logind: {msg[:80]}", ["syslog","systemd"], "systemd")

    if "systemd" in prog and "systemd-logind" not in prog:
        return ("1002", 2, f"systemd: {msg[:80]}", ["syslog","systemd"], "systemd")

    if "openvpn" in prog or "ovpn" in prog:
        if re.search(r'failed|error', msg, re.I):
            return ("8001", 5, f"OpenVPN: {msg[:80]}",
                    ["syslog","openvpn","authentication_failed"], "openvpn")
        return ("8000", 3, f"OpenVPN: {msg[:80]}", ["syslog","openvpn"], "openvpn")

    if prog in ("audit", "auditd"):
        return ("80700", 3, f"audit: {msg[:80]}", ["syslog","audit"], "auditd")

    if prog == "kernel":
        return ("1010", 2, f"kernel: {msg[:80]}", ["syslog","kernel"], "kernel")

    if "smartd" in prog:
        if "prefailure" in msg.lower():
            return ("2900", 8, f"smartd: {msg[:80]}", ["syslog","disk","prefailure"], "smartd")
        return ("2900", 2, f"smartd: {msg[:80]}", ["syslog","disk"], "smartd")

    if "snapd" in prog or "dbus-daemon" in prog or "fwupd" in prog or "fwupdmgr" in prog \\
            or "fstrim" in prog or "50-motd-news" in prog or "apt-helper" in prog \\
            or "systemd-networkd-wait-online" in prog or "systemd-resolved" in prog:
        return ("1002", 1, f"{program}: {msg[:80]}", ["syslog","platform_noise"], prog)

    if "python" in prog or "python3" in prog:
        return ("1003", 2, f"{program}: {msg[:80]}", ["syslog","application"], "python")

    if "opensearch" in prog:
        return ("1003", 1, f"opensearch: {msg[:80]}", ["syslog","application"], "opensearch")

    return ("1002", 2, f"{program}: {msg[:80]}", ["syslog","linux"], "syslog")


def normalize_linux_event(archive_evt: dict) -> Optional[dict]:
    full_log_raw = archive_evt.get("full_log", "")
    data         = archive_evt.get("data", {}) or {}
    rule         = archive_evt.get("rule", {}) or {}
    agent        = archive_evt.get("agent", {}) or {}
    decoder      = archive_evt.get("decoder", {}) or {}
    predecoder   = archive_evt.get("predecoder", {}) or {}

    # Nếu chưa có rule (raw text trực tiếp, chưa pre-processed) → tự classify
    if not rule.get("id") and full_log_raw:
        m = LINUX_SYSLOG_RE.match(full_log_raw.strip())
        if m:
            program = m.group("program").strip()
            message = m.group("message").strip()
            host    = m.group("host")
            rule_id, rule_level, rule_desc, groups, decoder_name = \\
                classify_linux_program(program, message)
            rule = {"id": rule_id, "level": rule_level, "description": rule_desc, "groups": groups}
            decoder = {"name": decoder_name}
            predecoder = {"hostname": host, "program_name": program, "pid": m.group("pid") or ""}
            if not archive_evt.get("timestamp"):
                archive_evt["timestamp"] = _parse_linux_syslog_ts(
                    m.group("month"), m.group("day"), m.group("time")
                )

    rule_id          = rule.get("id", "")
    rule_level       = rule.get("level", 0)
    rule_description = rule.get("description", "")
    decoder_name     = decoder.get("name", "")
    action   = classify_linux_action(rule_id, full_log_raw, decoder_name)
    outcome  = outcome_from_wazuh_level(rule_level)
    src_ip   = extract_linux_source_ip(full_log_raw, data)
    user     = extract_linux_user(full_log_raw, data)
    hostname = predecoder.get("hostname") or agent.get("name") or agent.get("ip") or ""'''

# ── 2. Viết lại normalize_cisco_event() để tự parse từ raw text ────────────
OLD_CISCO_FUNC = '''def normalize_cisco_event(archive_evt: dict) -> Optional[dict]:
    """Cisco IOS syslog đã qua pre-processor → normalize về schema chuẩn."""
    data      = archive_evt.get("data", {}) or {}
    rule      = archive_evt.get("rule", {}) or {}
    agent     = archive_evt.get("agent", {}) or {}
    predecoder = archive_evt.get("predecoder", {}) or {}

    facility = data.get("facility", "")
    severity = int(data.get("severity", "5"))
    mnemonic = data.get("mnemonic", "")
    message  = data.get("message", archive_evt.get("full_log", "")[:200])
    src_host = agent.get("ip") or agent.get("name") or predecoder.get("hostname", "")'''

NEW_CISCO_FUNC = '''CISCO_TEXT_RE = re.compile(r'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\\d)-(?P<mnemonic>[A-Z0-9_]+):\\s*(?P<message>.*)')


def normalize_cisco_event(archive_evt: dict) -> Optional[dict]:
    """Normalize Cisco IOS syslog — hỗ trợ cả raw text trực tiếp và pre-processed."""
    data      = archive_evt.get("data", {}) or {}
    rule      = archive_evt.get("rule", {}) or {}
    agent     = archive_evt.get("agent", {}) or {}
    predecoder = archive_evt.get("predecoder", {}) or {}
    full_log_raw = archive_evt.get("full_log", "")

    # Nếu chưa có data đã pre-processed → tự parse từ raw text
    if not data.get("mnemonic") and full_log_raw:
        m = CISCO_TEXT_RE.search(full_log_raw)
        if m:
            data = {
                "facility": m.group("facility"),
                "severity": m.group("severity"),
                "mnemonic": m.group("mnemonic"),
                "message":  m.group("message").strip(),
            }
            # Tìm IP thiết bị ở đầu dòng (syslog header)
            ip_m = re.search(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b', full_log_raw[:60])
            device_ip = ip_m.group(1) if ip_m else ""
            agent = {"ip": device_ip, "name": device_ip}
            predecoder = {"hostname": device_ip}

    facility = data.get("facility", "")
    severity = int(data.get("severity", "5") or "5")
    mnemonic = data.get("mnemonic", "")
    message  = data.get("message", full_log_raw[:200] if full_log_raw else "")
    src_host = agent.get("ip") or agent.get("name") or predecoder.get("hostname", "")'''

# ── 3. Sửa Fortinet để chấp nhận raw text trực tiếp (đã hoạt động qua full_log) ──
# normalize_fortinet_event() đã hoạt động đúng nếu archive_evt = {"full_log": line}
# Không cần sửa hàm, chỉ cần đảm bảo main() wrap đúng.

# ── 4. Thêm hàm route_text_line() để thử các parser theo thứ tự ưu tiên ────
INSERT_BEFORE = "def _is_linux_event(archive_evt: dict) -> bool:"

NEW_ROUTER_FUNC = '''def route_text_line(line: str) -> Optional[dict]:
    """
    Nhận diện và normalize một dòng raw text (không phải JSON, không phải
    MSWinEventLog) — thử lần lượt Cisco, FortiGate, rồi Linux syslog.
    Trả về normalized dict hoặc None nếu không khớp loại nào.
    """
    stripped = line.strip()
    if not stripped:
        return None

    # 1. Cisco IOS — pattern %FACILITY-SEV-MNEMONIC rất đặc trưng, thử trước
    if re.search(r'%[A-Z0-9_]+-\\d-[A-Z0-9_]+:', stripped):
        result = normalize_cisco_event({"full_log": stripped})
        if result:
            return result

    # 2. FortiGate — đặc trưng bởi devname= hoặc devid=
    if "devname=" in stripped or "devid=" in stripped:
        result = normalize_fortinet_event({"full_log": stripped})
        if result:
            return result

    # 3. Linux syslog — fallback cuối cùng (pattern chung nhất)
    if LINUX_SYSLOG_RE.match(stripped):
        archive_evt = {"full_log": stripped}
        result = normalize_linux_event(archive_evt)
        if result:
            return result

    return None


def _is_linux_event(archive_evt: dict) -> bool:'''

# ── 5. Sửa main() loop để gọi route_text_line() khi JSON parse thất bại ────
OLD_MAIN_JSON_FAIL = '''            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                stats["errors"] += 1
                continue
            norm = normalize_event(evt)
            if not norm:
                stats["skipped"] += 1
                continue'''

NEW_MAIN_JSON_FAIL = '''            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                # Không phải JSON — thử các parser text trực tiếp
                # (Cisco IOS, FortiGate, Linux syslog)
                norm = route_text_line(line)
                if norm:
                    out.write(json.dumps(norm, ensure_ascii=False) + "\\n")
                    out.flush()
                    log_type = norm.get("log_type")
                    mapped = TYPE_MAP.get(log_type)
                    if mapped:
                        stats[mapped] += 1
                        total = sum(stats[k] for k in ("waf","vpc","windows","linux","fortinet","cloudtrail","cisco"))
                        print(f"[normalize] +1 {log_type:10s} | total={total} (direct text)")
                    continue
                stats["errors"] += 1
                continue
            norm = normalize_event(evt)
            if not norm:
                stats["skipped"] += 1
                continue'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "route_text_line" in content:
        print("⏭️  Already applied")
        return

    patches = [
        ("Linux syslog direct classifier", OLD_LINUX_FUNC_START, NEW_LINUX_FUNC_START),
        ("Cisco direct parser",            OLD_CISCO_FUNC, NEW_CISCO_FUNC),
        ("Router function insert",         INSERT_BEFORE, NEW_ROUTER_FUNC),
        ("Main loop text fallback",        OLD_MAIN_JSON_FAIL, NEW_MAIN_JSON_FAIL),
    ]

    for name, old, new in patches:
        count = content.count(old)
        if count == 1:
            content = content.replace(old, new)
            print(f"✅ {name}: applied")
        elif count == 0:
            print(f"⚠️  {name}: pattern NOT FOUND")
        else:
            print(f"⚠️  {name}: found {count} times — ambiguous")

    with open(PATH, "w") as f:
        f.write(content)

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    if r.returncode == 0:
        print("\\n✅ Syntax check PASSED")
    else:
        print(f"\\n❌ Syntax error:\\n{r.stderr}")


if __name__ == "__main__":
    apply_patch()
