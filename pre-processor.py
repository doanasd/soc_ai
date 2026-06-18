#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pre-processor: Convert raw log lines → Wazuh-like JSON archive
Supports: syslog text, Cisco IOS, WAF JSON, VPC JSON, CloudTrail JSON
Output: JSONL, each line is a Wazuh-like JSON object ready for normalize-service.py
"""
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

RAW_LOG_PATH = os.getenv("ORIGINAL_RAW_LOG", "/home/ubuntu/soc_ai/raw_sample.json")
OUTPUT_FILE  = os.getenv("NORMALIZED_PATH", "/home/ubuntu/soc_ai/log_normalized.json")
# Pre-processor writes to an intermediate file
OUTPUT_FILE  = os.getenv("PREPROCESSED_PATH", "/home/ubuntu/soc_ai/log_preprocessed.json")
LOG_START_POSITION = os.getenv("LOG_START_POSITION", "end")

# ── Syslog patterns ───────────────────────────────────────────────────────────

SYSLOG_RE = re.compile(
    r'^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<program>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$',
    re.DOTALL
)

CISCO_RE = re.compile(r'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)')

# MSWinEventLog: syslog-forwarded Windows Event Log (PRI header + MSWinEventLog marker)
# Format: <PRI>MMM DD HH:MM:SS hostname MSWinEventLog\tTYPE\tLOGNAME\tRECID\tTIMEGEN\tSOURCE\t...\tCATEGORY\tHOSTNAME\tEVENTID/SRC\tMESSAGE\tRECID2
MSWINEVENTLOG_RE = re.compile(
    r'^(?:<\d+>)?'                                    # optional PRI <14>
    r'(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'MSWinEventLog\s+(?P<rest>.*)$'
)


# SSH decoder patterns
SSH_FAIL_RE    = re.compile(r'(?:Failed password|Invalid user|authentication failure).*?from\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)', re.I)
SSH_ACCEPT_RE  = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)', re.I)
SSH_CLOSED_RE  = re.compile(r'Connection closed by (?:invalid user \S+ )?(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)', re.I)
SUDO_RE        = re.compile(r'(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)', re.I)
PAM_RE         = re.compile(r'pam_unix\(([^)]+)\):\s*(.*)')

MONTH_MAP = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12
}

def parse_syslog_timestamp(month: str, day: str, time_str: str) -> str:
    now = datetime.now(timezone.utc)
    try:
        m = MONTH_MAP.get(month, 1)
        d = int(day)
        h, mi, s = map(int, time_str.split(":"))
        year = now.year if m <= now.month else now.year - 1
        dt = datetime(year, m, d, h, mi, s, tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return now.isoformat().replace("+00:00", "Z")

def classify_syslog(program: str, message: str):
    """Returns (rule_id, rule_level, rule_description, groups, decoder_name, src_ip, src_port, user)"""
    prog = program.strip().lower()
    msg  = message.strip()

    # SSH
    if prog in ("sshd",):
        m = SSH_FAIL_RE.search(msg)
        if m:
            return ("5710", 10, "sshd: Attempt to login using a non-existent user",
                    ["syslog","sshd","authentication_failed"], "sshd",
                    m.group(1), m.group(2), None)
        m = SSH_ACCEPT_RE.search(msg)
        if m:
            return ("5715", 3, "sshd: authentication success",
                    ["syslog","sshd","authentication_success"], "sshd",
                    m.group(2), m.group(3), m.group(1))
        m = SSH_CLOSED_RE.search(msg)
        if m:
            return ("5710", 5, "sshd: connection closed",
                    ["syslog","sshd"], "sshd", m.group(1), m.group(2), None)
        if "invalid user" in msg.lower():
            ip_m = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg)
            return ("5710", 10, "sshd: Invalid user",
                    ["syslog","sshd","authentication_failed"], "sshd",
                    ip_m.group(1) if ip_m else None, None, None)
        return ("5700", 5, f"sshd: {msg[:80]}",
                ["syslog","sshd"], "sshd", None, None, None)

    # sudo
    if prog in ("sudo",):
        m = SUDO_RE.search(msg)
        if m:
            return ("5402", 3, f"sudo: {m.group(1)} ran {m.group(3)[:60]} as {m.group(2)}",
                    ["syslog","sudo"], "sudo", None, None, m.group(1))
        return ("5400", 3, f"sudo: {msg[:80]}", ["syslog","sudo"], "sudo", None, None, None)

    # PAM
    if "pam" in prog or "pam_unix" in msg.lower():
        m = PAM_RE.search(msg)
        if m:
            context, detail = m.group(1), m.group(2)
            if "session opened" in detail:
                user_m = re.search(r'for user (\S+)', detail)
                return ("5501", 3, f"PAM: session opened for {context}",
                        ["syslog","pam","authentication_success"], "pam",
                        None, None, user_m.group(1) if user_m else None)
            if "session closed" in detail:
                return ("5502", 3, f"PAM: session closed for {context}",
                        ["syslog","pam"], "pam", None, None, None)
        return ("5500", 3, f"PAM: {msg[:80]}", ["syslog","pam"], "pam", None, None, None)

    # CRON
    if prog in ("cron", "crond"):
        return ("2830", 3, f"CRON: {msg[:80]}", ["syslog","cron"], "cron", None, None, None)

    # systemd / systemd-logind
    if "systemd" in prog:
        if "new session" in msg.lower():
            return ("5501", 3, f"systemd-logind: {msg[:80]}",
                    ["syslog","systemd","authentication_success"], "systemd",
                    None, None, None)
        return ("1002", 3, f"systemd: {msg[:80]}", ["syslog","systemd"], "systemd", None, None, None)

    # openvpn
    if "openvpn" in prog or "ovpn" in prog:
        if "failed" in msg.lower() or "error" in msg.lower():
            return ("8001", 5, f"OpenVPN: {msg[:80]}",
                    ["syslog","openvpn","authentication_failed"], "openvpn",
                    None, None, None)
        return ("8000", 3, f"OpenVPN: {msg[:80]}", ["syslog","openvpn"], "openvpn", None, None, None)

    # audit
    if prog in ("audit", "auditd"):
        return ("80700", 3, f"audit: {msg[:80]}", ["syslog","audit"], "auditd", None, None, None)

    # kernel
    if prog in ("kernel",):
        return ("1010", 3, f"kernel: {msg[:80]}", ["syslog","kernel"], "kernel", None, None, None)

    # Default
    return ("1002", 3, f"{program}: {msg[:80]}", ["syslog","linux"], "syslog", None, None, None)

def wrap_syslog(line: str) -> Optional[dict]:
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    host    = m.group("host")
    program = m.group("program").strip()
    pid     = m.group("pid")
    message = m.group("message").strip()
    ts      = parse_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"))

    rule_id, rule_level, rule_desc, groups, decoder_name, src_ip, src_port, user = \
        classify_syslog(program, message)

    return {
        "timestamp": ts,
        "location":  f"/var/log/syslog",
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule_desc,
            "groups": groups,
        },
        "agent": {"name": host, "ip": ""},
        "decoder": {"name": decoder_name},
        "predecoder": {
            "hostname": host,
            "program_name": program,
            "pid": pid or "",
        },
        "data": {
            "srcip": src_ip or "",
            "srcport": src_port or "",
            "dstuser": user or "",
        },
        "full_log": line.strip(),
        "_pre_processed": True,
        "_source_format": "syslog",
    }

def wrap_cisco(line: str) -> Optional[dict]:
    m = CISCO_RE.search(line.strip())
    if not m:
        return None
    facility = m.group("facility")
    sev      = int(m.group("severity"))
    mnemonic = m.group("mnemonic")
    message  = m.group("message").strip()

    # Extract source IP từ syslog header (tìm IP trong các token đầu)
    src_host = "cisco"
    for token in line.strip().split()[:5]:
        if re.match(r'\d+\.\d+\.\d+\.\d+', token):
            src_host = token
            break

    rule_level = {0:12, 1:12, 2:10, 3:8, 4:6, 5:4, 6:3, 7:3}.get(sev, 3)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "location":  f"/cisco/syslog",
        "rule": {
            "id": f"cisco_{mnemonic.lower()}",
            "level": rule_level,
            "description": f"Cisco {facility}-{sev}-{mnemonic}: {message[:80]}",
            "groups": ["cisco", "network", facility.lower()],
        },
        "agent": {"name": src_host, "ip": src_host if re.match(r'\d+\.\d+\.\d+\.\d+', src_host) else ""},
        "decoder": {"name": "cisco-ios"},
        "predecoder": {"hostname": src_host, "program_name": "cisco-ios"},
        "data": {
            "facility": facility,
            "severity": str(sev),
            "mnemonic": mnemonic,
            "message":  message,
        },
        "full_log": line.strip(),
        "_pre_processed": True,
        "_source_format": "cisco_ios",
    }

def classify_mswineventlog(fields: list, full_line: str):
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
    ip_m = re.search(r'(?:Source Network Address|IP Address|Network Address):\s*(\d+\.\d+\.\d+\.\d+)', message, re.I)
    if ip_m:
        src_ip = ip_m.group(1)
    else:
        ip_m2 = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
        if ip_m2:
            src_ip = ip_m2.group(1)

    # Extract target user nếu có
    target_user = None
    user_m = re.search(r'(?:Account Name|Logon Account|User):\s*(\S+)', message, re.I)
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
    fields = [f.strip() for f in rest.split("\t") if f.strip() != ""]
    if not fields:
        # Thử split bằng nhiều space liên tiếp nếu không có tab
        fields = [f.strip() for f in re.split(r'\s{2,}', rest) if f.strip() != ""]

    if len(fields) < 3:
        return None

    rule_id, rule_level, rule_desc, groups, event_id, src_ip, target_user, outcome = \
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


def wrap_cloudtrail(evt: dict) -> Optional[dict]:
    """CloudTrail JSON → Wazuh-like archive"""
    aws = evt.get("aws", {})
    if not aws:
        return None

    event_name   = aws.get("eventName", "")
    event_source = aws.get("eventSource", "")
    event_time   = aws.get("eventTime", datetime.now(timezone.utc).isoformat())
    src_ip       = aws.get("sourceIPAddress", "")
    user_agent   = aws.get("userAgent", "")
    region       = aws.get("awsRegion", "")
    read_only    = aws.get("readOnly", True)
    account_id   = aws.get("aws_account_id") or aws.get("accountId", "")

    user_identity = aws.get("userIdentity", {})
    user_type     = user_identity.get("type", "")
    user_arn      = user_identity.get("arn", "")
    user_name     = ""
    if "sessionContext" in user_identity:
        user_name = user_identity["sessionContext"].get("sessionIssuer", {}).get("userName", "")
    if not user_name:
        user_name = user_identity.get("userName", user_arn.split("/")[-1] if user_arn else "")

    # Risk classification
    HIGH_RISK_EVENTS = {
        "CreateUser","DeleteUser","AttachUserPolicy","DetachUserPolicy",
        "CreateAccessKey","DeleteAccessKey","PutUserPolicy","AddUserToGroup",
        "CreateRole","DeleteRole","AttachRolePolicy","PutRolePolicy",
        "CreateGroup","DeleteGroup","AttachGroupPolicy",
        "AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress",
        "CreateSecurityGroup","DeleteSecurityGroup",
        "ModifyInstanceAttribute","RunInstances","TerminateInstances",
        "CreateBucket","DeleteBucket","PutBucketPolicy","DeleteBucketPolicy",
        "ConsoleLogin","StopLogging","DeleteTrail","UpdateTrail",
    }
    MEDIUM_RISK_EVENTS = {
        "ListUsers","ListRoles","ListBuckets","DescribeInstances",
        "GetSecretValue","ListSecrets","DescribeSecurityGroups",
        "ListAnalyzers","GetBucketAcl","GetBucketPolicy",
    }

    if event_name in HIGH_RISK_EVENTS:
        rule_level = 10
        rule_id    = "cloudtrail_high"
        groups     = ["cloudtrail","aws","high_risk_api"]
    elif event_name in MEDIUM_RISK_EVENTS:
        rule_level = 5
        rule_id    = "cloudtrail_medium"
        groups     = ["cloudtrail","aws","enumeration"]
    elif not read_only:
        rule_level = 6
        rule_id    = "cloudtrail_write"
        groups     = ["cloudtrail","aws","write_api"]
    else:
        rule_level = 3
        rule_id    = "cloudtrail_read"
        groups     = ["cloudtrail","aws","read_api"]

    # Service-specific context message
    error_code = aws.get("errorCode", "")
    error_msg  = aws.get("errorMessage", "")
    if error_code:
        rule_level = min(rule_level + 2, 12)
        groups.append("api_error")

    description = f"CloudTrail: {event_name} via {event_source}"
    if error_code:
        description += f" [ERROR: {error_code}]"

    return {
        "timestamp": event_time,
        "location":  f"/aws/cloudtrail/{region}",
        "rule": {
            "id":          rule_id,
            "level":       rule_level,
            "description": description,
            "groups":      groups,
        },
        "agent": {
            "name": f"aws-{account_id}",
            "ip":   src_ip if re.match(r'\d+\.\d+\.\d+\.\d+', src_ip) else "",
        },
        "decoder": {"name": "cloudtrail"},
        "predecoder": {
            "hostname":     f"aws-{region}",
            "program_name": "cloudtrail",
        },
        "data": {
            "srcip":        src_ip,
            "dstuser":      user_name,
            "aws_event":    event_name,
            "aws_source":   event_source,
            "aws_region":   region,
            "aws_account":  account_id,
            "user_type":    user_type,
            "user_arn":     user_arn,
            "user_agent":   user_agent,
            "read_only":    str(read_only),
            "error_code":   error_code,
            "error_message": error_msg,
            "request_id":   aws.get("requestID", ""),
            "event_id":     aws.get("eventID", ""),
        },
        "full_log": json.dumps(aws, ensure_ascii=False)[:500],
        "cloudtrail": aws,
        "_pre_processed": True,
        "_source_format": "cloudtrail",
    }

def is_passthrough(evt: dict) -> bool:
    """Log đã là Wazuh-like JSON hoặc WAF/VPC → pass-through không wrap"""
    loc = evt.get("location", "")
    if isinstance(loc, str):
        if loc.startswith("/tmp/aws-waf/"):
            return True
        if loc.startswith("/tmp/fortinet/"):
            return True
    if evt.get("rule") and evt.get("full_log"):
        return True  # Đã là Wazuh archive
    data = evt.get("data", {})
    if isinstance(data, dict) and data.get("type") == "aws_vpc_flow":
        return True
    if "httpRequest" in evt and "webaclId" in evt:
        return True
    return False

def preprocess_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None

    # Try JSON parse first
    if line.startswith("{"):
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            return None

        # CloudTrail format
        if evt.get("integration") == "aws" and "aws" in evt:
            aws = evt.get("aws", {})
            if aws.get("source") == "cloudtrail" or aws.get("eventVersion"):
                return wrap_cloudtrail(evt)

        # Pass-through (WAF, VPC, Wazuh archive)
        if is_passthrough(evt):
            return evt

        # Unknown JSON — try to pass through anyway
        return evt

    # Cisco IOS syslog — '%' phải có trong line
    if '%' in line and re.search(r'%[A-Z0-9_]+-\d-[A-Z0-9_]+:', line):
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

    return None


def follow_file(path, start_from_beginning=False):
    f = None; last_inode = None; first_open = True; buf = ""
    while True:
        try:
            st = os.stat(path); inode = st.st_ino
            if f is None or inode != last_inode:
                if f:
                    try: f.close()
                    except: pass
                f = open(path, "r", encoding="utf-8", errors="replace")
                last_inode = inode; buf = ""
                if first_open:
                    if not start_from_beginning:
                        f.seek(0, os.SEEK_END)
                    first_open = False
                else:
                    f.seek(0, os.SEEK_SET)
            if st.st_size < f.tell():
                f.seek(0, os.SEEK_SET); buf = ""
            chunk = f.read(4096)
            if not chunk:
                time.sleep(0.05); continue
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                yield line
        except FileNotFoundError:
            time.sleep(0.5)
        except Exception as e:
            print(f"[WARN] follow_file: {e}"); time.sleep(0.5)


def main():
    os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_FILE)), exist_ok=True)
    start_beginning = LOG_START_POSITION.strip().lower() == "beginning"

    stats = {"passthrough":0, "syslog":0, "cisco":0, "cloudtrail":0, "mswineventlog":0, "skipped":0, "errors":0}

    print(f"[pre-processor] Starting...")
    print(f"[pre-processor] Input:  {RAW_LOG_PATH}")
    print(f"[pre-processor] Output: {OUTPUT_FILE}")
    print(f"[pre-processor] Start position: {'beginning' if start_beginning else 'end (tail mode)'}")

    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        for line in follow_file(RAW_LOG_PATH, start_from_beginning=start_beginning):
            if not line.strip():
                continue
            try:
                result = preprocess_line(line)
            except Exception as e:
                print(f"[pre-processor] ERROR: {e} | line: {line[:80]}")
                stats["errors"] += 1
                continue

            if result is None:
                stats["skipped"] += 1
                continue

            src = result.get("_source_format", "passthrough")
            stats[src if src in stats else "passthrough"] += 1

            out.write(json.dumps(result, ensure_ascii=False, default=str) + "\n")
            out.flush()

            total = sum(stats[k] for k in ("passthrough","syslog","cisco","cloudtrail","mswineventlog"))
            print(
                f"[pre-processor] +1 {src:14s} | "
                f"total={total} pass={stats['passthrough']} "
                f"syslog={stats['syslog']} cisco={stats['cisco']} "
                f"cloudtrail={stats['cloudtrail']} win={stats['mswineventlog']} "
                f"skip={stats['skipped']}"
            )

if __name__ == "__main__":
    main()
