#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Log Normalizer — AWS WAF, VPC Flow, Windows, Linux, Fortinet FortiGate
"""

import json
import os
import re
import time
from typing import Optional

RAW_LOG_PATH = os.getenv("RAW_LOG_PATH",    "/home/ubuntu/soc_ai/raw_sample.json")
OUTPUT_FILE  = os.getenv("NORMALIZED_PATH", "/home/ubuntu/soc_ai/log_normalized.json")

WAF_LOCATION_PREFIX        = "/tmp/aws-waf/waf/"
VPC_LOCATION_PREFIX        = "/tmp/aws-waf/vpc/"
FORTINET_LOCATION_PREFIX   = "/tmp/fortinet/"
CISCO_LOCATION_PREFIX      = "/tmp/cisco/"

LINUX_LOG_LOCATIONS = (
    "/var/log/syslog", "/var/log/auth.log", "/var/log/secure",
    "/var/log/messages", "/var/log/kern.log", "/var/log/cron",
    "/var/log/audit/audit.log", "/var/log/daemon.log", "/var/log/maillog",
    "/var/log/boot.log", "/var/log/firewalld", "/var/log/journal",
)

def safe_get(d, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return ""
        cur = cur[k]
    return cur if cur is not None else ""

def parse_json_safe(raw):
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}

WAF_ACTION_GROUPS = {
    "allowed": {"ALLOW", "PERMIT", "ACCEPT", "PASS"},
    "blocked": {"BLOCK", "DENY", "DROP", "REJECT"},
    "monitor": {"COUNT", "MONITOR", "LOG", "DETECT"},
}
ACTION_GROUP_TO_OUTCOME = {"allowed": "allowed", "blocked": "blocked", "monitor": "allowed"}

def outcome_from_waf_action(action: str) -> str:
    a = (action or "").strip().upper()
    for group, actions in WAF_ACTION_GROUPS.items():
        if a in actions:
            return ACTION_GROUP_TO_OUTCOME.get(group, "unknown")
    return "unknown"

def extract_user_agent(headers) -> str:
    if not isinstance(headers, list):
        return ""
    for h in headers:
        if isinstance(h, dict) and h.get("name", "").lower() == "user-agent":
            return h.get("value", "")
    return ""

def normalize_waf_event(archive_evt: dict) -> Optional[dict]:
    waf = parse_json_safe(archive_evt.get("full_log", ""))
    if not waf:
        data = archive_evt.get("data", {})
        if isinstance(data, dict):
            waf = data
    if not isinstance(waf, dict) or not waf:
        return None
    if "httpRequest" not in waf and "webaclId" not in waf and "action" not in waf:
        return None
    action  = waf.get("action", "")
    headers = safe_get(waf, "httpRequest", "headers")
    if not isinstance(headers, list):
        headers = []
    return {
        "time":           waf.get("timestamp", ""),
        "log_type":       "waf",
        "vendor":         "aws",
        "action":         action.lower(),
        "outcome":        outcome_from_waf_action(action),
        "asset_host":     waf.get("httpSourceId", ""),
        "correlation_id": safe_get(waf, "httpRequest", "requestId"),
        "network": {
            "source_ip":        safe_get(waf, "httpRequest", "clientIp"),
            "source_port":      None,
            "country":          safe_get(waf, "httpRequest", "country"),
            "destination_ip":   safe_get(waf, "httpRequest", "host"),
            "destination_port": None,
            "protocol":         safe_get(waf, "httpRequest", "httpVersion"),
            "method":           safe_get(waf, "httpRequest", "httpMethod"),
        },
        "message":     f"WAF {action} request to {safe_get(waf, 'httpRequest', 'uri')}",
        "maliciousIP": None,
        "waf": {
            "webacl_id":                      waf.get("webaclId"),
            "http_source_name":               waf.get("httpSourceName"),
            "terminating_rule_id":            waf.get("terminatingRuleId"),
            "terminating_rule_type":          waf.get("terminatingRuleType"),
            "terminating_rule_match_details": waf.get("terminatingRuleMatchDetails", []),
            "labels":                         waf.get("labels", []),
            "rule_groups":                    waf.get("ruleGroupList", []),
            "rate_based":                     waf.get("rateBasedRuleList", []),
            "non_terminating_matching_rules": waf.get("nonTerminatingMatchingRules", []),
            "response_code_sent":             waf.get("responseCodeSent"),
            "uri":                            safe_get(waf, "httpRequest", "uri"),
            "args":                           safe_get(waf, "httpRequest", "args"),
            "host_header":                    safe_get(waf, "httpRequest", "host"),
            "scheme":                         safe_get(waf, "httpRequest", "scheme"),
            "user_agent":                     extract_user_agent(headers),
            "headers":                        headers,
            "ja3":                            waf.get("ja3Fingerprint"),
            "ja4":                            waf.get("ja4Fingerprint"),
            "requestBodySize":                waf.get("requestBodySize"),
        },
        "flow": "", "winEvent": "", "linuxEvent": "", "fortinet": "",
    }

def get_protocol_name(protocol_num: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol_num, str(protocol_num))

def outcome_from_vpc_action(action: str, log_status: str) -> str:
    outcome_map = {
        ("ACCEPT", "OK"):     "allowed",
        ("REJECT", "OK"):     "blocked",
        ("ACCEPT", "NODATA"): "allowed",
        ("REJECT", "NODATA"): "blocked",
    }
    a = (action or "").upper()
    s = (log_status or "").upper()
    if s == "SKIPDATA":
        return "unknown"
    return outcome_map.get((a, s), "unknown")

def normalize_vpc_flow_event(archive_evt: dict) -> Optional[dict]:
    log_data = archive_evt.get("data", {})
    if not isinstance(log_data, dict) or not log_data:
        log_data = parse_json_safe(archive_evt.get("full_log", ""))
    if not isinstance(log_data, dict) or log_data.get("type") != "aws_vpc_flow":
        return None
    flow = log_data.get("flow", {})
    if not isinstance(flow, dict) or not flow:
        return None
    protocol_num = flow.get("protocol")
    try:
        protocol_num = int(protocol_num) if protocol_num is not None else None
    except Exception:
        protocol_num = None
    def to_int(val):
        try:
            return int(val) if val not in (None, "", "null") else None
        except Exception:
            return None
    return {
        "time":           log_data.get("event_timestamp"),
        "log_type":       "vpc",
        "vendor":         "aws",
        "action":         (flow.get("action") or "").lower(),
        "outcome":        outcome_from_vpc_action(flow.get("action"), flow.get("log_status")),
        "asset_host":     flow.get("interface_id"),
        "correlation_id": log_data.get("event_id"),
        "network": {
            "source_ip":        flow.get("srcaddr"),
            "source_port":      to_int(flow.get("srcport")),
            "country":          None,
            "destination_ip":   flow.get("dstaddr"),
            "destination_port": to_int(flow.get("dstport")),
            "protocol":         get_protocol_name(protocol_num) if protocol_num is not None else None,
            "method":           None,
        },
        "message":     log_data.get("raw_message"),
        "maliciousIP": None,
        "flow": {
            "interface_id": flow.get("interface_id"),
            "packets":      to_int(flow.get("packets")),
            "bytes":        to_int(flow.get("bytes")),
            "start":        flow.get("start"),
            "end":          flow.get("end"),
            "action":       flow.get("action"),
            "log_status":   flow.get("log_status"),
            "account_id":   flow.get("account_id"),
            "logGroup":     log_data.get("logGroup"),
            "logStream":    log_data.get("logStream"),
        },
        "waf": "", "winEvent": "", "linuxEvent": "", "fortinet": "",
    }

def outcome_from_wazuh_level(level) -> str:
    try:
        lvl = int(level) if level is not None else 0
    except (ValueError, TypeError):
        return "unknown"
    if lvl >= 12: return "critical"
    if lvl >= 8:  return "failure"
    if lvl >= 5:  return "warning"
    if lvl >= 1:  return "success"
    return "info"

def classify_linux_action(rule_id, full_log: str, decoder_name: str) -> str:
    try:
        rid = int(rule_id) if rule_id else 0
    except (ValueError, TypeError):
        rid = 0
    fl  = (full_log or "").lower()
    dec = (decoder_name or "").lower()

    if rid in (5715, 5716):       return "ssh_login_success"
    if rid in (5710, 5711, 5712): return "ssh_login_failed"
    if rid in (5400, 5401, 5402): return "sudo_executed"
    if rid in (5901, 5902):       return "user_created"
    if rid in (5903, 5904):       return "user_deleted"

    if "sshd" in dec or "sshd" in fl:
        if "accepted" in fl:                          return "ssh_login_success"
        if "failed" in fl or "invalid user" in fl:    return "ssh_login_failed"
        if "disconnected" in fl:                      return "ssh_disconnect"
        return "ssh_event"
    if "sudo" in dec or "sudo" in fl:
        if "command" in fl: return "sudo_executed"
        return "sudo_event"
    if "useradd" in fl or "adduser" in fl: return "user_created"
    if "userdel" in fl:                    return "user_deleted"
    if "pam" in dec:
        if "authentication failure" in fl: return "pam_auth_failed"
        if "session opened" in fl:         return "pam_session_opened"
        if "session closed" in fl:         return "pam_session_closed"
        return "pam_event"

    # CRON
    if "cron" in dec:
        if "session opened" in fl:  return "cron_session_opened"
        if "session closed" in fl:  return "cron_session_closed"
        if "cmd" in fl or "command" in fl: return "cron_command_executed"
        return "cron_event"

    # systemd-logind (session events)
    if "systemd" in dec and "new session" in fl:
        return "session_opened"
    if "systemd" in dec:
        if "starting" in fl: return "service_starting"
        if "finished" in fl: return "service_finished"
        if "deactivated" in fl: return "service_stopped"
        return "systemd_event"

    # OpenVPN
    if "openvpn" in dec:
        if "failed" in fl or "error" in fl: return "vpn_connection_failed"
        return "vpn_event"

    # Audit
    if "auditd" in dec:
        if "syscall" in fl: return "audit_syscall"
        if "user_acct" in fl or "cred_acq" in fl: return "audit_account_action"
        return "audit_event"

    # Kernel
    if "kernel" in dec:
        if "apparmor" in fl: return "apparmor_event"
        if "capacity change" in fl: return "device_capacity_change"
        return "kernel_event"

    # Disk health
    if "smartd" in dec:
        if "prefailure" in fl: return "disk_prefailure_warning"
        return "disk_health_check"

    # Platform noise (snapd, dbus, fwupd, motd, apt, network-wait, resolved)
    if "platform_noise" in dec or dec in (
        "snapd", "dbus-daemon", "fwupd", "fwupdmgr", "fstrim",
        "50-motd-news", "apt-helper", "systemd-networkd-wait-online",
        "systemd-resolved",
    ):
        return "platform_maintenance"

    # Application logs (python, opensearch)
    if "python" in dec:
        return "application_log"
    if "opensearch" in dec:
        return "siem_index_event"

    return "syslog_event"

def extract_linux_source_ip(full_log: str, data: dict) -> str:
    if isinstance(data, dict):
        for key in ("srcip", "src_ip", "srcaddr", "ip"):
            val = data.get(key)
            if val:
                return str(val)
    if full_log:
        for pattern in [
            r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        ]:
            m = re.search(pattern, full_log)
            if m:
                return m.group(1)
    return ""

def extract_linux_user(full_log: str, data: dict) -> str:
    if isinstance(data, dict):
        for key in ("dstuser", "srcuser", "user", "acct"):
            val = data.get(key)
            if val:
                return str(val)
    if full_log:
        for pattern in [r'for\s+(?:invalid\s+user\s+)?(\S+)', r'USER=(\S+)']:
            m = re.search(pattern, full_log, re.IGNORECASE)
            if m:
                return m.group(1)
    return ""

# Standard Linux syslog format: MMM DD HH:MM:SS host program[pid]: message
LINUX_SYSLOG_RE = re.compile(
    r'^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<program>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s*'
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

    if "snapd" in prog or "dbus-daemon" in prog or "fwupd" in prog or "fwupdmgr" in prog \
            or "fstrim" in prog or "50-motd-news" in prog or "apt-helper" in prog \
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
            rule_id, rule_level, rule_desc, groups, decoder_name = \
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
    hostname = predecoder.get("hostname") or agent.get("name") or agent.get("ip") or ""
    message  = rule_description or (full_log_raw.split("\n")[0].strip()[:200] if full_log_raw else "")
    rule_groups = rule.get("groups", [])
    if isinstance(rule_groups, str):
        rule_groups = [rule_groups]
    return {
        "time":           archive_evt.get("timestamp"),
        "log_type":       "linux",
        "vendor":         "Linux",
        "action":         action,
        "outcome":        outcome,
        "asset_host":     hostname,
        "correlation_id": "",
        "network": {
            "source_ip":        src_ip,
            "source_port":      None,
            "country":          "",
            "destination_ip":   agent.get("ip", ""),
            "destination_port": None,
            "protocol":         "",
            "method":           "",
        },
        "message":     message,
        "maliciousIP": None,
        "waf": "", "flow": "", "winEvent": "", "fortinet": "",
        "linuxEvent": {
            "hostname":        hostname,
            "program":         predecoder.get("program_name", ""),
            "user":            user,
            "ruleID":          str(rule_id),
            "ruleLevel":       rule_level,
            "ruleDescription": rule_description,
            "ruleGroups":      rule_groups,
            "decoderName":     decoder_name,
            "fullLog":         full_log_raw[:500] if full_log_raw else "",
        },
    }

LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive", "11": "CachedInteractive",
}
WINDOWS_EVENT_OUTCOMES = {
    4624: "success", 4625: "failure", 4634: "success", 4720: "success",
    4722: "success", 4725: "success", 4726: "success", 4688: "success",
    4740: "success",
}

def outcome_windows_event(event_id: str) -> str:
    try:
        return WINDOWS_EVENT_OUTCOMES.get(int(event_id), "unknown")
    except (ValueError, TypeError):
        return "unknown"

def normalize_windows_event(archive_evt: dict) -> Optional[dict]:
    full_log_raw = archive_evt.get("full_log", "")
    win_data     = None
    try:
        if full_log_raw and isinstance(full_log_raw, str):
            parsed   = json.loads(full_log_raw)
            win_data = parsed.get("win", {})
    except Exception:
        pass
    if not win_data:
        data = archive_evt.get("data", {})
        if isinstance(data, dict):
            win_data = data.get("win", {})
    if not win_data:
        return None
    system    = win_data.get("system", {})
    eventdata = win_data.get("eventdata", {})
    agent     = archive_evt.get("agent", {}) or {}
    event_id  = system.get("eventID", "")
    def first_line(msg):
        if not msg: return ""
        for sep in [".\r\n", ".\n", ". "]:
            if sep in msg:
                return msg.split(sep)[0].strip() + "."
        return msg.strip()[:200]
    return {
        "time":           system.get("systemTime"),
        "log_type":       "win",
        "vendor":         "Microsoft",
        "action":         event_id,
        "outcome":        outcome_windows_event(event_id),
        "asset_host":     system.get("computer", ""),
        "correlation_id": "",
        "network": {
            "source_ip":        eventdata.get("ipAddress") or eventdata.get("workstationName") or "",
            "source_port":      eventdata.get("ipPort") or "",
            "country":          "",
            "destination_ip":   agent.get("ip", ""),
            "destination_port": "",
            "protocol":         "",
            "method":           "",
        },
        "message":     first_line(system.get("message", "")),
        "maliciousIP": None,
        "waf": "", "flow": "", "linuxEvent": "", "fortinet": "",
        "winEvent": {
            "providerName":              system.get("providerName", ""),
            "channel":                   system.get("channel", ""),
            "eventID":                   event_id,
            "logonType":                 LOGON_TYPES.get(eventdata.get("logonType", ""), eventdata.get("logonType", "")),
            "processName":               eventdata.get("processName", ""),
            "subjectUserName":           eventdata.get("subjectUserName", ""),
            "subjectDomainName":         eventdata.get("subjectDomainName", ""),
            "targetUserName":            eventdata.get("targetUserName", ""),
            "targetDomainName":          eventdata.get("targetDomainName", ""),
            "authenticationPackageName": eventdata.get("authenticationPackageName", ""),
            "workstationName":           eventdata.get("workstationName", ""),
            "ipAddress":                 eventdata.get("ipAddress", ""),
        },
    }

def parse_fortinet_kv(raw_line: str) -> dict:
    result  = {}
    pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]*)')
    for m in pattern.finditer(raw_line):
        key   = m.group(1)
        value = m.group(2)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        result[key] = value
    return result

def outcome_from_fortinet_action(action: str, subtype: str) -> str:
    a = (action or "").lower()
    if a in ("accept", "allow", "tunnel-up", "passthrough"): return "allowed"
    if a in ("deny", "block", "dropped", "close", "blocked"): return "blocked"
    return "unknown"

def normalize_fortinet_event(archive_evt: dict) -> Optional[dict]:
    full_log_raw = archive_evt.get("full_log", "")
    if not full_log_raw or not isinstance(full_log_raw, str):
        return None
    if "devname" not in full_log_raw and "devid" not in full_log_raw:
        return None
    kv = parse_fortinet_kv(full_log_raw)
    if not kv:
        return None
    log_type_fg = kv.get("type", "")
    subtype     = kv.get("subtype", "")
    action      = kv.get("action", "")
    # Event-type logs (security-rating, system, user) thường không có action=
    # → dùng logdesc hoặc subtype làm action thay thế để không bị rỗng
    if not action:
        if log_type_fg == "event":
            logdesc = kv.get("logdesc", "")
            if logdesc:
                action = re.sub(r'[^a-zA-Z0-9]+', '_', logdesc.strip().lower()).strip('_')
            else:
                action = f"event_{subtype}" if subtype else "event_unknown"
        else:
            action = kv.get("eventtype", "") or f"{log_type_fg}_{subtype}" if log_type_fg else "unknown"
    outcome     = outcome_from_fortinet_action(action, subtype)
    src_ip      = kv.get("srcip", "")
    dst_ip      = kv.get("dstip", "")
    def to_int_safe(val):
        try:
            return int(val) if val else None
        except (ValueError, TypeError):
            return None
    proto_int  = to_int_safe(kv.get("proto"))
    proto_name = get_protocol_name(proto_int) if proto_int else kv.get("proto", "")
    if log_type_fg == "utm" and subtype == "ips":
        message = f"FortiGate IPS {action}: {kv.get('attack','?')} from {src_ip}"
    elif log_type_fg == "utm" and subtype == "webfilter":
        message = f"FortiGate WebFilter {action}: {kv.get('url','')} [{kv.get('catdesc','')}]"
    elif log_type_fg == "event" and subtype == "vpn":
        message = f"FortiGate VPN {action}: user={kv.get('user','')} from {kv.get('remip', src_ip)}"
    else:
        message = f"FortiGate {log_type_fg}/{subtype} {action}: {src_ip} -> {dst_ip}:{kv.get('dstport','?')}"
    return {
        "time":           kv.get("eventtime") or archive_evt.get("timestamp", ""),
        "log_type":       "fortinet",
        "vendor":         "Fortinet",
        "action":         action.lower(),
        "outcome":        outcome,
        "asset_host":     kv.get("devname", ""),
        "correlation_id": kv.get("sessionid", ""),
        "network": {
            "source_ip":        src_ip,
            "source_port":      to_int_safe(kv.get("srcport")),
            "country":          kv.get("srccountry", ""),
            "destination_ip":   dst_ip,
            "destination_port": to_int_safe(kv.get("dstport")),
            "protocol":         proto_name,
            "method":           None,
        },
        "message":     message,
        "maliciousIP": None,
        "waf": "", "flow": "", "winEvent": "", "linuxEvent": "",
        "fortinet": {
            "devname": kv.get("devname",""), "devid": kv.get("devid",""),
            "logid":   kv.get("logid",""),   "type":  log_type_fg,
            "subtype": subtype,              "level": kv.get("level",""),
            "policyid": kv.get("policyid",""), "service": kv.get("service",""),
            "app":     kv.get("app",""),     "appcat": kv.get("appcat",""),
            "srcintf": kv.get("srcintf",""), "dstintf": kv.get("dstintf",""),
            "srccountry": kv.get("srccountry",""), "dstcountry": kv.get("dstcountry",""),
            "sentbyte": to_int_safe(kv.get("sentbyte")),
            "rcvdbyte": to_int_safe(kv.get("rcvdbyte")),
            "sentpkt":  to_int_safe(kv.get("sentpkt")),
            "rcvdpkt":  to_int_safe(kv.get("rcvdpkt")),
            "duration": to_int_safe(kv.get("duration")),
            "attack":   kv.get("attack",""), "attackid": kv.get("attackid",""),
            "url":      kv.get("url",""),    "catdesc":  kv.get("catdesc",""),
            "user":     kv.get("user",""),   "tunneltype": kv.get("tunneltype",""),
            "remip":    kv.get("remip",""),  "utmaction": kv.get("utmaction",""),
            "msg":      kv.get("msg",""),
        },
    }


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
        r'(?:Source Network Address|IP Address|Network Address|Caller Computer Name):\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        message, re.I
    )
    if m:
        return m.group(1)
    m2 = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
    return m2.group(1) if m2 else ""


def extract_win_user_from_message(message: str) -> str:
    m = re.search(r'(?:Account Name|Logon Account|Target Account Name|New Account Name):\s*(\S+)', message, re.I)
    return m.group(1) if m else ""


# MSWinEventLog raw direct format (PRI header + tab-separated fields)
MSWINEVENTLOG_DIRECT_RE = re.compile(
    r'^(?:<\d+>)?'
    r'(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'MSWinEventLog\t(?P<rest>.*)$'
)


# EventID → action name mapping (Security + System + Application events)
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
    fields = rest.split("\t")

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
        for sep in [".\r\n", ".\n", ". "]:
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
    }


def route_text_line(line: str) -> Optional[dict]:
    """
    Nhận diện và normalize một dòng raw text (không phải JSON, không phải
    MSWinEventLog) — thử lần lượt Cisco, FortiGate, rồi Linux syslog.
    Trả về normalized dict hoặc None nếu không khớp loại nào.
    """
    stripped = line.strip()
    if not stripped:
        return None

    # 1. Cisco IOS — pattern %FACILITY-SEV-MNEMONIC rất đặc trưng, thử trước
    if re.search(r'%[A-Z0-9_]+-\d-[A-Z0-9_]+:', stripped):
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


def _is_linux_event(archive_evt: dict) -> bool:
    location = archive_evt.get("location", "")
    if isinstance(location, str):
        for prefix in LINUX_LOG_LOCATIONS:
            if location.startswith(prefix):
                return True
    decoder = archive_evt.get("decoder", {})
    if isinstance(decoder, dict):
        dec_name = (decoder.get("name") or "").lower()
        linux_decoders = {
            "sshd","sudo","pam","cron","su","syslog","systemd",
            "iptables","nftables","auditd","useradd","userdel",
            "groupadd","groupdel","passwd","kernel","dpkg","yum","apt",
        }
        if dec_name in linux_decoders:
            return True
    agent = archive_evt.get("agent", {})
    if isinstance(agent, dict):
        agent_os = safe_get(agent, "os", "platform") or safe_get(agent, "os", "name") or ""
        if isinstance(agent_os, str) and any(
            kw in agent_os.lower()
            for kw in ("linux","ubuntu","centos","debian","rhel","fedora","amazon")
        ):
            return True
    rule = archive_evt.get("rule", {})
    if isinstance(rule, dict):
        groups = rule.get("groups", [])
        if isinstance(groups, str):
            groups = [groups]
        linux_groups = {
            "syslog","sshd","authentication_success","authentication_failed",
            "pam","sudo","cron","firewall","audit","systemd",
            "linux","local","adduser","account_changed",
        }
        for g in (groups or []):
            if isinstance(g, str) and g.lower() in linux_groups:
                return True
    return False


# High-risk CloudTrail events — luôn được severity cao bất kể readOnly
CLOUDTRAIL_HIGH_RISK_EVENTS = {
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
CLOUDTRAIL_MEDIUM_RISK_EVENTS = {
    "ListUsers","ListRoles","ListBuckets","DescribeInstances",
    "GetSecretValue","ListSecrets","DescribeSecurityGroups",
    "GetBucketAcl","GetBucketPolicy",
}


def normalize_cloudtrail_event(archive_evt: dict) -> Optional[dict]:
    """
    Normalize raw AWS CloudTrail JSON TRỰC TIẾP (không qua pre-processor).
    Input format thật: {"integration":"aws","aws":{...CloudTrail fields...}}
    """
    aws = archive_evt.get("aws") or {}
    if not isinstance(aws, dict):
        return None

    event_name   = aws.get("eventName", "")
    event_source = aws.get("eventSource", "")
    event_time   = aws.get("eventTime") or archive_evt.get("timestamp", "")
    if not event_name:
        return None

    region      = aws.get("awsRegion", "")
    account_id  = aws.get("aws_account_id") or aws.get("recipientAccountId", "")
    src_ip      = aws.get("sourceIPAddress") or aws.get("source_ip_address") or ""
    user_agent  = aws.get("userAgent", "")
    request_id  = aws.get("requestID") or aws.get("eventID", "")
    error_code  = aws.get("errorCode", "")
    error_msg   = aws.get("errorMessage", "")
    read_only   = bool(aws.get("readOnly", True))
    event_type  = aws.get("eventType", "")

    user_identity = aws.get("userIdentity") or {}
    user_type     = user_identity.get("type", "")
    user_arn      = user_identity.get("arn", "")
    principal_id  = user_identity.get("principalId", "")

    # Ưu tiên lấy email/username thật từ principalId (ROLE_ID:email@domain.com)
    user_name = ""
    if ":" in principal_id:
        candidate = principal_id.split(":", 1)[1]
        if candidate:
            user_name = candidate
    if not user_name and user_arn and "/" in user_arn:
        last_segment = user_arn.rsplit("/", 1)[-1]
        if "@" in last_segment:
            user_name = last_segment
    role_name = ""
    if "sessionContext" in user_identity:
        role_name = user_identity["sessionContext"].get("sessionIssuer", {}).get("userName", "")
    if not user_name:
        user_name = role_name or user_identity.get("userName", "")
    if not user_name and user_arn:
        user_name = user_arn.split("/")[-1]

    # MFA tracking
    mfa_authenticated = "false"
    if "sessionContext" in user_identity:
        mfa_authenticated = str(
            user_identity["sessionContext"].get("attributes", {}).get("mfaAuthenticated", "false")
        ).lower()
    additional_data = aws.get("additionalEventData", {}) or {}
    if "MFAUsed" in additional_data:
        mfa_authenticated = "true" if str(additional_data.get("MFAUsed")).lower() in ("yes", "true") else "false"

    invoked_by = user_identity.get("invokedBy", "")
    is_aws_service = (
        src_ip in ("config.amazonaws.com", "cloudtrail.amazonaws.com",
                   "s3.amazonaws.com", "lambda.amazonaws.com")
        or invoked_by != ""
    )

    # Action + severity classification
    if event_name == "ConsoleLogin" and user_type == "Root":
        action = "console_login_root"
        rule_level = 12
    elif error_code:
        action = "api_error"
        rule_level = 8 if event_name in CLOUDTRAIL_HIGH_RISK_EVENTS else 5
    elif event_name in CLOUDTRAIL_HIGH_RISK_EVENTS:
        action = f"cloudtrail_{event_name.lower()}"
        rule_level = 10
    elif event_name in CLOUDTRAIL_MEDIUM_RISK_EVENTS:
        action = f"cloudtrail_{event_name.lower()}"
        rule_level = 5
    elif not read_only:
        action = "api_write"
        rule_level = 6
    else:
        action = "api_read"
        rule_level = 3

    outcome = "failure" if error_code else "success"
    if event_name == "ConsoleLogin" and user_type == "Root" and mfa_authenticated != "true":
        outcome = "critical"

    network_src_ip = src_ip if re.match(r'\d+\.\d+\.\d+\.\d+', src_ip) else ""

    message = f"CloudTrail: {event_name} via {event_source} by {user_name or user_type}"
    if error_code:
        message += f" [ERROR: {error_code}]"

    return {
        "time":           event_time,
        "log_type":       "cloudtrail",
        "vendor":         "aws",
        "action":         action,
        "outcome":        outcome,
        "asset_host":     f"aws-{account_id}" if account_id else "",
        "correlation_id": request_id,
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
            "eventName":    event_name,
            "eventSource":  event_source,
            "eventType":    event_type,
            "awsRegion":    region,
            "accountId":    account_id,
            "userType":     user_type,
            "userName":     user_name,
            "roleName":     role_name,
            "userArn":      user_arn,
            "sourceIP":     src_ip,
            "userAgent":    user_agent,
            "readOnly":     str(read_only),
            "errorCode":    error_code,
            "errorMessage": error_msg,
            "mfaAuthenticated": mfa_authenticated,
            "invokedBy":    invoked_by,
            "isAwsService": is_aws_service,
            "ruleLevel":    rule_level,
        },
    }


CISCO_TEXT_RE = re.compile(r'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)')


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
            ip_m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', full_log_raw[:60])
            device_ip = ip_m.group(1) if ip_m else ""
            agent = {"ip": device_ip, "name": device_ip}
            predecoder = {"hostname": device_ip}

    facility = data.get("facility", "")
    severity = int(data.get("severity", "5") or "5")
    mnemonic = data.get("mnemonic", "")
    message  = data.get("message", full_log_raw[:200] if full_log_raw else "")
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
    iface_match = re.search(r'Interface (\S+)', message)
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
            "source_ip":        src_host if re.match(r'\d+\.\d+\.\d+\.\d+', src_host) else "",
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

def normalize_event(archive_evt: dict) -> Optional[dict]:
    location     = archive_evt.get("location", "")
    data         = archive_evt.get("data", {})
    full_log_raw = archive_evt.get("full_log", "")
    parsed_full  = parse_json_safe(full_log_raw)
    loc          = str(location) if location else ""
    decoder_name = str((archive_evt.get("decoder") or {}).get("name", ""))

    if isinstance(location, str):
        if location.startswith(WAF_LOCATION_PREFIX):
            return normalize_waf_event(archive_evt)
        if location.startswith(VPC_LOCATION_PREFIX):
            return normalize_vpc_flow_event(archive_evt)
        if location.startswith(FORTINET_LOCATION_PREFIX):
            return normalize_fortinet_event(archive_evt)

    if isinstance(data, dict):
        if data.get("type") == "aws_vpc_flow":
            return normalize_vpc_flow_event(archive_evt)
        if "httpRequest" in data and "action" in data:
            return normalize_waf_event(archive_evt)
        if "win" in data:
            return normalize_windows_event(archive_evt)

    if isinstance(parsed_full, dict):
        if parsed_full.get("type") == "aws_vpc_flow":
            return normalize_vpc_flow_event(archive_evt)
        if "httpRequest" in parsed_full and "action" in parsed_full:
            return normalize_waf_event(archive_evt)
        if "win" in parsed_full:
            return normalize_windows_event(archive_evt)

    if isinstance(full_log_raw, str) and "devname=" in full_log_raw:
        return normalize_fortinet_event(archive_evt)

    if _is_linux_event(archive_evt):
        return normalize_linux_event(archive_evt)

    # CloudTrail — đã qua pre-processor
    if (isinstance(location, str) and location.startswith("/aws/cloudtrail/")) or decoder_name == "cloudtrail":
        return normalize_cloudtrail_event(archive_evt)

    # CloudTrail raw trực tiếp (không qua pre-processor): {"integration":"aws","aws":{...}}
    if isinstance(archive_evt.get("aws"), dict) and archive_evt["aws"].get("eventName"):
        return normalize_cloudtrail_event(archive_evt)
    if archive_evt.get("integration") == "aws" and isinstance(archive_evt.get("aws"), dict):
        return normalize_cloudtrail_event(archive_evt)

    # Cisco IOS — đã qua pre-processor
    if (isinstance(location, str) and location.startswith("/cisco/")) or decoder_name == "cisco-ios":
        return normalize_cisco_event(archive_evt)

    return None

NORMALIZE_OFFSET_FILE = os.path.join(
    os.path.dirname(os.path.abspath(os.getenv("NORMALIZED_PATH", "/home/ubuntu/soc_ai/log_normalized.json"))),
    ".normalize_offset"
)


def _load_normalize_offset():
    """Đọc offset đã lưu: trả về (inode, byte_offset) hoặc (None, None)."""
    try:
        if os.path.exists(NORMALIZE_OFFSET_FILE):
            with open(NORMALIZE_OFFSET_FILE) as f:
                parts = f.read().strip().split(":")
                if len(parts) == 2:
                    return int(parts[0]), int(parts[1])
    except Exception:
        pass
    return None, None


def _save_normalize_offset(inode: int, byte_offset: int):
    """Ghi offset hiện tại ra file để resume sau restart."""
    try:
        with open(NORMALIZE_OFFSET_FILE, "w") as f:
            f.write(f"{inode}:{byte_offset}")
    except Exception as e:
        print(f"[WARN] save_normalize_offset: {e}")


def follow_file(path, start_from_beginning=False):
    """
    Follow file với offset persistence:
    - Nếu có .normalize_offset và inode khớp → resume đúng vị trí
    - Nếu start_from_beginning=True → đọc từ byte 0 (test mode)
    - Nếu không có offset + start_from_beginning=False → seek to end (production)
    Yield từng dòng hoàn chỉnh (không kèm newline).
    """
    f = None; last_inode = None; first_open = True; buf = ""
    saved_inode, saved_offset = _load_normalize_offset()

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
                    if start_from_beginning:
                        # Test mode: đọc từ đầu, xóa offset cũ
                        f.seek(0, os.SEEK_SET)
                        if os.path.exists(NORMALIZE_OFFSET_FILE):
                            os.remove(NORMALIZE_OFFSET_FILE)
                        print(f"[normalize] Offset: reading from beginning (test mode)")
                    elif saved_inode == inode and saved_offset is not None:
                        # Resume từ vị trí đã lưu
                        f.seek(min(saved_offset, st.st_size), os.SEEK_SET)
                        print(f"[normalize] Offset: resumed at byte {saved_offset} (inode={inode})")
                    else:
                        # Production default: seek to end, bỏ qua log cũ
                        f.seek(0, os.SEEK_END)
                        _save_normalize_offset(inode, f.tell())
                        print(f"[normalize] Offset: starting at end (byte {f.tell()}, inode={inode})")
                    first_open = False
                else:
                    # File rotation (inode thay đổi): đọc từ đầu file mới
                    f.seek(0, os.SEEK_SET)
                    print(f"[normalize] Offset: file rotated, reading new file from beginning")

            # File bị truncate (logrotate): reset
            current_pos = f.tell()
            if st.st_size < current_pos:
                print(f"[normalize] Offset: file truncated ({st.st_size} < {current_pos}), resetting")
                f.seek(0, os.SEEK_SET); buf = ""
                _save_normalize_offset(inode, 0)

            chunk = f.read(4096)
            if not chunk:
                time.sleep(0.05); continue

            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                # Lưu offset sau mỗi dòng hoàn chỉnh
                _save_normalize_offset(inode, f.tell() - len(buf.encode("utf-8")))
                yield line

        except FileNotFoundError:
            time.sleep(0.5)
        except Exception as e:
            print(f"[WARN] follow_file: {e}"); time.sleep(0.5)

def main():
    os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_FILE)), exist_ok=True)
    stats = {"waf":0,"vpc":0,"windows":0,"linux":0,"fortinet":0,"cloudtrail":0,"cisco":0,"skipped":0,"errors":0}
    TYPE_MAP = {"waf":"waf","vpc":"vpc","win":"windows","linux":"linux","fortinet":"fortinet","cloudtrail":"cloudtrail","cisco":"cisco"}

    print(f"[normalize] Starting...")
    print(f"[normalize] Input:  {RAW_LOG_PATH}")
    print(f"[normalize] Output: {OUTPUT_FILE}")

    start_beginning = os.getenv("LOG_START_POSITION", "end").strip().lower() == "beginning"
    print(f"[normalize] Start position: {'beginning' if start_beginning else 'end (tail mode)'}")
    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        for line in follow_file(RAW_LOG_PATH, start_from_beginning=start_beginning):
            if not line.strip():
                continue

            # MSWinEventLog raw (syslog-forwarded, không phải JSON) — xử lý trước JSON parse
            if "MSWinEventLog" in line and "\t" in line:
                norm = normalize_windows_eventlog_direct(line)
                if norm:
                    out.write(json.dumps(norm, ensure_ascii=False) + "\n")
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
                # Không phải JSON — thử các parser text trực tiếp
                # (Cisco IOS, FortiGate, Linux syslog)
                norm = route_text_line(line)
                if norm:
                    out.write(json.dumps(norm, ensure_ascii=False) + "\n")
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
                continue
            out.write(json.dumps(norm, ensure_ascii=False) + "\n")
            out.flush()
            log_type = norm.get("log_type")
            mapped   = TYPE_MAP.get(log_type)
            if mapped:
                stats[mapped] += 1
                total = sum(stats[k] for k in ("waf","vpc","windows","linux","fortinet","cloudtrail","cisco"))
                print(
                    f"[normalize] +1 {log_type:10s} | "
                    f"WAF={stats['waf']} VPC={stats['vpc']} "
                    f"WIN={stats['windows']} LNX={stats['linux']} "
                    f"FTN={stats['fortinet']} CT={stats['cloudtrail']} "
                    f"CS={stats['cisco']} | total={total}"
                )
            else:
                stats["skipped"] += 1

if __name__ == "__main__":
    main()
