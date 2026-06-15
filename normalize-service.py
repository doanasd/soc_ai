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

WAF_LOCATION_PREFIX      = "/tmp/aws-waf/waf/"
VPC_LOCATION_PREFIX      = "/tmp/aws-waf/vpc/"
FORTINET_LOCATION_PREFIX = "/tmp/fortinet/"

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
        return "pam_event"
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

def normalize_linux_event(archive_evt: dict) -> Optional[dict]:
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

def normalize_event(archive_evt: dict) -> Optional[dict]:
    location     = archive_evt.get("location", "")
    data         = archive_evt.get("data", {})
    full_log_raw = archive_evt.get("full_log", "")
    parsed_full  = parse_json_safe(full_log_raw)

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
    stats = {"waf":0,"vpc":0,"windows":0,"linux":0,"fortinet":0,"skipped":0,"errors":0}
    TYPE_MAP = {"waf":"waf","vpc":"vpc","win":"windows","linux":"linux","fortinet":"fortinet"}

    print(f"[normalize] Starting...")
    print(f"[normalize] Input:  {RAW_LOG_PATH}")
    print(f"[normalize] Output: {OUTPUT_FILE}")

    start_beginning = os.getenv("LOG_START_POSITION", "end").strip().lower() == "beginning"
    print(f"[normalize] Start position: {'beginning' if start_beginning else 'end (tail mode)'}")
    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
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
                continue
            out.write(json.dumps(norm, ensure_ascii=False) + "\n")
            out.flush()
            log_type = norm.get("log_type")
            mapped   = TYPE_MAP.get(log_type)
            if mapped:
                stats[mapped] += 1
                total = sum(stats[k] for k in ("waf","vpc","windows","linux","fortinet"))
                print(
                    f"[normalize] +1 {log_type:10s} | "
                    f"WAF={stats['waf']} VPC={stats['vpc']} "
                    f"WIN={stats['windows']} LNX={stats['linux']} "
                    f"FTN={stats['fortinet']} | total={total}"
                )
            else:
                stats["skipped"] += 1

if __name__ == "__main__":
    main()
