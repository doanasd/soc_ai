#!/usr/bin/env python3
"""
Patch normalize-service.py: mở rộng classify_linux_action() để nhận diện
đầy đủ các process/unit Linux journald (CRON, systemd, smartd, openvpn,
kernel, snapd, platform_noise...) thay vì chỉ sshd/sudo/pam.

Đồng thời fix FortiGate action rỗng cho event/security-rating type.

Chạy trên EC2: python3 patch_linux_action_fix.py
"""

PATH = "/home/ubuntu/soc_ai/normalize-service.py"

# ── 1. Mở rộng classify_linux_action() ──────────────────────────────────────
OLD_CLASSIFY = '''def classify_linux_action(rule_id, full_log: str, decoder_name: str) -> str:
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
    return "syslog_event"'''

NEW_CLASSIFY = '''def classify_linux_action(rule_id, full_log: str, decoder_name: str) -> str:
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

    return "syslog_event"'''

# ── 2. Fix FortiGate action rỗng cho event type (security-rating, system) ──
OLD_FORTI_ACTION = '''    log_type_fg = kv.get("type", "")
    subtype     = kv.get("subtype", "")
    action      = kv.get("action", "")
    outcome     = outcome_from_fortinet_action(action, subtype)'''

NEW_FORTI_ACTION = '''    log_type_fg = kv.get("type", "")
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
    outcome     = outcome_from_fortinet_action(action, subtype)'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "cron_session_opened" in content:
        print("⏭️  classify_linux_action already extended")
    else:
        if OLD_CLASSIFY in content:
            content = content.replace(OLD_CLASSIFY, NEW_CLASSIFY)
            print("✅ classify_linux_action(): extended")
        else:
            print("⚠️  classify_linux_action pattern NOT FOUND")

    if "security_rating" in content.lower() and "logdesc.strip" in content:
        print("⏭️  FortiGate action fix already applied")
    else:
        if OLD_FORTI_ACTION in content:
            content = content.replace(OLD_FORTI_ACTION, NEW_FORTI_ACTION)
            print("✅ FortiGate action fallback: applied")
        else:
            print("⚠️  FortiGate action pattern NOT FOUND")

    with open(PATH, "w") as f:
        f.write(content)

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")


if __name__ == "__main__":
    apply_patch()
