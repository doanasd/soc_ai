#!/usr/bin/env python3
"""
Patch dedup-service.py: fix Linux grouping key để không lẫn "user" sai
cho các action không liên quan authentication (platform_maintenance,
kernel_event, disk_health_check...) — vốn bị extract_linux_user() bắt nhầm
từ text thường trong message.

Chạy trên EC2: python3 patch_dedup_linux_key.py
"""

PATH = "/home/ubuntu/soc_ai/dedup-service.py"

OLD_LINUX_KEY = '''        elif log_type == "linux":
            linux = log.get("linuxEvent", {}) or {}
            prog  = linux.get("program", "")
            user  = linux.get("user", "")
            rid   = linux.get("ruleID", "")
            return f"linux|{src_ip}|{host}|{action}|{prog}|{user}|{rid}"'''

NEW_LINUX_KEY = '''        elif log_type == "linux":
            linux = log.get("linuxEvent", {}) or {}
            prog  = linux.get("program", "")
            rid   = linux.get("ruleID", "")
            # Chỉ dùng "user" trong key cho các action thật sự liên quan auth/account
            # (tránh nhiễu do extract_linux_user() bắt nhầm từ message text thường)
            auth_related_actions = {
                "ssh_login_success", "ssh_login_failed", "ssh_disconnect", "ssh_event",
                "sudo_executed", "sudo_event", "user_created", "user_deleted",
                "pam_auth_failed", "pam_session_opened", "pam_session_closed", "pam_event",
                "cron_session_opened", "cron_session_closed", "session_opened",
            }
            user = linux.get("user", "") if action in auth_related_actions else ""
            return f"linux|{src_ip}|{host}|{action}|{prog}|{user}|{rid}"'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "auth_related_actions" in content:
        print("⏭️  Already applied")
        return

    if OLD_LINUX_KEY in content:
        content = content.replace(OLD_LINUX_KEY, NEW_LINUX_KEY)
        print("✅ Linux dedup key fixed: user field now scoped to auth-related actions")
    else:
        print("⚠️  Pattern NOT FOUND — manual check needed")
        idx = content.find('elif log_type == "linux"')
        if idx > 0:
            print("Context found:")
            print(content[idx:idx+400])
        return

    with open(PATH, "w") as f:
        f.write(content)

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")


if __name__ == "__main__":
    apply_patch()
