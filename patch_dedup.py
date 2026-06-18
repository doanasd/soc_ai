#!/usr/bin/env python3
"""
Patch dedup-service.py: thêm grouping key cho CloudTrail và Cisco IOS
Chạy trên EC2: python3 patch_dedup.py
"""
 
PATH = "/home/ubuntu/soc_ai/dedup-service.py"
 
OLD_ELIF_FORTINET = '''        elif log_type == "fortinet":
            ftn     = log.get("fortinet", {}) or {}
            fg_type = ftn.get("type", "")
            subtype = ftn.get("subtype", "")
            policy  = ftn.get("policyid", "")
            attack  = ftn.get("attack", "")
            # IPS/WebFilter: group by attack/url signature
            if fg_type == "utm" and subtype == "ips":
                return f"fortinet|ips|{src_ip}|{dst_ip}|{attack}|{action}"
            elif fg_type == "utm" and subtype == "webfilter":
                url = ftn.get("url", "")[:100]  # truncate long URLs
                return f"fortinet|webfilter|{src_ip}|{url}|{action}"
            else:
                return f"fortinet|{fg_type}|{subtype}|{src_ip}|{dst_ip}|{dst_port}|{action}"
 
        return None'''
 
NEW_ELIF_FORTINET = '''        elif log_type == "fortinet":
            ftn     = log.get("fortinet", {}) or {}
            fg_type = ftn.get("type", "")
            subtype = ftn.get("subtype", "")
            policy  = ftn.get("policyid", "")
            attack  = ftn.get("attack", "")
            if fg_type == "utm" and subtype == "ips":
                return f"fortinet|ips|{src_ip}|{dst_ip}|{attack}|{action}"
            elif fg_type == "utm" and subtype == "webfilter":
                url = ftn.get("url", "")[:100]
                return f"fortinet|webfilter|{src_ip}|{url}|{action}"
            else:
                return f"fortinet|{fg_type}|{subtype}|{src_ip}|{dst_ip}|{dst_port}|{action}"
 
        elif log_type == "cloudtrail":
            ct         = log.get("cloudtrail", {}) or {}
            event_name = ct.get("eventName", action)
            username   = ct.get("username", "")
            account_id = log.get("asset_host", "")
            error_code = ct.get("errorCode", "")
            # Group by: event + user + account + error (dedup repeated API calls)
            return f"cloudtrail|{event_name}|{username}|{account_id}|{error_code}"
 
        elif log_type == "cisco":
            cs        = log.get("cisco", {}) or {}
            mnemonic  = cs.get("mnemonic", "")
            interface = cs.get("interface", "")
            device_ip = cs.get("device_ip", host)
            state     = cs.get("state", "")
            return f"cisco|{device_ip}|{mnemonic}|{interface}|{state}"
 
        return None'''
 
 
def apply_patch():
    with open(PATH) as f:
        content = f.read()
 
    if OLD_ELIF_FORTINET in content:
        content = content.replace(OLD_ELIF_FORTINET, NEW_ELIF_FORTINET)
        print("✅ Patch: CloudTrail + Cisco grouping keys added to dedup")
    elif "cloudtrail" in content and "cisco" in content:
        print("⏭️  Already applied")
    else:
        print("⚠️  Pattern not found - checking file...")
        idx = content.find("elif log_type == \"fortinet\":")
        if idx > 0:
            print(f"  fortinet block found at char {idx}")
            print(f"  Context: {content[idx:idx+200]}")
        return
 
    with open(PATH, "w") as f:
        f.write(content)
 
    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    if r.returncode == 0:
        print("✅ Syntax check PASSED")
    else:
        print(f"❌ Syntax error:\n{r.stderr}")
 
    print(f"Verify - cloudtrail key: {'cloudtrail|' in content}")
    print(f"Verify - cisco key: {'cisco|' in content}")
 
 
if __name__ == "__main__":
    apply_patch()
