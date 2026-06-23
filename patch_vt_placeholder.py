#!/usr/bin/env python3
"""
Patch malicious-enricher.py: thêm virustotal_context field trống
(placeholder để sau này integrate VT API mà không cần sửa schema)

Chạy trên EC2: python3 patch_vt_placeholder.py
"""

PATH = "/home/ubuntu/soc_ai/malicious-enricher.py"

OLD_THREAT_FEED = '''    if threatfeed_data:
        record["threat_feed_context"] = {
            "urlhaus_url_count": threatfeed_data.get("urlhaus_url_count", 0),
            "urlhaus_tags":      threatfeed_data.get("urlhaus_tags", []),
            "threatfox_malware": threatfeed_data.get("threatfox_malware", []),
        }

    return record'''

NEW_THREAT_FEED = '''    if threatfeed_data:
        record["threat_feed_context"] = {
            "urlhaus_url_count": threatfeed_data.get("urlhaus_url_count", 0),
            "urlhaus_tags":      threatfeed_data.get("urlhaus_tags", []),
            "threatfox_malware": threatfeed_data.get("threatfox_malware", []),
        }

    # VirusTotal placeholder — để trống cho đến khi có API key trả phí
    # Schema chuẩn bị sẵn để sau này điền vào không cần sửa downstream
    record["virustotal_context"] = {
        "enabled":          False,
        "detection_ratio":  None,   # vd: "12/94" (detected/total engines)
        "malicious_count":  None,   # số engine phát hiện malicious
        "suspicious_count": None,
        "last_analysis":    None,   # ISO timestamp lần quét gần nhất
        "categories":       [],     # vd: ["malware", "phishing"]
        "tags":             [],     # vd: ["trojan", "c2"]
        "community_score":  None,   # VT community reputation score
    }

    return record'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "virustotal_context" in content:
        print("⏭️  Already applied")
        return

    if OLD_THREAT_FEED not in content:
        print("⚠️  Pattern NOT FOUND")
        return

    content = content.replace(OLD_THREAT_FEED, NEW_THREAT_FEED)
    with open(PATH, "w") as f:
        f.write(content)
    print("✅ virustotal_context placeholder: applied")

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")


if __name__ == "__main__":
    apply_patch()
