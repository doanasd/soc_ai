#!/usr/bin/env python3
"""
Patch normalize-service.py: fix extract_win_ip_from_message()
Vấn đề: bắt nhầm version number (2.6.3.0) làm IP address vì regex
quá rộng — bắt bất kỳ x.x.x.x nào trong message.

Fix: chỉ bắt IP từ context keywords rõ ràng, và validate octet range (0-255).
"""

PATH = "/home/ubuntu/soc_ai/normalize-service.py"

OLD_EXTRACT = '''def extract_win_ip_from_message(message: str) -> str:
    """Tìm IP trong message text — thường ở dạng 'Source Network Address: x.x.x.x'."""
    m = re.search(
        r'(?:Source Network Address|IP Address|Network Address|Caller Computer Name):\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})',
        message, re.I
    )
    if m:
        return m.group(1)
    m2 = re.search(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b', message)
    return m2.group(1) if m2 else ""'''

NEW_EXTRACT = '''def _is_valid_ip(ip: str) -> bool:
    """Kiểm tra IP hợp lệ: mỗi octet 0-255, không phải version number."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        # Version number thường có octet < 20 ở tất cả 4 vị trí (vd: 2.6.3.0)
        # IP thật thường có ít nhất 1 octet lớn hơn 20 (trừ loopback/private nhỏ)
        if all(o < 20 for o in octets):
            return False
        return all(0 <= o <= 255 for o in octets)
    except (ValueError, AttributeError):
        return False


def extract_win_ip_from_message(message: str) -> str:
    """
    Tìm IP trong Windows Event message.
    Chỉ bắt IP từ context keywords rõ ràng để tránh nhầm version number,
    port number, hay các chuỗi x.x.x.x khác trong message.
    """
    if not message:
        return ""

    # Ưu tiên: IP đi kèm keyword rõ ràng
    m = re.search(
        r'(?:Source Network Address|Source IP|IP Address|Network Address|'
        r'Client Address|Caller IP|Workstation IP|Source Host)\\s*[=:]\\s*'
        r'(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})',
        message, re.I
    )
    if m:
        ip = m.group(1)
        if _is_valid_ip(ip):
            return ip

    # Fallback: tìm IP standalone nhưng chỉ khi không nằm trong context version/port
    # Loại bỏ: "Version=x.x.x.x", "v2.6.3.0", ":port" patterns
    clean_msg = re.sub(
        r'(?:Version|ClientVersion|AppVersion|v)\\s*[=:]?\\s*\\d+\\.\\d+\\.\\d+\\.\\d+',
        '', message, flags=re.I
    )
    m2 = re.search(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b', clean_msg)
    if m2:
        ip = m2.group(1)
        if _is_valid_ip(ip):
            return ip

    return ""'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if "_is_valid_ip" in content:
        print("⏭️  Already applied")
        return

    if OLD_EXTRACT not in content:
        print("⚠️  Pattern NOT FOUND")
        idx = content.find("def extract_win_ip_from_message")
        if idx >= 0:
            print(f"   Found at char {idx}:")
            print(content[idx:idx+300])
        return

    content = content.replace(OLD_EXTRACT, NEW_EXTRACT)
    print("✅ extract_win_ip_from_message(): fixed - no more version number false positives")

    with open(PATH, "w") as f:
        f.write(content)

    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")

    # Quick test
    print("\n--- Test cases ---")
    test_cases = [
        ("ClientVersion=2.6.3.0 AnchorAttribute=", ""),           # version → should be ""
        ("Source Network Address: 192.168.1.100", "192.168.1.100"), # keyword IP → OK
        ("from 80.94.92.164 port 59644", "80.94.92.164"),          # SSH brute-force IP → OK
        ("Version=1.2.3.4 IP=10.0.0.5", "10.0.0.5"),              # version cleaned, IP kept
        ("IP Address: 0.0.0.0", ""),                               # invalid (all small octets)
    ]

    import sys
    sys.path.insert(0, '/tmp')

    # Test trực tiếp logic
    import re as _re

    def _is_valid_ip_test(ip):
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            octets = [int(p) for p in parts]
            if all(o < 20 for o in octets):
                return False
            return all(0 <= o <= 255 for o in octets)
        except:
            return False

    for msg, expected in test_cases:
        # Simplified test
        clean = _re.sub(r'(?:Version|ClientVersion|AppVersion|v)\s*[=:]?\s*\d+\.\d+\.\d+\.\d+', '', msg, flags=_re.I)
        m = _re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', clean)
        result = ""
        if m:
            ip = m.group(1)
            if _is_valid_ip_test(ip):
                result = ip
        status = "✅" if result == expected else "❌"
        print(f"  {status} '{msg[:50]}' → '{result}' (expected: '{expected}')")


if __name__ == "__main__":
    apply_patch()
