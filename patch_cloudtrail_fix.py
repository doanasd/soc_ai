#!/usr/bin/env python3
"""
Patch pre-processor.py:
1. Fix username extraction — ưu tiên email trong principalId, không lấy sessionIssuer.userName
2. Fix outcome field — dùng "success"/"failure" thay vì "critical"
3. Thêm MFA tracking cho ConsoleLogin
Chạy trên EC2: python3 patch_cloudtrail_fix.py
"""
 
PATH = "/home/ubuntu/soc_ai/pre-processor.py"
 
OLD_USER_EXTRACT = '''    user_identity = aws.get("userIdentity", {})
    user_type     = user_identity.get("type", "")
    user_arn      = user_identity.get("arn", "")
    user_name     = ""
    if "sessionContext" in user_identity:
        user_name = user_identity["sessionContext"].get("sessionIssuer", {}).get("userName", "")
    if not user_name:
        user_name = user_identity.get("userName", user_arn.split("/")[-1] if user_arn else "")'''
 
NEW_USER_EXTRACT = '''    user_identity = aws.get("userIdentity", {})
    user_type     = user_identity.get("type", "")
    user_arn      = user_identity.get("arn", "")
    principal_id  = user_identity.get("principalId", "")
 
    # Ưu tiên lấy email/username thật từ principalId (format ROLE_ID:email@domain.com)
    # vì đây là identity thực tế của người gọi API, không phải tên IAM Role chung
    user_name = ""
    if ":" in principal_id:
        candidate = principal_id.split(":", 1)[1]
        if candidate and candidate != "":
            user_name = candidate
 
    # Fallback: ARN cuối cùng có thể chứa email (role/.../email@domain.com)
    if not user_name and user_arn and "/" in user_arn:
        last_segment = user_arn.rsplit("/", 1)[-1]
        if "@" in last_segment:
            user_name = last_segment
 
    # Fallback: sessionIssuer userName (tên Role, không phải người dùng cụ thể)
    if not user_name and "sessionContext" in user_identity:
        user_name = user_identity["sessionContext"].get("sessionIssuer", {}).get("userName", "")
 
    # Fallback cuối: userIdentity.userName trực tiếp (IAMUser, Root)
    if not user_name:
        user_name = user_identity.get("userName", "")
    if not user_name and user_arn:
        user_name = user_arn.split("/")[-1]
 
    # Lưu riêng tên Role (để phân biệt với user thật khi cần)
    role_name = ""
    if "sessionContext" in user_identity:
        role_name = user_identity["sessionContext"].get("sessionIssuer", {}).get("userName", "")
 
    # MFA tracking — quan trọng cho ConsoleLogin / root actions
    mfa_authenticated = "false"
    if "sessionContext" in user_identity:
        mfa_authenticated = str(
            user_identity["sessionContext"].get("attributes", {}).get("mfaAuthenticated", "false")
        ).lower()
    additional_data = aws.get("additionalEventData", {}) or {}
    if "MFAUsed" in additional_data:
        mfa_authenticated = "true" if str(additional_data.get("MFAUsed")).lower() in ("yes", "true") else "false"'''
 
OLD_RULE_LOGIC = '''    if event_name in HIGH_RISK_EVENTS:
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
        groups     = ["cloudtrail","aws","read_api"]'''
 
NEW_RULE_LOGIC = '''    if event_name in HIGH_RISK_EVENTS:
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
 
    # Root login without MFA — luôn escalate bất kể HIGH_RISK_EVENTS list
    if event_name == "ConsoleLogin" and user_type == "Root":
        rule_level = 12
        rule_id    = "cloudtrail_root_login"
        groups     = ["cloudtrail","aws","root_access"]
        if mfa_authenticated != "true":
            groups.append("no_mfa")
 
    # Repeated AccessDenied từ cùng user trong thời gian ngắn → bump severity
    # (xử lý ở mức window correlation trong AI Alert, ở đây chỉ tag để dedup nhận diện)
    if error_code == "AccessDenied" and user_name and "@" in user_name:
        groups.append("human_access_denied")'''
 
OLD_RETURN_DATA = '''        "data": {
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
        },'''
 
NEW_RETURN_DATA = '''        "data": {
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
            "role_name":    role_name,
            "mfa_authenticated": mfa_authenticated,
        },'''
 
 
def apply_patch():
    with open(PATH) as f:
        content = f.read()
 
    patches = [
        ("User extraction fix", OLD_USER_EXTRACT, NEW_USER_EXTRACT),
        ("Rule logic (root/MFA)", OLD_RULE_LOGIC, NEW_RULE_LOGIC),
        ("Return data (role_name/mfa)", OLD_RETURN_DATA, NEW_RETURN_DATA),
    ]
 
    if "role_name" in content and "mfa_authenticated" in content:
        print("⏭️  Already applied")
        return
 
    for name, old, new in patches:
        if old in content:
            content = content.replace(old, new)
            print(f"✅ {name}: applied")
        else:
            print(f"⚠️  {name}: pattern NOT FOUND")
 
    with open(PATH, "w") as f:
        f.write(content)
 
    import subprocess
    r = subprocess.run(["python3", "-m", "py_compile", PATH], capture_output=True, text=True)
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")
 
 
if __name__ == "__main__":
    apply_patch()
