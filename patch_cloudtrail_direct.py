#!/usr/bin/env python3
"""
Patch normalize-service.py:
Viết lại normalize_cloudtrail_event() để đọc TRỰC TIẾP raw CloudTrail JSON gốc
{"integration": "aws", "aws": {...}} — KHÔNG qua pre-processor.

Đồng thời sửa routing trong normalize_event() để nhận diện đúng format này.

Chạy trên EC2: python3 patch_cloudtrail_direct.py
"""

PATH = "/home/ubuntu/soc_ai/normalize-service.py"

# ── 1. Thay thế toàn bộ normalize_cloudtrail_event() cũ ────────────────────
OLD_FUNC = '''def normalize_cloudtrail_event(archive_evt: dict) -> Optional[dict]:
    """CloudTrail event đã qua pre-processor → normalize về schema chuẩn."""
    data      = archive_evt.get("data", {}) or {}
    rule      = archive_evt.get("rule", {}) or {}
    agent     = archive_evt.get("agent", {}) or {}
    predecoder = archive_evt.get("predecoder", {}) or {}
    cloudtrail = archive_evt.get("cloudtrail", {}) or {}

    aws_event   = data.get("aws_event", "")
    aws_source  = data.get("aws_source", "")
    aws_region  = data.get("aws_region", "")
    aws_account = data.get("aws_account", "")
    src_ip      = data.get("srcip", "")
    user_name   = data.get("dstuser", "")
    user_arn    = data.get("user_arn", "")
    user_type   = data.get("user_type", "")
    read_only   = data.get("read_only", "True")
    error_code  = data.get("error_code", "")

    # Classify action
    if error_code:
        action = "api_error"
    elif read_only in ("True", "true", True):
        action = "api_read"
    else:
        action = "api_write"

    # Source IP — AWS service calls dùng service name, không phải IP
    network_src_ip = src_ip if re.match(r'\\d+\\.\\d+\\.\\d+\\.\\d+', src_ip) else ""
    network_src_host = src_ip if not network_src_ip else ""

    rule_level = rule.get("level", 3)
    outcome = "unknown"
    if rule_level >= 10: outcome = "critical"
    elif rule_level >= 8: outcome = "failure"
    elif rule_level >= 5: outcome = "warning"
    elif rule_level >= 3: outcome = "success"

    message = rule.get("description", f"CloudTrail: {aws_event}")
    if error_code:
        message += f" [ERROR: {error_code}: {data.get('error_message', '')}]"

    return {
        "time":           archive_evt.get("timestamp"),
        "log_type":       "cloudtrail",
        "vendor":         "aws",
        "action":         action,
        "outcome":        outcome,
        "asset_host":     f"aws-{aws_account}" if aws_account else agent.get("name", ""),
        "correlation_id": data.get("request_id", ""),
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
            "eventName":    aws_event,
            "eventSource":  aws_source,
            "awsRegion":    aws_region,
            "accountId":    aws_account,
            "userType":     user_type,
            "userName":     user_name,
            "userArn":      user_arn,
            "sourceIP":     src_ip,
            "readOnly":     read_only,
            "errorCode":    error_code,
            "ruleLevel":    rule_level,
            "ruleGroups":   rule.get("groups", []),
            "ruleId":       rule.get("id", ""),
        },
    }'''

NEW_FUNC = '''# High-risk CloudTrail events — luôn được severity cao bất kể readOnly
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

    network_src_ip = src_ip if re.match(r'\\d+\\.\\d+\\.\\d+\\.\\d+', src_ip) else ""

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
    }'''


# ── 2. Sửa routing condition trong normalize_event() ───────────────────────
OLD_ROUTING = '''    if (isinstance(location, str) and location.startswith("/aws/cloudtrail/")) or decoder_name == "cloudtrail":
        return normalize_cloudtrail_event(archive_evt)'''

NEW_ROUTING = '''    if (isinstance(location, str) and location.startswith("/aws/cloudtrail/")) or decoder_name == "cloudtrail":
        return normalize_cloudtrail_event(archive_evt)

    # CloudTrail raw trực tiếp (không qua pre-processor): {"integration":"aws","aws":{...}}
    if isinstance(archive_evt.get("aws"), dict) and archive_evt["aws"].get("eventName"):
        return normalize_cloudtrail_event(archive_evt)
    if archive_evt.get("integration") == "aws" and isinstance(archive_evt.get("aws"), dict):
        return normalize_cloudtrail_event(archive_evt)'''


def apply_patch():
    with open(PATH) as f:
        content = f.read()

    if 'archive_evt.get("aws") or {}' in content:
        print("⏭️  CloudTrail direct parser already applied")
        return

    patches = [
        ("Rewrite normalize_cloudtrail_event()", OLD_FUNC, NEW_FUNC),
        ("Fix routing condition",                 OLD_ROUTING, NEW_ROUTING),
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
    print("\n✅ Syntax OK" if r.returncode == 0 else f"\n❌ Syntax error:\n{r.stderr}")


if __name__ == "__main__":
    apply_patch()
