#!/usr/bin/env python3
"""
Patch Phần 4: Telegram enrichment nâng cao
1. batching.py: đọc sample_event.enrichments (dict mới) thay vì chỉ maliciousIP cũ
2. telegram_writer.py: thêm section enrichment vào format_telegram_message()

Chạy trên EC2: python3 patch_telegram_enrichment.py
"""

import subprocess, sys

BATCHING_PATH      = "/home/ubuntu/soc_ai/AI_alert/app/batching.py"
TELEGRAM_PATH      = "/home/ubuntu/soc_ai/AI_alert/app/writers/telegram_writer.py"

# ── 1. Patch batching.py ─────────────────────────────────────────────────────
OLD_BATCHING = '''        # Extract maliciousIP from sample_event for threat intel context
        mal_ip = sample_event.get("maliciousIP")
        mal_info = None
        if isinstance(mal_ip, dict) and mal_ip.get("confidence_score", 0) > 0:
            mal_info = {
                "confidence_score": mal_ip.get("confidence_score"),
                "isp":              mal_ip.get("isp", ""),
                "country_code":     mal_ip.get("country_code", ""),
                "categories":       mal_ip.get("categories", []),
                "is_tor":           bool(mal_ip.get("is_tor")),
                "total_reports":    mal_ip.get("total_reports", 0),
                "source":           mal_ip.get("source", "abuseipdb"),
            }'''

NEW_BATCHING = '''        # Extract enrichment data từ enrichments dict (enricher v2) + backward-compat maliciousIP
        enrichments = sample_event.get("enrichments") or {}
        mal_ip      = sample_event.get("maliciousIP")
        mal_info    = None

        # Ưu tiên enrichments dict mới (đầy đủ hơn)
        # Tìm IP nguồn trong enrichments trước
        _src_candidate = data.get("src_ip") or network.get("source_ip") or ""
        _enrich_rec = enrichments.get(_src_candidate) if _src_candidate else None

        # Nếu không tìm được theo src_ip, lấy bất kỳ record nào is_malicious=True
        if not _enrich_rec:
            for _ip_key, _rec in enrichments.items():
                if isinstance(_rec, dict) and _rec.get("confidence_score", 0) > 0:
                    _enrich_rec = _rec
                    break

        if isinstance(_enrich_rec, dict) and _enrich_rec.get("confidence_score", 0) >= 0:
            otx = _enrich_rec.get("otx_context") or {}
            tf  = _enrich_rec.get("threat_feed_context") or {}
            mal_info = {
                "confidence_score":  _enrich_rec.get("confidence_score", 0),
                "is_malicious":      bool(_enrich_rec.get("is_malicious")),
                "threat_severity":   _enrich_rec.get("threat_severity", "none"),
                "reputation":        _enrich_rec.get("reputation", "benign"),
                "isp":               _enrich_rec.get("isp", ""),
                "asn":               _enrich_rec.get("asn", ""),
                "country_code":      _enrich_rec.get("country", ""),
                "country_name":      _enrich_rec.get("country_name", ""),
                "city":              _enrich_rec.get("city", ""),
                "usage_type":        _enrich_rec.get("usage_type", ""),
                "hostname":          _enrich_rec.get("hostname", ""),
                "domain":            _enrich_rec.get("domain", ""),
                "categories":        [_enrich_rec.get("category", "")] if _enrich_rec.get("category","") not in ("","clean") else [],
                "is_tor":            bool(_enrich_rec.get("is_tor")),
                "is_whitelisted":    bool(_enrich_rec.get("is_whitelisted")),
                "total_reports":     _enrich_rec.get("total_reports", 0),
                "source":            "abuseipdb",
                # OTX context
                "otx_pulse_count":   otx.get("pulse_count", 0),
                "otx_tags":          otx.get("tags", [])[:5],
                "otx_malware":       otx.get("malware_families", [])[:3],
                # ThreatFeed context
                "urlhaus_count":     tf.get("urlhaus_url_count", 0),
                "urlhaus_tags":      tf.get("urlhaus_tags", [])[:3],
                "threatfox_malware": tf.get("threatfox_malware", [])[:3],
            }
        elif isinstance(mal_ip, dict) and mal_ip.get("confidence_score", 0) > 0:
            # Fallback backward-compat
            mal_info = {
                "confidence_score": mal_ip.get("confidence_score"),
                "is_malicious":     True,
                "threat_severity":  "high" if mal_ip.get("confidence_score",0) >= 75 else "medium",
                "reputation":       "malicious",
                "isp":              mal_ip.get("isp", ""),
                "asn":              "",
                "country_code":     mal_ip.get("country_code", ""),
                "country_name":     "",
                "city":             "",
                "usage_type":       "",
                "hostname":         "",
                "domain":           "",
                "categories":       mal_ip.get("categories", []),
                "is_tor":           bool(mal_ip.get("is_tor")),
                "is_whitelisted":   False,
                "total_reports":    mal_ip.get("total_reports", 0),
                "source":           mal_ip.get("source", "abuseipdb"),
                "otx_pulse_count":  0,
                "otx_tags":         [],
                "otx_malware":      [],
                "urlhaus_count":    0,
                "urlhaus_tags":     [],
                "threatfox_malware": [],
            }'''

# ── 2. Patch telegram_writer.py ──────────────────────────────────────────────
OLD_TELEGRAM = '''def format_telegram_message(alert: Alert) -> str:
    analysis = alert.analysis
    event = alert.event
    window = event.get("window")
    period = event.get("period")
    usage = alert.usage or {}
    request_usage = usage.get("request") if isinstance(usage, dict) else {}
    daily_usage = usage.get("daily") if isinstance(usage, dict) else {}

    lines = [
        f"ALERT {analysis.severity.upper()} {analysis.confidence}%",
        analysis.title,
        f"Category: {analysis.category}",
    ]

    if isinstance(window, dict):
        start = window.get("start") or "-"
        end = window.get("end") or "-"
        total = window.get("aggregated_record_count") or window.get("event_count") or "-"
        dominant_log_type = event.get("dominant_log_type") or "-"
        flush_reason = window.get("flush_reason") or "-"
        lines.append(
            f"Window: {start} -> {end} | total={total} | type={dominant_log_type} | reason={flush_reason}"
        )
    elif isinstance(period, dict):
        start = period.get("start") or "-"
        end = period.get("end") or "-"
        batches = event.get("batches_analyzed") or "-"
        events = event.get("event_count") or "-"
        lines.append(f"Period: {start} -> {end} | batches={batches} | events={events}")
    else:
        src_ip = event.get("src_ip") or "-"
        dst_ip = event.get("dst_ip") or "-"
        log_type = event.get("log_type") or "-"
        lines.append(f"Event: src={src_ip} dst={dst_ip} type={log_type}")

    if isinstance(request_usage, dict):
        lines.append(
            "LLM usage: "
            f"prompt={request_usage.get('prompt_tokens', 0)} "
            f"cached={request_usage.get('cached_tokens', 0)} "
            f"completion={request_usage.get('completion_tokens', 0)} "
            f"cost={_format_cost(request_usage.get('total_cost_usd'))} "
            f"today={_format_cost((daily_usage or {}).get('total_cost_usd'))}"
        )

    correlation_line = _format_correlation_line(event)
    if correlation_line:
        lines.append(correlation_line)

    if analysis.summary:
        lines.append(f"Summary: {analysis.summary}")

    if analysis.recommended_actions:
        lines.append("Actions:")
        for action in analysis.recommended_actions[:4]:
            lines.append(f"- {action}")

    lines.append(f"Dedup: {analysis.dedup_key or '-'}")
    return "\\n".join(lines)'''

NEW_TELEGRAM = '''def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
        "none":     "⚪",
    }.get((severity or "").lower(), "⚪")


def _format_enrichment_section(top_groups: list) -> list[str]:
    """Tạo section enrichment IP cho Telegram message từ top_groups."""
    lines = []
    seen_ips = set()

    for row in (top_groups or []):
        mal = row.get("malicious_src")
        src_ip = row.get("src_ip") or ""

        # Hiển thị info cho mọi IP public (không chỉ malicious)
        if not src_ip or src_ip in seen_ips:
            continue
        seen_ips.add(src_ip)

        if not isinstance(mal, dict):
            continue

        score    = mal.get("confidence_score", 0)
        severity = mal.get("threat_severity", "none")
        is_mal   = mal.get("is_malicious", False)
        is_tor   = mal.get("is_tor", False)
        isp      = mal.get("isp", "")
        country  = mal.get("country_name") or mal.get("country_code", "")
        city     = mal.get("city", "")
        asn      = mal.get("asn", "")
        hostname = mal.get("hostname", "")
        domain   = mal.get("domain", "")
        usage    = mal.get("usage_type", "")
        cats     = mal.get("categories", [])
        reports  = mal.get("total_reports", 0)

        otx_pulses  = mal.get("otx_pulse_count", 0)
        otx_tags    = mal.get("otx_tags", [])
        otx_malware = mal.get("otx_malware", [])
        uh_count    = mal.get("urlhaus_count", 0)
        tf_malware  = mal.get("threatfox_malware", [])

        sev_icon = _severity_emoji(severity)
        mal_flag = " ⚠️ MALICIOUS" if is_mal else ""
        tor_flag = " 🧅 TOR" if is_tor else ""

        lines.append(f"[IP] {src_ip}{mal_flag}{tor_flag}")
        lines.append(f"  AbuseIPDB: score={score} | severity={severity} {sev_icon} | reports={reports}")

        loc_parts = [p for p in [city, country] if p]
        if loc_parts:
            lines.append(f"  Location: {', '.join(loc_parts)}")
        if isp:
            isp_line = f"  ISP: {isp}"
            if asn:
                isp_line += f" | ASN: {asn}"
            if usage:
                isp_line += f" | Usage: {usage}"
            lines.append(isp_line)
        if hostname or domain:
            lines.append(f"  Host: {hostname or domain}")
        if cats:
            lines.append(f"  Categories: {', '.join(cats[:3])}")

        if otx_pulses > 0:
            otx_line = f"  OTX: {otx_pulses} pulse(s)"
            if otx_tags:
                otx_line += f" | tags={', '.join(otx_tags[:3])}"
            if otx_malware:
                otx_line += f" | malware={', '.join(otx_malware[:2])}"
            lines.append(otx_line)

        tf_parts = []
        if uh_count > 0:
            tf_parts.append(f"URLhaus={uh_count} URLs")
        if tf_malware:
            tf_parts.append(f"ThreatFox={', '.join(tf_malware[:2])}")
        if tf_parts:
            lines.append(f"  ThreatFeed: {' | '.join(tf_parts)}")

    return lines


def format_telegram_message(alert: Alert) -> str:
    analysis = alert.analysis
    event = alert.event
    window = event.get("window")
    period = event.get("period")
    usage = alert.usage or {}
    request_usage = usage.get("request") if isinstance(usage, dict) else {}
    daily_usage = usage.get("daily") if isinstance(usage, dict) else {}

    sev_icon = _severity_emoji(analysis.severity)
    lines = [
        f"{sev_icon} ALERT {analysis.severity.upper()} {analysis.confidence}% {sev_icon}",
        analysis.title,
        f"Category: {analysis.category}",
    ]

    if isinstance(window, dict):
        start = window.get("start") or "-"
        end = window.get("end") or "-"
        total = window.get("aggregated_record_count") or window.get("event_count") or "-"
        dominant_log_type = event.get("dominant_log_type") or "-"
        flush_reason = window.get("flush_reason") or "-"
        lines.append(
            f"Window: {start} -> {end} | total={total} | type={dominant_log_type} | reason={flush_reason}"
        )
    elif isinstance(period, dict):
        start = period.get("start") or "-"
        end = period.get("end") or "-"
        batches = event.get("batches_analyzed") or "-"
        events = event.get("event_count") or "-"
        lines.append(f"Period: {start} -> {end} | batches={batches} | events={events}")
    else:
        src_ip = event.get("src_ip") or "-"
        dst_ip = event.get("dst_ip") or "-"
        log_type = event.get("log_type") or "-"
        lines.append(f"Event: src={src_ip} dst={dst_ip} type={log_type}")

    # ── Enrichment section ────────────────────────────────────────────────────
    top_groups = event.get("top_groups") or []
    enrichment_lines = _format_enrichment_section(top_groups)
    if enrichment_lines:
        lines.append("── Threat Intel ──")
        lines.extend(enrichment_lines)

    if isinstance(request_usage, dict):
        lines.append(
            "LLM usage: "
            f"prompt={request_usage.get('prompt_tokens', 0)} "
            f"cached={request_usage.get('cached_tokens', 0)} "
            f"completion={request_usage.get('completion_tokens', 0)} "
            f"cost={_format_cost(request_usage.get('total_cost_usd'))} "
            f"today={_format_cost((daily_usage or {}).get('total_cost_usd'))}"
        )

    correlation_line = _format_correlation_line(event)
    if correlation_line:
        lines.append(correlation_line)

    if analysis.summary:
        lines.append(f"Summary: {analysis.summary}")

    if analysis.recommended_actions:
        lines.append("Actions:")
        for action in analysis.recommended_actions[:4]:
            lines.append(f"- {action}")

    lines.append(f"Dedup: {analysis.dedup_key or '-'}")
    return "\\n".join(lines)'''


def apply_patch(path: str, name: str, old: str, new: str):
    with open(path) as f:
        content = f.read()

    if old not in content:
        # Kiểm tra xem đã patch chưa (dấu hiệu từ code mới)
        marker = "_format_enrichment_section" if "telegram" in path else "otx_pulse_count"
        if marker in content:
            print(f"⏭️  {name}: already applied")
        else:
            print(f"⚠️  {name}: pattern NOT FOUND — manual check needed")
            # In ra 5 dòng đầu của old để debug
            print(f"   Looking for: {repr(old[:80])}")
        return

    content = content.replace(old, new)
    with open(path, "w") as f:
        f.write(content)
    print(f"✅ {name}: applied")


def main():
    import shutil

    # Backup
    shutil.copy(BATCHING_PATH, BATCHING_PATH + ".bak")
    shutil.copy(TELEGRAM_PATH, TELEGRAM_PATH + ".bak")

    apply_patch(BATCHING_PATH, "batching.py enrichment reader", OLD_BATCHING, NEW_BATCHING)
    apply_patch(TELEGRAM_PATH, "telegram_writer.py enrichment section", OLD_TELEGRAM, NEW_TELEGRAM)

    # Syntax check
    for path in [BATCHING_PATH, TELEGRAM_PATH]:
        r = subprocess.run(
            ["python3", "-m", "py_compile", path],
            capture_output=True, text=True
        )
        name = path.split("/")[-1]
        if r.returncode == 0:
            print(f"✅ {name}: syntax OK")
        else:
            print(f"❌ {name}: syntax ERROR\n{r.stderr}")


if __name__ == "__main__":
    main()
