#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malicious IP/Indicator Enricher v2 — Multi-source threat intelligence
Nguồn: AbuseIPDB (score chính) + AlienVault OTX (context) + URLhaus/ThreatFox (malware context)

Cache-aside per source: 3 SQLite DB riêng biệt
  - abuseipdb.db  : IP reputation, score chính (is_malicious = score >= 50)
  - otx.db        : OTX pulse context (categories, pulse names, tags)
  - threat_feeds.db: URLhaus + ThreatFox (malware family, botnet C2)

Whitelist: file text, mỗi dòng 1 IP, bỏ qua hoàn toàn việc lookup.

Output schema (trong sample_event):
  "enrichments": {
    "<ip>": {
      "source": "AbuseIPDB",
      "confidence_score": 0-100,
      "is_malicious": bool,        # score >= 50
      "threat_severity": "none|low|medium|high|critical",
      "reputation": "benign|suspicious|malicious",
      "category": "...",
      "country": "..",
      "usage_type": "...",
      "is_tor": bool,
      "is_whitelisted": bool,
      "isp": "...", "asn": "...", "hostname": "...", "domain": "...",
      "city": "...",
      "otx_context": {"pulse_count": N, "pulse_names": [...], "tags": [...]},
      "threat_feed_context": {"urlhaus_tags": [...], "threatfox_malware": [...]}
    }
  }
"""

import copy
import ipaddress
import json
import logging
import os
import signal
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ── Paths & Config ────────────────────────────────────────────────────────────
INPUT_FILE   = os.getenv("DEDUP_PATH",     "/home/ubuntu/soc_ai/log_dedup.json")
OUTPUT_FILE  = os.getenv("ENRICHED_PATH",  "/home/ubuntu/soc_ai/log_enriched.json")
DATA_DIR     = os.getenv("ENRICHER_DATA_DIR", "/home/ubuntu/soc_ai/data")

ABUSEIPDB_DB_PATH    = os.getenv("ABUSEIPDB_DB",     os.path.join(DATA_DIR, "abuseipdb.db"))
OTX_DB_PATH          = os.getenv("OTX_DB",           os.path.join(DATA_DIR, "otx.db"))
THREAT_FEEDS_DB_PATH = os.getenv("THREAT_FEEDS_DB",  os.path.join(DATA_DIR, "threat_feeds.db"))
WHITELIST_PATH       = os.getenv("WHITELIST_PATH",   "/home/ubuntu/soc_ai/whitelist_ips.txt")

ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY        = os.getenv("OTX_API_KEY", "")

ABUSEIPDB_URL       = "https://api.abuseipdb.com/api/v2/check"
OTX_URL_TEMPLATE    = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
URLHAUS_HOST_URL    = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API_URL   = "https://threatfox-api.abuse.ch/api/v1/"

MAX_AGE_DAYS_QUERY = int(os.getenv("ABUSE_MAX_AGE_DAYS", "90"))
API_RATE_DELAY     = float(os.getenv("API_RATE_DELAY", "0.5"))

TTL_HIGH   = int(os.getenv("TTL_HIGH_RISK_DAYS", "3"))   * 86400
TTL_MEDIUM = int(os.getenv("TTL_MEDIUM_DAYS",    "7"))   * 86400
TTL_LOW    = int(os.getenv("TTL_LOW_RISK_DAYS",  "14"))  * 86400
TTL_ERROR  = int(os.getenv("TTL_ERROR_HOURS",    "1"))   * 3600
TTL_OTX    = int(os.getenv("TTL_OTX_DAYS",       "7"))   * 86400
TTL_THREATFEED = int(os.getenv("TTL_THREATFEED_DAYS", "3")) * 86400

POLL_INTERVAL    = float(os.getenv("ENRICHER_POLL", "1"))
METRICS_INTERVAL = 30

AUTHORIZED_IPS = {
    "13.228.154.28","18.138.71.183","18.141.241.219",
    "165.173.9.115","52.74.202.90",
}

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [enricher] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


# ── Whitelist ─────────────────────────────────────────────────────────────────

def load_whitelist(path: str) -> set:
    """Đọc file whitelist, mỗi dòng 1 IP (hoặc CIDR đơn giản /32). Comment bằng #."""
    whitelist = set()
    p = Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            "# Whitelist IPs — mỗi dòng 1 IP, bỏ qua hoàn toàn enrichment lookup\n"
            "# Thêm IP khách hàng / đối tác tin cậy vào đây\n"
            "# Ví dụ: 203.0.113.5\n",
            encoding="utf-8",
        )
        logger.info(f"Created empty whitelist file: {path}")
        return whitelist

    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        whitelist.add(line)
    return whitelist


# ── SQLite Cache (3 DB riêng biệt) ──────────────────────────────────────────

def init_abuseipdb_db(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip               TEXT PRIMARY KEY,
            score            INTEGER NOT NULL DEFAULT 0,
            country_code     TEXT DEFAULT '',
            country_name     TEXT DEFAULT '',
            city              TEXT DEFAULT '',
            isp              TEXT DEFAULT '',
            asn              TEXT DEFAULT '',
            usage_type       TEXT DEFAULT '',
            domain           TEXT DEFAULT '',
            hostnames        TEXT DEFAULT '[]',
            total_reports    INTEGER DEFAULT 0,
            num_distinct_users INTEGER DEFAULT 0,
            last_reported    TEXT DEFAULT '',
            categories       TEXT DEFAULT '[]',
            is_whitelisted   INTEGER DEFAULT 0,
            is_tor           INTEGER DEFAULT 0,
            fetch_status     TEXT DEFAULT 'ok',
            fetched_at       TEXT NOT NULL,
            expires_at       TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_abuseipdb_expires ON ip_reputation(expires_at)")
    conn.commit()
    logger.info(f"AbuseIPDB cache ready: {db_path}")
    return conn


def init_otx_db(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS otx_indicators (
            ip               TEXT PRIMARY KEY,
            pulse_count      INTEGER DEFAULT 0,
            pulse_names      TEXT DEFAULT '[]',
            tags             TEXT DEFAULT '[]',
            malware_families TEXT DEFAULT '[]',
            country          TEXT DEFAULT '',
            asn              TEXT DEFAULT '',
            reputation_raw   INTEGER DEFAULT 0,
            fetch_status     TEXT DEFAULT 'ok',
            fetched_at       TEXT NOT NULL,
            expires_at       TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_otx_expires ON otx_indicators(expires_at)")
    conn.commit()
    logger.info(f"OTX cache ready: {db_path}")
    return conn


def init_threat_feeds_db(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_feed_indicators (
            ip                  TEXT PRIMARY KEY,
            urlhaus_url_count   INTEGER DEFAULT 0,
            urlhaus_tags        TEXT DEFAULT '[]',
            urlhaus_status      TEXT DEFAULT '',
            threatfox_malware   TEXT DEFAULT '[]',
            threatfox_confidence INTEGER DEFAULT 0,
            fetch_status        TEXT DEFAULT 'ok',
            fetched_at          TEXT NOT NULL,
            expires_at          TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tf_expires ON threat_feed_indicators(expires_at)")
    conn.commit()
    logger.info(f"Threat feeds cache ready: {db_path}")
    return conn


def get_cached(conn: sqlite3.Connection, table: str, ip: str) -> Optional[dict]:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        f"SELECT * FROM {table} WHERE ip=? AND expires_at>?", (ip, now)
    )
    cols = [d[0] for d in cur.description]
    row  = cur.fetchone()
    if not row:
        return None
    record = dict(zip(cols, row))
    for json_field in ("categories", "hostnames", "pulse_names", "tags",
                        "malware_families", "urlhaus_tags", "threatfox_malware"):
        if json_field in record:
            try:
                record[json_field] = json.loads(record.get(json_field) or "[]")
            except Exception:
                record[json_field] = []
    return record


def save_abuseipdb_cache(conn, ip: str, data: dict, ttl_seconds: int):
    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    conn.execute("""
        INSERT INTO ip_reputation
            (ip,score,country_code,country_name,city,isp,asn,usage_type,domain,
             hostnames,total_reports,num_distinct_users,last_reported,categories,
             is_whitelisted,is_tor,fetch_status,fetched_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            score=excluded.score, country_code=excluded.country_code,
            country_name=excluded.country_name, city=excluded.city,
            isp=excluded.isp, asn=excluded.asn, usage_type=excluded.usage_type,
            domain=excluded.domain, hostnames=excluded.hostnames,
            total_reports=excluded.total_reports,
            num_distinct_users=excluded.num_distinct_users,
            last_reported=excluded.last_reported, categories=excluded.categories,
            is_whitelisted=excluded.is_whitelisted, is_tor=excluded.is_tor,
            fetch_status=excluded.fetch_status, fetched_at=excluded.fetched_at,
            expires_at=excluded.expires_at
    """, (
        ip, data.get("score",0), data.get("country_code",""), data.get("country_name",""),
        data.get("city",""), data.get("isp",""), data.get("asn",""),
        data.get("usage_type",""), data.get("domain",""),
        json.dumps(data.get("hostnames",[])),
        data.get("total_reports",0), data.get("num_distinct_users",0),
        data.get("last_reported",""), json.dumps(data.get("categories",[])),
        1 if data.get("is_whitelisted") else 0,
        1 if data.get("is_tor") else 0,
        data.get("fetch_status","ok"),
        now.isoformat(), expires_at,
    ))
    conn.commit()


def save_otx_cache(conn, ip: str, data: dict, ttl_seconds: int):
    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    conn.execute("""
        INSERT INTO otx_indicators
            (ip,pulse_count,pulse_names,tags,malware_families,country,asn,
             reputation_raw,fetch_status,fetched_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            pulse_count=excluded.pulse_count, pulse_names=excluded.pulse_names,
            tags=excluded.tags, malware_families=excluded.malware_families,
            country=excluded.country, asn=excluded.asn,
            reputation_raw=excluded.reputation_raw,
            fetch_status=excluded.fetch_status, fetched_at=excluded.fetched_at,
            expires_at=excluded.expires_at
    """, (
        ip, data.get("pulse_count",0), json.dumps(data.get("pulse_names",[])),
        json.dumps(data.get("tags",[])), json.dumps(data.get("malware_families",[])),
        data.get("country",""), data.get("asn",""), data.get("reputation_raw",0),
        data.get("fetch_status","ok"), now.isoformat(), expires_at,
    ))
    conn.commit()


def save_threat_feeds_cache(conn, ip: str, data: dict, ttl_seconds: int):
    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    conn.execute("""
        INSERT INTO threat_feed_indicators
            (ip,urlhaus_url_count,urlhaus_tags,urlhaus_status,
             threatfox_malware,threatfox_confidence,fetch_status,fetched_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            urlhaus_url_count=excluded.urlhaus_url_count,
            urlhaus_tags=excluded.urlhaus_tags, urlhaus_status=excluded.urlhaus_status,
            threatfox_malware=excluded.threatfox_malware,
            threatfox_confidence=excluded.threatfox_confidence,
            fetch_status=excluded.fetch_status, fetched_at=excluded.fetched_at,
            expires_at=excluded.expires_at
    """, (
        ip, data.get("urlhaus_url_count",0), json.dumps(data.get("urlhaus_tags",[])),
        data.get("urlhaus_status",""), json.dumps(data.get("threatfox_malware",[])),
        data.get("threatfox_confidence",0), data.get("fetch_status","ok"),
        now.isoformat(), expires_at,
    ))
    conn.commit()


def cleanup_expired(conn: sqlite3.Connection, table: str):
    now    = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(f"DELETE FROM {table} WHERE expires_at<=?", (now,))
    if cursor.rowcount > 0:
        conn.commit()
        logger.info(f"Cleaned {cursor.rowcount} expired records from {table}")


# ── Source 1: AbuseIPDB ──────────────────────────────────────────────────────

ABUSE_CATEGORIES = {
    1:"DNS_Compromise",2:"DNS_Poisoning",3:"Fraud_Orders",4:"DDoS_Attack",
    5:"FTP_Brute_Force",6:"Ping_of_Death",7:"Phishing",8:"Fraud_VoIP",
    9:"Open_Proxy",10:"Web_Spam",11:"Email_Spam",12:"Blog_Spam",13:"VPN_IP",
    14:"Port_Scan",15:"Hacking",16:"SQL_Injection",17:"Spoofing",
    18:"Brute_Force",19:"Bad_Web_Bot",20:"Exploited_Host",21:"Web_App_Attack",
    22:"SSH_Brute_Force",23:"IoT_Targeted",
}


def call_abuseipdb(ip: str) -> Optional[dict]:
    if not ABUSEIPDB_API_KEY:
        return None
    url = f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays={MAX_AGE_DAYS_QUERY}&verbose"
    req = urllib.request.Request(url, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read().decode()).get("data", {})
        score     = int(d.get("abuseConfidenceScore", 0))
        reports   = d.get("reports", [])
        cat_ids   = reports[0].get("categories", []) if reports else []
        cat_names = [ABUSE_CATEGORIES.get(c, str(c)) for c in cat_ids]
        hostnames = d.get("hostnames", [])
        return {
            "score":              score,
            "country_code":       d.get("countryCode",""),
            "country_name":       d.get("countryName",""),
            "city":               "",
            "isp":                d.get("isp",""),
            "asn":                str(d.get("asn","") or ""),
            "usage_type":         d.get("usageType",""),
            "domain":             d.get("domain",""),
            "hostnames":          hostnames if isinstance(hostnames, list) else [],
            "total_reports":      int(d.get("totalReports",0)),
            "num_distinct_users": int(d.get("numDistinctUsers", 0)),
            "last_reported":      d.get("lastReportedAt",""),
            "categories":         cat_names,
            "is_whitelisted":     bool(d.get("isWhitelisted",False)),
            "is_tor":             bool(d.get("isTor",False)),
            "fetch_status":       "ok",
        }
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning(f"AbuseIPDB rate limit hit for {ip}, sleeping 60s")
            time.sleep(60)
        else:
            logger.error(f"AbuseIPDB HTTP {e.code} for {ip}")
        return None
    except Exception as e:
        logger.error(f"AbuseIPDB error for {ip}: {e}")
        return None


def get_abuseipdb_ttl(score: int) -> int:
    if score >= 75:  return TTL_HIGH
    if score >= 25:  return TTL_MEDIUM
    return TTL_LOW


def lookup_abuseipdb(conn, ip: str, stats: dict) -> Optional[dict]:
    cached = get_cached(conn, "ip_reputation", ip)
    if cached:
        stats["abuseipdb_cache_hits"] += 1
        return cached

    stats["abuseipdb_cache_misses"] += 1
    if not ABUSEIPDB_API_KEY:
        placeholder = {
            "score":0,"country_code":"","country_name":"","city":"","isp":"",
            "asn":"","usage_type":"","domain":"","hostnames":[],"total_reports":0,
            "num_distinct_users":0,"last_reported":"","categories":[],
            "is_whitelisted":False,"is_tor":False,"fetch_status":"no_api_key",
        }
        save_abuseipdb_cache(conn, ip, placeholder, TTL_LOW)
        return placeholder

    result = call_abuseipdb(ip)
    time.sleep(API_RATE_DELAY)

    if result is None:
        error_rec = {
            "score":0,"country_code":"","country_name":"","city":"","isp":"",
            "asn":"","usage_type":"","domain":"","hostnames":[],"total_reports":0,
            "num_distinct_users":0,"last_reported":"","categories":[],
            "is_whitelisted":False,"is_tor":False,"fetch_status":"error",
        }
        save_abuseipdb_cache(conn, ip, error_rec, TTL_ERROR)
        stats["abuseipdb_api_errors"] += 1
        return None

    save_abuseipdb_cache(conn, ip, result, get_abuseipdb_ttl(result["score"]))
    stats["abuseipdb_api_calls"] += 1

    if result["score"] >= 75:
        logger.warning(f"HIGH RISK (AbuseIPDB): {ip} score={result['score']} isp={result['isp']}")
    elif result["score"] >= 25:
        logger.info(f"Medium risk (AbuseIPDB): {ip} score={result['score']}")

    return result


# ── Source 2: AlienVault OTX ─────────────────────────────────────────────────

def call_otx(ip: str) -> Optional[dict]:
    if not OTX_API_KEY:
        return None
    url = OTX_URL_TEMPLATE.format(ip=ip)
    req = urllib.request.Request(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read().decode())

        pulse_info = d.get("pulse_info", {}) or {}
        pulses     = pulse_info.get("pulses", []) or []
        pulse_count = pulse_info.get("count", len(pulses))
        pulse_names = [p.get("name", "") for p in pulses[:10] if p.get("name")]

        tags = set()
        malware_families = set()
        for p in pulses[:10]:
            for t in p.get("tags", []) or []:
                tags.add(t)
            for mf in p.get("malware_families", []) or []:
                if isinstance(mf, dict):
                    malware_families.add(mf.get("display_name", ""))
                elif isinstance(mf, str):
                    malware_families.add(mf)

        country = d.get("country_name", "") or ""
        asn     = d.get("asn", "") or ""
        reputation_raw = d.get("reputation", 0) or 0

        return {
            "pulse_count":      pulse_count,
            "pulse_names":      pulse_names,
            "tags":             sorted(t for t in tags if t),
            "malware_families": sorted(m for m in malware_families if m),
            "country":          country,
            "asn":              str(asn),
            "reputation_raw":   reputation_raw,
            "fetch_status":     "ok",
        }
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning(f"OTX rate limit hit for {ip}, sleeping 30s")
            time.sleep(30)
        elif e.code == 404:
            return {
                "pulse_count": 0, "pulse_names": [], "tags": [],
                "malware_families": [], "country": "", "asn": "",
                "reputation_raw": 0, "fetch_status": "ok",
            }
        else:
            logger.error(f"OTX HTTP {e.code} for {ip}")
        return None
    except Exception as e:
        logger.error(f"OTX error for {ip}: {e}")
        return None


def lookup_otx(conn, ip: str, stats: dict) -> Optional[dict]:
    cached = get_cached(conn, "otx_indicators", ip)
    if cached:
        stats["otx_cache_hits"] += 1
        return cached

    stats["otx_cache_misses"] += 1
    if not OTX_API_KEY:
        return None

    result = call_otx(ip)
    time.sleep(API_RATE_DELAY)

    if result is None:
        error_rec = {
            "pulse_count": 0, "pulse_names": [], "tags": [],
            "malware_families": [], "country": "", "asn": "",
            "reputation_raw": 0, "fetch_status": "error",
        }
        save_otx_cache(conn, ip, error_rec, TTL_ERROR)
        stats["otx_api_errors"] += 1
        return None

    save_otx_cache(conn, ip, result, TTL_OTX)
    stats["otx_api_calls"] += 1

    if result["pulse_count"] > 0:
        logger.info(f"OTX context: {ip} pulses={result['pulse_count']} tags={result['tags'][:3]}")

    return result


# ── Source 3: URLhaus + ThreatFox (abuse.ch) ────────────────────────────────

def call_urlhaus(ip: str) -> dict:
    """URLhaus host lookup — trả về URLs lưu trữ malware trên IP này."""
    try:
        req = urllib.request.Request(
            URLHAUS_HOST_URL,
            data=f"host={ip}".encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read().decode())

        if d.get("query_status") != "ok":
            return {"urlhaus_url_count": 0, "urlhaus_tags": [], "urlhaus_status": "clean"}

        urls = d.get("urls", []) or []
        tags = set()
        for u in urls[:10]:
            for t in (u.get("tags") or []):
                tags.add(t)

        return {
            "urlhaus_url_count": len(urls),
            "urlhaus_tags":      sorted(tags),
            "urlhaus_status":    "listed" if urls else "clean",
        }
    except Exception as e:
        logger.debug(f"URLhaus error for {ip}: {e}")
        return {"urlhaus_url_count": 0, "urlhaus_tags": [], "urlhaus_status": "error"}


def call_threatfox(ip: str) -> dict:
    """ThreatFox IOC search — trả về malware family nếu IP là IOC đã biết."""
    try:
        payload = json.dumps({"query": "search_ioc", "search_term": ip}).encode()
        req = urllib.request.Request(
            THREATFOX_API_URL, data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read().decode())

        if d.get("query_status") != "ok":
            return {"threatfox_malware": [], "threatfox_confidence": 0}

        data = d.get("data", []) or []
        if not isinstance(data, list):
            return {"threatfox_malware": [], "threatfox_confidence": 0}

        malware = set()
        max_confidence = 0
        for entry in data[:10]:
            mw = entry.get("malware_printable") or entry.get("malware", "")
            if mw:
                malware.add(mw)
            conf = entry.get("confidence_level", 0) or 0
            max_confidence = max(max_confidence, conf)

        return {
            "threatfox_malware":    sorted(malware),
            "threatfox_confidence": max_confidence,
        }
    except Exception as e:
        logger.debug(f"ThreatFox error for {ip}: {e}")
        return {"threatfox_malware": [], "threatfox_confidence": 0}


def lookup_threat_feeds(conn, ip: str, stats: dict) -> Optional[dict]:
    cached = get_cached(conn, "threat_feed_indicators", ip)
    if cached:
        stats["threatfeed_cache_hits"] += 1
        return cached

    stats["threatfeed_cache_misses"] += 1

    urlhaus_result = call_urlhaus(ip)
    time.sleep(API_RATE_DELAY)
    threatfox_result = call_threatfox(ip)
    time.sleep(API_RATE_DELAY)

    result = {**urlhaus_result, **threatfox_result, "fetch_status": "ok"}
    save_threat_feeds_cache(conn, ip, result, TTL_THREATFEED)
    stats["threatfeed_api_calls"] += 1

    if result["urlhaus_url_count"] > 0 or result["threatfox_malware"]:
        logger.warning(
            f"Threat feed hit: {ip} urlhaus_urls={result['urlhaus_url_count']} "
            f"threatfox_malware={result['threatfox_malware']}"
        )

    return result


# ── IP Filter ─────────────────────────────────────────────────────────────────

def should_lookup(ip: str, whitelist: set) -> bool:
    if not ip or not isinstance(ip, str) or not ip.strip():
        return False
    ip = ip.strip()
    if ip in AUTHORIZED_IPS or ip in whitelist:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


def is_ip_whitelisted(ip: str, whitelist: set) -> bool:
    return ip in whitelist or ip in AUTHORIZED_IPS


# ── Severity / Reputation mapping ────────────────────────────────────────────

def severity_from_score(score: int) -> str:
    if score >= 90: return "critical"
    if score >= 75: return "high"
    if score >= 50: return "medium"
    if score >= 25: return "low"
    return "none"


def reputation_from_score(score: int) -> str:
    if score >= 50: return "malicious"
    if score >= 25: return "suspicious"
    return "benign"


# ── Build unified enrichment record cho 1 IP ─────────────────────────────────

def build_enrichment_record(
    ip: str,
    abuse_data: Optional[dict],
    otx_data: Optional[dict],
    threatfeed_data: Optional[dict],
    whitelist: set,
) -> dict:
    """Gộp kết quả 3 nguồn thành 1 record enrichment thống nhất cho 1 IP."""
    is_wl = is_ip_whitelisted(ip, whitelist)

    score = abuse_data.get("score", 0) if abuse_data else 0
    is_malicious = (score >= 50) and not is_wl

    record = {
        "source":           "AbuseIPDB",
        "confidence_score":  score,
        "is_malicious":      is_malicious,
        "threat_severity":   severity_from_score(score) if not is_wl else "none",
        "reputation":        reputation_from_score(score) if not is_wl else "benign",
        "category":          (abuse_data.get("categories", ["clean"])[0]
                              if abuse_data and abuse_data.get("categories") else "clean"),
        "country":           abuse_data.get("country_code", "") if abuse_data else "",
        "country_name":      abuse_data.get("country_name", "") if abuse_data else "",
        "city":              abuse_data.get("city", "") if abuse_data else "",
        "usage_type":        abuse_data.get("usage_type", "") if abuse_data else "",
        "is_tor":            bool(abuse_data.get("is_tor")) if abuse_data else False,
        "is_whitelisted":    is_wl,
        "isp":               abuse_data.get("isp", "") if abuse_data else "",
        "asn":               abuse_data.get("asn", "") if abuse_data else "",
        "hostname":          (abuse_data.get("hostnames", [""])[0]
                              if abuse_data and abuse_data.get("hostnames") else ""),
        "domain":            abuse_data.get("domain", "") if abuse_data else "",
        "total_reports":     abuse_data.get("total_reports", 0) if abuse_data else 0,
    }

    if otx_data:
        record["otx_context"] = {
            "pulse_count":      otx_data.get("pulse_count", 0),
            "pulse_names":      otx_data.get("pulse_names", []),
            "tags":             otx_data.get("tags", []),
            "malware_families": otx_data.get("malware_families", []),
        }

    if threatfeed_data:
        record["threat_feed_context"] = {
            "urlhaus_url_count": threatfeed_data.get("urlhaus_url_count", 0),
            "urlhaus_tags":      threatfeed_data.get("urlhaus_tags", []),
            "threatfox_malware": threatfeed_data.get("threatfox_malware", []),
        }

    return record


# ── Enrich 1 event ────────────────────────────────────────────────────────────

def enrich_event(event: dict, conns: dict, whitelist: set, stats: dict) -> dict:
    sample  = event.get("sample_event", {}) or {}
    network = sample.get("network", {}) or {}
    src_ip  = (network.get("source_ip") or "").strip()
    dst_ip  = (network.get("destination_ip") or "").strip()

    enriched = copy.deepcopy(event)
    sample_e = enriched.setdefault("sample_event", {})
    enrichments = {}

    for ip in {src_ip, dst_ip}:
        if not ip:
            continue
        if not should_lookup(ip, whitelist):
            continue

        stats["ips_checked"] += 1

        abuse_data      = lookup_abuseipdb(conns["abuseipdb"], ip, stats)
        otx_data        = lookup_otx(conns["otx"], ip, stats) if OTX_API_KEY else None
        threatfeed_data = lookup_threat_feeds(conns["threat_feeds"], ip, stats)

        record = build_enrichment_record(ip, abuse_data, otx_data, threatfeed_data, whitelist)
        enrichments[ip] = record

        if record["is_malicious"]:
            stats["high_risk_found"] += 1

    sample_e["enrichments"] = enrichments

    src_record = enrichments.get(src_ip)
    if src_record and src_record.get("is_malicious"):
        sample_e["maliciousIP"] = {
            "ip":               src_ip,
            "confidence_score": src_record["confidence_score"],
            "country_code":     src_record["country"],
            "isp":              src_record["isp"],
            "categories":       [src_record["category"]] if src_record["category"] != "clean" else [],
            "is_tor":           src_record["is_tor"],
            "total_reports":    src_record["total_reports"],
            "source":           "abuseipdb",
        }
    else:
        sample_e["maliciousIP"] = None

    return enriched


# ── Main Service ──────────────────────────────────────────────────────────────

class EnricherService:
    def __init__(self):
        self.running   = True
        self.whitelist = load_whitelist(WHITELIST_PATH)
        self.conns = {
            "abuseipdb":     init_abuseipdb_db(ABUSEIPDB_DB_PATH),
            "otx":           init_otx_db(OTX_DB_PATH),
            "threat_feeds":  init_threat_feeds_db(THREAT_FEEDS_DB_PATH),
        }
        self.stats = {
            "processed": 0, "written": 0, "ips_checked": 0, "high_risk_found": 0,
            "abuseipdb_cache_hits": 0, "abuseipdb_cache_misses": 0,
            "abuseipdb_api_calls": 0, "abuseipdb_api_errors": 0,
            "otx_cache_hits": 0, "otx_cache_misses": 0,
            "otx_api_calls": 0, "otx_api_errors": 0,
            "threatfeed_cache_hits": 0, "threatfeed_cache_misses": 0,
            "threatfeed_api_calls": 0,
        }
        self.start_time         = time.time()
        self.last_metrics_print = time.time()
        self.last_cleanup       = time.time()

    def print_metrics(self):
        s      = self.stats
        uptime = int(time.time() - self.start_time)
        abuse_total = s["abuseipdb_cache_hits"] + s["abuseipdb_cache_misses"]
        abuse_hit_rate = f"{s['abuseipdb_cache_hits']/max(abuse_total,1)*100:.1f}%"
        logger.info(
            f"METRICS | uptime={uptime}s | processed={s['processed']} | written={s['written']} | "
            f"ips_checked={s['ips_checked']} | high_risk={s['high_risk_found']} | "
            f"abuseipdb[hit_rate={abuse_hit_rate} calls={s['abuseipdb_api_calls']} err={s['abuseipdb_api_errors']}] | "
            f"otx[calls={s['otx_api_calls']} err={s['otx_api_errors']}] | "
            f"threatfeed[calls={s['threatfeed_api_calls']}]"
        )

    def run(self):
        logger.info("Starting enricher v2 (multi-source)")
        logger.info(f"Input:      {INPUT_FILE}")
        logger.info(f"Output:     {OUTPUT_FILE}")
        logger.info(f"Whitelist:  {WHITELIST_PATH} ({len(self.whitelist)} IPs)")
        logger.info(f"AbuseIPDB:  {'SET ✓' if ABUSEIPDB_API_KEY else 'NOT SET'}")
        logger.info(f"OTX:        {'SET ✓' if OTX_API_KEY else 'NOT SET — context skipped'}")
        logger.info(f"ThreatFeeds: URLhaus + ThreatFox (no key required)")

        Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)

        while not os.path.exists(INPUT_FILE):
            logger.info(f"Waiting for: {INPUT_FILE}")
            time.sleep(2)

        f             = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
        st            = os.stat(INPUT_FILE)
        current_inode = st.st_ino
        f.seek(0, os.SEEK_END)
        logger.info("Ready — watching for new dedup events...")

        try:
            while self.running:
                try:
                    st        = os.stat(INPUT_FILE)
                    new_inode = st.st_ino
                    new_size  = st.st_size
                except FileNotFoundError:
                    time.sleep(POLL_INTERVAL)
                    continue

                if new_inode != current_inode:
                    logger.info("File rotation detected")
                    f.close()
                    f             = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
                    current_inode = new_inode
                    f.seek(0)
                elif new_size < f.tell():
                    logger.info("File truncated, resetting")
                    f.seek(0)

                line = f.readline()
                if not line:
                    time.sleep(POLL_INTERVAL)
                    now = time.time()
                    if now - self.last_metrics_print >= METRICS_INTERVAL:
                        self.print_metrics()
                        self.last_metrics_print = now
                    if now - self.last_cleanup >= 3600:
                        for table_conn, table_name in [
                            (self.conns["abuseipdb"], "ip_reputation"),
                            (self.conns["otx"], "otx_indicators"),
                            (self.conns["threat_feeds"], "threat_feed_indicators"),
                        ]:
                            cleanup_expired(table_conn, table_name)
                        self.last_cleanup = now
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                self.stats["processed"] += 1
                enriched = enrich_event(event, self.conns, self.whitelist, self.stats)

                with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
                    out.write(json.dumps(enriched, ensure_ascii=False) + "\n")
                    out.flush()
                self.stats["written"] += 1

                enrichments = (enriched.get("sample_event") or {}).get("enrichments", {})
                for ip, rec in enrichments.items():
                    if rec.get("is_malicious"):
                        logger.warning(
                            f"MALICIOUS | log_type={enriched.get('log_type')} | "
                            f"ip={ip} | score={rec['confidence_score']} | "
                            f"severity={rec['threat_severity']} | "
                            f"isp={rec.get('isp')} | otx_pulses={rec.get('otx_context',{}).get('pulse_count',0)}"
                        )

        finally:
            for conn in self.conns.values():
                conn.close()
            f.close()
            logger.info("Enricher stopped.")
            self.print_metrics()

    def shutdown(self, signum, frame):
        logger.info(f"Signal {signum} — shutting down...")
        self.running = False


if __name__ == "__main__":
    service = EnricherService()
    signal.signal(signal.SIGINT,  service.shutdown)
    signal.signal(signal.SIGTERM, service.shutdown)
    service.run()
