#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malicious IP Enricher — SQLite cache + AbuseIPDB API
Cache-aside: check DB -> miss -> call API -> save DB
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

# ── Config từ env ─────────────────────────────────────────────────────────────
INPUT_FILE  = os.getenv("DEDUP_PATH",    "/home/ubuntu/soc_ai/log_dedup.json")
OUTPUT_FILE = os.getenv("ENRICHED_PATH", "/home/ubuntu/soc_ai/log_enriched.json")
DB_PATH     = os.getenv("ENRICHER_DB",   "/home/ubuntu/soc_ai/data/ip_reputation.db")

ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL      = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS_QUERY = int(os.getenv("ABUSE_MAX_AGE_DAYS", "90"))
API_RATE_DELAY     = float(os.getenv("API_RATE_DELAY", "0.5"))

TTL_HIGH   = int(os.getenv("TTL_HIGH_RISK_DAYS", "3"))   * 86400
TTL_MEDIUM = int(os.getenv("TTL_MEDIUM_DAYS",    "7"))   * 86400
TTL_LOW    = int(os.getenv("TTL_LOW_RISK_DAYS",  "14"))  * 86400
TTL_ERROR  = int(os.getenv("TTL_ERROR_HOURS",    "1"))   * 3600

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


# ── SQLite Cache ──────────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip               TEXT PRIMARY KEY,
            score            INTEGER NOT NULL DEFAULT 0,
            country_code     TEXT DEFAULT '',
            isp              TEXT DEFAULT '',
            usage_type       TEXT DEFAULT '',
            domain           TEXT DEFAULT '',
            total_reports    INTEGER DEFAULT 0,
            last_reported    TEXT DEFAULT '',
            categories       TEXT DEFAULT '[]',
            is_whitelisted   INTEGER DEFAULT 0,
            is_tor           INTEGER DEFAULT 0,
            fetch_status     TEXT DEFAULT 'ok',
            fetched_at       TEXT NOT NULL,
            expires_at       TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON ip_reputation(expires_at)")
    conn.commit()
    logger.info(f"SQLite cache ready: {db_path}")
    return conn


def get_cached(conn: sqlite3.Connection, ip: str) -> Optional[dict]:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "SELECT * FROM ip_reputation WHERE ip=? AND expires_at>?", (ip, now)
    )
    cols = [d[0] for d in cur.description]
    row  = cur.fetchone()
    if not row:
        return None
    record = dict(zip(cols, row))
    try:
        record["categories"] = json.loads(record.get("categories") or "[]")
    except Exception:
        record["categories"] = []
    return record


def save_to_cache(conn: sqlite3.Connection, ip: str, data: dict, ttl_seconds: int):
    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    conn.execute("""
        INSERT INTO ip_reputation
            (ip,score,country_code,isp,usage_type,domain,
             total_reports,last_reported,categories,
             is_whitelisted,is_tor,fetch_status,fetched_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            score=excluded.score, country_code=excluded.country_code,
            isp=excluded.isp, usage_type=excluded.usage_type,
            domain=excluded.domain, total_reports=excluded.total_reports,
            last_reported=excluded.last_reported, categories=excluded.categories,
            is_whitelisted=excluded.is_whitelisted, is_tor=excluded.is_tor,
            fetch_status=excluded.fetch_status, fetched_at=excluded.fetched_at,
            expires_at=excluded.expires_at
    """, (
        ip, data.get("score",0), data.get("country_code",""),
        data.get("isp",""), data.get("usage_type",""), data.get("domain",""),
        data.get("total_reports",0), data.get("last_reported",""),
        json.dumps(data.get("categories",[])),
        1 if data.get("is_whitelisted") else 0,
        1 if data.get("is_tor") else 0,
        data.get("fetch_status","ok"),
        now.isoformat(), expires_at,
    ))
    conn.commit()


def cleanup_expired(conn: sqlite3.Connection):
    now    = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute("DELETE FROM ip_reputation WHERE expires_at<=?", (now,))
    if cursor.rowcount > 0:
        conn.commit()
        logger.info(f"Cleaned {cursor.rowcount} expired cache records")


# ── AbuseIPDB API ─────────────────────────────────────────────────────────────

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
        return {
            "score":          score,
            "country_code":   d.get("countryCode",""),
            "isp":            d.get("isp",""),
            "usage_type":     d.get("usageType",""),
            "domain":         d.get("domain",""),
            "total_reports":  int(d.get("totalReports",0)),
            "last_reported":  d.get("lastReportedAt",""),
            "categories":     cat_names,
            "is_whitelisted": bool(d.get("isWhitelisted",False)),
            "is_tor":         bool(d.get("isTor",False)),
            "fetch_status":   "ok",
        }
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning(f"Rate limit hit for {ip}, sleeping 60s")
            time.sleep(60)
        else:
            logger.error(f"AbuseIPDB HTTP {e.code} for {ip}")
        return None
    except Exception as e:
        logger.error(f"AbuseIPDB error for {ip}: {e}")
        return None


def get_ttl(score: int) -> int:
    if score >= 75:  return TTL_HIGH
    if score >= 25:  return TTL_MEDIUM
    return TTL_LOW


# ── IP Filter ─────────────────────────────────────────────────────────────────

def should_lookup(ip: str) -> bool:
    if not ip or not isinstance(ip, str) or not ip.strip():
        return False
    if ip.strip() in AUTHORIZED_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


# ── Lookup with cache-aside ───────────────────────────────────────────────────

def lookup_ip(conn: sqlite3.Connection, ip: str, stats: dict) -> Optional[dict]:
    # 1. Cache hit
    cached = get_cached(conn, ip)
    if cached:
        stats["cache_hits"] += 1
        return cached

    # 2. Cache miss → API
    stats["cache_misses"] += 1

    if not ABUSEIPDB_API_KEY:
        # Không có API key → lưu placeholder score=0
        placeholder = {
            "score":0,"country_code":"","isp":"","usage_type":"",
            "domain":"","total_reports":0,"last_reported":"",
            "categories":[],"is_whitelisted":False,"is_tor":False,
            "fetch_status":"no_api_key",
        }
        save_to_cache(conn, ip, placeholder, TTL_LOW)
        return placeholder

    result = call_abuseipdb(ip)
    time.sleep(API_RATE_DELAY)

    if result is None:
        error_rec = {
            "score":0,"country_code":"","isp":"","usage_type":"",
            "domain":"","total_reports":0,"last_reported":"",
            "categories":[],"is_whitelisted":False,"is_tor":False,
            "fetch_status":"error",
        }
        save_to_cache(conn, ip, error_rec, TTL_ERROR)
        stats["api_errors"] += 1
        return None

    save_to_cache(conn, ip, result, get_ttl(result["score"]))
    stats["api_calls"] += 1

    if result["score"] >= 75:
        logger.warning(f"HIGH RISK: {ip} score={result['score']} isp={result['isp']} cats={result['categories']}")
    elif result["score"] >= 25:
        logger.info(f"Medium risk: {ip} score={result['score']}")

    return result


# ── Enrich 1 event ────────────────────────────────────────────────────────────

def enrich_event(event: dict, conn: sqlite3.Connection, stats: dict) -> dict:
    sample  = event.get("sample_event", {}) or {}
    network = sample.get("network", {}) or {}
    src_ip  = (network.get("source_ip") or "").strip()
    dst_ip  = (network.get("destination_ip") or "").strip()

    enriched = copy.deepcopy(event)
    sample_e = enriched.setdefault("sample_event", {})

    # Enrich source IP
    if should_lookup(src_ip):
        stats["ips_checked"] += 1
        rec = lookup_ip(conn, src_ip, stats)
        if rec and rec["fetch_status"] == "ok" and rec["score"] > 0:
            sample_e["maliciousIP"] = {
                "ip":               src_ip,
                "confidence_score": rec["score"],
                "country_code":     rec["country_code"],
                "isp":              rec["isp"],
                "usage_type":       rec["usage_type"],
                "categories":       rec["categories"],
                "is_tor":           rec["is_tor"],
                "total_reports":    rec["total_reports"],
                "source":           "abuseipdb",
            }
            if rec["score"] >= 75:
                stats["high_risk_found"] += 1
        else:
            sample_e["maliciousIP"] = None
    else:
        sample_e["maliciousIP"] = None

    # Enrich destination IP (chỉ khi là public)
    if should_lookup(dst_ip):
        stats["ips_checked"] += 1
        rec = lookup_ip(conn, dst_ip, stats)
        if rec and rec["fetch_status"] == "ok" and rec["score"] > 0:
            sample_e["maliciousDstIP"] = {
                "ip":               dst_ip,
                "confidence_score": rec["score"],
                "country_code":     rec["country_code"],
                "isp":              rec["isp"],
                "categories":       rec["categories"],
                "source":           "abuseipdb",
            }

    return enriched


# ── Main Service ──────────────────────────────────────────────────────────────

class EnricherService:
    def __init__(self):
        self.running  = True
        self.conn     = init_db(DB_PATH)
        self.stats    = {
            "processed":0,"ips_checked":0,"cache_hits":0,
            "cache_misses":0,"api_calls":0,"api_errors":0,
            "high_risk_found":0,"written":0,
        }
        self.start_time         = time.time()
        self.last_metrics_print = time.time()
        self.last_cleanup       = time.time()

    def print_metrics(self):
        s        = self.stats
        uptime   = int(time.time() - self.start_time)
        total_lu = s["cache_hits"] + s["cache_misses"]
        hit_rate = f"{s['cache_hits']/max(total_lu,1)*100:.1f}%"
        logger.info(
            f"METRICS | uptime={uptime}s | processed={s['processed']} | "
            f"written={s['written']} | ips_checked={s['ips_checked']} | "
            f"cache_hit_rate={hit_rate} | api_calls={s['api_calls']} | "
            f"api_errors={s['api_errors']} | high_risk={s['high_risk_found']}"
        )

    def run(self):
        logger.info(f"Starting enricher")
        logger.info(f"Input:   {INPUT_FILE}")
        logger.info(f"Output:  {OUTPUT_FILE}")
        logger.info(f"DB:      {DB_PATH}")
        logger.info(f"API key: {'SET ✓' if ABUSEIPDB_API_KEY else 'NOT SET — score=0 for all'}")

        Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)

        # Chờ file input xuất hiện
        while not os.path.exists(INPUT_FILE):
            logger.info(f"Waiting for: {INPUT_FILE}")
            time.sleep(2)

        f             = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
        st            = os.stat(INPUT_FILE)
        current_inode = st.st_ino
        f.seek(0, os.SEEK_END)  # chỉ xử lý log mới
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
                        cleanup_expired(self.conn)
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
                enriched = enrich_event(event, self.conn, self.stats)

                with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
                    out.write(json.dumps(enriched, ensure_ascii=False) + "\n")
                    out.flush()
                self.stats["written"] += 1

                # Log nếu tìm thấy IP nguy hiểm
                mal = (enriched.get("sample_event") or {}).get("maliciousIP")
                if mal and (mal.get("confidence_score") or 0) >= 25:
                    src = (enriched.get("sample_event",{}).get("network") or {}).get("source_ip","")
                    logger.warning(
                        f"MALICIOUS | log_type={enriched.get('log_type')} | "
                        f"src={src} | score={mal['confidence_score']} | "
                        f"isp={mal.get('isp')} | cats={mal.get('categories')}"
                    )
        finally:
            self.conn.close()
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
