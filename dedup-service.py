#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dedup Service — gom log giống nhau trong time window thành 1 bản ghi tổng hợp
Input:  log_normalized.json
Output: log_dedup.json
"""

import json
import os
import signal
import sys
import time
from copy import deepcopy
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
INPUT_FILE  = os.getenv("NORMALIZED_PATH", "log_normalized.json")
OUTPUT_FILE = os.getenv("DEDUP_PATH",      "log_dedup.json")
OFFSET_FILE = os.getenv("DEDUP_OFFSET",    ".dedup_offset")

# ── Config ───────────────────────────────────────────────────────────────────
WINDOW_SECONDS      = int(os.getenv("DEDUP_WINDOW_SECONDS", "60"))
POLL_INTERVAL       = float(os.getenv("DEDUP_POLL_INTERVAL", "1"))
MAX_CACHE_SIZE      = int(os.getenv("DEDUP_MAX_CACHE", "50000"))
OFFSET_SAVE_INTERVAL = 2
METRICS_INTERVAL    = 30


class DedupService:
    def __init__(self):
        self.cache               = {}
        self.running             = True
        self.offset              = 0
        self.total_processed     = 0
        self.total_flushed       = 0
        self.total_evicted       = 0
        self.start_time          = time.time()
        self.last_offset_save    = time.time()
        self.last_metrics_print  = time.time()

    # ── Offset ────────────────────────────────────────────────────────────────

    def load_offset(self):
        try:
            if os.path.exists(OFFSET_FILE):
                with open(OFFSET_FILE, "r") as f:
                    self.offset = int(f.read().strip() or 0)
        except Exception:
            self.offset = 0
        print(f"[dedup] Resuming from offset: {self.offset}")

    def save_offset(self, position):
        try:
            with open(OFFSET_FILE, "w") as f:
                f.write(str(position))
        except Exception as e:
            print(f"[dedup][WARN] Failed to save offset: {e}")

    # ── Event time ────────────────────────────────────────────────────────────

    def extract_event_time(self, log) -> float:
        raw = log.get("time")
        if raw in (None, ""):
            return time.time()
        try:
            val = float(str(raw))
            # Nếu là milliseconds (> year 2100 in seconds)
            if val > 4_000_000_000:
                return val / 1000.0
            return val
        except Exception:
            return time.time()

    # ── Grouping key ──────────────────────────────────────────────────────────

    def build_key(self, log) -> str | None:
        log_type = log.get("log_type")
        net      = log.get("network", {}) or {}
        action   = log.get("action", "")
        host     = log.get("asset_host", "")
        src_ip   = net.get("source_ip", "")
        dst_ip   = net.get("destination_ip", "")
        dst_port = net.get("destination_port", "")
        protocol = net.get("protocol", "")

        if log_type == "waf":
            waf     = log.get("waf", {}) or {}
            uri     = waf.get("uri", "")
            rule_id = waf.get("terminating_rule_id", "")
            host_h  = waf.get("host_header", "")
            method  = net.get("method", "")
            return f"waf|{src_ip}|{dst_ip}|{host_h}|{uri}|{method}|{rule_id}|{action}"

        elif log_type == "vpc":
            return f"vpc|{host}|{src_ip}|{dst_ip}|{dst_port}|{protocol}|{action}"

        elif log_type == "linux":
            linux = log.get("linuxEvent", {}) or {}
            prog  = linux.get("program", "")
            user  = linux.get("user", "")
            rid   = linux.get("ruleID", "")
            return f"linux|{src_ip}|{host}|{action}|{prog}|{user}|{rid}"

        elif log_type == "win":
            win    = log.get("winEvent", {}) or {}
            evtid  = win.get("eventID", "")
            tuser  = win.get("targetUserName", "")
            return f"win|{host}|{src_ip}|{evtid}|{tuser}|{action}"

        elif log_type == "fortinet":
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

        elif log_type == "cloudtrail":
            ct     = log.get("cloudtrailEvent", {}) or {}
            event  = ct.get("eventName", "")
            account= ct.get("accountId", "")
            user   = ct.get("userName", "")
            region = ct.get("awsRegion", "")
            return f"cloudtrail|{account}|{region}|{event}|{user}"

        elif log_type == "cisco":
            ce     = log.get("ciscoEvent", {}) or {}
            mnemonic  = ce.get("mnemonic", "")
            interface = ce.get("interface", "").rstrip(",")
            return f"cisco|{host}|{mnemonic}|{interface}"

        return None

    # ── Flush expired ─────────────────────────────────────────────────────────

    def flush_expired(self):
        now     = time.time()
        expired = [
            key for key, entry in self.cache.items()
            if now - entry["last_update_wallclock"] >= WINDOW_SECONDS
        ]
        for key in expired:
            self.write_output(key, self.cache[key])
            del self.cache[key]

    # ── Write output ──────────────────────────────────────────────────────────

    def write_output(self, key: str, entry: dict):
        duration = max(entry["last_seen"] - entry["first_seen"], 1)
        rate     = round(entry["count"] / duration, 2)

        output_event = {
            "log_type":  entry["log"].get("log_type"),
            "group_key": key,
            "aggregation": {
                "count":            entry["count"],
                "window_seconds":   WINDOW_SECONDS,
                "first_seen":       entry["first_seen"],
                "last_seen":        entry["last_seen"],
                "duration_seconds": round(duration, 2),
                "rate_per_sec":     rate,
            },
            "sample_event": deepcopy(entry["log"]),
        }

        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(output_event, ensure_ascii=False) + "\n")
            f.flush()

        self.total_flushed += 1
        log_type = entry["log"].get("log_type", "?")
        src_ip   = (entry["log"].get("network") or {}).get("source_ip", "?")
        print(
            f"[dedup] FLUSH {log_type:10s} | count={entry['count']:5d} "
            f"| rate={rate:.2f}/s | src={src_ip} | key={key[:60]}"
        )

    # ── Evict oldest ──────────────────────────────────────────────────────────

    def evict_oldest(self):
        if not self.cache:
            return
        oldest_key = min(self.cache, key=lambda k: self.cache[k]["last_seen"])
        self.write_output(oldest_key, self.cache[oldest_key])
        del self.cache[oldest_key]
        self.total_evicted += 1

    # ── Process line ──────────────────────────────────────────────────────────

    def process_line(self, line: str):
        try:
            log = json.loads(line)
        except Exception:
            return

        self.total_processed += 1
        key = self.build_key(log)
        if not key:
            return

        event_time = self.extract_event_time(log)
        now        = time.time()

        if key in self.cache:
            entry                          = self.cache[key]
            entry["count"]                += 1
            entry["last_seen"]             = event_time
            entry["last_update_wallclock"] = now
        else:
            self.cache[key] = {
                "count":                 1,
                "first_seen":            event_time,
                "last_seen":             event_time,
                "last_update_wallclock": now,
                "log":                   log,
            }

        if len(self.cache) > MAX_CACHE_SIZE:
            self.evict_oldest()

    # ── Metrics ───────────────────────────────────────────────────────────────

    def print_metrics(self):
        uptime = int(time.time() - self.start_time)
        print(
            f"[dedup] METRICS | uptime={uptime}s | "
            f"processed={self.total_processed} | flushed={self.total_flushed} | "
            f"evicted={self.total_evicted} | cache_size={len(self.cache)}"
        )

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        print(f"[dedup] Starting...")
        print(f"[dedup] Input:        {INPUT_FILE}")
        print(f"[dedup] Output:       {OUTPUT_FILE}")
        print(f"[dedup] Window:       {WINDOW_SECONDS}s")
        print(f"[dedup] Max cache:    {MAX_CACHE_SIZE}")

        Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(OUTPUT_FILE).touch(exist_ok=True)
        Path(os.path.dirname(OFFSET_FILE)).mkdir(parents=True, exist_ok=True)

        self.load_offset()

        # Chờ file input tồn tại
        while not os.path.exists(INPUT_FILE):
            print(f"[dedup] Waiting for input file: {INPUT_FILE}")
            time.sleep(2)

        f = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
        st            = os.stat(INPUT_FILE)
        current_inode = st.st_ino

        # Validate offset
        file_size = st.st_size
        if self.offset > file_size:
            print(f"[dedup] Offset {self.offset} > file size {file_size}, resetting to 0")
            self.offset = 0
        f.seek(self.offset)

        try:
            while self.running:
                try:
                    st       = os.stat(INPUT_FILE)
                    new_inode = st.st_ino
                    new_size  = st.st_size
                except FileNotFoundError:
                    time.sleep(POLL_INTERVAL)
                    continue

                # File rotation
                if new_inode != current_inode:
                    print("[dedup] Log rotation detected. Reopening file.")
                    f.close()
                    f             = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
                    current_inode = new_inode
                    self.offset   = 0
                    f.seek(0)
                # File truncated
                elif new_size < f.tell():
                    print("[dedup] File truncated. Resetting offset.")
                    f.close()
                    f           = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
                    self.offset = 0
                    f.seek(0)

                line = f.readline()
                if not line:
                    self.flush_expired()
                    time.sleep(POLL_INTERVAL)
                    now = time.time()
                    if now - self.last_metrics_print >= METRICS_INTERVAL:
                        self.print_metrics()
                        self.last_metrics_print = now
                    continue

                self.process_line(line)
                self.offset = f.tell()

                now = time.time()
                if now - self.last_offset_save >= OFFSET_SAVE_INTERVAL:
                    self.save_offset(self.offset)
                    self.last_offset_save = now
                if now - self.last_metrics_print >= METRICS_INTERVAL:
                    self.print_metrics()
                    self.last_metrics_print = now

        finally:
            print("[dedup] Flushing remaining cache before exit...")
            for key, entry in list(self.cache.items()):
                self.write_output(key, entry)
            self.cache.clear()
            self.save_offset(self.offset)
            f.close()
            print(f"[dedup] Stopped. Total flushed: {self.total_flushed}")

    # ── Graceful shutdown ─────────────────────────────────────────────────────

    def shutdown(self, signum, frame):
        print(f"\n[dedup] Signal {signum} received. Shutting down gracefully...")
        self.running = False


if __name__ == "__main__":
    service = DedupService()
    signal.signal(signal.SIGINT,  service.shutdown)
    signal.signal(signal.SIGTERM, service.shutdown)
    service.run()