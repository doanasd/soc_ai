import json
import time
import os

INPUT_FILE = "/var/ossec/logs/log_dedup.json"
OUTPUT_FILE = "/var/ossec/logs/log_enriched.json"
MALICIOUS_FILE = "/var/script/malicious_ips.txt"
POLL_INTERVAL = 1
RELOAD_INTERVAL = 30  # reload malicious IP list mỗi 30s


class MaliciousIPEnricher:

    def __init__(self):
        self.malicious_ips = {}
        self.last_reload = 0

    def load_malicious_ips(self):
        malicious = {}
        try:
            with open(MALICIOUS_FILE, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        try:
                            score = int(parts[1])
                            malicious[ip] = score
                        except ValueError:
                            continue

            self.malicious_ips = malicious
            self.last_reload = time.time()
            print(f"[INFO] Loaded {len(self.malicious_ips)} malicious IPs")

        except Exception as e:
            print(f"[ERROR] Failed loading malicious IP file: {e}")

    def maybe_reload(self):
        if time.time() - self.last_reload > RELOAD_INTERVAL:
            self.load_malicious_ips()

    def enrich_event(self, event):
        try:
            source_ip = event["sample_event"]["network"]["source_ip"].strip()
        except KeyError:
            return event

        score = self.malicious_ips.get(source_ip)

        if score is not None:
            print(f"[MATCH] {source_ip} score={score}")
            event["sample_event"]["maliciousIP"] = {
                "confidence_score": score,
                "source": "abuseipdb"
            }
        else:
            event["sample_event"]["maliciousIP"] = None

        return event

    def run(self):
        self.load_malicious_ips()

        with open(INPUT_FILE, "r") as infile, \
             open(OUTPUT_FILE, "a") as outfile:

            infile.seek(0, os.SEEK_END)

            current_inode = os.fstat(infile.fileno()).st_ino

            while True:
                self.maybe_reload()

                line = infile.readline()

                # Handle file rotation
                try:
                    new_inode = os.stat(INPUT_FILE).st_ino
                    if new_inode != current_inode:
                        print("[INFO] Detected log rotation. Reopening file.")
                        infile.close()
                        infile = open(INPUT_FILE, "r")
                        current_inode = new_inode
                except FileNotFoundError:
                    time.sleep(POLL_INTERVAL)
                    continue

                if not line:
                    time.sleep(POLL_INTERVAL)
                    continue

                try:
                    event = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                enriched = self.enrich_event(event)

                outfile.write(json.dumps(enriched) + "\n")
                outfile.flush()


if __name__ == "__main__":
    service = MaliciousIPEnricher()
    service.run()