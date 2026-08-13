#!/usr/bin/env python3
"""
response_mechanism.py
----------------------
TASK 4 - Point 4: Implement response mechanisms for detected intrusions.

Watches Suricata's eve.json alert stream. When a single source IP generates
`--threshold` or more alerts within `--window` seconds, it is treated as an
active attacker and an automated response is triggered:

  1. Block the offending IP using iptables (requires root).
  2. Log the incident (IP, reason, signature, timestamp) to blocked_ips.log.
  3. (Optional) Send a notification via a webhook/email stub — plug in your
     own Slack/Teams/SMTP integration in notify_admin().
  4. Automatically unblock the IP after `--cooldown` seconds, so a false
     positive doesn't permanently lock out a legitimate host.

This gives a software-based response layer that works even when Suricata
itself is running in passive/IDS mode (not inline IPS/NFQUEUE mode).

Usage:
    sudo python3 response_mechanism.py --eve /var/log/suricata/eve.json \
        --threshold 5 --window 60 --cooldown 600

    # Safe demo mode (no real firewall changes, just logs what WOULD happen):
    python3 response_mechanism.py --eve alerts_sample_stream.json --dry-run
"""

import argparse
import json
import os
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

WHITELIST = {"127.0.0.1"}   # never auto-block these IPs (add trusted hosts/gateway here)


class ResponseEngine:
    def __init__(self, threshold, window, cooldown, dry_run, log_path):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.dry_run = dry_run
        self.log_path = log_path
        self.alert_times = defaultdict(deque)   # ip -> deque[timestamps]
        self.blocked = {}                        # ip -> unblock_time

    # ---------------------------------------------------------------
    def record_alert(self, ip, signature):
        now = time.time()
        dq = self.alert_times[ip]
        dq.append(now)
        # drop alerts outside the sliding window
        while dq and now - dq[0] > self.window:
            dq.popleft()

        if len(dq) >= self.threshold and ip not in self.blocked and ip not in WHITELIST:
            self.trigger_response(ip, signature, count=len(dq))

    # ---------------------------------------------------------------
    def trigger_response(self, ip, signature, count):
        reason = f"{count} alerts in {self.window}s (last: {signature})"
        self.block_ip(ip, reason)
        self.log_incident(ip, reason)
        self.notify_admin(ip, reason)
        unblock_at = time.time() + self.cooldown
        self.blocked[ip] = unblock_at
        threading.Timer(self.cooldown, self.unblock_ip, args=(ip,)).start()

    # ---------------------------------------------------------------
    def block_ip(self, ip, reason):
        print(f"[RESPONSE] Blocking {ip} — {reason}")
        if self.dry_run:
            print(f"           (dry-run: would execute) iptables -A INPUT -s {ip} -j DROP")
            return
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
        except FileNotFoundError:
            print("           [!] iptables not available on this system (dry-run fallback).")
        except subprocess.CalledProcessError as e:
            print(f"           [!] Failed to block {ip}: {e.stderr.decode(errors='ignore')}")
            print("           (Are you running as root?)")

    def unblock_ip(self, ip):
        print(f"[RESPONSE] Cooldown expired — unblocking {ip}")
        if not self.dry_run:
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True,
                )
            except Exception:
                pass
        self.blocked.pop(ip, None)
        self.log_incident(ip, "Auto-unblocked after cooldown")

    # ---------------------------------------------------------------
    def log_incident(self, ip, reason):
        ts = datetime.now(timezone.utc).isoformat()
        with open(self.log_path, "a") as f:
            f.write(f"{ts} | {ip} | {reason}\n")

    def notify_admin(self, ip, reason):
        # STUB: wire this up to a real channel, e.g.:
        #   requests.post(SLACK_WEBHOOK_URL, json={"text": f"Blocked {ip}: {reason}"})
        #   smtplib.SMTP(...).sendmail(...)
        print(f"[NOTIFY] (stub) Admin would be notified: {ip} blocked — {reason}")


# ---------------------------------------------------------------
def follow(filepath):
    with open(filepath, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                if os.path.getsize(filepath) < f.tell():
                    f.seek(0)
                time.sleep(0.5)
                continue
            yield line


def main():
    parser = argparse.ArgumentParser(description="Automated intrusion response engine.")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json")
    parser.add_argument("--threshold", type=int, default=5, help="Alerts needed to trigger a block")
    parser.add_argument("--window", type=int, default=60, help="Sliding time window (seconds)")
    parser.add_argument("--cooldown", type=int, default=600, help="Seconds before auto-unblock")
    parser.add_argument("--dry-run", action="store_true", help="Log actions without touching iptables")
    parser.add_argument("--log", default="blocked_ips.log")
    args = parser.parse_args()

    engine = ResponseEngine(args.threshold, args.window, args.cooldown, args.dry_run, args.log)
    print(f"[+] Response engine active — block after {args.threshold} alerts / {args.window}s "
          f"(cooldown {args.cooldown}s, dry_run={args.dry_run})")

    try:
        for line in follow(args.eve):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                ip = event.get("src_ip")
                sig = event.get("alert", {}).get("signature", "Unknown")
                if ip:
                    engine.record_alert(ip, sig)
    except KeyboardInterrupt:
        print("\n[+] Response engine stopped.")
    except FileNotFoundError:
        print(f"[!] {args.eve} not found. Is Suricata installed and running?")


if __name__ == "__main__":
    main()
