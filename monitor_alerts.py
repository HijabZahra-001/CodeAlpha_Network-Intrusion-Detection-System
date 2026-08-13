#!/usr/bin/env python3
"""
monitor_alerts.py
------------------
TASK 4 - Point 3: Monitor network traffic continuously for potential threats.

Tails Suricata's eve.json log file in real time, parses alert events, prints
a human-readable console feed, and appends a row per alert to a rolling CSV
log (alerts_log.csv) that the visualization dashboard can consume.

Usage:
    sudo python3 monitor_alerts.py --eve /var/log/suricata/eve.json
    sudo python3 monitor_alerts.py --eve /var/log/suricata/eve.json --csv alerts_log.csv

Run as a systemd service for 24/7 monitoring — sample unit file at the
bottom of this docstring.

---------------------------------------------------------------------
[Unit]
Description=NIDS Alert Monitor
After=suricata.service
Requires=suricata.service

[Service]
ExecStart=/usr/bin/python3 /opt/nids_project/monitor_alerts.py --eve /var/log/suricata/eve.json
Restart=always
User=root

[Install]
WantedBy=multi-user.target
---------------------------------------------------------------------
Save as /etc/systemd/system/nids-monitor.service then:
    sudo systemctl daemon-reload
    sudo systemctl enable --now nids-monitor
"""

import argparse
import csv
import json
import os
import time
from datetime import datetime, timezone

CSV_FIELDS = [
    "timestamp", "src_ip", "src_port", "dest_ip", "dest_port",
    "proto", "signature", "signature_id", "category", "severity",
]


def follow(filepath):
    """Generator that yields new lines appended to a growing log file
    (like `tail -f`), tolerating log rotation/truncation."""
    with open(filepath, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                # handle truncation/rotation
                if os.path.getsize(filepath) < f.tell():
                    f.seek(0)
                time.sleep(0.5)
                continue
            yield line


def ensure_csv(csv_path):
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()


def severity_label(sev):
    # Suricata severity: 1 = high, 2 = medium, 3 = low (lower number = worse)
    return {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(sev, "UNKNOWN")


def handle_alert(event, csv_path):
    alert = event.get("alert", {})
    row = {
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "src_ip": event.get("src_ip", ""),
        "src_port": event.get("src_port", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", ""),
        "proto": event.get("proto", ""),
        "signature": alert.get("signature", "Unknown"),
        "signature_id": alert.get("signature_id", ""),
        "category": alert.get("category", "Unknown"),
        "severity": severity_label(alert.get("severity", 3)),
    }

    print(
        f"[{row['timestamp']}] {row['severity']:6s} | "
        f"{row['src_ip']}:{row['src_port']} -> {row['dest_ip']}:{row['dest_port']} "
        f"| {row['signature']} (sid:{row['signature_id']})"
    )

    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Continuously monitor Suricata eve.json for alerts.")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to Suricata eve.json")
    parser.add_argument("--csv", default="alerts_log.csv", help="Path to output CSV log")
    args = parser.parse_args()

    ensure_csv(args.csv)
    print(f"[+] Monitoring {args.eve} for intrusion alerts... (Ctrl+C to stop)")
    print(f"[+] Logging structured alerts to {args.csv}")

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
                handle_alert(event, args.csv)
    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped.")
    except FileNotFoundError:
        print(f"[!] {args.eve} not found. Is Suricata installed and running?")


if __name__ == "__main__":
    main()
