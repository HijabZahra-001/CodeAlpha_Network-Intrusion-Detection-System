#!/usr/bin/env python3
"""
eve_to_dashboard_json.py
--------------------------
Converts a real Suricata eve.json log into the flat JSON array format that
dashboard.html expects (same schema as alerts_sample.json), so the
visualization dashboard (Task 4, Point 5) can plot real captured attacks
instead of the bundled demo data.

Usage:
    python3 eve_to_dashboard_json.py --eve /var/log/suricata/eve.json --out alerts_sample.json
"""
import argparse
import json


def severity_label(sev):
    return {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(sev, "UNKNOWN")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--eve", required=True)
    parser.add_argument("--out", default="alerts_sample.json")
    args = parser.parse_args()

    events = []
    with open(args.eve) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") != "alert":
                continue
            alert = e.get("alert", {})
            events.append({
                "timestamp": e.get("timestamp"),
                "src_ip": e.get("src_ip"),
                "src_port": e.get("src_port"),
                "dest_ip": e.get("dest_ip"),
                "dest_port": e.get("dest_port"),
                "proto": e.get("proto"),
                "signature": alert.get("signature", "Unknown"),
                "signature_id": alert.get("signature_id"),
                "category": alert.get("category", "Unknown"),
                "severity": severity_label(alert.get("severity", 3)),
            })

    with open(args.out, "w") as f:
        json.dump(events, f, indent=2)
    print(f"[+] Wrote {len(events)} alerts to {args.out}")


if __name__ == "__main__":
    main()
