# Network Intrusion Detection System (NIDS) 

Built with **Suricata**. Covers all five task requirements:
1. IDS setup (Suricata)
2. Custom rules & alerting (`local.rules`)
3. Continuous monitoring (`monitor_alerts.py`)
4. Automated response (`response_mechanism.py`)
5. Visualization dashboard (`dashboard.html`)

---

## 1. Installation (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y suricata suricata-update
sudo suricata-update                     # pull the official Emerging Threats Open ruleset
sudo suricata -T -c /etc/suricata/suricata.yaml -v   # test config is valid
```

Find your monitoring interface:
```bash
ip a
```

## 2. Configuration

1. Copy `suricata_config_snippet.yaml` sections into `/etc/suricata/suricata.yaml`
   (edit `HOME_NET`, `interface`, and file paths for your machine).
2. Copy the custom ruleset:
   ```bash
   sudo cp local.rules /etc/suricata/rules/local.rules
   ```
3. Test and restart:
   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml -v
   sudo systemctl restart suricata
   sudo systemctl enable suricata
   sudo systemctl status suricata
   ```

## 3. Continuous Monitoring

Suricata writes every alert as a JSON line to `/var/log/suricata/eve.json`.
`monitor_alerts.py` tails this file in real time, filters for `event_type: alert`,
prints a readable console feed, and writes a rolling CSV log (`alerts_log.csv`)
that the dashboard reads.

```bash
sudo python3 monitor_alerts.py --eve /var/log/suricata/eve.json
```

Run it as a background service (systemd) so monitoring survives reboots — a
sample unit file is included at the bottom of `monitor_alerts.py`'s docstring.

## 4. Automated Response

`response_mechanism.py` watches the same alert stream. When a source IP
crosses a configurable severity/frequency threshold it automatically:
- Blocks the IP with `iptables` (or logs a dry-run action if not root).
- Writes an incident record to `blocked_ips.log` with timestamp and reason.
- Optionally sends an email/webhook notification (stubbed — plug in your
  SMTP/Slack/Teams webhook credentials).
- Auto-unblocks after a configurable cool-down period (prevents permanently
  locking out misidentified/legit hosts).

```bash
sudo python3 response_mechanism.py --eve /var/log/suricata/eve.json --threshold 5
```

## 5. Visualization Dashboard

`dashboard.html` is a self-contained, offline dashboard (Chart.js) that
visualizes:
- Alerts over time (line chart)
- Top attacking source IPs (bar chart)
- Alert severity breakdown (pie chart)
- Alert category breakdown (bar chart)
- Live/recent alerts table

It reads `alerts_sample.json` by default so it can be demoed without a live
sensor. To visualize real traffic, point it at the CSV produced by
`monitor_alerts.py` (instructions inside the file), or convert `eve.json`
alerts to the same schema with `eve_to_dashboard_json.py`.

Just open `dashboard.html` in a browser — no server required.

## 6. Suggested Test Traffic (to prove the rules fire)

From another machine on the same network:
```bash
nmap -sS <target-ip>                 # triggers SYN scan rule (sid 1000001)
nmap -sX <target-ip>                 # XMAS scan (sid 1000003)
hydra -l admin -P wordlist.txt ssh://<target-ip>   # SSH brute force (sid 1000005)
ping -f <target-ip>                  # ICMP flood (sid 1000013) — needs root
curl "http://<target-ip>/?id=1' OR '1'='1"          # SQLi (sid 1000008)
```
Watch alerts appear in `fast.log`, `eve.json`, the monitor console, and the
dashboard.

## File Manifest

| File | Purpose |
|---|---|
| `local.rules` | Custom Suricata detection rules (18 rules, 6 categories) |
| `suricata_config_snippet.yaml` | Config sections to merge into suricata.yaml |
| `monitor_alerts.py` | Real-time alert monitoring + CSV logging |
| `response_mechanism.py` | Automated threat response (block/alert/unblock) |
| `dashboard.html` | Interactive attack visualization dashboard |
| `alerts_sample.json` | Sample alert data to demo the dashboard |
| `eve_to_dashboard_json.py` | Converts real eve.json alerts to dashboard format |
