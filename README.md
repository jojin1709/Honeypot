# Honeypot Lab v2.0 — Cybersecurity Attack & Defense Laboratory

> **17 honeypot types · 8 dashboard pages · 12 built-in features · 25+ API endpoints**
> **Developed by JOJIN JOHN**

A comprehensive honeypot laboratory for cybersecurity enthusiasts, SOC analysts, penetration testers, CTF players, and malware researchers. Captures real attacker behavior across 17 protocols, with GeoIP tracking, attack correlation, live dashboard, notification alerts, and a full REST API. Runs on **Windows** and **Kali/Linux** — no Docker required.

---

## Table of Contents

- [What Is This?](#what-is-this)
- [17 Honeypot Types](#17-honeypot-types)
- [8 Dashboard Pages](#8-dashboard-pages)
- [12 Built-in Features](#12-built-in-features)
- [Quick Start](#quick-start)
- [Dashboard Pages](#dashboard-pages)
- [REST API Endpoints](#rest-api-endpoints)
- [Notification Setup](#notification-setup)
- [Threat Intelligence](#threat-intelligence)
- [Red Team Tools](#red-team-tools)
- [Blue Team Tools](#blue-team-tools)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Learning Path](#learning-path)
- [Security Warnings](#security-warnings)
- [Troubleshooting](#troubleshooting)

---

## What Is This?

A **honeypot lab** sets up **fake services** that look real to attackers. When someone connects:

- Their **IP** is logged with GeoIP location (country/city/ISP)
- Their **commands** are recorded
- Any **credentials they try** are captured
- Any **malware they upload** is saved and hashed (MD5/SHA256)
- You get **notifications** via Telegram/Discord/Slack/Email
- You can **analyze and correlate** everything in the dashboard
- You can **export** reports as PDF, JSON, or CSV

### What You Can Learn

| Skill | How This Lab Helps |
|-------|-------------------|
| **Threat Intelligence** | See what real attackers/scanners do in real-time |
| **Incident Response** | Practice detecting and analyzing intrusions |
| **Malware Analysis** | Capture malware samples, analyze with MD5/SHA256 |
| **Red Teaming** | Attack your own lab without legal risk |
| **Blue Teaming** | Build detection rules from log patterns |
| **Network Security** | Understand scanning, brute force, exploitation |
| **ICS/SCADA Security** | Learn Modbus/S7/BACnet attack patterns |
| **IoT Security** | See Mirai/botnet scanning Telnet, MQTT |
| **Forensics** | Trace attacker activity across 17 services |

---

## 17 Honeypot Types

| # | Type | Protocol(s) | Port(s) | What Gets Captured |
|---|------|-------------|---------|-------------------|
| 1 | **SSH/Telnet** | SSH, Telnet | 2222 | Attacker commands, brute force, malware downloads |
| 2 | **ICS/SCADA** | Modbus, S7, BACnet | 502, 102, 47808 | Industrial control system probes |
| 3 | **Credential Capture** | FTP, SMTP, POP3, HTTP, MySQL | 21, 25, 110, 8080, 3306 | Usernames & passwords attackers try |
| 4 | **Web Traps** | HTTP/HTTPS | 80, 8081, 8082 | WordPress scans, admin login attempts, API probes |
| 5 | **Database Traps** | Elasticsearch, MongoDB | 9200, 27017 | DB exploitation attempts, NoSQL probes |
| 6 | **Malware Capture** | HTTP, TFTP | 8888, 69 | Malware uploads, webshell attempts, exploit kits |
| 7 | **RDP Trap** | RDP | 3389 | RDP brute force, client info extraction |
| 8 | **SMB Trap** | SMB/CIFS | 445 | EternalBlue, WannaCry, SMB enumeration |
| 9 | **DNS Trap** | DNS | 5353 | DNS tunneling, amplification queries |
| 10 | **SIP Trap** | SIP/VoIP | 5060 | SIP scanning, registration, call invites |
| 11 | **Redis Trap** | Redis | 6379 | Unsecured Redis probes, key enumeration |
| 12 | **VNC Trap** | VNC/RFB | 5900 | VNC scanning, remote desktop attacks |
| 13 | **Telnet Trap** | Telnet | 23 | IoT/Mirai botnet scanning |
| 14 | **Memcached Trap** | Memcached | 11211 | DDoS amplification probes |
| 15 | **MQTT Trap** | MQTT | 1883 | IoT protocol attacks |
| 16 | **SNMP Trap** | SNMP | 161 | Network device scanning, community string brute force |
| 17 | **NTP Trap** | NTP | 123 | NTP amplification DDoS probes |

> Only SSH/Telnet (#1) uses Cowrie. All other 16 are custom Python socket servers — no Docker needed.

---

## 8 Dashboard Pages

| Page | URL | What It Shows |
|------|-----|---------------|
| **Overview** | `/` | Live stats, GeoIP columns, all log tables, alerts panel |
| **Heatmap** | `/heatmap` | Hourly activity grid + events by type breakdown |
| **Correlation** | `/correlation` | Multi-service attackers, top attackers, service tags |
| **API** | `/api` | 25+ REST endpoint documentation with "Try it" buttons |
| **Settings** | `/settings` | API keys, notifications, feature toggles, backup/restore |
| **Attack Map** | `/attack-map` | SVG world map showing attacker locations |
| **Timeline** | `/timeline` | Chronological attack view with type filters |
| **Statistics** | `/statistics` | Bar charts, attack distribution, hourly activity timeline |

---

## 12 Built-in Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **PDF Report Export** | Download threat analysis report as PDF |
| 2 | **Attack Map** | SVG world map showing attacker locations with tooltips |
| 3 | **Dark/Light Theme** | Toggle between dark and light themes |
| 4 | **Attack Timeline** | Chronological view with SSH/Web/Creds/Malware filters |
| 5 | **IP Blacklist** | Add/remove blocked IP addresses via API |
| 6 | **Real-time Updates** | Server-Sent Events for live dashboard updates |
| 7 | **Dashboard Login** | Password protection for the dashboard |
| 8 | **Scheduled Reports** | Configure daily/weekly email reports |
| 9 | **Attack Statistics** | Bar charts + hourly activity timeline |
| 10 | **Malware Analysis** | Auto-hash captured files with MD5/SHA256 |
| 11 | **Backup/Restore** | Download/upload ZIP backups of all data |
| 12 | **Custom Alert Rules** | Trigger alerts on custom conditions |

### Additional Features

| Feature | Description |
|---------|-------------|
| **GeoIP Tracking** | Resolves attacker IPs to country/city/ISP via ip-api.com |
| **Notifications** | Alerts via Telegram, Discord, Slack, or Email |
| **Threat Intel** | IP reputation via AbuseIPDB, VirusTotal, Shodan, GreyNoise |
| **Attack Correlation** | Links the same attacker across multiple services |
| **Activity Heatmap** | Visual timeline of attacks by hour/day |
| **Log Rotation** | Auto-archives logs, prevents disk full |
| **REST API** | 25+ JSON endpoints for stats, logs, GeoIP, intel, export |
| **Export** | Download all logs as JSON, CSV, or PDF |
| **Cross-Platform** | Windows + Kali/Linux — same codebase |

---

## Quick Start

### Windows

```powershell
# 1. Open PowerShell as Administrator (for ports < 1024)

# 2. Navigate to lab
cd D:\Security Tools\honey pot

# 3. Install
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 4. Start all 17 honeypots
python start_all.py

# 5. Open dashboard
python dashboard.py
# Browser: http://127.0.0.1:5000

# 6. Test your lab (new terminal)
python tools\test_scanner.py

# 7. Stop everything
python stop_all.py
```

### Kali / Linux

```bash
# 1. Open terminal
cd /path/to/honey-pot

# 2. Install (use --user for system Python)
pip3 install --user --break-system-packages -r requirements.txt

# 3. Start all 17 honeypots
python3 start_all.py

# 4. Open dashboard
python3 dashboard.py
# Browser: http://127.0.0.1:5000

# 5. Test in another terminal
python3 tools/test_scanner.py

# 6. Stop
python3 stop_all.py
```

> **Kali note:** DNS uses port 5353 (port 53 is reserved by WSL2).
> For ports < 1024, use `sudo python3 start_all.py`.

---

## Dashboard Pages

### Overview (`/`)
- 17 honeypot stat cards with live counters
- GeoIP columns (Country, City) in SSH and Web tables
- Total events, unique IPs, honeypot types, lab status
- Recent Alerts panel
- Auto-refresh every 5 seconds

### Heatmap (`/heatmap`)
- Hourly attack activity grid (24h x 7 days)
- Events by honeypot type with bar charts
- Color-coded intensity levels

### Correlation (`/correlation`)
- Multi-service attackers table with service tags
- Top attackers ranking
- Total events, unique IPs, multi-service count

### Settings (`/settings`)
- **Threat Intel API Keys:** AbuseIPDB, VirusTotal, Shodan, GreyNoise
- **Notifications:** Telegram bot token, Discord webhook, Slack webhook, Email SMTP
- **Feature Toggles:** GeoIP, Correlation, Log Rotation, Intel Feeds
- **Backup & Restore:** Download ZIP backup, Download PDF report

### Attack Map (`/attack-map`)
- SVG world map with attacker location dots
- Tooltips showing IP, country, event count, services
- Stats: Total events, unique IPs, countries, attack sources

### Timeline (`/timeline`)
- Chronological attack view with colored dots
- Filter buttons: All, SSH, Web, Creds, Malware, RDP, SMB, DNS
- Each event shows timestamp, type badge, IP, and detail

### Statistics (`/statistics`)
- Bar chart: Events by honeypot type (color-coded)
- Attack distribution legend
- Hourly activity timeline (last 24h)

### API (`/api`)
- 25+ endpoint documentation table
- "Try it" buttons for each endpoint
- Usage notes for query parameters

---

## REST API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Live event counts per honeypot + unique IPs |
| GET | `/api/logs/<type>?n=20` | Last N log entries (max 100) |
| GET | `/api/alerts?n=50` | Recent notification alerts |
| GET | `/api/geoip/<ip>` | GeoIP lookup for an IP |
| GET | `/api/intel/<ip>` | Threat intel lookup (AbuseIPDB, VirusTotal) |

### Log Endpoints (all 17 types)

```
GET /api/logs/ssh      GET /api/logs/web       GET /api/logs/creds
GET /api/logs/ics      GET /api/logs/db        GET /api/logs/malware
GET /api/logs/rdp      GET /api/logs/smb       GET /api/logs/dns
GET /api/logs/sip      GET /api/logs/redis     GET /api/logs/vnc
GET /api/logs/telnet   GET /api/logs/memcached GET /api/logs/mqtt
GET /api/logs/snmp     GET /api/logs/ntp
```

### Feature Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/export?format=json` | Export all logs as JSON |
| GET | `/api/export?format=csv` | Export all logs as CSV |
| GET | `/api/report/pdf` | Download PDF threat report |
| GET | `/api/backup` | Download ZIP backup |
| POST | `/api/restore` | Upload ZIP backup to restore |
| GET/POST | `/api/blacklist` | Manage IP blacklist |
| GET/POST | `/api/rules` | Manage alert rules |
| GET | `/api/rules/check` | Check if any rules are triggered |
| GET | `/api/malware/analyze` | Analyze captured malware (MD5/SHA256) |
| GET/POST | `/api/schedule` | Configure scheduled reports |
| POST | `/api/login` | Authenticate dashboard |
| GET/POST | `/api/login/config` | Configure login settings |
| GET | `/api/events/stream` | Server-Sent Events (real-time) |

---

## Notification Setup

### Via Dashboard
Go to **Settings** page and configure:
- Telegram Bot Token + Chat ID
- Discord Webhook URL
- Slack Webhook URL
- Email SMTP settings

### Via Config File
```bash
python features/notifications.py
# Interactive setup wizard
```

### Supported Channels
- **Telegram** — Bot token + chat ID
- **Discord** — Webhook URL
- **Slack** — Webhook URL
- **Email** — SMTP (Gmail, Outlook, custom)

---

## Threat Intelligence

### Configure API Keys
In **Settings** page or `config.ini`:
```ini
abuseipdb_key = your_api_key_here
virustotal_key = your_api_key_here
shodan_key = your_api_key_here
greynoise_key = your_api_key_here
```

### API Lookup
```bash
# Get threat intel for an IP
curl http://127.0.0.1:5000/api/intel/8.8.8.8

# Get GeoIP for an IP
curl http://127.0.0.1:5000/api/geoip/8.8.8.8
```

---

## Red Team Tools

### Port Scanner + Attack Simulator
```bash
python tools/test_scanner.py
# Option 1: Quick port scan
# Option 2: Full attack simulation (all 17 protocols)
# Option 3: Web attacks only
# Option 4: ICS/SCADA only
```

### Brute Force Simulator
```bash
python tools/test_bruteforce.py
# SSH brute force
# HTTP form brute force
# FTP brute force
# Multi-threaded attacks
```

---

## Blue Team Tools

### Log Analyzer + Threat Report
```bash
python tools/analyzer.py
# Option 1: Generate full report
# Option 2: Top attackers
# Option 3: Activity timeline
# Option 4: Deep dive into specific honeypot
# Option 5: Export to JSON
```

### Attack Correlation
```bash
python features/correlation.py
# Shows which IPs are hitting multiple services
```

---

## Configuration

### config.ini
```ini
[general]
enable_ssh_cowrie = yes
enable_smb = yes
enable_geoip = yes
enable_notifications = no
enable_correlation = yes
enable_log_rotation = yes

[ports]
ssh_port = 2222
dns_port = 5353        # Use 5353 on WSL2 (53 is reserved)
smb_port = 445
# ... all 17 ports configurable

[features]
abuseipdb_key =
virustotal_key =
shodan_key =
greynoise_key =
```

### Settings Page
Access at `http://127.0.0.1:5000/settings` to configure:
- API keys (no need to edit config.ini)
- Notification channels
- Feature toggles
- Backup/restore

---

## Project Structure

```
honey-pot/
├── start_all.py           # Launch all 17 honeypots
├── stop_all.py            # Stop all honeypots
├── dashboard.py           # Flask dashboard (8 pages + 25+ API endpoints)
├── alert_helper.py        # Shared notification helper
├── config.ini             # Enable/disable, set ports, API keys
├── notify_config.json     # Notification channel config
├── blacklist.json         # IP blacklist
├── alert_rules.json       # Custom alert rules
├── login.json             # Dashboard login config
├── schedule.json          # Scheduled reports config
├── requirements.txt       # Python dependencies
├── README.md              # This file
│
├── honeypots/             # 17 honeypot implementations
│   ├── 01_ssh_cowrie/     # SSH/Telnet (Cowrie)
│   ├── 02_ics_conpot/     # ICS/SCADA
│   ├── 03_creds_heralding/# Credential capture
│   ├── 04_web_traps/      # Web traps
│   ├── 05_db_traps/       # Database traps
│   ├── 06_malware_capture/# Malware capture
│   ├── 07_rdp_trap/       # RDP trap
│   ├── 08_smb/            # SMB/CIFS
│   ├── 09_dns/            # DNS
│   ├── 10_sip/            # SIP/VoIP
│   ├── 11_redis/          # Redis
│   ├── 12_vnc/            # VNC
│   ├── 13_telnet/         # Telnet (IoT)
│   ├── 14_memcached/      # Memcached
│   ├── 15_mqtt/           # MQTT
│   ├── 16_snmp/           # SNMP
│   └── 17_ntp/            # NTP
│
├── features/              # Feature modules
│   ├── geoip.py           # GeoIP tracking
│   ├── notifications.py   # Telegram/Discord/Slack/Email
│   ├── correlation.py     # Attack correlation
│   ├── heatmap.py         # Activity heatmap
│   ├── intel.py           # Threat intel feeds
│   └── log_rotation.py    # Log rotation/cleanup
│
├── tools/                 # Red vs Blue tools
│   ├── test_scanner.py    # Port scanner + attack simulator
│   ├── test_bruteforce.py # Brute force simulator
│   └── analyzer.py        # Log analyzer + threat report
│
├── logs/                  # All captured data (17 subdirs + alerts.jsonl)
└── docs/                  # Documentation
```

---

## Learning Path

### Beginner
1. Deploy: `python start_all.py`
2. Open dashboard: `http://localhost:5000`
3. Test with: `python tools/test_scanner.py`
4. Watch attacks appear on the dashboard

### Intermediate
1. Run `python tools/test_bruteforce.py`
2. See credentials captured in the dashboard
3. Run `python tools/analyzer.py` for the report
4. Enable Telegram/Discord notifications in Settings

### Advanced
1. Deploy on a cloud VM (AWS/DigitalOcean)
2. Open ports in firewall
3. Watch real attackers find you within minutes
4. Analyze malware samples collected
5. Correlate attackers across services

### Expert (CTF)
1. Two machines: Red (Kali) vs Blue (your lab)
2. Red team attacks using custom tools
3. Blue team monitors dashboard + writes analysis
4. Switch roles and compare

---

## Security Warnings

| Risk | Mitigation |
|------|-----------|
| Open ports expose your machine | Run on isolated VM or private network only |
| Malware capture downloads real samples | Handle in sandbox — never run on host |
| Legal issues — honeypots may be regulated | Check local laws before internet exposure |
| Ports < 1024 need admin | Use higher ports or run as admin/root |
| Port 3389 conflicts with Windows RDP | Disable Windows RDP or change port |
| Corporate networks trigger security alerts | Get written permission first |

### Safe Deployment
```bash
# Local only (safest — edit config.ini):
bind_host = 127.0.0.1

# VM (recommended): VirtualBox/VMware with NAT
# Cloud (expert): DigitalOcean/AWS — real internet traffic
```

---

## Windows-Specific Notes

- **Console encoding:** All scripts force UTF-8 on startup
- **Cowrie on Windows:** `start_all.py` invokes `twistd` directly (bypasses POSIX-only CLI)
- **Stopping honeypots:** `stop_all.py` uses `taskkill` fallback for reliability
- **Admin only needed** for ports < 1024 (default config avoids this)

---

## Troubleshooting

**Port already in use?**
```bash
netstat -ano | findstr :2222     # Windows
sudo netstat -tlnp | grep 2222   # Linux
# Change port in config.ini
```

**Permission denied on ports < 1024?**
```bash
# Windows: Run as Administrator
# Linux: sudo python3 start_all.py
# Or use higher ports (> 1024)
```

**Module not found?**
```bash
pip install -r requirements.txt
# Or on Kali:
pip3 install --user --break-system-packages -r requirements.txt
```

**Nothing appears in dashboard?**
```bash
python tools/test_scanner.py  # Generate test traffic
python status.py              # Check honeypots are running
```

**Dashboard won't start?**
```bash
# Port 5000 might be in use:
netstat -ano | findstr :5000
```

**PDF download not working?**
```bash
pip install reportlab
# Or on Kali:
pip3 install --user --break-system-packages reportlab
```

---

## What's New in v2.0

### Cross-Platform Fixes
- Fixed `LAB_DIR` path calculation in all 17 honeypot scripts
- Fixed Cowrie SSH output plugins (absolute paths)
- Patched Cowrie root check for Linux
- DNS port changed to 5353 (WSL2 conflict on port 53)

### Dashboard Overhaul
- Modern SOC-style UI with cyan accent theme
- 8 pages: Overview, Heatmap, Correlation, API, Settings, Attack Map, Timeline, Statistics
- GeoIP columns in log tables (Country, City)
- Recent Alerts panel
- Dark/Light theme toggle

### 12 New Features
- PDF Report Export
- Attack Map with SVG world map
- Attack Timeline with type filters
- IP Blacklist management
- Real-time Server-Sent Events
- Dashboard Login system
- Scheduled Reports configuration
- Attack Statistics with charts
- Malware Analysis (MD5/SHA256)
- Backup/Restore (ZIP)
- Custom Alert Rules
- Settings page for all configuration

### 25+ API Endpoints
- Stats, Logs, Alerts, GeoIP, Intel, Export, Backup, Restore
- Blacklist, Rules, Malware Analysis, Schedule, Login, SSE

### Integration
- Notifications integrated in all 16 honeypot scripts
- GeoIP enrichment in dashboard log tables
- Threat intel lookup via AbuseIPDB/VirusTotal
- Analyzer tool fixed (counts all events correctly)

---

## License

All Rights Reserved — Copyright (c) 2026 **JOJIN JOHN**

This software and associated documentation files are protected by copyright law. No part may be reproduced, distributed, or transmitted without prior written permission.

For licensing inquiries: **jojin1709@gmail.com**

---

**Built for the cybersecurity community.**
**Stay safe, hack ethically.**
