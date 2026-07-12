# 🍯 Honeypot Lab v2.0 — Cybersecurity Attack & Defense Laboratory

> **17 honeypot types · 13+ analysis features · Red vs Blue tools · Web dashboard**
> **Developed by JOJIN JOHN**

A comprehensive honeypot laboratory for cybersecurity enthusiasts, SOC analysts, penetration testers, CTF players, and malware researchers. Captures real attacker behavior across 17 protocols, with GeoIP tracking, attack correlation, live dashboard, and notification alerts. Runs on **Windows** and **Kali/Linux** — no Docker required.

---

## 📋 Table of Contents

- [What Is This?](#-what-is-this)
- [Who Uses This?](#-who-uses-this)
- [17 Honeypot Types](#-17-honeypot-types)
- [Features](#-features)
- [Quick Start — Windows](#windows)
- [Quick Start — Kali / Linux](#kali--linux)
- [How To Use](#-how-to-use)
- [Dashboard (Web UI)](#-dashboard-web-ui)
- [Notification Setup](#-notification-setup)
- [Red Team Tools](#-red-team--attack-your-own-lab)
- [Blue Team Tools](#-blue-team--analyze-the-attacks)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Learning Path (Beginner→Expert)](#-learning-path)
- [Security Warnings](#-security-warnings)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 What Is This?

A **honeypot lab** sets up **fake services** that look real to attackers. When someone connects:

- ✅ Their **IP** is logged with GeoIP location (country/city/ISP)
- ✅ Their **commands** are recorded
- ✅ Any **credentials they try** are captured
- ✅ Any **malware they upload** is saved and hashed
- ✅ You get **notifications** via Telegram/Discord/Slack/Email
- ✅ You can **analyze and correlate** everything in the dashboard

### What You Can Learn

| Skill | How This Lab Helps |
|-------|-------------------|
| **Threat Intelligence** | See what real attackers/scanners do in real-time |
| **Incident Response** | Practice detecting and analyzing intrusions |
| **Malware Analysis** | Capture malware samples, analyze them |
| **Red Teaming** | Attack your own lab without legal risk |
| **Blue Teaming** | Build detection rules from log patterns |
| **Network Security** | Understand scanning, brute force, exploitation |
| **ICS/SCADA Security** | Learn Modbus/S7/BACnet attack patterns |
| **IoT Security** | See Mirai/botnet scanning Telnet, MQTT |
| **Forensics** | Trace attacker activity across 17 services |

---

## 👥 Who Uses This?

| Role | How They Use It |
|------|----------------|
| 🎓 **Cybersecurity Students** | Practice hands-on attack & defense safely |
| 🔴 **Penetration Testers** | Test attack tools against honeypot signatures |
| 🔵 **SOC Analysts** | Build detection rules, practice incident response |
| 🏭 **ICS Security Engineers** | Learn Modbus/S7/BACnet attack patterns |
| 🏴‍☠️ **CTF Players** | Train for Red vs Blue challenges |
| 🔬 **Malware Researchers** | Capture malware droppers, analyze them |
| 📊 **Threat Intel Analysts** | Collect data on scanning campaigns |
| 🧪 **IT/Network Students** | Understand how attackers find services |

---

## 🏗️ 17 Honeypot Types

| # | Type | Icon | Protocol(s) | Port(s) | What Gets Captured |
|---|------|------|-------------|---------|-------------------|
| 1 | **SSH/Telnet** | 🐚 | SSH, Telnet | 2222 | Attacker commands, brute force, malware downloads |
| 2 | **ICS/SCADA** | 🏭 | Modbus, S7, BACnet | 502, 102, 47808 | Industrial control system probes |
| 3 | **Credential Capture** | 🔑 | FTP, SMTP, POP3, HTTP, MySQL | 21, 25, 110, 8080, 3306 | Usernames & passwords attackers try |
| 4 | **Web Traps** | 🌐 | HTTP/HTTPS | 80, 8081, 8082 | WordPress scans, admin login attempts, API probes |
| 5 | **Database Traps** | 🗄️ | Elasticsearch, MongoDB | 9200, 27017 | DB exploitation attempts, NoSQL probes |
| 6 | **Malware Capture** | 🦠 | HTTP, TFTP | 8888, 69 | Malware uploads, webshell attempts, exploit kits |
| 7 | **RDP Trap** | 🖥️ | RDP | 3389 | RDP brute force, client info extraction |
| 8 | **SMB Trap** | 📁 | SMB/CIFS | 445 | EternalBlue, WannaCry, SMB enumeration |
| 9 | **DNS Trap** | 🌐 | DNS | 53 | DNS tunneling, amplification queries |
| 10 | **SIP Trap** | 📞 | SIP/VoIP | 5060 | SIP scanning, registration, call invites |
| 11 | **Redis Trap** | 🔴 | Redis | 6379 | Unsecured Redis probes, key enumeration |
| 12 | **VNC Trap** | 🖥️ | VNC/RFB | 5900 | VNC scanning, remote desktop attacks |
| 13 | **Telnet Trap** | 📟 | Telnet | 23 | IoT/Mirai botnet scanning |
| 14 | **Memcached Trap** | 📦 | Memcached | 11211 | DDoS amplification probes |
| 15 | **MQTT Trap** | 📡 | MQTT | 1883 | IoT protocol attacks |
| 16 | **SNMP Trap** | 🌐 | SNMP | 161 | Network device scanning, community string brute force |
| 17 | **NTP Trap** | 🕐 | NTP | 123 | NTP amplification DDoS probes |

---

## ⚡ Features

| Feature | Description | Status |
|---------|-------------|--------|
| 📊 **Live Dashboard** | Web UI with auto-refresh — see attacks in real-time | ✅ Built-in |
| 🌍 **GeoIP Tracking** | Resolves attacker IPs to country/city/ISP | ✅ Built-in |
| 🔗 **Attack Correlation** | Links the same attacker across multiple services | ✅ Built-in |
| 🔥 **Activity Heatmap** | Visual timeline of attacks by hour/day | ✅ Built-in |
| 🔔 **Notifications** | Alerts via Telegram, Discord, Slack, or Email | ✅ Configurable |
| 📦 **Log Rotation** | Auto-archives logs, prevents disk full | ✅ Built-in |
| 🎯 **Red Team Tools** | Port scanner, brute forcer, full attack simulator | ✅ Built-in |
| 📈 **Blue Team Tools** | Log analyzer, threat report generator | ✅ Built-in |
| 🌐 **REST API** | JSON endpoints for all stats and logs | ✅ Built-in |
| 🖥️ **Cross-Platform** | Windows + Kali/Linux — same codebase | ✅ Verified |

---

## 🚀 Quick Start

### Windows

```powershell
# 1. Open PowerShell as Administrator (for ports < 1024)

# 2. Navigate to lab
cd D:\honey pot

# 3. Install
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 4. Start all 17 honeypots
python start_all.py

# 5. Open dashboard
python dashboard.py
# → Browser: http://127.0.0.1:5000

# 6. Test your lab (in new terminal)
python tools\test_scanner.py

# 7. Stop everything
python stop_all.py
```

### Kali / Linux

```bash
# 1. Open terminal
cd /path/to/honey-pot

# 2. Install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install native C builds (optional, works without)
pip install conpot heralding 2>/dev/null

# 3. Start all 17 honeypots
python3 start_all.py

# 4. Open dashboard
python3 dashboard.py
# → Browser: http://127.0.0.1:5000

# 5. Test in another terminal
python3 tools/test_scanner.py

# 6. Stop
python3 stop_all.py
```

> **💡 Root on Kali:** For ports < 1024, use `sudo`:
> ```bash
> sudo python3 start_all.py
> ```

---

## 📊 Dashboard (Web UI)

```
http://127.0.0.1:5000
```

### What It Shows
- **17 honeypot stat cards** — live counter for each type
- **Recent activity tables** — last 15 events per honeypot
- **Total events + unique IPs** — at a glance
- **Auto-refresh** — every 5 seconds
- **API endpoints** — `/api/stats`, `/api/logs/<type>`, `/api/heatmap`

---

## 🔔 Notification Setup

Get instant alerts when something hits your honeypots:

```bash
python features/notifications.py
```

Supports:
- **Telegram** — bot token + chat ID
- **Discord** — webhook URL
- **Slack** — webhook URL
- **Email** — SMTP (Gmail, Outlook, custom)

Configure in `notify_config.json` (auto-generated) or via the interactive setup.

---

## 🔴 Red Team — Attack Your Own Lab

```bash
# Full attack simulator
python tools/test_scanner.py
# Option 1: Quick port scan
# Option 2: Full attack (ports + web + SSH + DB + ICS + RDP + more)
# Option 3: Web attacks only
# Option 4: ICS/SCADA only

# Brute force simulator
python tools/test_bruteforce.py
# SSH brute force, HTTP form brute, FTP brute, multi-threaded
```

---

## 🔵 Blue Team — Analyze the Attacks

```bash
# Full threat report
python tools/analyzer.py
# Option 1: Generate complete report across all 17 honeypots
# Option 2: Show top attackers
# Option 3: Activity timeline
# Option 4: Deep dive into specific honeypot
# Option 5: Export all to JSON

# Attack correlation
python features/correlation.py
# Shows which IPs are hitting multiple services
```

---

## 📁 Project Structure

```
D:\honey pot\
├── start_all.py           # Launch all 17 honeypots + features
├── stop_all.py            # Stop all honeypots
├── status.py              # Check what's running
├── dashboard.py           # Flask web dashboard (localhost:5000)
├── config.ini             # Enable/disable, set ports
├── requirements.txt       # Python dependencies
├── Makefile               # make start/stop/dashboard/test
├── install.sh             # Linux one-command installer
├── install.bat            # Windows one-command installer
├── LICENSE                # All Rights Reserved
├── README.md              # This file
│
├── honeypots\
│   ├── 01_ssh_cowrie\     # 🐚 Cowrie SSH
│   ├── 02_ics_conpot\     # 🏭 ICS/SCADA
│   ├── 03_creds_heralding\ # 🔑 Credential capture
│   ├── 04_web_traps\      # 🌐 Web traps
│   ├── 05_db_traps\       # 🗄️ Database traps
│   ├── 06_malware_capture\ # 🦠 Malware capture
│   ├── 07_rdp_trap\       # 🖥️ RDP
│   ├── 08_smb\            # 📁 SMB/CIFS
│   ├── 09_dns\            # 🌐 DNS
│   ├── 10_sip\            # 📞 SIP/VoIP
│   ├── 11_redis\          # 🔴 Redis
│   ├── 12_vnc\            # 🖥️ VNC
│   ├── 13_telnet\         # 📟 Telnet (IoT)
│   ├── 14_memcached\      # 📦 Memcached
│   ├── 15_mqtt\           # 📡 MQTT
│   ├── 16_snmp\           # 🌐 SNMP
│   └── 17_ntp\            # 🕐 NTP
│
├── features\              # Feature modules
│   ├── geoip.py           # 🌍 GeoIP tracking
│   ├── notifications.py   # 🔔 Telegram/Discord/Slack/Email
│   ├── correlation.py     # 🔗 Attack correlation
│   ├── heatmap.py         # 🔥 Activity heatmap
│   ├── intel.py           # 🛡️ Threat intel feeds
│   └── log_rotation.py    # 📦 Log rotation/cleanup
│
├── logs\                  # All captured data (17 subdirs)
├── tools\                 # Red vs Blue tools
└── venv\                  # Python virtual environment
```

---

## ⚙️ Configuration

Edit `config.ini`:

```ini
[general]
# Disable any honeypot by setting to "no"
enable_ssh_cowrie = yes
enable_smb = yes
# Enable features
enable_geoip = yes
enable_log_rotation = yes

[ports]
ssh_port = 2222        # Change to 22 for real SSH (needs admin)
smb_port = 445
dns_port = 53
# ... all 17 ports configurable
```

---

## 🧪 Learning Path

### 🟢 Beginner
1. Deploy: `python start_all.py`
2. Open dashboard: `http://localhost:5000`
3. Test with: `python tools/test_scanner.py`
4. Watch attacks appear on the dashboard

### 🟡 Intermediate
1. Run `python tools/test_bruteforce.py`
2. See credentials captured in the dashboard
3. Run `python tools/analyzer.py` for the report
4. Enable Telegram/Discord notifications

### 🔴 Advanced
1. Deploy on a cloud VM (AWS/DigitalOcean)
2. Open ports in firewall
3. Watch **real** attackers find you within minutes
4. Analyze malware samples collected
5. Correlate attackers across services

### 🏆 Expert — CTF
1. Two machines: Red (Kali) vs Blue (your lab)
2. Red team attacks using custom tools
3. Blue team monitors dashboard + writes analysis
4. Switch roles and compare

---

## 🔒 Security Warnings

> ⚠️ **⚠️ READ THIS BEFORE RUNNING!**

| Risk | Mitigation |
|------|-----------|
| 🚪 **Open ports** expose your machine | Run on isolated VM or private network only |
| 🦠 **Malware capture** downloads real samples | Handle in sandbox — never run on host |
| ⚖️ **Legal issues** — honeypots may be regulated | Check local laws before internet exposure |
| 🔓 **Ports < 1024** need admin | Use higher ports or run as admin/root |
| 🖥️ **Port 3389** conflicts with Windows RDP | Disable Windows RDP or change port |
| 🏢 **Corporate networks** — triggers security alerts | Get written permission first |

### Safe Deployment
```bash
# Local only (safest — edit config.ini):
bind_host = 127.0.0.1

# VM (recommended): VirtualBox/VMware with NAT
# Cloud (expert): DigitalOcean/AWS — real internet traffic
```

---

## ❓ Troubleshooting

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
```

**Nothing appears in dashboard?**
```bash
python tools/test_scanner.py  # Generate test traffic
python status.py              # Check honeypots are running
```

**Dashboard won't start?**
```bash
# Port 5000 might be in use — check:
netstat -ano | findstr :5000
```

---

## 📄 License

All Rights Reserved — Copyright (c) 2026 **JOJIN JOHN**

This software and associated documentation files are protected by copyright law. No part may be reproduced, distributed, or transmitted without prior written permission.

For licensing inquiries: **jojin1709@gmail.com**

---

**Built with ❤️ for the cybersecurity community.**
**Stay safe, hack ethically. 🏴‍☠️**
