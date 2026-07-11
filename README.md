# 🍯 Honeypot Lab — Cybersecurity Attack & Defense Laboratory

> **A comprehensive honeypot laboratory for cybersecurity enthusiasts, SOC analysts, penetration testers, and CTF players.**
> Captures real attacker behavior, logs credential theft, collects malware samples, and lets you practice **Red vs Blue** — all in Python.

---

## 📋 Table of Contents

- [What Is This?](#-what-is-this)
- [Who Uses This?](#-who-uses-this)
- [Honeypot Types (7)](#-honeypot-types-7)
- [Quick Start](#-quick-start)
  - [Windows Setup](#windows)
  - [Kali / Linux Setup](#kali--linux)
- [How To Use](#-how-to-use)
- [Dashboard (Web UI)](#-dashboard-web-ui)
- [Red Team Tools (Attack Yourself)](#-red-team--attack-your-own-lab)
- [Blue Team Tools (Analyze Attacks)](#-blue-team--analyze-the-attacks)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Learning Path](#-learning-path)
- [Security Warnings](#-security-warnings)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## 🎯 What Is This?

A **honeypot lab** is a cybersecurity training environment where you set up **fake services** (SSH, web servers, databases, industrial systems, etc.) that look real to attackers. When someone (or an automated scanner) connects to them:

- ✅ Their **IP address** is logged
- ✅ Their **commands** are recorded
- ✅ Any **credentials they try** are captured
- ✅ Any **malware they upload** is saved
- ✅ You can **analyze all of it** to learn attacker techniques

This lab runs **entirely in Python** — no Docker, no VMs, no complex setup. It works on **Windows 10/11**, **Kali Linux**, **Ubuntu**, **Debian**, and any system with Python 3.10+.

### 🧠 What You Can Learn

| Skill | How This Lab Helps |
|-------|-------------------|
| **Threat Intelligence** | See what real attackers/scanners do in real-time |
| **Incident Response** | Practice detecting and analyzing intrusions |
| **Malware Analysis** | Capture malware samples and analyze them |
| **Red Teaming** | Attack your own lab without legal risk |
| **Blue Teaming** | Build detection rules from log patterns |
| **Network Security** | Understand scanning, brute force, and exploitation |
| **ICS/SCADA Security** | Learn industrial control system attack patterns |
| **Forensics** | Trace attacker activity across multiple services |

---

## 👥 Who Uses This?

| Role | How They Use It |
|------|----------------|
| 🎓 **Cybersecurity Students** | Practice hands-on attack & defense in a safe environment |
| 🔴 **Penetration Testers** | Test attack tools against known honeypot signatures |
| 🔵 **SOC Analysts** | Build detection rules and practice incident response |
| 🏭 **ICS Security Engineers** | Learn Modbus/S7/BACnet attack patterns |
| 🏴‍☠️ **CTF Players** | Train for Red vs Blue challenges |
| 🔬 **Malware Researchers** | Capture malware droppers and analyze them |
| 🧪 **IT Students** | Understand how attackers find and exploit services |
| 📊 **Threat Intelligence Analysts** | Collect data on scanning campaigns and botnets |

---

## 🏗️ Honeypot Types (7)

| # | Type | What It Emulates | Port(s) | What Gets Captured |
|---|------|-----------------|---------|-------------------|
| 1 | 🐚 **SSH/Telnet** | Fake Linux server | `2222` | Attacker commands, brute force attempts, malware downloads |
| 2 | 🏭 **ICS/SCADA** | Siemens PLC, Modbus, BACnet | `502`, `102`, `47808` | Industrial control system probes, Shodan scans |
| 3 | 🔑 **Credential Capture** | FTP, SMTP, POP3, HTTP login | `21`, `25`, `110`, `8080`, `3306` | Usernames & passwords attackers try |
| 4 | 🌐 **Web Traps** | WordPress, phpMyAdmin, API | `80`, `8081`, `8082` | Web attacks, SQLi probes, admin scans |
| 5 | 🗄️ **Database Traps** | Elasticsearch, MongoDB | `9200`, `27017` | Database exploitation attempts, NoSQL probes |
| 6 | 🦠 **Malware Capture** | Vulnerable web app + TFTP | `8888`, `69` | Malware uploads, Webshell attempts, exploit kits |
| 7 | 🖥️ **RDP Trap** | Windows Remote Desktop | `3389` | RDP brute force attempts, client info |

---

## 🚀 Quick Start

### Windows

```powershell
# 1. Open PowerShell or CMD as Administrator (for ports < 1024)
#    Otherwise, higher ports work without admin

# 2. Go to the lab directory
cd D:\honey pot

# 3. Create & activate virtual environment
python -m venv venv
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Start ALL honeypots
python start_all.py

# 6. Open the LIVE dashboard in your browser
python dashboard.py
# → Open http://127.0.0.1:5000

# 7. In a second terminal, test your lab
python tools\test_scanner.py

# 8. Stop everything when done
python stop_all.py
```

### Kali / Linux

```bash
# 1. Open terminal
cd /path/to/honey-pot

# 2. Create & activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install ALL dependencies (includes cowrie on Linux)
pip install -r requirements.txt

# Optional: install conpot & heralding on Linux (native C build works)
pip install conpot heralding

# 4. Start all honeypots
python3 start_all.py

# 5. Open the live dashboard
python3 dashboard.py
# → Open http://127.0.0.1:5000

# 6. In another terminal, run Red Team tests
python3 tools/test_scanner.py
python3 tools/test_bruteforce.py

# 7. Stop everything
python3 stop_all.py
```

> **💡 Note on Kali:** If you get `permission denied` on ports below 1024, run as root or use `sudo`:
> ```bash
> sudo python3 start_all.py
> ```
> Or change ports in `config.ini` to higher values.

---

## 📊 Dashboard (Web UI)

The **Flask web dashboard** gives you live visibility into all attacks:

```
http://127.0.0.1:5000
```

### Features:
- ✅ **Auto-refresh** every 5 seconds
- ✅ **Stats per honeypot type** — see which traps are catching the most
- ✅ **Live activity tables** — all 7 honeypots with latest events
- ✅ **Unique attacker IPs** — see how many distinct attackers hit your lab
- ✅ **JSON API** — programmatic access at `/api/stats` and `/api/logs/<type>`

### Screenshot:
```
┌────────────────────────────────────────────────────────────┐
│  🍯 Honeypot Lab Dashboard                     [🔃 auto] │
├────────────────────────────────────────────────────────────┤
│  🐚 12  🏭 3  🔑 45  🌐 89  🗄️ 7  🦠 23  🖥️ 15        │
├────────────────────────────────────────────────────────────┤
│  📊 Total Events: 194  |  Unique IPs: 37  |  7 Active    │
├────────────────────────────────────────────────────────────┤
│  🌐 Recent Web Activity               🗄️ DB & RDP       │
│  2026-07-11 10.0.0.1  POST /wp-admin  │ ES probe from X  │
│  2026-07-11 10.0.0.2  GET  /admin     │ RDP conn from Y │
│  ...                                  │ ...              │
└────────────────────────────────────────────────────────────┘
```

---

## 🔴 Red Team — Attack Your Own Lab

Test that your honeypots are working by simulating real attacks:

```bash
# Interactive port scan & attack simulator
python tools/test_scanner.py

# Options:
#   1) Quick scan (port only) — checks what's listening
#   2) Full attack simulation — ports + web + SSH + DB + ICS + RDP
#   3) Web attacks only
#   4) ICS/SCADA probes only
```

```bash
# Brute force simulator — test your traps under pressure
python tools/test_bruteforce.py

# Options:
#   1) SSH brute force (tries 40+ credential combinations)
#   2) HTTP form brute force (tries 15 passwords against /wp-admin)
#   3) FTP brute force
#   4) Multi-threaded SSH brute (5 threads, 24 creds)
#   5) ALL of the above
```

---

## 🔵 Blue Team — Analyze the Attacks

```bash
# Launch the interactive log analyzer
python tools/analyzer.py

# Options:
#   1) Full threat report — stats across ALL honeypots
#   2) Top attackers — who's hitting you the most
#   3) Activity timeline — when attacks happen (hourly/daily)
#   4) Analyze specific honeypot — deep dive into one
#   5) Export all data to JSON

# Example output:
# ┌─────────────────────────────────────────────────────────────┐
# │  📊 THREAT ANALYSIS REPORT                                 │
# ├─────────────────────────────────────────────────────────────┤
# │  🐚 SSH:       12 connections, 5 unique IPs                │
# │  🌐 Web:       89 requests, /wp-login.php most attacked    │
# │  🔑 Creds:     45 login attempts, "admin" most common      │
# │  🗄️ DB:        7 probes                                   │
# │  🏭 ICS:       3 Modbus probes                              │
# │  🦠 Malware:   2 files captured                             │
# │  🖥️ RDP:       15 connections                              │
# │  📈 TOTAL:     173 events | 37 unique attackers            │
# └─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
D:\honey pot\
├── start_all.py              # Launch all honeypots (one command)
├── stop_all.py               # Stop all honeypots
├── status.py                 # Check which honeypots are running
├── dashboard.py              # Flask web dashboard (http://localhost:5000)
├── config.ini                # Enable/disable honeypots, set ports
├── requirements.txt          # Python dependencies
├── .gitignore
├── README.md                 # This file
│
├── honeypots\
│   ├── 01_ssh_cowrie\        # 🐚 Cowrie SSH honeypot
│   │   └── cowrie.cfg
│   ├── 02_ics_conpot\        # 🏭 ICS/SCADA honeypot (custom Python)
│   │   ├── conpot.xml        # (for Kali where conpot is installed)
│   │   └── ics_honeypot.py   # (cross-platform fallback)
│   ├── 03_creds_heralding\   # 🔑 Credential capture
│   │   ├── heralding.yml     # (for Kali)
│   │   └── cred_traps.py     # (cross-platform fallback)
│   ├── 04_web_traps\         # 🌐 Web honeypots
│   │   └── web_traps.py
│   ├── 05_db_traps\          # 🗄️ Database honeypots
│   │   └── db_traps.py
│   ├── 06_malware_capture\   # 🦠 Malware capture
│   │   └── malware_capture.py
│   └── 07_rdp_trap\          # 🖥️ RDP honeypot
│       └── rdp_trap.py
│
├── logs\                     # All captured data (auto-created)
│   ├── ssh\                  # Cowrie logs
│   ├── ics\                  # ICS/SCADA probe logs
│   ├── creds\                # Captured credentials (JSON + CSV)
│   ├── web\                  # Web attack logs
│   ├── db\                   # Database probe logs
│   ├── malware\              # Malware traffic + captured files/
│   └── rdp\                  # RDP connection logs
│
└── tools\                    # Red vs Blue tools
    ├── test_scanner.py       # 🎯 Port scanner & attack simulator
    ├── test_bruteforce.py    # 🔐 Brute force simulator
    └── analyzer.py           # 📊 Log analyzer & report generator
```

---

## ⚙️ Configuration

Edit `config.ini` to customize your lab:

```ini
[general]
# Set any to "no" to disable that honeypot
enable_ssh_cowrie = yes
enable_ics_conpot = yes
enable_creds_heralding = yes
enable_web_traps = yes
enable_db_traps = yes
enable_malware_capture = yes
enable_rdp_trap = yes

[ports]
# Change ports if there are conflicts
ssh_port = 2222           # Change to 22 for real SSH port (needs admin)
wordpress_port = 80       # Change if port 80 is in use
```

---

## 🧪 Learning Path

### 🟢 Beginner — "Watch the attacks come in"

1. Deploy the lab (`python start_all.py`)
2. Open the dashboard (`http://127.0.0.1:5000`)
3. Wait for automated scanners to find you
4. Check what they tried

### 🟡 Intermediate — "Attack yourself and analyze"

1. Deploy the lab
2. Run `python tools/test_scanner.py` (option 2 — full attack)
3. Check the dashboard — see what was logged
4. Run `python tools/analyzer.py` — generate the report
5. Understand the attack patterns

### 🔴 Advanced — "Go live on the internet"

> ⚠️ **WARNING:** Only do this in a VM on an isolated network!

1. Deploy on a cloud VM (AWS, DigitalOcean, Vultr)
2. Expose ports through firewall
3. Watch REAL attackers find you within minutes
4. Analyze malware samples collected
5. Build detection rules from the patterns

### 🏆 Expert — "Red vs Blue CTF"

1. Set up two machines:
   - **Red machine:** Attack tools, Kali Linux
   - **Blue machine:** Your honeypot lab
2. Red team attacks the honeypots using `test_bruteforce.py` + custom tools
3. Blue team monitors the dashboard and writes analysis reports
4. Switch roles and compare scores

---

## 🔒 Security Warnings

> ⚠️ **⚠️ CRITICAL: Read this before running!**

| Risk | Mitigation |
|------|-----------|
| 🚪 **Open ports** expose your machine to the internet | Only run on isolated networks or VMs |
| 🦠 **Malware capture** downloads real malware samples | Handle captured files in sandboxed environment only |
| ⚖️ **Legal issues** — running honeypots may be regulated | Check local laws before exposing to internet |
| 🔓 **Ports < 1024** require admin/root | Use ports > 1024 or run as admin |
| 🌐 **Port 3389** (RDP) conflicts with Windows RDP | Disable Windows RDP first, or change port |
| 🏢 **Corporate networks** — may trigger security alerts | Get permission first |

### 🛡️ Safe Deployment Options

```bash
# Option 1: Local only (safe)
# Your honeypots will only be accessible from your own machine
# → bind_host = 127.0.0.1 in config.ini

# Option 2: VM (recommended for learning)
# Run in VirtualBox/VMware with NAT network

# Option 3: Cloud VM (advanced)
# Deploy on DigitalOcean/AWS and analyze real internet traffic
```

---

## ❓ Troubleshooting

### Port already in use?
```bash
# Check what's using the port
netstat -ano | findstr :2222    # Windows
sudo netstat -tlnp | grep 2222  # Linux

# Change port in config.ini and restart
```

### Permission denied (Windows)?
```powershell
# Run PowerShell as Administrator, OR
# Change to higher ports in config.ini (> 1024)
```

### Permission denied (Kali/Linux)?
```bash
# Run with sudo, OR
sudo python3 start_all.py
# Change to higher ports in config.ini
```

### "Module not found" errors?
```bash
pip install -r requirements.txt  # Install all dependencies
# On Kali, extra install:
pip install conpot heralding     # Native C builds work on Linux
```

### Nothing appears in dashboard?
```bash
# Generate test traffic:
python tools/test_scanner.py
# Check honeypots are running:
python status.py
```

### RDP port (3389) won't start on Windows?
```powershell
# Windows uses port 3389 for its own RDP server
# Either:
#   1. Stop Windows RDP: sc stop TermService
#   2. Or change port in config.ini to 13389
```

---

## 📄 License

MIT License — use freely for learning, training, and research.

---

**Built with ❤️ for the cybersecurity community.**
**Happy hunting! 🏴‍☠️**
