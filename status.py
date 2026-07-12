#!/usr/bin/env python3
import sys as _sys, os as _os
if _sys.platform == "win32":
    _os.environ.setdefault("PYTHONUTF8", "1")
    _os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
"""
HoneyPot Lab - Status Check (all 17 honeypots)
"""
import os, sys, signal, socket, datetime

LAB_DIR = os.path.dirname(os.path.abspath(__file__))

def check_process(pid):
    try: os.kill(pid, 0); return True
    except: return False

def check_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex(("127.0.0.1", int(port)))
        s.close()
        return r == 0
    except: return False

def fmt_row(name, status, port, pid=""):
    icon = "🟢" if status else "🔴"
    return f"  {icon}  {name:<35} {'RUNNING' if status else 'STOPPED':<10} Port {str(port):<6} {pid}"

def main():
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    pids = {}
    if os.path.exists(pid_path):
        with open(pid_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    name, pid = line.split(":", 1)
                    pids[name.strip()] = int(pid.strip())

    honeypots = [
        ("🐚 Cowrie (SSH)", "2222", pids.get("🐚 Cowrie")),
        ("🏭 ICS/SCADA", "502", pids.get("🏭 ICS/SCADA")),
        ("🔑 Credential Capture", "21", pids.get("🔑 Credential Capture")),
        ("🌐 Web Traps", "80", pids.get("🌐 Web Traps")),
        ("🗄️ DB Traps", "9200", pids.get("🗄️ DB Traps")),
        ("🦠 Malware Capture", "8888", pids.get("🦠 Malware Capture")),
        ("🖥️ RDP Trap", "3389", pids.get("🖥️ RDP Trap")),
        ("📁 SMB Trap", "445", pids.get("📁 SMB Trap")),
        ("🌐 DNS Trap", "53", pids.get("🌐 DNS Trap")),
        ("📞 SIP Trap", "5060", pids.get("📞 SIP Trap")),
        ("🔴 Redis Trap", "6379", pids.get("🔴 Redis Trap")),
        ("🖥️ VNC Trap", "5900", pids.get("🖥️ VNC Trap")),
        ("📟 Telnet Trap", "23", pids.get("📟 Telnet Trap")),
        ("📦 Memcached Trap", "11211", pids.get("📦 Memcached Trap")),
        ("📡 MQTT Trap", "1883", pids.get("📡 MQTT Trap")),
        ("🌐 SNMP Trap", "161", pids.get("🌐 SNMP Trap")),
        ("🕐 NTP Trap", "123", pids.get("🕐 NTP Trap")),
    ]

    print(f"\n  {'='*60}")
    print(f"  📊 HONEYPOT LAB - Status Report")
    print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {'='*60}\n")

    any_running = False
    for name, port, pid in honeypots:
        pid = pid or 0
        running = (pid > 0 and check_process(name, pid)) or check_port(port)
        if running: any_running = True
        print(fmt_row(name, running, port, f"PID {pid}" if pid else ""))

    print(f"\n  {'─'*60}")
    if any_running:
        print(f"  ✅ Some honeypots are active")
        print(f"  🛑  Stop all: python stop_all.py")
    else:
        print(f"  ⏹️   All honeypots are stopped")
        print(f"  ▶️   Start: python start_all.py")
    print(f"  {'='*60}\n")

if __name__ == "__main__":
    main()
