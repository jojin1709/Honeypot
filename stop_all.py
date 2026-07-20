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
HoneyPot Lab - Stop All Honeypots (17 types + Features)
"""
import os, sys, signal, subprocess

LAB_DIR = os.path.dirname(os.path.abspath(__file__))

def load_pids():
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    if not os.path.exists(pid_path): return {}
    pids = {}
    with open(pid_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                name, pid = line.split(":", 1)
                pids[name.strip()] = int(pid.strip())
    return pids

def kill_proc_by_name(name):
    """Kill processes by their command-line containing name"""
    try:
        if os.name == "nt":  # Windows
            subprocess.run(["taskkill", "/F", "/IM", "python.exe", "/FI", f"CMDLINE like '%{name}%'"], capture_output=True, timeout=5)
        else:  # Linux/Kali
            subprocess.run(["pkill", "-f", name], capture_output=True, timeout=5)
    except: pass

def main():
    print("=" * 60)
    print("  🛑  HONEYPOT LAB - Stopping All Honeypots  ")
    print("=" * 60)

    pids = load_pids()
    killed = 0

    for name, pid in pids.items():
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"  ✅ Stopped {name} (PID {pid})")
            killed += 1
        except (ProcessLookupError, OSError):
            print(f"  ℹ️  {name} — will be cleaned up by fallback sweep")

    # Clean up PID file
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    if os.path.exists(pid_path):
        os.remove(pid_path)

    # Aggressive kill of all honeypot Python processes
    honeypot_names = ["cowrie", "ics_honeypot", "cred_traps", "web_traps", "db_traps", "malware_capture", "rdp_trap", "smb_trap", "dns_trap", "sip_trap", "redis_trap", "vnc_trap", "telnet_trap", "memcached_trap", "mqtt_trap", "snmp_trap", "ntp_trap", "all_traps"]
    for name in honeypot_names:
        kill_proc_by_name(name)

    print("-" * 60)
    print(f"  ✅ {killed} processes stopped")
    print("=" * 60)

if __name__ == "__main__":
    main()
