#!/usr/bin/env python3
"""
HoneyPot Lab - Start All Honeypots
Launches each enabled honeypot as a background process.
"""
import os
import sys
import subprocess
import configparser
import time
import signal

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
HONEYPOTS_DIR = os.path.join(LAB_DIR, "honeypots")
LOGS_DIR = os.path.join(LAB_DIR, "logs")

PROCESSES = {}

def load_config():
    config = configparser.ConfigParser()
    config_path = os.path.join(LAB_DIR, "config.ini")
    config.read(config_path)
    return config

def start_cowrie(config):
    """SSH/Telnet honeypot - Cowrie"""
    if config.get("general", "enable_ssh_cowrie", fallback="yes").lower() != "yes":
        return None
    port = config.get("ports", "ssh_port", fallback="2222")
    log_file = open(os.path.join(LOGS_DIR, "ssh", "cowrie_stdout.log"), "ab", 0)
    cfg_dir = os.path.join(HONEYPOTS_DIR, "01_ssh_cowrie")

    # Cowrie needs a data directory
    data_dir = os.path.join(cfg_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    proc = subprocess.Popen(
        [sys.executable, "-m", "cowrie", "start", f"--port={port}"],
        cwd=cfg_dir,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={**os.environ, "COWRIE_DATA_DIR": data_dir}
    )
    return proc

def start_conpot(config):
    """ICS/SCADA honeypot - Custom Python (cross-platform)"""
    if config.get("general", "enable_ics_conpot", fallback="yes").lower() != "yes":
        return None
    log_file = open(os.path.join(LOGS_DIR, "ics", "ics_honeypot_stdout.log"), "ab", 0)
    script_path = os.path.join(HONEYPOTS_DIR, "02_ics_conpot", "ics_honeypot.py")

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    return proc

def start_heralding(config):
    """Credential capture honeypot - Custom Python (cross-platform)"""
    if config.get("general", "enable_creds_heralding", fallback="yes").lower() != "yes":
        return None
    log_file = open(os.path.join(LOGS_DIR, "creds", "cred_traps_stdout.log"), "ab", 0)
    script_path = os.path.join(HONEYPOTS_DIR, "03_creds_heralding", "cred_traps.py")

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    return proc

def start_web_traps(config):
    """Web honeypots - WordPress + Generic + Admin traps"""
    if config.get("general", "enable_web_traps", fallback="yes").lower() != "yes":
        return None
    log_file = open(os.path.join(LOGS_DIR, "web", "web_traps_stdout.log"), "ab", 0)
    script_path = os.path.join(HONEYPOTS_DIR, "04_web_traps", "web_traps.py")

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    return proc

def start_db_traps(config):
    """Database honeypots - Elasticsearch + MongoDB"""
    if config.get("general", "enable_db_traps", fallback="yes").lower() != "yes":
        return None
    log_file = open(os.path.join(LOGS_DIR, "db", "db_traps_stdout.log"), "ab", 0)
    script_path = os.path.join(HONEYPOTS_DIR, "05_db_traps", "db_traps.py")

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    return proc

def start_malware_capture(config):
    """Malware capture honeypot"""
    if config.get("general", "enable_malware_capture", fallback="yes").lower() != "yes":
        return None
    log_file = open(os.path.join(LOGS_DIR, "malware", "malware_capture_stdout.log"), "ab", 0)
    script_path = os.path.join(HONEYPOTS_DIR, "06_malware_capture", "malware_capture.py")

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    return proc

def start_rdp_trap(config):
    """RDP honeypot"""
    if config.get("general", "enable_rdp_trap", fallback="yes").lower() != "yes":
        return None
    log_file = open(os.path.join(LOGS_DIR, "rdp", "rdp_trap_stdout.log"), "ab", 0)
    script_path = os.path.join(HONEYPOTS_DIR, "07_rdp_trap", "rdp_trap.py")

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    return proc

def save_pids(processes):
    """Save PIDs so stop_all.py can kill them"""
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    with open(pid_path, "w") as f:
        for name, proc in processes.items():
            if proc and proc.poll() is None:
                f.write(f"{name}:{proc.pid}\n")

def main():
    config = load_config()
    print("=" * 60)
    print("  🍯  HONEYPOT LAB - Starting All Honeypots  ")
    print("=" * 60)

    starters = [
        ("🐚  Cowrie (SSH/Telnet)", start_cowrie),
        ("🏭  Conpot (ICS/SCADA)", start_conpot),
        ("🔑  Heralding (Credential Capture)", start_heralding),
        ("🌐  Web Traps (WordPress + Admin + API)", start_web_traps),
        ("🗄️  DB Traps (Elasticsearch + MongoDB)", start_db_traps),
        ("🦠  Malware Capture (HTTP/TFTP)", start_malware_capture),
        ("🖥️  RDP Trap", start_rdp_trap),
    ]

    success_count = 0
    for label, starter in starters:
        try:
            proc = starter(config)
            if proc:
                name = label.split("(")[0].strip()
                PROCESSES[name] = proc
                print(f"  ✅ {label} — PID {proc.pid}")
                success_count += 1
            else:
                print(f"  ⏭️  {label} — disabled in config")
        except Exception as e:
            print(f"  ❌ {label} — FAILED: {e}")

    save_pids(PROCESSES)
    print("-" * 60)
    print(f"  ✅ {success_count} honeypots running")
    print(f"  📁 Logs: {LOGS_DIR}")
    print(f"  📊 Dashboard: python dashboard.py")
    print(f"  🛑  Stop: python stop_all.py")
    print("=" * 60)

if __name__ == "__main__":
    main()
