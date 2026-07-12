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
HoneyPot Lab - Start All Honeypots (17 types + Features)
Launches each enabled honeypot as a background process, plus feature modules.
"""
import os, sys, subprocess, configparser, time, signal, threading, re

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
HONEYPOTS_DIR = os.path.join(LAB_DIR, "honeypots")
LOGS_DIR = os.path.join(LAB_DIR, "logs")
PROCESSES = {}

def load_config():
    config = configparser.ConfigParser()
    config.read(os.path.join(LAB_DIR, "config.ini"))
    return config

def is_enabled(config, key):
    return config.get("general", key, fallback="yes").lower() == "yes"

def get_port(config, key, default):
    return config.get("ports", key, fallback=str(default))

def start_script(config, enable_key, script_rel, name, log_subdir, log_name):
    if not is_enabled(config, enable_key):
        return None
    log_dir = os.path.join(LOGS_DIR, log_subdir)
    os.makedirs(log_dir, exist_ok=True)
    log_file = open(os.path.join(log_dir, log_name), "ab", 0)
    script_path = os.path.join(HONEYPOTS_DIR, script_rel)
    proc = subprocess.Popen([sys.executable, script_path], stdout=log_file, stderr=subprocess.STDOUT)
    return proc

# === HONEYPOT STARTERS ===
def start_cowrie(config):
    if not is_enabled(config, "enable_ssh_cowrie"): return None
    port = get_port(config, "ssh_port", 2222)
    cfg_dir = os.path.join(HONEYPOTS_DIR, "01_ssh_cowrie")
    os.makedirs(os.path.join(cfg_dir, "data"), exist_ok=True)

    # Cowrie requires its config at ./etc/cowrie.cfg relative to cwd.
    # Our lab keeps a flat cowrie.cfg; sync it into etc/ and apply the
    # configured port so config.ini stays the single source of truth.
    etc_dir = os.path.join(cfg_dir, "etc")
    os.makedirs(etc_dir, exist_ok=True)
    cfg_src = os.path.join(cfg_dir, "cowrie.cfg")
    cfg_dst = os.path.join(etc_dir, "cowrie.cfg")
    if os.path.exists(cfg_src):
        with open(cfg_src, encoding="utf-8") as f:
            cfg_text = f.read()
        cfg_text = re.sub(r"listen_endpoints\s*=\s*tcp:\d+", f"listen_endpoints = tcp:{port}", cfg_text)
        with open(cfg_dst, "w", encoding="utf-8") as f:
            f.write(cfg_text)

    # cowrie's own CLI wrapper passes --umask to twistd, which the Windows
    # build of twistd doesn't support, and its os.execvp() re-exec relies on
    # "twistd" being resolvable via PATH. Invoke twistd directly instead so
    # this works cross-platform and keeps the process trackable for stop_all.py.
    venv_scripts = os.path.dirname(sys.executable)
    twistd_bin = os.path.join(venv_scripts, "twistd.exe" if os.name == "nt" else "twistd")
    log_file = open(os.path.join(LOGS_DIR, "ssh", "cowrie_stdout.log"), "ab", 0)
    env = {
        **os.environ,
        "COWRIE_DATA_DIR": os.path.join(cfg_dir, "data"),
        "PATH": venv_scripts + os.pathsep + os.environ.get("PATH", ""),
    }
    proc = subprocess.Popen([twistd_bin, "-n", "-l", "-", "cowrie"], cwd=cfg_dir, stdout=log_file, stderr=subprocess.STDOUT, env=env)
    return proc

def start_ics(config):
    return start_script(config, "enable_ics_conpot", "02_ics_conpot/ics_honeypot.py", "🏭 ICS/SCADA", "ics", "ics_stdout.log")

def start_creds(config):
    return start_script(config, "enable_creds_heralding", "03_creds_heralding/cred_traps.py", "🔑 Credential Capture", "creds", "cred_traps_stdout.log")

def start_web(config):
    return start_script(config, "enable_web_traps", "04_web_traps/web_traps.py", "🌐 Web Traps", "web", "web_traps_stdout.log")

def start_db(config):
    return start_script(config, "enable_db_traps", "05_db_traps/db_traps.py", "🗄️ DB Traps", "db", "db_traps_stdout.log")

def start_malware(config):
    return start_script(config, "enable_malware_capture", "06_malware_capture/malware_capture.py", "🦠 Malware Capture", "malware", "malware_stdout.log")

def start_rdp(config):
    return start_script(config, "enable_rdp_trap", "07_rdp_trap/rdp_trap.py", "🖥️ RDP Trap", "rdp", "rdp_stdout.log")

# === NEW HONEYPOT STARTERS (8-17) ===
def start_smb(config):
    return start_script(config, "enable_smb", "08_smb/smb_trap.py", "📁 SMB Trap", "smb", "smb_stdout.log")

def start_dns(config):
    return start_script(config, "enable_dns", "09_dns/dns_trap.py", "🌐 DNS Trap", "dns", "dns_stdout.log")

def start_sip(config):
    return start_script(config, "enable_sip", "10_sip/sip_trap.py", "📞 SIP Trap", "sip", "sip_stdout.log")

def start_redis(config):
    return start_script(config, "enable_redis", "11_redis/redis_trap.py", "🔴 Redis Trap", "redis", "redis_stdout.log")

def start_vnc(config):
    return start_script(config, "enable_vnc", "12_vnc/vnc_trap.py", "🖥️ VNC Trap", "vnc", "vnc_stdout.log")

def start_telnet(config):
    return start_script(config, "enable_telnet", "13_telnet/telnet_trap.py", "📟 Telnet Trap", "telnet", "telnet_stdout.log")

def start_memcached(config):
    return start_script(config, "enable_memcached", "14_memcached/memcached_trap.py", "📦 Memcached Trap", "memcached", "memcached_stdout.log")

def start_mqtt(config):
    return start_script(config, "enable_mqtt", "15_mqtt/mqtt_trap.py", "📡 MQTT Trap", "mqtt", "mqtt_stdout.log")

def start_snmp(config):
    return start_script(config, "enable_snmp", "16_snmp/snmp_trap.py", "🌐 SNMP Trap", "snmp", "snmp_stdout.log")

def start_ntp(config):
    return start_script(config, "enable_ntp", "17_ntp/ntp_trap.py", "🕐 NTP Trap", "ntp", "ntp_stdout.log")

# === FEATURES ===
def start_features(config):
    started = []
    if is_enabled(config, "enable_log_rotation"):
        try:
            sys.path.insert(0, LAB_DIR)
            import importlib
            rot = importlib.import_module("features.log_rotation")
            rot.start_background()
            started.append("📦 Log Rotation")
        except Exception as e:
            print(f"  ⚠️  Features: Log rotation failed: {e}")
    if is_enabled(config, "enable_geoip"):
        started.append("🌍 GeoIP Tracking")
    if is_enabled(config, "enable_notifications") or config.get("general", "telegram_alerts", fallback="no").lower() == "yes":
        started.append("🔔 Notifications")
    return started

def save_pids(processes):
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    with open(pid_path, "w", encoding="utf-8") as f:
        for name, proc in processes.items():
            if proc and proc.poll() is None:
                f.write(f"{name}:{proc.pid}\n")

def main():
    config = load_config()
    print("=" * 65)
    print("  🍯  HONEYPOT LAB v2.0 — All 17 Honeypots + Features  ")
    print("  Developed by JOJIN JOHN")
    print("=" * 65)

    starters = [
        ("🐚  Cowrie (SSH/Telnet)", start_cowrie),
        ("🏭  ICS/SCADA (Modbus/S7/BACnet)", start_ics),
        ("🔑  Credential Capture (FTP/SMTP/POP3/HTTP/MySQL)", start_creds),
        ("🌐  Web Traps (WordPress/Admin/API)", start_web),
        ("🗄️  DB Traps (Elasticsearch/MongoDB)", start_db),
        ("🦠  Malware Capture (HTTP/TFTP)", start_malware),
        ("🖥️  RDP Trap", start_rdp),
        ("📁  SMB Trap (EternalBlue/WannaCry)", start_smb),
        ("🌐  DNS Trap", start_dns),
        ("📞  SIP Trap (VoIP)", start_sip),
        ("🔴  Redis Trap", start_redis),
        ("🖥️  VNC Trap", start_vnc),
        ("📟  Telnet Trap (IoT/Mirai)", start_telnet),
        ("📦  Memcached Trap (DDoS amp)", start_memcached),
        ("📡  MQTT Trap (IoT)", start_mqtt),
        ("🌐  SNMP Trap", start_snmp),
        ("🕐  NTP Trap (DDoS amp)", start_ntp),
    ]

    success_count = 0
    for label, starter in starters:
        try:
            proc = starter(config)
            if proc:
                name = label.split("(")[0].strip()
                PROCESSES[name] = proc
                print(f"  ✅ {label}")
                success_count += 1
            else:
                print(f"  ⏭️  {label} — disabled")
        except Exception as e:
            print(f"  ❌ {label} — FAILED: {e}")

    # Start features
    print(f"\n  {'─'*55}")
    print(f"  ⚙️  Features:")
    feat_list = start_features(config)
    if feat_list:
        for f in feat_list:
            print(f"     ✅ {f}")
    else:
        print(f"     ℹ️  All features disabled in config")

    save_pids(PROCESSES)
    print(f"\n  {'='*55}")
    print(f"  ✅ {success_count}/17 honeypots running")
    print(f"  📁 Logs: {LOGS_DIR}")
    print(f"  📊 Dashboard: http://localhost:5000")
    print(f"  🎯 Test:     python tools/test_scanner.py")
    print(f"  📈 Analyze:  python tools/analyzer.py")
    print(f"  🛑  Stop:     python stop_all.py")
    print(f"  {'='*55}")

if __name__ == "__main__":
    main()
