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
Red Team: Honeypot Lab Scanner
Scan your own honeypots to test they're working.
Simulates attacker behavior against your own traps.
"""
import os
import sys
import json
import time
import socket
import datetime
import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError

LAB_DIR = os.path.dirname(os.path.abspath(__file__))

TARGETS = {
    "SSH (Cowrie)": {"host": "127.0.0.1", "port": 2222, "protocol": "tcp"},
    "HTTP Web Trap": {"host": "127.0.0.1", "port": 80, "protocol": "http"},
    "Admin Panel": {"host": "127.0.0.1", "port": 8081, "protocol": "http"},
    "API Gateway": {"host": "127.0.0.1", "port": 8082, "protocol": "http"},
    "Elasticsearch": {"host": "127.0.0.1", "port": 9200, "protocol": "http"},
    "MongoDB": {"host": "127.0.0.1", "port": 27017, "protocol": "tcp"},
    "HTTP Malware Trap": {"host": "127.0.0.1", "port": 8888, "protocol": "http"},
    "Modbus (Conpot)": {"host": "127.0.0.1", "port": 502, "protocol": "tcp"},
    "S7 (Conpot)": {"host": "127.0.0.1", "port": 102, "protocol": "tcp"},
    "FTP (Heralding)": {"host": "127.0.0.1", "port": 21, "protocol": "tcp"},
    "SMTP (Heralding)": {"host": "127.0.0.1", "port": 25, "protocol": "tcp"},
    "RDP Trap": {"host": "127.0.0.1", "port": 3389, "protocol": "tcp"},
}


def check_tcp_port(host, port, timeout=2):
    """Test if a TCP port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_all():
    """Scan all honeypot ports"""
    print("=" * 60)
    print("  🎯 HONEYPOT LAB - Port Scan Test")
    print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"  Scanning {len(TARGETS)} honeypot endpoints...\n")

    open_ports = 0
    closed_ports = 0

    for name, target in sorted(TARGETS.items()):
        is_open = check_tcp_port(target["host"], target["port"])
        icon = "🟢" if is_open else "🔴"
        status = "OPEN  " if is_open else "CLOSED"

        if is_open:
            open_ports += 1
        else:
            closed_ports += 1

        print(f"  {icon} {name:<25} {target['host']:>12}:{target['port']:<5} {status}")

    print(f"\n  {'=' * 56}")
    print(f"  ✅  {open_ports} honeypots are listening")
    print(f"  ❌  {closed_ports} honeypots are down")
    print(f"  {'=' * 56}")
    return open_ports


def http_probe(url, path="/"):
    """Send HTTP request and check response"""
    try:
        req = Request(f"http://{url}:{path}", method="GET",
                      headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        resp = urlopen(req, timeout=3)
        return resp.status, len(resp.read())
    except Exception as e:
        return None, str(e)


def simulate_ssh_brute():
    """Simulate SSH brute force (using paramiko)"""
    print("\n  🔐 Simulating SSH brute force attack...")
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        creds = [
            ("root", "admin"),
            ("root", "123456"),
            ("admin", "admin"),
            ("user", "password"),
        ]

        for username, password in creds:
            try:
                client.connect("127.0.0.1", port=2222, username=username,
                               password=password, timeout=3)
                print(f"  ✅ SSH login SUCCESS: {username}:{password}")
                client.close()
                break
            except paramiko.AuthenticationException:
                print(f"  ❌ SSH login FAILED: {username}:{password}")
            except Exception as e:
                print(f"  ⚠️  SSH error: {e}")
    except ImportError:
        print("  ⚠️  paramiko not installed. Install with: pip install paramiko")


def simulate_web_attacks():
    """Simulate web attacks against web traps"""
    print("\n  🌐 Simulating web attacks...")
    attacks = [
        ("WordPress login", "http://127.0.0.1/wp-login.php",
         "POST", b"log=admin&pwd=test123"),
        ("Admin panel", "http://127.0.0.1:8081/admin",
         "GET", None),
        ("API probe", "http://127.0.0.1:8082/api/users",
         "GET", None),
        ("phpMyAdmin scan", "http://127.0.0.1/phpmyadmin",
         "GET", None),
        ("GraphQL probe", "http://127.0.0.1:8082/graphql",
         "GET", None),
        ("Malware upload test", "http://127.0.0.1:8888/upload",
         "GET", None),
        ("Config leak test", "http://127.0.0.1:8888/.env",
         "GET", None),
        ("Shell probe", "http://127.0.0.1:8888/shell?cmd=whoami",
         "GET", None),
    ]

    for name, url, method, body in attacks:
        try:
            data = body if body else None
            req = Request(url, data=data, method=method)
            req.add_header("User-Agent",
                           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            resp = urlopen(req, timeout=3)
            print(f"  🌐 {name:<25} ✅ {resp.status} ({len(resp.read())} bytes)")
        except URLError as e:
            print(f"  🌐 {name:<25} ❌ {e.reason}")
        except Exception as e:
            print(f"  🌐 {name:<25} ⚠️  {e}")


def simulate_db_probes():
    """Simulate database probes"""
    print("\n  🗄️  Simulating database probes...")

    # Elasticsearch probes
    es_paths = ["/", "/_cluster/health", "/_search?q=*",
                "/_cat/indices", "/production/_search"]
    for path in es_paths:
        try:
            req = Request(f"http://127.0.0.1:9200{path}")
            resp = urlopen(req, timeout=3)
            print(f"  🗄️  ES {path:<30} ✅ {resp.status}")
        except Exception as e:
            print(f"  🗄️  ES {path:<30} ❌ {e}")

    # MongoDB probe (raw TCP)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("127.0.0.1", 27017))
        # Send MongoDB wire protocol "isMaster" command (simplified)
        sock.send(b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
                  b"\x00\x00\x00\x00\x00\x00\x00\x00s\x00\x00\x00\x10isMaster\x00\x01"
                  b"\x00\x00\x00\x00")
        sock.close()
        print(f"  🗄️  MongoDB probe                    ✅ Connected")
    except Exception as e:
        print(f"  🗄️  MongoDB probe                    ❌ {e}")


def simulate_rdp_scan():
    """Simulate RDP connection attempt"""
    print("\n  🖥️  Simulating RDP connection...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("127.0.0.1", 3389))
        # Send RDP Connection Request
        sock.send(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00")
        sock.close()
        print(f"  🖥️  RDP Connection                    ✅ Connected")
    except Exception as e:
        print(f"  🖥️  RDP Connection                    ❌ {e}")


def simulate_ics_probes():
    """Simulate ICS/SCADA probes"""
    print("\n  🏭  Simulating ICS/SCADA probes...")

    # Modbus probe
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("127.0.0.1", 502))
        # Modbus Read Holding Registers request
        sock.send(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01")
        sock.close()
        print(f"  🏭  Modbus probe                      ✅ Connected")
    except Exception as e:
        print(f"  🏭  Modbus probe                      ❌ {e}")

    # S7 probe
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(("127.0.0.1", 102))
        sock.close()
        print(f"  🏭  S7 (Siemens) probe                ✅ Connected")
    except Exception as e:
        print(f"  🏭  S7 (Siemens) probe                ❌ {e}")


def main():
    print("🎯 HONEYPOT LAB - Red Team Test Suite")
    print("   Testing your own honeypots like an attacker would\n")

    choice = input("Select test:\n"
                   "  1) Quick scan (ports only)\n"
                   "  2) Full attack simulation (port scan + web + SSH + DB + ICS + RDP)\n"
                   "  3) Web attacks only\n"
                   "  4) ICS/SCADA probes only\n"
                   "  Choice [1-4]: ").strip()

    if choice == "1":
        scan_all()
    elif choice == "2":
        scan_all()
        simulate_web_attacks()
        simulate_ssh_brute()
        simulate_db_probes()
        simulate_ics_probes()
        simulate_rdp_scan()
    elif choice == "3":
        simulate_web_attacks()
    elif choice == "4":
        simulate_ics_probes()
    else:
        print("Invalid choice")

    print("\n✅ Test complete! Check the dashboard or log files for captured data.")


if __name__ == "__main__":
    main()
