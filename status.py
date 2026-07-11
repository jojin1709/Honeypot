#!/usr/bin/env python3
"""
HoneyPot Lab - Status Check
Shows which honeypots are currently running.
"""
import os
import sys
import signal

LAB_DIR = os.path.dirname(os.path.abspath(__file__))

def check_process(name, pid):
    """Check if a process with given PID is running"""
    try:
        os.kill(pid, 0)  # Signal 0 checks existence
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Running but we can't signal it
    except:
        return False

def check_port(port):
    """Check if a port is in use (simple TCP connect check)"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", int(port)))
        sock.close()
        return result == 0
    except:
        return False

def format_row(name, status, port, pid=""):
    """Format a status row"""
    icon = "🟢" if status else "🔴"
    status_text = "RUNNING" if status else "STOPPED"
    pid_info = f"PID {pid}" if pid else ""
    return f"  {icon}  {name:<30} {status_text:<10} Port {str(port):<8} {pid_info}"

def main():
    print("=" * 60)
    print("  📊 HONEYPOT LAB - Status Report")
    print(f"  {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Load PIDs
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    pids = {}
    if os.path.exists(pid_path):
        with open(pid_path) as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    name, pid = line.split(":", 1)
                    pids[name.strip()] = int(pid.strip())

    honeypots = [
        ("🐚 Cowrie (SSH)", "2222", pids.get("🐚 Cowrie")),
        ("🏭 Conpot (ICS/SCADA)", "502", pids.get("🏭 Conpot")),
        ("🔑 Heralding (Creds)", "21", pids.get("🔑 Heralding")),
        ("🌐 Web Traps", "80", pids.get("🌐 Web Traps")),
        ("🗄️ DB Traps", "9200", pids.get("🗄️ DB Traps")),
        ("🦠 Malware Capture", "8888", pids.get("🦠 Malware Capture")),
        ("🖥️ RDP Trap", "3389", pids.get("🖥️ RDP Trap")),
    ]

    any_running = False
    for name, port, pid in honeypots:
        pid = pid or 0
        running_pid = pid > 0 and check_process(name, pid)
        port_open = check_port(port)

        if port_open or running_pid:
            any_running = True
            print(format_row(name, True, port, str(pid)))
        else:
            print(format_row(name, False, port))

    print("-" * 60)
    if any_running:
        print("  ✅ Some honeypots are active")
        print("  🛑  Stop all: python stop_all.py")
    else:
        print("  ⏹️   All honeypots are stopped")
        print("  ▶️   Start: python start_all.py")
    print("=" * 60)

if __name__ == "__main__":
    main()
