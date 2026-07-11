#!/usr/bin/env python3
"""
HoneyPot Lab - Stop All Honeypots
Gracefully stops all running honeypot processes.
"""
import os
import sys
import signal

LAB_DIR = os.path.dirname(os.path.abspath(__file__))

def load_pids():
    """Load saved PIDs from file"""
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    if not os.path.exists(pid_path):
        return {}
    pids = {}
    with open(pid_path) as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                name, pid = line.split(":", 1)
                pids[name.strip()] = int(pid.strip())
    return pids

def find_python_processes():
    """Also find honeypot processes not saved in PID file"""
    import subprocess
    proc = subprocess.run(
        [sys.executable, "-c", """
import psutil, sys
for p in psutil.process_iter(['pid', 'name', 'cmdline']):
    try:
        cmdline = ' '.join(p.info['cmdline'] or [])
        if sys.argv[1] in cmdline:
            print(f"{p.info['pid']}")
    except:
        pass
"""],
        capture_output=True, text=True, timeout=10
    )
    return proc.stdout.strip().splitlines()

def main():
    print("=" * 60)
    print("  🛑  HONEYPOT LAB - Stopping All Honeypots  ")
    print("=" * 60)

    pids = load_pids()
    killed = 0

    # Kill by saved PIDs
    for name, pid in pids.items():
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"  ✅ Stopped {name} (PID {pid})")
            killed += 1
        except ProcessLookupError:
            print(f"  ⚠️  {name} (PID {pid}) — already stopped")
        except Exception as e:
            print(f"  ❌ {name} (PID {pid}) — error: {e}")

    # Clean up PID file
    pid_path = os.path.join(LAB_DIR, ".honeypot_pids")
    if os.path.exists(pid_path):
        os.remove(pid_path)

    # Also try to kill any lingering cowrie/conpot/heralding processes
    import subprocess
    for proc_name in ["cowrie", "conpot", "heralding", "web_traps", "db_traps", "malware_capture", "rdp_trap"]:
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", f"{proc_name}.exe", "/FI", "STATUS eq RUNNING"],
                capture_output=True, text=True, timeout=5
            )
            # Also try python processes with these names in cmdline
            result2 = subprocess.run(
                ["taskkill", "/F", "/IM", "python.exe", "/FI", f"CMDLINE like '%{proc_name}%'"],
                capture_output=True, text=True, timeout=5
            )
        except:
            pass

    print("-" * 60)
    print(f"  ✅ {killed} processes stopped")
    print("=" * 60)

if __name__ == "__main__":
    main()
