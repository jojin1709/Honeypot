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
import os, sys, json, socket, datetime, threading
import sys as _sys2; _sys2.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')); from alert_helper import log_alert

LAB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(LAB_DIR, "logs", "memcached")
os.makedirs(LOG_DIR, exist_ok=True)

class MemcachedTrap:
    def __init__(self, host="0.0.0.0", port=11211):
        self.host, self.port, self.running = host, port, False; self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port)); self.sock.settimeout(1); self.running = True
            print(f"
            log_alert("memcached", client_ip, "probe")  📦 Memcached trap on port {self.port} (DDoS amp)")
            def s():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(4096); client_ip = addr[0]
                        ts = datetime.datetime.now().isoformat()
                        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "Memcached", "data_length": len(data)}
                        with open(os.path.join(LOG_DIR, "memcached_probes.jsonl"), "a", encoding="utf-8") as f: f.write(json.dumps(entry)+"\n")
                        print(f"  📦 Memcache | {ts[:19]} | {client_ip:>15}")
                        self.sock.sendto(b"STAT pid 1\r\nSTAT uptime 99999\r\nSTAT version 1.6.18\r\nSTAT curr_items 999999\r\nSTAT total_items 9999999\r\nSTAT bytes 999999999\r\nEND\r\n", addr)
                    except socket.timeout: continue
            threading.Thread(target=s, daemon=True).start()
        except Exception as e: print(f"  ❌ Memcached trap failed: {e}")
    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

if __name__ == "__main__":
    print("="*50); t = MemcachedTrap(); t.start(); print(f"  📁 Logs: {LOG_DIR}"); print("="*50)
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt: print("\n  🛑  Stopping..."); t.stop()
