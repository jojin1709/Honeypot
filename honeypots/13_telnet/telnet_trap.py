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

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
LOG_DIR = os.path.join(LAB_DIR, "logs", "telnet")
os.makedirs(LOG_DIR, exist_ok=True)

class TelnetTrap:
    def __init__(self, host="0.0.0.0", port=23):
        self.host, self.port, self.running = host, port, False; self.server = None
    def handle(self, conn, addr):
        client_ip = addr[0]
        try:
            conn.settimeout(30); data = conn.recv(4096)
            if not data: return
            ts = datetime.datetime.now().isoformat()
            entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "Telnet-IoT", "data": data.decode(errors="replace")[:500]}
            with open(os.path.join(LOG_DIR, "telnet_attempts.jsonl"), "a", encoding="utf-8") as f: f.write(json.dumps(entry)+"\n")
            print(f"  📟 Telnet | {ts[:19]} | {client_ip:>15} | {data.decode(errors='replace')[:60].strip()}")
            conn.send(b"\r\nBusyBox v1.30.1 login: ")
        except: pass
        finally: conn.close()
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port)); self.server.listen(50); self.server.settimeout(1); self.running = True
            print(f"  📟 Telnet trap on port {self.port} (IoT/Mirai)")
            def s():
                while self.running:
                    try: conn, addr = self.server.accept(); threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout: continue
            threading.Thread(target=s, daemon=True).start()
        except Exception as e: print(f"  ❌ Telnet trap failed: {e}")
    def stop(self):
        self.running = False
        if self.server: self.server.close()

if __name__ == "__main__":
    print("="*50); t = TelnetTrap(); t.start(); print(f"  📁 Logs: {LOG_DIR}"); print("="*50)
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt: print("\n  🛑  Stopping..."); t.stop()
