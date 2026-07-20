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
SMB/CIFS Honeypot — Emulates Windows file sharing (port 445)
Captures EternalBlue scans, WannaCry probes, and SMB enumeration.
"""
import os, sys, json, socket, struct, datetime, threading
import sys as _sys2; _sys2.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')); from alert_helper import log_alert

LAB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(LAB_DIR, "logs", "smb")
os.makedirs(LOG_DIR, exist_ok=True)

SMB_NEGOTIATE_PROTOCOL = bytes([
    0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02,
    0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
    0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
    0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
    0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46,
    0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52,
    0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x33, 0x00,
    0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f,
    0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
    0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00,
    0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31,
    0x2e, 0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e,
    0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x44,
    0x4f, 0x53, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x55,
    0x4e, 0x58, 0x00,
])

class SMBTrap:
    def __init__(self, host="0.0.0.0", port=445):
        self.host, self.port, self.running = host, port, False
        self.server = None
    def log(self, client_ip, data, note=""):
        ts = datetime.datetime.now().isoformat()
        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "SMB", "data_length": len(data), "data_hex": data[:300].hex(), "note": note}
        with open(os.path.join(LOG_DIR, "smb_probes.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"  📁 SMB | {ts[:19]} | {client_ip:>15} | {len(data)} bytes {note}")
    def handle(self, conn, addr):
        client_ip = addr[0]
        try:
            conn.settimeout(30)
            data = conn.recv(4096)
            if not data: return
            if b"\xffSMB" in data[:4] or b"\xfeSMB" in data[:4]:
                self.log(client_ip, data
            log_alert("smb", client_ip, note), "[SMBv1/EternalBlue probe]")
            elif b"\x00\x00\x00" in data[:4]:
                self.log(client_ip, data, "[NetBIOS/SMB session request]")
            else:
                self.log(client_ip, data)
            # Respond with SMB Negotiate Protocol Response
            conn.send(SMB_NEGOTIATE_PROTOCOL)
        except: pass
        finally: conn.close()
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50)
            self.server.settimeout(1)
            self.running = True
            print(f"  📁 SMB trap on port {self.port} (EternalBlue/WannaCry)")
            threading.Thread(target=lambda: [self.handle(*a) for a in iter(lambda: (lambda: self.server.accept())(), None) if self.running and (self.handle(*a) or 1)] if False else None, daemon=True).start()
            def serve():
                while self.running:
                    try:
                        conn, addr = self.server.accept()
                        threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e:
            print(f"  ❌ SMB trap failed: {e}")
    def stop(self):
        self.running = False
        if self.server: self.server.close()

if __name__ == "__main__":
    print("=" * 50)
    t = SMBTrap()
    t.start()
    print(f"  📁 SMB trap active — logs: {LOG_DIR}")
    print("  (Captures EternalBlue, WannaCry, SMB scans)")
    print("=" * 50)
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt:
        print("\n  🛑  Stopping SMB trap..."); t.stop(); print("  ✅ Done")
