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
SIP/VoIP Honeypot — Captures SIP scanning, registration attempts, and call invites.
"""
import os, sys, json, socket, datetime, threading
import sys as _sys2; _sys2.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')); from alert_helper import log_alert

LAB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(LAB_DIR, "logs", "sip")
os.makedirs(LOG_DIR, exist_ok=True)

class SIPTrap:
    def __init__(self, host="0.0.0.0", port=5060):
        self.host, self.port, self.running = host, port, False
        self.sock = None
    def log(self, client_ip, method, uri, data):
        ts = datetime.datetime.now().isoformat()
        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "SIP", "method": method, "uri": uri, "raw": data[:500].decode(errors="replace")}
        with open(os.path.join(LOG_DIR, "sip_attempts.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"  📞 SIP | {ts[:19]} | {client_ip:>15} | {method} {uri}")
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1)
            self.running = True
            print(f"  📞 SIP trap on port {self.port} (UDP)")
            def serve():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(65535)
                        client_ip = addr[0]
                        text = data.decode("utf-8", errors="replace")
                        first_line = text.split("\r\n")[0] if text else ""
                        parts = first_line.split(" ")
                        method = parts[0] if len(parts) > 0 else "UNKNOWN"
                        uri = parts[1] if len(parts) > 1 else ""
                        self.log(client_ip, method
            log_alert("sip", client_ip, f"{method} {uri}"), uri, data)
                        # Send fake SIP response
                        resp = f"SIP/2.0 200 OK\r\nVia: {first_line}\r\nFrom: <sip:trap@lab>;tag=1234\r\nTo: <{uri}>\r\nCall-ID: trap\r\nCSeq: 1 INVITE\r\nContact: <sip:trap@127.0.0.1>\r\nContent-Length: 0\r\n\r\n"
                        self.sock.sendto(resp.encode(), addr)
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e: print(f"  ❌ SIP trap failed: {e}")
    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

if __name__ == "__main__":
    print("=" * 50)
    t = SIPTrap()
    t.start()
    print(f"  📞 SIP trap active — logs: {LOG_DIR}")
    print("  (Captures SIP scans, registration, call invites)")
    print("=" * 50)
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt: print("\n  🛑  Stopping..."); t.stop(); print("  ✅ Done")
