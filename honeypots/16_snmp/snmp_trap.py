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
LOG_DIR = os.path.join(LAB_DIR, "logs", "snmp")
os.makedirs(LOG_DIR, exist_ok=True)

class SNMPTrap:
    def __init__(self, host="0.0.0.0", port=161):
        self.host, self.port, self.running = host, port, False; self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port)); self.sock.settimeout(1); self.running = True
            print(f"  🌐 SNMP trap on port {self.port} (UDP)")
            def s():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(4096); client_ip = addr[0]; ts = datetime.datetime.now().isoformat()
                        community = ""
                        if len(data) > 20:
                            try: community = data[data.index(b"\x04")+1:data.index(b"\x04")+1+data[data.index(b"\x04")-1]].decode(errors="replace")
                            except: pass
                        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "SNMP", "community": community, "data_length": len(data)}
                        with open(os.path.join(LOG_DIR, "snmp_queries.jsonl"), "a", encoding="utf-8") as f: f.write(json.dumps(entry)+"\n")
                        print(f"  🌐 SNMP | {ts[:19]} | {client_ip:>15} | community='{community}'")
                        # Send fake SNMP response
                        import struct
                        req_id = data[20:24] if len(data) > 24 else b"\x00\x00\x00\x00"
                        resp = b"0,\x02\x01\x01\x04\x06public\xa2\x1f\x02\x04" + req_id + b"\x02\x01\x00\x02\x01\x000\x12\x06\x10+\x06\x01\x04\x01\x82\xdf\x15\xc0\xa7\x01\x00\x01\x00\x00\x00\x05\x00"
                        self.sock.sendto(resp, addr)
                    except socket.timeout: continue
            threading.Thread(target=s, daemon=True).start()
        except Exception as e: print(f"  ❌ SNMP trap failed: {e}")
    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

if __name__ == "__main__":
    print("="*50); t = SNMPTrap(); t.start(); print(f"  📁 Logs: {LOG_DIR}"); print("="*50)
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt: print("\n  🛑  Stopping..."); t.stop()
