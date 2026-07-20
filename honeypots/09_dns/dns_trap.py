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
DNS Honeypot — Captures DNS tunneling, amplification probes, and lookup queries.
"""
import os, sys, json, socket, struct, datetime, threading
import sys as _sys2; _sys2.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')); from alert_helper import log_alert

LAB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(LAB_DIR, "logs", "dns")
os.makedirs(LOG_DIR, exist_ok=True)

class DNSTrap:
    def __init__(self, host="0.0.0.0", port=None):
        if port is None:
            port = int(os.environ.get("DNS_PORT", "5353"))
        self.host, self.port, self.running = host, port, False
        self.sock = None
    def log(self, client_ip, query_name="", query_type="", data=b""):
        ts = datetime.datetime.now().isoformat()
        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "DNS", "query": query_name, "query_type": query_type, "data_length": len(data)}
        with open(os.path.join(LOG_DIR, "dns_queries.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"  🌐 DNS | {ts[:19]} | {client_ip:>15} | {query_type} {query_name}")
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1)
            self.running = True
            print(f"  🌐 DNS trap on port {self.port} (UDP)")
            def serve():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        client_ip = addr[0]
                        qname = ""
                        qtype = ""
                        if len(data) > 12:
                            try:
                                i = 12
                                labels = []
                                while data[i] != 0 and i < len(data):
                                    length = data[i]
                                    if length > 0:
                                        labels.append(data[i+1:i+1+length].decode(errors="replace"))
                                        i += length + 1
                                qname = ".".join(labels)
                                qtype = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA", 255: "ANY", 35: "NAPTR", 65: "HTTPS"}.get(struct.unpack("!H", data[i+1:i+3])[0], "OTHER")
                            except: qname = "[parse error]"
                        self.log(client_ip, qname
            log_alert("dns", client_ip, qname), qtype, data)
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e: print(f"  ❌ DNS trap failed: {e}")
    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

if __name__ == "__main__":
    print("=" * 50)
    t = DNSTrap()
    t.start()
    print(f"  🌐 DNS trap active — logs: {LOG_DIR}")
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt: print("\n  🛑  Stopping..."); t.stop()
