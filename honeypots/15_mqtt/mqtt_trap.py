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
LOG_DIR = os.path.join(LAB_DIR, "logs", "mqtt")
os.makedirs(LOG_DIR, exist_ok=True)

class MQTTTrap:
    def __init__(self, host="0.0.0.0", port=1883):
        self.host, self.port, self.running = host, port, False; self.server = None
    def handle(self, conn, addr):
        client_ip = addr[0]
        try:
            conn.settimeout(30); data = conn.recv(4096)
            if not data or len(data) < 2: return
            ts = datetime.datetime.now().isoformat()
            msg_type = (data[0] & 0xF0) >> 4
            types = {1: "CONNECT", 3: "PUBLISH", 8: "SUBSCRIBE", 12: "PINGREQ"}
            mtype = types.get(msg_type, f"TYPE_{msg_type}")
            topic = ""
            if msg_type == 3 and len(data) > 4:
                tlen = (data[2] << 8) | data[3]
                topic = data[4:4+tlen].decode(errors="replace") if tlen > 0 else ""
            conn.send(bytes([0x20, 0x02, 0x00, 0x00]))  # CONNACK
            entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "MQTT", "packet_type": mtype, "topic": topic}
            with open(os.path.join(LOG_DIR, "mqtt_messages.jsonl"), "a", encoding="utf-8") as f: f.write(json.dumps(entry)+"\n")
            print(f"  📡 MQTT | {ts[:19]} | {client_ip:>15} | {mtype} {topic}")
        except: pass
        finally: conn.close()
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port)); self.server.listen(50); self.server.settimeout(1); self.running = True
            print(f"  📡 MQTT trap on port {self.port} (IoT)")
            def s():
                while self.running:
                    try: conn, addr = self.server.accept(); threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout: continue
            threading.Thread(target=s, daemon=True).start()
        except Exception as e: print(f"  ❌ MQTT trap failed: {e}")
    def stop(self):
        self.running = False
        if self.server: self.server.close()

if __name__ == "__main__":
    print("="*50); t = MQTTTrap(); t.start(); print(f"  📁 Logs: {LOG_DIR}"); print("="*50)
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt: print("\n  🛑  Stopping..."); t.stop()
