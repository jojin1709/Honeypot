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
Redis Honeypot — Captures unsecured Redis probes, key enumeration, and exploitation.
"""
import os, sys, json, socket, datetime, threading

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
LOG_DIR = os.path.join(LAB_DIR, "logs", "redis")
os.makedirs(LOG_DIR, exist_ok=True)

class RedisTrap:
    def __init__(self, host="0.0.0.0", port=6379):
        self.host, self.port, self.running = host, port, False
        self.server = None
    def handle(self, conn, addr):
        client_ip = addr[0]
        try:
            conn.settimeout(30)
            data = conn.recv(8192)
            if not data: return
            ts = datetime.datetime.now().isoformat()
            entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "Redis", "data": data.decode(errors="replace")[:500]}
            with open(os.path.join(LOG_DIR, "redis_probes.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            print(f"  🔴 Redis | {ts[:19]} | {client_ip:>15} | {data[:100].decode(errors='replace').strip()}")
            # Respond like a real Redis server (no auth required)
            conn.send(b"+OK\r\n")
        except: pass
        finally: conn.close()
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50)
            self.server.settimeout(1); self.running = True
            print(f"  🔴 Redis trap on port {self.port}")
            def serve():
                while self.running:
                    try: conn, addr = self.server.accept(); threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e: print(f"  ❌ Redis trap failed: {e}")
    def stop(self):
        self.running = False
        if self.server: self.server.close()

class VNCTrap:
    def __init__(self, host="0.0.0.0", port=5900):
        self.host, self.port, self.running = host, port, False
        self.server = None
    def handle(self, conn, addr):
        client_ip = addr[0]
        try:
            conn.settimeout(30)
            data = conn.recv(4096)
            if not data: return
            ts = datetime.datetime.now().isoformat()
            entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "VNC", "data_length": len(data), "data_hex": data[:200].hex()}
            with open(os.path.join(LOG_DIR, "vnc_attempts.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            print(f"  🖥️  VNC | {ts[:19]} | {client_ip:>15} | {len(data)} bytes")
            # VNC protocol handshake - send RFB version
            conn.send(b"RFB 003.008\n")
        except: pass
        finally: conn.close()
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50); self.server.settimeout(1); self.running = True
            print(f"  🖥️  VNC trap on port {self.port}")
            def serve():
                while self.running:
                    try: conn, addr = self.server.accept(); threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except: print(f"  ❌ VNC trap failed")
    def stop(self):
        self.running = False
        if self.server: self.server.close()

class TelnetTrap:
    def __init__(self, host="0.0.0.0", port=23):
        self.host, self.port, self.running = host, port, False
        self.server = None
    def handle(self, conn, addr):
        client_ip = addr[0]
        try:
            conn.settimeout(30)
            data = conn.recv(4096)
            if not data: return
            ts = datetime.datetime.now().isoformat()
            entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "Telnet-IoT", "data": data.decode(errors="replace")[:500]}
            with open(os.path.join(LOG_DIR, "telnet_attempts.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            print(f"  📟 Telnet | {ts[:19]} | {client_ip:>15} | {data.decode(errors='replace')[:80].strip()}")
            conn.send(b"\r\nBusyBox v1.30.1 login: ")
        except: pass
        finally: conn.close()
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50); self.server.settimeout(1); self.running = True
            print(f"  📟 Telnet trap on port {self.port} (IoT/Mirai)")
            def serve():
                while self.running:
                    try: conn, addr = self.server.accept(); threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except: print(f"  ❌ Telnet trap failed")
    def stop(self):
        self.running = False
        if self.server: self.server.close()

class MemcachedTrap:
    def __init__(self, host="0.0.0.0", port=11211):
        self.host, self.port, self.running = host, port, False
        self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1); self.running = True
            print(f"  📦 Memcached trap on port {self.port} (DDoS amp)")
            def serve():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        client_ip = addr[0]
                        ts = datetime.datetime.now().isoformat()
                        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "Memcached", "data_length": len(data)}
                        with open(os.path.join(LOG_DIR, "memcached_probes.jsonl"), "a", encoding="utf-8") as f:
                            f.write(json.dumps(entry) + "\n")
                        print(f"  📦 Memcache | {ts[:19]} | {client_ip:>15}")
                        # Amplification response: send large stats
                        self.sock.sendto(b"STAT pid 1\r\nSTAT uptime 99999\r\nSTAT version 1.6.18\r\nSTAT curr_items 999999\r\nSTAT total_items 9999999\r\nSTAT bytes 999999999\r\nEND\r\n", addr)
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e: print(f"  ❌ Memcached trap failed: {e}")
    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

class MQTTTrap:
    def __init__(self, host="0.0.0.0", port=1883):
        self.host, self.port, self.running = host, port, False
        self.server = None
    def handle(self, conn, addr):
        client_ip = addr[0]
        try:
            conn.settimeout(30)
            data = conn.recv(4096)
            if not data or len(data) < 2: return
            ts = datetime.datetime.now().isoformat()
            # MQTT CONNECT packet
            msg_type = (data[0] & 0xF0) >> 4
            types = {1: "CONNECT", 3: "PUBLISH", 8: "SUBSCRIBE", 12: "PINGREQ"}
            mtype = types.get(msg_type, f"TYPE_{msg_type}")
            topic = ""
            if msg_type == 3 and len(data) > 4:
                tlen = (data[2] << 8) | data[3]
                topic = data[4:4+tlen].decode(errors="replace") if tlen > 0 else ""
            conn.send(bytes([0x20, 0x02, 0x00, 0x00]))  # CONNACK
            entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "MQTT", "packet_type": mtype, "topic": topic}
            with open(os.path.join(LOG_DIR, "mqtt_messages.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            print(f"  📡 MQTT | {ts[:19]} | {client_ip:>15} | {mtype} {topic}")
        except: pass
        finally: conn.close()
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50); self.server.settimeout(1); self.running = True
            print(f"  📡 MQTT trap on port {self.port} (IoT)")
            def serve():
                while self.running:
                    try: conn, addr = self.server.accept(); threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except: print(f"  ❌ MQTT trap failed")
    def stop(self):
        self.running = False
        if self.server: self.server.close()

class SNMPTrap:
    def __init__(self, host="0.0.0.0", port=161):
        self.host, self.port, self.running = host, port, False
        self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1); self.running = True
            print(f"  🌐 SNMP trap on port {self.port} (UDP)")
            def serve():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        client_ip = addr[0]
                        ts = datetime.datetime.now().isoformat()
                        community = ""
                        if len(data) > 20:
                            try: community = data[data.index(b"\x04")+1:data.index(b"\x04")+1+data[data.index(b"\x04")-1]].decode(errors="replace")
                            except: pass
                        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "SNMP", "community": community, "data_length": len(data)}
                        with open(os.path.join(LOG_DIR, "snmp_queries.jsonl"), "a", encoding="utf-8") as f:
                            f.write(json.dumps(entry) + "\n")
                        print(f"  🌐 SNMP | {ts[:19]} | {client_ip:>15} | community='{community}'")
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except: print(f"  ❌ SNMP trap failed")
    def stop(self):
        self.running = False
        if self.sock: self.sock.close()

class NTPTrap:
    def __init__(self, host="0.0.0.0", port=123):
        self.host, self.port, self.running = host, port, False
        self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1); self.running = True
            print(f"  🕐 NTP trap on port {self.port} (DDoS amp)")
            def serve():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        client_ip = addr[0]
                        ts = datetime.datetime.now().isoformat()
                        entry = {"timestamp": ts, "source_ip": client_ip, "protocol": "NTP", "data_length": len(data)}
                        with open(os.path.join(LOG_DIR, "ntp_queries.jsonl"), "a", encoding="utf-8") as f:
                            f.write(json.dumps(entry) + "\n")
                        print(f"  🕐 NTP | {ts[:19]} | {client_ip:>15} | {len(data)} bytes")
                    except socket.timeout: continue
            threading.Thread(target=serve, daemon=True).start()
        except: print(f"  ❌ NTP trap failed")
    def stop(self):
        self.running = False
        if self.sock: self.sock.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Honeypot Lab - Multi-Protocol Trap")
    parser.add_argument("--type", choices=["redis", "vnc", "telnet", "memcached", "mqtt", "snmp", "ntp"], required=True)
    args = parser.parse_args()
    traps = {"redis": RedisTrap, "vnc": VNCTrap, "telnet": TelnetTrap, "memcached": MemcachedTrap, "mqtt": MQTTTrap, "snmp": SNMPTrap, "ntp": NTPTrap}
    t = traps[args.type]()
    t.start()
    print(f"  Logs: {LOG_DIR}")
    print("=" * 50)
    try:
        while True: import time; time.sleep(1)
    except KeyboardInterrupt: print("\n  🛑  Stopping..."); t.stop(); print("  ✅ Done")
