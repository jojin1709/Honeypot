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
Custom ICS/SCADA Honeypot (Cross-platform replacement for Conpot)
Emulates Modbus, Siemens S7, BACnet, and other industrial protocols.
Works on both Windows and Kali/Linux with zero C dependencies.
"""
import os
import sys
import json
import socket
import struct
import datetime
import threading
import hashlib

LAB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(LAB_DIR, "logs", "ics")
os.makedirs(LOG_DIR, exist_ok=True)


class ICSLogger:
    """Shared logging for all ICS protocols"""

    @staticmethod
    def log(protocol, client_ip, client_port, data_hex, details=None):
        """Log an ICS probe attempt"""
        timestamp = datetime.datetime.now().isoformat()
        entry = {
            "timestamp": timestamp,
            "protocol": protocol,
            "source_ip": client_ip,
            "source_port": client_port,
            "data_length": len(data_hex) // 2 if isinstance(data_hex, str) else 0,
            "data_hex": data_hex[:500],
            "details": details or {},
        }

        log_file = os.path.join(LOG_DIR, f"{protocol.lower()}_probes.jsonl")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"  🏭 {protocol:<8} | {timestamp[:19]} | {client_ip:>15}:{client_port}")


class ModbusTrap:
    """Modbus TCP honeypot (port 502)"""

    def __init__(self, host="0.0.0.0", port=502):
        self.host = host
        self.port = port
        self.server = None
        self.running = False

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(30)
            data = conn.recv(4096)
            if not data:
                return

            ICSLogger.log("Modbus", client_ip, client_port, data.hex())

            if len(data) >= 12:
                # Parse Modbus header
                transaction_id = struct.unpack("!H", data[0:2])[0]
                protocol_id = struct.unpack("!H", data[2:4])[0]
                length = struct.unpack("!H", data[4:6])[0]
                unit_id = data[6]
                func_code = data[7] if len(data) > 7 else 0

                details = {
                    "transaction_id": transaction_id,
                    "unit_id": unit_id,
                    "function_code": func_code,
                    "function_name": self._get_func_name(func_code),
                }
                ICSLogger.log("Modbus", client_ip, client_port, data.hex(), details)

                # Respond like a real Siemens S7-1200 PLC
                if func_code == 0x01:  # Read Coils
                    response = self._build_response(transaction_id, unit_id,
                                                     bytes([func_code, 0x01, 0x00]))
                elif func_code == 0x03:  # Read Holding Registers
                    response = self._build_response(transaction_id, unit_id,
                                                     bytes([func_code, 0x04, 0x00, 0x01, 0x02, 0x03]))
                elif func_code == 0x10:  # Write Multiple Registers
                    response = self._build_response(transaction_id, unit_id,
                                                     bytes([func_code, data[8], data[9]]))
                elif func_code == 0x2B:  # Encapsulated Interface Transport
                    response = self._build_response(transaction_id, unit_id,
                                                     bytes([func_code, 0x0E, 0x01, 0x00]))
                else:
                    response = self._build_response(transaction_id, unit_id,
                                                     bytes([func_code | 0x80, 0x01]))  # Exception

                conn.send(response)
        except socket.timeout:
            pass
        except Exception as e:
            print(f"  ⚠️  Modbus error: {e}")
        finally:
            conn.close()

    def _get_func_name(self, code):
        names = {
            0x01: "Read Coils", 0x02: "Read Discrete Inputs",
            0x03: "Read Holding Registers", 0x04: "Read Input Registers",
            0x05: "Write Single Coil", 0x06: "Write Single Register",
            0x0F: "Write Multiple Coils", 0x10: "Write Multiple Registers",
            0x2B: "Encapsulated Interface Transport",
        }
        return names.get(code, f"Unknown (0x{code:02x})")

    def _build_response(self, transaction_id, unit_id, payload):
        length = len(payload) + 1
        header = struct.pack("!HHHB", transaction_id, 0, length, unit_id)
        return header + payload

    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50)
            self.server.settimeout(1)
            self.running = True
            print(f"  🏭 Modbus PLC trap on port {self.port}")

            def serve():
                while self.running:
                    try:
                        conn, addr = self.server.accept()
                        threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e:
            print(f"  ❌ Modbus trap failed: {e}")

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()


class S7Trap:
    """Siemens S7comm honeypot (port 102)"""

    def __init__(self, host="0.0.0.0", port=102):
        self.host = host
        self.port = port
        self.server = None
        self.running = False

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(30)
            data = conn.recv(4096)
            if not data:
                return

            ICSLogger.log("S7", client_ip, client_port, data.hex())

            if len(data) >= 7 and data[0] == 0x03:
                # ISO-COTP / S7 connection request
                if data[6] == 0xe0:  # CR
                    # Send Connection Confirmation
                    conn.send(bytes([
                        0x03, 0x00, 0x00, 0x16,
                        0x11, 0xe0, 0x00, 0x00,
                        0x00, 0x01, 0x00, 0xc0,
                        0x01, 0x0a, 0xc1, 0x02,
                        0x01, 0x00, 0xc2, 0x02,
                        0x01, 0x00
                    ]))
                    # Wait for S7 communication setup
                    data2 = conn.recv(4096)
                    if data2:
                        ICSLogger.log("S7", client_ip, client_port, data2.hex(),
                                      {"note": "S7 communication setup"})
                        # Respond with S7 ack
                        conn.send(bytes([
                            0x03, 0x00, 0x00, 0x1c,
                            0x02, 0xf0, 0x80, 0x72,
                            0x02, 0x00, 0x00, 0x01,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00
                        ]))
                elif len(data) >= 22 and data[21] == 0x32:
                    # S7 Read/Write request
                    ICSLogger.log("S7", client_ip, client_port, data.hex(),
                                  {"note": "S7 data access request"})
                    # Send a simple response
                    conn.send(bytes([
                        0x03, 0x00, 0x00, 0x1c,
                        0x02, 0xf0, 0x80, 0x72,
                        0x02, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00
                    ]))
        except socket.timeout:
            pass
        except Exception as e:
            print(f"  ⚠️  S7 error: {e}")
        finally:
            conn.close()

    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50)
            self.server.settimeout(1)
            self.running = True
            print(f"  🏭 Siemens S7 trap on port {self.port}")

            def serve():
                while self.running:
                    try:
                        conn, addr = self.server.accept()
                        threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e:
            print(f"  ❌ S7 trap failed: {e}")

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()


class BACnetTrap:
    """BACnet honeypot (port 47808 - UDP)"""

    def __init__(self, host="0.0.0.0", port=47808):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1)
            self.running = True
            print(f"  🏭 BACnet trap on port {self.port} (UDP)")

            def serve():
                while self.running:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        client_ip, client_port = addr
                        ICSLogger.log("BACnet", client_ip, client_port, data.hex())
                    except socket.timeout:
                        continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e:
            print(f"  ❌ BACnet trap failed: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


class HTTPICSTrap:
    """Fake ICS web interface (port 8000)"""

    def __init__(self, host="0.0.0.0", port=8000):
        self.host = host
        self.port = port
        self.server = None
        self.running = False

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(10)
            data = conn.recv(8192)
            if not data:
                return

            ICSLogger.log("ICS-HTTP", client_ip, client_port, data.hex(),
                          {"note": "ICS web interface probe"})

            # Respond with Siemens HMI login page
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Server: Siemens-SIMATIC-WINCC/7.5\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<!DOCTYPE html><html><head><title>Siemens SIMATIC HMI</title>"
                "<style>body{font-family:sans-serif;background:#f0f0f0;padding:20px}"
                ".panel{background:white;border:2px solid #ccc;padding:20px;margin:10px 0}"
                ".warn{color:red;font-weight:bold}</style></head><body>"
                "<h1>Siemens SIMATIC HMI - Panel #1</h1>"
                "<p class='warn'>⚠ Station: Production Line 3</p>"
                "<div class='panel'><h3>System Status</h3>"
                "<p>CPU: RUN | Mode: Operate | Connections: 4</p>"
                "<p>Firmware: V7.5.2 | Build: 2024/03/15</p></div>"
                "<div class='panel'><h3>Diagnostics</h3>"
                "<p>Temperature: 42°C | Pressure: 3.2 bar</p>"
                "<p>Last Maintenance: 2026-06-28</p></div>"
                "<div class='panel'><h3>Login</h3>"
                "<form method='POST'><input type='text' name='user' placeholder='User'>"
                "<input type='password' name='pass' placeholder='Password'>"
                "<input type='submit' value='Login'></form></div>"
                "</body></html>"
            )
            conn.send(response.encode())
        except:
            pass
        finally:
            conn.close()

    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50)
            self.server.settimeout(1)
            self.running = True
            print(f"  🏭 ICS Web HMI trap on port {self.port}")

            def serve():
                while self.running:
                    try:
                        conn, addr = self.server.accept()
                        threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue
            threading.Thread(target=serve, daemon=True).start()
        except Exception as e:
            print(f"  ❌ ICS Web trap failed: {e}")

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()


def main():
    print("=" * 50)
    print("  🏭 ICS/SCADA Honeypot")
    print("=" * 50)

    traps = [
        ModbusTrap(),
        S7Trap(),
        BACnetTrap(),
        HTTPICSTrap(),
    ]

    for trap in traps:
        trap.start()

    print(f"  📁 Logs: {LOG_DIR}")
    print("=" * 50)
    print("  Listening for ICS/SCADA probes...")
    print("  (Press Ctrl+C to stop)")
    print("=" * 50)

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  🛑  Shutting down ICS honeypots...")
        for trap in traps:
            trap.stop()
        print("  ✅ ICS honeypots stopped")


if __name__ == "__main__":
    main()
