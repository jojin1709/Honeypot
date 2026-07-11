#!/usr/bin/env python3
"""
RDP Honeypot Trap
Logs RDP connection attempts and extracts client info.
"""
import os
import sys
import json
import datetime
import socket
import struct
import threading

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(LAB_DIR, "logs", "rdp")
os.makedirs(LOG_DIR, exist_ok=True)

# RDP protocol constants
RDP_NEG_REQ = 0x01  # RDP Negotiation Request


class RDPTrap:
    """Fake RDP server that logs connection attempts"""

    def __init__(self, host="0.0.0.0", port=3389):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.total_connections = 0

    def handle_client(self, conn, addr):
        """Handle RDP connection attempt"""
        client_ip = addr[0]
        self.total_connections += 1
        conn_id = self.total_connections
        timestamp = datetime.datetime.now().isoformat()

        try:
            conn.settimeout(30)

            # Read the RDP Connection Request (X.224 Connection Request)
            data = conn.recv(4096)

            if not data:
                conn.close()
                return

            # Parse RDP negotiation request
            rdp_info = self._parse_rdp_request(data, client_ip)

            entry = {
                "timestamp": timestamp,
                "connection_id": conn_id,
                "source_ip": client_ip,
                "source_port": addr[1],
                "protocol": "RDP",
                "data_length": len(data),
                "rdp_info": rdp_info,
            }

            # Log to file
            log_file = os.path.join(LOG_DIR, "rdp_attempts.jsonl")
            with open(log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

            # Also log to CSV for easy analysis
            csv_file = os.path.join(LOG_DIR, "rdp_attempts.csv")
            if not os.path.exists(csv_file):
                with open(csv_file, "w") as f:
                    f.write("timestamp,source_ip,source_port,data_length,requested_protocols,client_name\n")

            with open(csv_file, "a") as f:
                f.write(f"{timestamp},{client_ip},{addr[1]},{len(data)},"
                       f"{rdp_info.get('requested_protocols', 'unknown')},"
                       f"{rdp_info.get('client_name', 'unknown')}\n")

            print(f"  🖥️  RDP | {timestamp[:19]} | {client_ip:>15}:{addr[1]} | "
                  f"Conn #{conn_id} | {len(data)} bytes")

            # Respond with RDP Negotiation Response
            # This makes the scanner think RDP is available
            self._send_rdp_response(conn)

        except socket.timeout:
            print(f"  ⚠️  RDP | {client_ip:>15} - timeout after 30s")
        except ConnectionResetError:
            print(f"  ⚠️  RDP | {client_ip:>15} - connection reset")
        except Exception as e:
            print(f"  ❌ RDP error from {client_ip}: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

    def _parse_rdp_request(self, data, client_ip):
        """Parse RDP connection request data"""
        info = {
            "requested_protocols": "unknown",
            "client_name": "unknown",
            "raw_hex": data[:100].hex(),
        }

        try:
            if len(data) >= 11:
                # X.224 Connection Request
                if data[0] == 0x03:  # X.224 TPKT header
                    info["tpkt_version"] = data[0]
                    info["tpkt_length"] = struct.unpack("!H", data[2:4])[0]

                    # X.224 CR
                    if len(data) > 7 and data[7] == 0xe0:
                        info["x224_type"] = "Connection Request"

                        # RDP Negotiation Request (RDP_NEG_REQ)
                        if len(data) > 11 and data[11] == RDP_NEG_REQ:
                            protocols = data[12]
                            proto_names = []
                            if protocols & 0x01:
                                proto_names.append("PROTOCOL_RDP")
                            if protocols & 0x02:
                                proto_names.append("PROTOCOL_SSL")
                            if protocols & 0x04:
                                proto_names.append("PROTOCOL_HYBRID")
                            if protocols & 0x08:
                                proto_names.append("PROTOCOL_HYBRID_EX")
                            info["requested_protocols"] = "+".join(proto_names) if proto_names else f"raw:{protocols}"

                # Try to extract client name from RDP Core Data
                # This is in the GCC Conference Create Request
                if len(data) > 200:
                    # Look for client name in the data stream
                    # Client name is usually in the Core Data block after offset ~200-400
                    for i in range(200, min(len(data) - 10, 400)):
                        # Check for ASCII string pattern (client name)
                        chunk = data[i:i+16]
                        try:
                            decoded = chunk.decode("ascii", errors="ignore").strip("\x00").strip()
                            if decoded and len(decoded) >= 2 and all(c.isprintable() or c.isspace() for c in decoded):
                                if decoded not in ["RDP", "MS"] and len(decoded) < 32:
                                    info["client_name"] = decoded
                                    break
                        except:
                            pass

        except Exception as e:
            info["parse_error"] = str(e)

        return info

    def _send_rdp_response(self, conn):
        """Send RDP Negotiation Response to keep the connection alive"""
        try:
            # TPKT Header + X.224 CC + RDP Negotiation Response
            # This tells the client we support RDP protocol
            response = bytes([
                0x03, 0x00,  # TPKT version 3
                0x00, 0x0b,  # Length: 11 bytes
                0x02, 0x0a,  # X.224 DT (Data Transfer)
                0x00, 0x01,  # X.224 - Calling/called selector
                0x02, 0x00,  # RDP Negotiation Response
                0x08,  # flags
            ])
            conn.send(response)
        except:
            pass

    def start(self):
        """Start the RDP trap server"""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(100)
            self.server.settimeout(1)
            self.running = True
            print(f"  🖥️  RDP trap on port {self.port}")
            print(f"  ⚠️  Port {self.port} may need admin privileges or port forwarding")
            print(f"  📁 Logs: {LOG_DIR}")

            def accept_loop():
                while self.running:
                    try:
                        conn, addr = self.server.accept()
                        thread = threading.Thread(
                            target=self.handle_client, args=(conn, addr), daemon=True
                        )
                        thread.start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            thread = threading.Thread(target=accept_loop, daemon=True)
            thread.start()
        except PermissionError:
            print(f"  ❌ RDP trap: Permission denied on port {self.port}")
            print(f"     Try: Run as Administrator, or change port in config")
        except OSError as e:
            print(f"  ❌ RDP trap: {e}")

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()


def main():
    print("=" * 50)
    print("  🖥️  RDP Honeypot Trap")
    print("=" * 50)

    # Check for port conflicts
    trap = RDPTrap()

    try:
        trap.start()
        if trap.running:
            print("  ✅ RDP trap is listening for connections")
            print("=" * 50)
            print("  Waiting for RDP scan/brute force attempts...")
            print("  (Press Ctrl+C to stop)")
            print("=" * 50)

            while True:
                import time
                time.sleep(1)
        else:
            print("  ❌ Failed to start RDP trap")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n  🛑  Shutting down RDP trap...")
        trap.stop()
        print(f"  📊 Total RDP connection attempts: {trap.total_connections}")
        print("  ✅ RDP trap stopped")


if __name__ == "__main__":
    main()
