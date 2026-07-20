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
Custom Credential Capture Honeypot (Cross-platform replacement for Heralding)
Captures login attempts across FTP, Telnet, HTTP, SMTP, POP3, IMAP, MySQL, SSH.
Works on both Windows and Kali/Linux with zero C dependencies.
"""
import os
import sys
import json
import socket
import datetime
import threading
import base64

LAB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LOG_DIR = os.path.join(LAB_DIR, "logs", "creds")
os.makedirs(LOG_DIR, exist_ok=True)

CSV_HEADER = "timestamp,protocol,source_ip,source_port,username,password,details\n"
CSV_FILE = os.path.join(LOG_DIR, "captured_creds.csv")
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", encoding="utf-8") as f:
        f.write(CSV_HEADER)

CRED_LOGS = []


def log_cred(protocol, client_ip
            log_alert("creds", client_ip, f"{protocol}:{username}:{password}"), client_port, username, password, details=""):
    """Log a captured credential"""
    timestamp = datetime.datetime.now().isoformat()

    entry = {
        "timestamp": timestamp,
        "protocol": protocol,
        "source_ip": client_ip,
        "source_port": client_port,
        "username": username,
        "password": password,
        "details": details,
    }

    CRED_LOGS.append(entry)

    # JSON log
    json_file = os.path.join(LOG_DIR, "captured_creds.jsonl")
    with open(json_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    # CSV log
    with open(CSV_FILE, "a", encoding="utf-8", newline="") as f:
        f.write(f'{timestamp},{protocol},{client_ip},{client_port},"{username}","{password}","{details}"\n')

    print(f"  🔑 {protocol:<10} | {timestamp[:19]} | {client_ip:>15} | {username}:{password}")


class BaseTrap:
    """Base class for all credential traps"""

    def __init__(self, host="0.0.0.0", port=0):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.name = "Base"

    def handle_client(self, conn, addr):
        """Override in subclass"""
        pass

    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(50)
            self.server.settimeout(1)
            self.running = True
            print(f"  🔑 {self.name} trap on port {self.port}")

            def serve():
                while self.running:
                    try:
                        conn, addr = self.server.accept()
                        threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            threading.Thread(target=serve, daemon=True).start()
        except Exception as e:
            print(f"  ❌ {self.name} trap failed: {e}")

    def stop(self):
        self.running = False
        if self.server:
            try:
                self.server.close()
            except:
                pass

    def send(self, conn, data):
        try:
            conn.send(data.encode() if isinstance(data, str) else data)
        except:
            pass

    def recv(self, conn, bufsize=4096):
        try:
            return conn.recv(bufsize)
        except:
            return b""


class FTPTrap(BaseTrap):
    """FTP credential capture"""

    def __init__(self, host="0.0.0.0", port=21):
        super().__init__(host, port)
        self.name = "FTP"

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(30)
            self.send(conn, "220 Welcome to FTP server\r\n")

            username = ""
            password = ""

            while True:
                data = self.recv(conn, 4096)
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()

                if line.upper().startswith("USER "):
                    username = line[5:].strip()
                    self.send(conn, "331 Password required for {}\r\n".format(username))
                elif line.upper().startswith("PASS "):
                    password = line[5:].strip()
                    log_cred("FTP", client_ip, client_port, username, password)
                    self.send(conn, "530 Login incorrect\r\n")
                elif line.upper().startswith("QUIT"):
                    self.send(conn, "221 Goodbye\r\n")
                    break
                else:
                    self.send(conn, "500 Unknown command\r\n")

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            conn.close()


class TelnetTrap(BaseTrap):
    """Telnet credential capture"""

    def __init__(self, host="0.0.0.0", port=2323):
        super().__init__(host, port)
        self.name = "Telnet"

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(30)
            self.send(conn, "\r\nUbuntu 22.04 LTS\r\nlogin: ")

            username = ""
            password = ""

            data = self.recv(conn, 4096)
            if data:
                username = data.decode("utf-8", errors="replace").strip()

            self.send(conn, "Password: ")
            data = self.recv(conn, 4096)
            if data:
                password = data.decode("utf-8", errors="replace").strip()

            if username:
                log_cred("Telnet", client_ip, client_port, username, password)
                self.send(conn, "\r\nLogin incorrect\r\nlogin: ")

        except (socket.timeout, ConnectionResetError):
            pass
        finally:
            conn.close()


class SMTPTrap(BaseTrap):
    """SMTP credential capture"""

    def __init__(self, host="0.0.0.0", port=25):
        super().__init__(host, port)
        self.name = "SMTP"

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(30)
            self.send(conn, "220 mail.example.com ESMTP Postfix\r\n")

            username = ""
            password = ""

            while True:
                data = self.recv(conn, 4096)
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()

                if line.upper().startswith("AUTH LOGIN"):
                    self.send(conn, "334 VXNlcm5hbWU6\r\n")
                    data = self.recv(conn, 4096)
                    if data:
                        try:
                            username = base64.b64decode(data.strip()).decode()
                        except:
                            username = data.decode(errors="replace").strip()
                    self.send(conn, "334 UGFzc3dvcmQ6\r\n")
                    data = self.recv(conn, 4096)
                    if data:
                        try:
                            password = base64.b64decode(data.strip()).decode()
                        except:
                            password = data.decode(errors="replace").strip()
                    log_cred("SMTP", client_ip, client_port, username, password)
                    self.send(conn, "535 Authentication failed\r\n")
                elif line.upper().startswith("QUIT"):
                    self.send(conn, "221 Bye\r\n")
                    break
                elif line.upper().startswith("EHLO") or line.upper().startswith("HELO"):
                    self.send(conn, "250 mail.example.com\r\n")
                else:
                    self.send(conn, "250 OK\r\n")

        except (socket.timeout, ConnectionResetError):
            pass
        finally:
            conn.close()


class POP3Trap(BaseTrap):
    """POP3 credential capture"""

    def __init__(self, host="0.0.0.0", port=110):
        super().__init__(host, port)
        self.name = "POP3"

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(30)
            self.send(conn, "+OK POP3 server ready\r\n")

            username = ""
            password = ""

            while True:
                data = self.recv(conn, 4096)
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()

                if line.upper().startswith("USER "):
                    username = line[5:].strip()
                    self.send(conn, "+OK\r\n")
                elif line.upper().startswith("PASS "):
                    password = line[5:].strip()
                    log_cred("POP3", client_ip, client_port, username, password)
                    self.send(conn, "-ERR Authentication failed\r\n")
                elif line.upper().startswith("QUIT"):
                    self.send(conn, "+OK Bye\r\n")
                    break
                else:
                    self.send(conn, "+OK\r\n")

        except (socket.timeout, ConnectionResetError):
            pass
        finally:
            conn.close()


class HTTPCredTrap(BaseTrap):
    """HTTP login form credential capture"""

    def __init__(self, host="0.0.0.0", port=8080):
        super().__init__(host, port)
        self.name = "HTTP-Creds"

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(15)
            data = self.recv(conn, 8192)
            if not data:
                return

            request = data.decode("utf-8", errors="replace")

            # Parse POST body for credentials
            username = ""
            password = ""

            if "POST" in request:
                # Extract body
                parts = request.split("\r\n\r\n")
                if len(parts) > 1:
                    body = parts[1]
                    # Parse form data
                    pairs = body.split("&")
                    for pair in pairs:
                        if "=" in pair:
                            key, value = pair.split("=", 1)
                            from urllib.parse import unquote_plus
                            value = unquote_plus(value)
                            if "user" in key.lower() or "log" in key.lower() or "login" in key.lower() or "email" in key.lower():
                                username = value
                            elif "pass" in key.lower() or "pwd" in key.lower():
                                password = value

                # Also check Basic Auth
                for line in request.split("\r\n"):
                    if line.lower().startswith("authorization: basic "):
                        try:
                            auth_b64 = line.split(" ", 2)[2]
                            auth_decoded = base64.b64decode(auth_b64).decode()
                            if ":" in auth_decoded:
                                username, password = auth_decoded.split(":", 1)
                        except:
                            pass

            if username or password:
                log_cred("HTTP", client_ip, client_port, username, password, request[:200])

            # Send fake login page response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<html><body><h2>Invalid credentials</h2>"
                '<form method="POST"><input type="text" name="username" placeholder="User">'
                '<input type="password" name="password" placeholder="Pass">'
                '<input type="submit" value="Login"></form></body></html>'
            )
            self.send(conn, response)

        except (socket.timeout, ConnectionResetError):
            pass
        finally:
            conn.close()


class MySQLTrap(BaseTrap):
    """MySQL credential capture"""

    def __init__(self, host="0.0.0.0", port=3306):
        super().__init__(host, port)
        self.name = "MySQL"

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(15)
            # MySQL protocol handshake - send greeting
            greeting = bytes([
                0x4a, 0x00, 0x00, 0x00,  # Packet length
                0x0a,  # Sequence ID
                0x35, 0x2e, 0x37, 0x2e, 0x32, 0x35,  # 5.7.25
                0x00,  # NUL
                0x0d, 0x00, 0x00, 0x00,  # Connection ID
                0x66, 0x6c, 0x61, 0x67,  # Auth plugin data part 1
                0x00,  # Filler
                0x08, 0xa2,  # Capability flags
                0x00,  # Character set
                0x02,  # Status flags
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
            conn.send(greeting)

            data = self.recv(conn, 4096)
            if data and len(data) > 4:
                # Parse MySQL login packet
                username = ""
                try:
                    username_end = data.index(b"\x00", 5)
                    username = data[5:username_end].decode("utf-8", errors="replace")
                except ValueError:
                    username = data[5:36].decode("utf-8", errors="replace").rstrip("\x00")

                log_cred("MySQL", client_ip, client_port, username, "[password_hash]")

                # Send auth error
                error_pkt = bytes([
                    0x26, 0x00, 0x00, 0x02,  # Packet header
                    0xff,  # Error marker
                    0x10, 0x04,  # Error code 1040
                    0x23, 0x32, 0x38, 0x30, 0x30, 0x30,  # SQL state
                ]) + b"Access denied for user '" + username.encode() + b"'@'localhost'"
                conn.send(error_pkt)

        except (socket.timeout, ConnectionResetError, OSError):
            pass
        finally:
            conn.close()


class SSHCredTrap(BaseTrap):
    """SSH credential capture (alternative port to Cowrie)"""

    def __init__(self, host="0.0.0.0", port=2223):
        super().__init__(host, port)
        self.name = "SSH-Creds"

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        try:
            conn.settimeout(30)
            # SSH banner
            self.send(conn, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            data = self.recv(conn, 4096)
            if data:
                log_cred("SSH", client_ip, client_port, "[ssh_client]",
                          f"banner: {data.decode('utf-8', errors='replace')[:100].strip()}")
        except (socket.timeout, ConnectionResetError):
            pass
        finally:
            conn.close()


def main():
    print("=" * 50)
    print("  🔑 Credential Capture Honeypot")
    print("=" * 50)

    traps = [
        FTPTrap(),
        TelnetTrap(),
        SMTPTrap(),
        POP3Trap(),
        HTTPCredTrap(),
        MySQLTrap(),
    ]

    for trap in traps:
        trap.start()

    print(f"  📁 Logs: {LOG_DIR}")
    print("=" * 50)
    print("  Listening for credential theft attempts...")
    print("  Captures: FTP, Telnet, SMTP, POP3, HTTP, MySQL")
    print("  (Press Ctrl+C to stop)")
    print("=" * 50)

    try:
        while True:
            import time
import sys as _sys2; _sys2.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')); from alert_helper import log_alert
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  🛑  Shutting down credential traps...")
        for trap in traps:
            trap.stop()
        print(f"  📊 Captured {len(CRED_LOGS)} credentials this session")
        print(f"  ✅ Credential traps stopped")


if __name__ == "__main__":
    main()
