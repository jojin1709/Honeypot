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
Red Team: Honeypot Lab Brute Forcer
Test your honeypots by simulating brute force attacks.
"""
import os
import sys
import time
import json
import datetime
import socket
import threading

LAB_DIR = os.path.dirname(os.path.abspath(__file__))


class BruteForceSimulator:
    """Simulate brute force attacks against your honeypots"""

    def __init__(self, target_host="127.0.0.1"):
        self.target_host = target_host
        self.successful = []

    def ssh_brute_force(self, port=2222, delay=0.1):
        """Simulate SSH brute force attempts"""
        print(f"\n  🔐 SSH Brute Force -> {self.target_host}:{port}")
        print(f"  {'=' * 50}")

        try:
            import paramiko
            usernames = ["root", "admin", "user", "test", "ubuntu", "pi", "oracle", "postgres"]
            passwords = [
                "123456", "admin", "password", "root", "test", "12345",
                "admin123", "letmein", "welcome", "P@ssw0rd", "changeme",
            ]

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            attempted = 0
            for username in usernames:
                for password in passwords[:5]:  # Limit to 5 per user
                    attempted += 1
                    try:
                        client.connect(self.target_host, port=port,
                                       username=username, password=password,
                                       timeout=2, look_for_keys=False,
                                       allow_agent=False)
                        print(f"     ✅ SUCCESS: {username}:{password}")
                        self.successful.append(("SSH", username, password))
                        client.close()
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    except paramiko.AuthenticationException:
                        print(f"     ❌ FAIL: {username}:{password}")
                    except Exception as e:
                        print(f"     ⚠️  {username}:{password} -> {e}")

                    time.sleep(delay)

            print(f"     {'=' * 30}")
            print(f"     Attempted: {attempted}, Successful: {len(self.successful)}")

        except ImportError:
            print("     ⚠️  paramiko not installed. Install with: pip install paramiko")

    def http_brute_force(self, url, port=80, path="/wp-login.php", delay=0.05):
        """Simulate HTTP form brute force"""
        from urllib.request import Request, urlopen
        from urllib.parse import urlencode

        print(f"\n  🌐 HTTP Brute Force -> http://{self.target_host}:{port}{path}")
        print(f"  {'=' * 50}")

        passwords = ["admin", "123456", "password", "letmein", "admin123",
                     "test", "Passw0rd", "root", "toor", "qwerty",
                     "12345678", "abc123", "monkey", "welcome", "changeme"]

        for i, pwd in enumerate(passwords):
            data = urlencode({"log": "admin", "pwd": pwd}).encode()
            try:
                req = Request(f"http://{self.target_host}:{port}{path}",
                              data=data, method="POST")
                req.add_header("User-Agent",
                               "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                resp = urlopen(req, timeout=3)
                print(f"     ❌ Attempt {i+1}: admin:{pwd} -> {resp.status}")
            except Exception as e:
                print(f"     ⚠️  Attempt {i+1}: admin:{pwd} -> {e}")
            time.sleep(delay)

        print(f"     Completed {len(passwords)} login attempts")

    def ftp_brute_force(self, port=21, delay=0.1):
        """Simulate FTP brute force"""
        print(f"\n  📁 FTP Brute Force -> {self.target_host}:{port}")
        print(f"  {'=' * 50}")

        creds = [
            ("anonymous", "anonymous"),
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("ftp", "ftp"),
        ]

        for username, password in creds:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_host, port))
                banner = sock.recv(1024).decode()
                sock.send(f"USER {username}\r\n".encode())
                response = sock.recv(1024).decode()
                sock.send(f"PASS {password}\r\n".encode())
                response = sock.recv(1024).decode()
                sock.close()

                if "230" in response:
                    print(f"     ✅ SUCCESS: {username}:{password}")
                else:
                    print(f"     ❌ FAIL: {username}:{password}")
            except Exception as e:
                print(f"     ⚠️  {username}:{password} -> {e}")
            time.sleep(delay)

    def multi_threaded_brute(self, target_type="ssh", threads=5):
        """Simulate multi-threaded brute force"""
        print(f"\n  🧵 Multi-threaded {target_type.upper()} brute force ({threads} threads)")
        print(f"  {'=' * 50}")

        def worker(thread_id, creds_list):
            try:
                import paramiko
                for username, password in creds_list:
                    try:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client.connect(self.target_host, port=2222,
                                       username=username, password=password,
                                       timeout=1, look_for_keys=False, allow_agent=False)
                        print(f"     [{thread_id}] ✅ {username}:{password}")
                        client.close()
                    except:
                        print(f"     [{thread_id}] ❌ {username}:{password}")
            except:
                pass

        # Generate credential list
        all_creds = []
        for u in ["admin", "root", "user", "test"]:
            for p in ["admin", "123456", "password", "test", "root", "letmein"]:
                all_creds.append((u, p))

        # Split across threads
        chunk_size = len(all_creds) // threads + 1
        threads_list = []
        for i in range(threads):
            chunk = all_creds[i * chunk_size:(i + 1) * chunk_size]
            t = threading.Thread(target=worker, args=(i, chunk))
            threads_list.append(t)
            t.start()

        for t in threads_list:
            t.join()

        print(f"     Completed {len(all_creds)} attempts across {threads} threads")


def main():
    print("=" * 60)
    print("  🎯 HONEYPOT LAB - Red Team Brute Force Simulator")
    print("  Tests your honeypots by simulating real brute force patterns")
    print("=" * 60)

    sim = BruteForceSimulator()

    print("\nSelect attack type:")
    print("  1) SSH brute force")
    print("  2) HTTP form brute force")
    print("  3) FTP brute force")
    print("  4) Multi-threaded SSH brute force")
    print("  5) All of the above")

    choice = input("  Choice [1-5]: ")

    if choice in ("1", "5"):
        sim.ssh_brute_force()
    if choice in ("2", "5"):
        sim.http_brute_force(sim.target_host)
    if choice in ("3", "5"):
        sim.ftp_brute_force()
    if choice in ("4", "5"):
        sim.multi_threaded_brute()

    print(f"\n  ✅ Attack simulation complete!")
    if sim.successful:
        print(f"  🔓 {len(sim.successful)} credentials cracked:")
        for s in sim.successful:
            print(f"     - {s[0]}: {s[1]}:{s[2]}")
    print("  📊 Check the logs in ../logs/creds/")
    print()

    input("  Press Enter to view captured credentials...")

    # Show captured creds
    creds_log = os.path.join(LAB_DIR, "..", "logs", "creds", "heralding.log")
    if os.path.exists(creds_log):
        print(f"\n  📄 Last 10 lines of {creds_log}:")
        with open(creds_log, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-10:]:
            print(f"    {line.strip()}")


if __name__ == "__main__":
    main()
