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
Web Honeypot Traps
Fake WordPress, admin panels, and API endpoints that log all attacks.
"""
import os
import sys
import json
import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

LAB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(LAB_DIR, "logs", "web")
os.makedirs(LOG_DIR, exist_ok=True)

CAPTURED_REQUESTS = []

class WebTrapHandler(BaseHTTPRequestHandler):
    """Generic HTTP honeypot that logs everything"""

    def log_request_info(self):
        """Log the full request details"""
        timestamp = datetime.datetime.now().isoformat()
        client_ip = self.client_address[0]
        path = self.path
        method = self.command

        content_length = int(self.headers.get("Content-Length", 0))
        body = ""
        if content_length > 0:
            try:
                body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            except:
                body = "[binary data]"

        headers = dict(self.headers)

        entry = {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "method": method,
            "path": path,
            "headers": headers,
            "body": body[:2000],  # Truncate large bodies
            "user_agent": self.headers.get("User-Agent", ""),
        }

        CAPTURED_REQUESTS.append(entry)
            log_alert("web", client_ip, f"{method} {path}")

        # Log to file
        log_file = os.path.join(LOG_DIR, "web_traps.jsonl")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        # Print alert
        print(f"  🌐 {timestamp} | {client_ip:>15} | {method:>4} {path} | UA: {entry['user_agent'][:50]}")

    def do_GET(self):
        self.log_request_info()
        self._handle_response()

    def do_POST(self):
        self.log_request_info()
        self._handle_response()

    def do_PUT(self):
        self.log_request_info()
        self._handle_response()

    def do_DELETE(self):
        self.log_request_info()
        self._handle_response()

    def do_PATCH(self):
        self.log_request_info()
        self._handle_response()

    def do_HEAD(self):
        self.log_request_info()
        self._handle_response()

    def _handle_response(self):
        path = urlparse(self.path).path
        params = parse_qs(urlparse(self.path).query)

        # WordPress admin login
        if "/wp-admin" in path or "/wp-login" in path:
            self._serve_wordpress_login()
        # Generic admin
        elif "/admin" in path or "/manager" in path or "/login" in path:
            self._serve_admin_login()
        # API endpoint
        elif "/api" in path or "/v1" in path or "/v2" in path or "/graphql" in path:
            self._serve_api()
        # phpMyAdmin
        elif "/phpmyadmin" in path or "/pma" in path or "/phpPgAdmin" in path:
            self._serve_phpmyadmin()
        # Default: WordPress homepage
        else:
            self._serve_wordpress_home()

    def _serve_wordpress_home(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Powered-By", "PHP/8.2.0")
        self.end_headers()
        self.wfile.write(b"""<!DOCTYPE html>
<html>
<head><title>My WordPress Blog</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; }
h1 { color: #21759b; }
.post { border-bottom: 1px solid #ddd; padding: 10px 0; }
</style></head>
<body>
<h1>Welcome to My Blog</h1>
<div class="post"><h2>Latest Update</h2><p>Posted on July 11, 2026</p></div>
<div class="post"><h2>Hello World!</h2><p>This is a WordPress site.</p></div>
<p><a href="/wp-admin">Login</a></p>
</body></html>""")

    def _serve_wordpress_login(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "nginx/1.24.0")
        self.end_headers()
        self.wfile.write(b"""<!DOCTYPE html>
<html><head><title>WordPress Login</title>
<style>
body { font-family: sans-serif; display: flex; justify-content: center; padding-top: 100px; background: #f1f1f1; }
form { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
input { display: block; width: 250px; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
input[type=submit] { background: #21759b; color: white; border: none; padding: 10px; cursor: pointer; }
</style></head><body>
<form method="POST" action="/wp-login.php">
<h2>WordPress Login</h2>
<input type="text" name="log" placeholder="Username or Email" required>
<input type="password" name="pwd" placeholder="Password" required>
<input type="submit" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
</form></body></html>""")

    def _serve_admin_login(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.57 (Ubuntu)")
        self.end_headers()
        self.wfile.write(b"""<!DOCTYPE html>
<html><head><title>Admin Panel</title>
<style>
body { font-family: sans-serif; background: #2c3e50; display: flex; justify-content: center; padding-top: 100px; }
form { background: #ecf0f1; padding: 30px; border-radius: 5px; }
input { display: block; width: 200px; padding: 8px; margin: 10px 0; }
</style></head><body>
<form method="POST" action="/login">
<h2>Administration Panel</h2>
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input type="submit" value="Sign In">
</form></body></html>""")

    def _serve_api(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "API Gateway v1.0")
        if "graphql" in self.path:
            self.send_header("Content-Type", "application/json")
            self.wfile.write(b'{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}')
        else:
            self.wfile.write(json.dumps({
                "status": "ok",
                "version": "2.4.1",
                "endpoints": ["/v1/users", "/v1/data", "/v1/config", "/graphql"],
                "docs": "https://api.example.com/docs"
            }).encode())
        self.end_headers()

    def _serve_phpmyadmin(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.57")
        self.end_headers()
        self.wfile.write(b"""<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>
body { font-family: sans-serif; padding: 20px; }
form { margin: 20px 0; }
</style></head><body>
<h1>phpMyAdmin</h1>
<form method="POST" action="/phpmyadmin/index.php">
Username: <input type="text" name="pma_username"><br>
Password: <input type="password" name="pma_password"><br>
<input type="submit" value="Go">
</form>
<p>Server: localhost via TCP/IP</p>
<p>Server version: 8.0.35</p>
</body></html>""")

    def log_message(self, format, *args):
        """Suppress default HTTP server logs"""
        pass


class WebTrapServer:
    """Manages multiple HTTP trap servers"""

    def __init__(self):
        self.servers = []

    def start_server(self, name, port, handler_class):
        server = HTTPServer(("0.0.0.0", port), handler_class)
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"  🌐 {name} trap running on port {port}")
        return server

    def start_all(self):
        print("🌐 Starting Web Honeypot Traps...")
        self.start_server("WordPress/HTTP", 80, WebTrapHandler)
        self.start_server("Admin Panel", 8081, WebTrapHandler)
        self.start_server("API Gateway", 8082, WebTrapHandler)
        print(f"🌐 Web traps active — logs: {LOG_DIR}")
        print("    Trapped endpoints: /wp-admin, /admin, /api, /phpmyadmin, etc.")

    def stop_all(self):
        for server in self.servers:
            server.shutdown()


def main():
    print("=" * 50)
    server = WebTrapServer()
    try:
        server.start_all()
        print("=" * 50)
        # Keep main thread alive
        while True:
            import time
import sys as _sys2; _sys2.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')); from alert_helper import log_alert
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  🛑  Shutting down web traps...")
        server.stop_all()
        print(f"  📊 Captured {len(CAPTURED_REQUESTS)} requests this session")

if __name__ == "__main__":
    main()
