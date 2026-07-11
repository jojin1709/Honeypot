#!/usr/bin/env python3
"""
Database Honeypot Traps
Fake Elasticsearch and MongoDB servers that log all queries.
"""
import os
import sys
import json
import datetime
import socket
import threading

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(LAB_DIR, "logs", "db")
os.makedirs(LOG_DIR, exist_ok=True)


class ElasticsearchTrap:
    """Fake Elasticsearch server that logs all requests"""

    def __init__(self, host="0.0.0.0", port=9200):
        self.host = host
        self.port = port
        self.server = None
        self.running = False

    def handle_client(self, conn, addr):
        """Handle HTTP connection to fake ES"""
        client_ip = addr[0]
        timestamp = datetime.datetime.now().isoformat()
        try:
            data = conn.recv(8192)
            if not data:
                return

            request_text = data.decode("utf-8", errors="replace")
            lines = request_text.split("\r\n")
            first_line = lines[0] if lines else ""

            # Extract request info
            parts = first_line.split(" ")
            method = parts[0] if len(parts) > 0 else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"

            # Extract headers
            headers = {}
            body = ""
            in_headers = True
            for line in lines[1:]:
                if in_headers and line == "":
                    in_headers = False
                    continue
                if in_headers and ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
                elif not in_headers:
                    body += line

            entry = {
                "timestamp": timestamp,
                "source_ip": client_ip,
                "method": method,
                "path": path,
                "headers": headers,
                "body": body[:1000],
            }

            # Log it
            log_file = os.path.join(LOG_DIR, "elasticsearch_traps.jsonl")
            with open(log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

            print(f"  🗄️  ES | {timestamp[:19]} | {client_ip:>15} | {method:>4} {path}")

            # Respond based on path
            if path.startswith("/_search") or "/_search" in path:
                response = self._search_response()
            elif path == "/_nodes" or path.startswith("/_nodes/"):
                response = self._nodes_response()
            elif path == "/_cluster/health":
                response = self._cluster_health()
            elif path == "/":
                response = self._root_response()
            elif path.startswith("/_cat"):
                response = self._cat_response()
            else:
                response = self._generic_response(path)

            conn.sendall(response.encode())
        except Exception as e:
            print(f"  ❌ ES error: {e}")
        finally:
            conn.close()

    def _root_response(self):
        return json.dumps({
            "name": "node-es-01",
            "cluster_name": "production-cluster",
            "cluster_uuid": "XjY5QmRqTkWvz4H8pL6sNg",
            "version": {
                "number": "7.17.15",
                "build_flavor": "default",
                "build_type": "deb",
                "build_hash": "a0e3f7f8e8e8",
                "build_date": "2024-01-15T10:00:00Z",
                "lucene_version": "8.11.1"
            },
            "tagline": "You Know, for Search"
        }) + "\n"

    def _cluster_health(self):
        return json.dumps({
            "cluster_name": "production-cluster",
            "status": "yellow",
            "timed_out": False,
            "number_of_nodes": 3,
            "number_of_data_nodes": 2,
            "active_primary_shards": 45,
            "active_shards": 90,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 5,
            "delayed_unassigned_shards": 0
        }) + "\n"

    def _nodes_response(self):
        return json.dumps({
            "_nodes": {"total": 3, "successful": 3, "failed": 0},
            "cluster_name": "production-cluster",
            "nodes": {
                "node1": {
                    "name": "node-es-01",
                    "transport_address": "10.0.0.1:9300",
                    "host": "10.0.0.1",
                    "ip": "10.0.0.1",
                    "version": "7.17.15",
                    "roles": ["data", "ingest", "master"]
                }
            }
        }) + "\n"

    def _search_response(self):
        return json.dumps({
            "took": 12,
            "timed_out": False,
            "_shards": {"total": 5, "successful": 5, "skipped": 0, "failed": 0},
            "hits": {
                "total": {"value": 0, "relation": "eq"},
                "max_score": None,
                "hits": []
            }
        }) + "\n"

    def _cat_response(self):
        return "green  open  .monitoring-es-7  abc123  5 1  0 0  10kb  5kb\n"

    def _generic_response(self, path):
        return json.dumps({
            "acknowledged": True,
            "shards_acknowledged": True,
            "index": path.strip("/").split("/")[0] if path.strip("/") else "unknown"
        }) + "\n"

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(50)
        self.running = True
        print(f"  🗄️  Elasticsearch trap on port {self.port}")

        def serve():
            while self.running:
                try:
                    conn, addr = self.server.accept()
                    thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                    thread.start()
                except:
                    break

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()


class MongoDumpTrap:
    """Fake MongoDB server that logs connection attempts"""

    def __init__(self, host="0.0.0.0", port=27017):
        self.host = host
        self.port = port
        self.server = None
        self.running = False

    def handle_client(self, conn, addr):
        """Handle TCP connection (basic MongoDB wire protocol logging)"""
        client_ip = addr[0]
        timestamp = datetime.datetime.now().isoformat()
        try:
            data = conn.recv(4096)
            if not data:
                return

            # MongoDB wire protocol: log the raw bytes header info
            entry = {
                "timestamp": timestamp,
                "source_ip": client_ip,
                "protocol": "mongodb",
                "data_length": len(data),
                "hex_dump": data[:200].hex()[:200],
            }

            log_file = os.path.join(LOG_DIR, "mongodb_traps.jsonl")
            with open(log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

            print(f"  🗄️  MDB | {timestamp[:19]} | {client_ip:>15} | {len(data)} bytes")

        except Exception as e:
            print(f"  ❌ MongoDB error: {e}")
        finally:
            conn.close()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(50)
        self.running = True
        print(f"  🗄️  MongoDB trap on port {self.port}")

        def serve():
            while self.running:
                try:
                    conn, addr = self.server.accept()
                    thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                    thread.start()
                except:
                    break

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()


def main():
    print("=" * 50)
    es = ElasticsearchTrap()
    mongo = MongoDumpTrap()

    try:
        es.start()
        mongo.start()
        print("=" * 50)
        print("  🗄️  DB Traps active — logging all queries")
        print("  📁 Logs:", LOG_DIR)
        print("=" * 50)

        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  🛑  Shutting down DB traps...")
        es.stop()
        mongo.stop()
        print("  ✅ DB traps stopped")


if __name__ == "__main__":
    main()
