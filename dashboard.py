#!/usr/bin/env python3
"""
Honeypot Lab Dashboard
Flask web app that shows live captured data from all honeypots.
"""
import os
import sys
import json
import glob
import datetime
import collections
from flask import Flask, render_template_string, jsonify, request

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(LAB_DIR, "logs")

app = Flask(__name__)


def get_log_files():
    """Get all log files grouped by honeypot type"""
    log_types = {
        "ssh": {"dir": os.path.join(LOGS_DIR, "ssh"), "pattern": "*.json", "label": "🐚 SSH/Cowrie", "icon": "🐚"},
        "ics": {"dir": os.path.join(LOGS_DIR, "ics"), "pattern": "*.log", "label": "🏭 ICS/Conpot", "icon": "🏭"},
        "creds": {"dir": os.path.join(LOGS_DIR, "creds"), "pattern": "*.json", "label": "🔑 Credentials", "icon": "🔑"},
        "web": {"dir": os.path.join(LOGS_DIR, "web"), "pattern": "*.jsonl", "label": "🌐 Web Traps", "icon": "🌐"},
        "db": {"dir": os.path.join(LOGS_DIR, "db"), "pattern": "*.jsonl", "label": "🗄️ DB Traps", "icon": "🗄️"},
        "malware": {"dir": os.path.join(LOGS_DIR, "malware"), "pattern": "*.jsonl", "label": "🦠 Malware", "icon": "🦠"},
        "rdp": {"dir": os.path.join(LOGS_DIR, "rdp"), "pattern": "*.jsonl", "label": "🖥️ RDP", "icon": "🖥️"},
    }
    return log_types


def tail_file(filepath, n=50):
    """Read last N lines of a file"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return lines[-n:]
    except:
        return []


def parse_log_entries(log_type, n=20):
    """Parse log entries from honeypot log files"""
    entries = []
    log_types = get_log_files()
    info = log_types.get(log_type, {})
    log_dir = info.get("dir", "")

    if not os.path.exists(log_dir):
        return []

    # Find log files
    patterns = info.get("pattern", "*")
    files = glob.glob(os.path.join(log_dir, patterns))

    for filepath in files:
        lines = tail_file(filepath, n)
        for line in lines:
            try:
                entry = json.loads(line.strip())
                entries.append(entry)
            except:
                entries.append({
                    "timestamp": "",
                    "raw": line.strip()[:200],
                    "source_ip": "parse error",
                })

    # Sort by timestamp descending
    entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return entries[:n]


def get_stats():
    """Get statistics from all honeypot logs"""
    stats = {}
    total_events = 0
    unique_ips = set()

    log_types = get_log_files()
    for log_type, info in log_types.items():
        log_dir = info["dir"]
        if not os.path.exists(log_dir):
            stats[log_type] = {"count": 0, "label": info["label"], "icon": info["icon"]}
            continue

        count = 0
        for filepath in glob.glob(os.path.join(log_dir, info["pattern"])):
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        count += 1
                        try:
                            entry = json.loads(line.strip())
                            if "source_ip" in entry and entry["source_ip"]:
                                unique_ips.add(entry["source_ip"])
                        except:
                            pass
            except:
                pass

        stats[log_type] = {
            "count": count,
            "label": info["label"],
            "icon": info["icon"],
        }
        total_events += count

    return stats, total_events, unique_ips


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🍯 Honeypot Lab - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0e17;
            color: #e0e0e0;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            padding: 20px 30px;
            border-bottom: 2px solid #e94560;
        }
        .header h1 { font-size: 24px; color: #fff; }
        .header p { color: #8899aa; font-size: 13px; margin-top: 5px; }
        .header .update-info { float: right; color: #8899aa; font-size: 12px; margin-top: 10px; }
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 10px;
            padding: 15px 30px;
            background: #111827;
        }
        .stat-card {
            background: #1e293b;
            padding: 12px 15px;
            border-radius: 8px;
            border-left: 3px solid #e94560;
        }
        .stat-card .icon { font-size: 20px; }
        .stat-card .count { font-size: 22px; font-weight: bold; color: #fff; margin-top: 5px; }
        .stat-card .label { font-size: 11px; color: #8899aa; text-transform: uppercase; }
        .main-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            padding: 15px 30px;
        }
        .big-stat {
            background: linear-gradient(135deg, #1e293b, #0f172a);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #334155;
        }
        .big-stat .number { font-size: 36px; font-weight: bold; color: #e94560; }
        .big-stat .desc { font-size: 12px; color: #8899aa; margin-top: 5px; }
        .content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 20px 30px;
        }
        .panel {
            background: #1e293b;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #334155;
        }
        .panel.full-width { grid-column: 1 / -1; }
        .panel-header {
            padding: 12px 20px;
            background: #0f172a;
            border-bottom: 1px solid #334155;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .panel-header h3 { font-size: 14px; color: #fff; }
        .panel-header .badge {
            background: #e94560;
            color: #fff;
            padding: 2px 10px;
            border-radius: 10px;
            font-size: 11px;
        }
        .log-table {
            width: 100%;
            font-size: 12px;
            border-collapse: collapse;
        }
        .log-table th {
            text-align: left;
            padding: 8px 15px;
            color: #8899aa;
            font-weight: 600;
            border-bottom: 1px solid #334155;
            position: sticky;
            top: 0;
            background: #1e293b;
        }
        .log-table td {
            padding: 6px 15px;
            border-bottom: 1px solid #2a3a4e;
            font-family: 'Courier New', monospace;
            color: #c8d6e5;
        }
        .log-table tr:hover td { background: #253544; }
        .log-table .ip { color: #48dbfb; }
        .log-table .method { color: #ff9f43; }
        .log-table .path { color: #54a0ff; }
        .log-table .timestamp { color: #5f6c80; }
        .empty-state { padding: 30px; text-align: center; color: #5f6c80; }
        .nav-tabs {
            display: flex;
            gap: 5px;
            padding: 10px 30px;
            background: #111827;
            flex-wrap: wrap;
        }
        .nav-tabs a {
            padding: 6px 14px;
            border-radius: 5px;
            text-decoration: none;
            color: #8899aa;
            font-size: 13px;
            transition: all 0.2s;
        }
        .nav-tabs a:hover, .nav-tabs a.active {
            background: #e94560;
            color: #fff;
        }
        .auto-refresh-toggle {
            margin-left: auto;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .auto-refresh-toggle input { cursor: pointer; }
        @media (max-width: 900px) {
            .content { grid-template-columns: 1fr; }
            .main-stats { grid-template-columns: 1fr; }
        }
        .top-attackers {
            padding: 15px;
        }
        .attacker-item {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #2a3a4e;
        }
        .attacker-ip { color: #48dbfb; font-family: monospace; }
        .attacker-count { color: #ff9f43; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🍯 Honeypot Lab Dashboard</h1>
        <p>Live monitoring of all honeypot traps — attacks captured in real-time</p>
        <span class="update-info">Last updated: {{ now }}</span>
    </div>

    <div class="nav-tabs">
        <a href="#" class="active">📊 Overview</a>
        <a href="#auto" style="cursor:default">
            <span class="auto-refresh-toggle">
                🔄 Auto-refresh:
                <input type="checkbox" id="autoRefresh" checked onchange="toggleRefresh()">
                <label for="autoRefresh" style="color:#8899aa;font-size:12px">every 5s</label>
            </span>
        </a>
    </div>

    <div class="stats-bar">
        {% for type, info in stats.items() %}
        <div class="stat-card">
            <div class="icon">{{ info.icon }}</div>
            <div class="count">{{ info.count }}</div>
            <div class="label">{{ info.label }}</div>
        </div>
        {% endfor %}
    </div>

    <div class="main-stats">
        <div class="big-stat">
            <div class="number">{{ total_events }}</div>
            <div class="desc">Total Events Captured</div>
        </div>
        <div class="big-stat">
            <div class="number">{{ unique_ips }}</div>
            <div class="desc">Unique IP Addresses</div>
        </div>
        <div class="big-stat">
            <div class="number">{{ running }}</div>
            <div class="desc">Honeypots Active</div>
        </div>
    </div>

    <div class="content">
        <!-- Recent SSH Activity -->
        <div class="panel">
            <div class="panel-header">
                <h3>🐚 Recent SSH Activity</h3>
                <span class="badge">{{ ssh_logs|length }}</span>
            </div>
            {% if ssh_logs %}
            <table class="log-table">
                <thead><tr><th>Time</th><th>Source IP</th><th>Activity</th></tr></thead>
                <tbody>
                {% for e in ssh_logs %}
                <tr>
                    <td class="timestamp">{{ e.timestamp[:19] if e.timestamp else '--' }}</td>
                    <td class="ip">{{ e.src_ip or e.source_ip or '--' }}</td>
                    <td>{{ e.message or e.event or 'connection' }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">⏳ No SSH activity yet. Attackers haven't found this port...</div>
            {% endif %}
        </div>

        <!-- Recent Web Activity -->
        <div class="panel">
            <div class="panel-header">
                <h3>🌐 Recent Web Activity</h3>
                <span class="badge">{{ web_logs|length }}</span>
            </div>
            {% if web_logs %}
            <table class="log-table">
                <thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th></tr></thead>
                <tbody>
                {% for e in web_logs %}
                <tr>
                    <td class="timestamp">{{ e.timestamp[:19] if e.timestamp else '--' }}</td>
                    <td class="ip">{{ e.source_ip or '--' }}</td>
                    <td class="method">{{ e.method or 'GET' }}</td>
                    <td class="path">{{ e.path or e.url or '/' }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">⏳ No web activity yet.</div>
            {% endif %}
        </div>

        <!-- Credential Capture Logs -->
        <div class="panel">
            <div class="panel-header">
                <h3>🔑 Captured Credentials</h3>
                <span class="badge">{{ creds_logs|length }}</span>
            </div>
            {% if creds_logs %}
            <table class="log-table">
                <thead><tr><th>Time</th><th>IP</th><th>Protocol</th><th>Details</th></tr></thead>
                <tbody>
                {% for e in creds_logs %}
                <tr>
                    <td class="timestamp">{{ e.timestamp[:19] if e.timestamp else '--' }}</td>
                    <td class="ip">{{ e.source_ip or '--' }}</td>
                    <td>{{ e.protocol or '--' }}</td>
                    <td>{{ e.message or e.username or '' }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">🔐 No credentials captured yet.</div>
            {% endif %}
        </div>

        <!-- ICS Activity -->
        <div class="panel">
            <div class="panel-header">
                <h3>🏭 ICS/SCADA Activity</h3>
                <span class="badge">{{ ics_logs|length }}</span>
            </div>
            {% if ics_logs %}
            <table class="log-table">
                <thead><tr><th>Time</th><th>Source</th><th>Event</th></tr></thead>
                <tbody>
                {% for e in ics_logs %}
                <tr>
                    <td class="timestamp">{{ e.timestamp[:19] if e.timestamp else '--' }}</td>
                    <td class="ip">{{ e.source_ip or e.remote or '--' }}</td>
                    <td>{{ e.event or e.message or 'probe' }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">🏭 No ICS probes detected. Shodan scanners haven't found you yet.</div>
            {% endif %}
        </div>

        <!-- Malware Capture -->
        <div class="panel">
            <div class="panel-header">
                <h3>🦠 Malware Capture</h3>
                <span class="badge">{{ malware_logs|length }}</span>
            </div>
            {% if malware_logs %}
            <table class="log-table">
                <thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Size</th></tr></thead>
                <tbody>
                {% for e in malware_logs %}
                <tr>
                    <td class="timestamp">{{ e.timestamp[:19] if e.timestamp else '--' }}</td>
                    <td class="ip">{{ e.source_ip or '--' }}</td>
                    <td>{{ e.method or 'GET' }}</td>
                    <td>{{ e.file_size or e.data_length or '-' }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">🦠 No malware uploads captured yet.</div>
            {% endif %}
        </div>

        <!-- DB Traps + RDP -->
        <div class="panel">
            <div class="panel-header">
                <h3>🗄️ Database & 🖥️ RDP Activity</h3>
                <span class="badge">{{ (db_logs|length) + (rdp_logs|length) }}</span>
            </div>
            {% if db_logs or rdp_logs %}
            <table class="log-table">
                <thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead>
                <tbody>
                {% for e in db_logs %}
                <tr>
                    <td class="timestamp">{{ e.timestamp[:19] if e.timestamp else '--' }}</td>
                    <td>🗄️ DB</td>
                    <td class="ip">{{ e.source_ip or '--' }}</td>
                    <td class="path">{{ e.method or '' }} {{ e.path or '' }}</td>
                </tr>
                {% endfor %}
                {% for e in rdp_logs %}
                <tr>
                    <td class="timestamp">{{ e.timestamp[:19] if e.timestamp else '--' }}</td>
                    <td>🖥️ RDP</td>
                    <td class="ip">{{ e.source_ip or '--' }}</td>
                    <td>Connection #{{ e.connection_id or '?' }} ({{ e.data_length or 0 }} bytes)</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">🗄️ No database or RDP probes detected.</div>
            {% endif %}
        </div>
    </div>

    <script>
        function toggleRefresh() {
            // Page will auto-refresh based on checkbox
        }
        setInterval(() => {
            if (document.getElementById('autoRefresh').checked) {
                location.reload();
            }
        }, 5000);
    </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    """Main dashboard page"""
    stats, total_events, unique_ips = get_stats()

    # Parse recent logs for each type
    ssh_logs = parse_log_entries("ssh", 15)
    web_logs = parse_log_entries("web", 15)
    creds_logs = parse_log_entries("creds", 15)
    ics_logs = parse_log_entries("ics", 15)
    malware_logs = parse_log_entries("malware", 15)
    db_logs = parse_log_entries("db", 10)
    rdp_logs = parse_log_entries("rdp", 10)

    # Count active honeypots (by checking log directories exist)
    running = sum(1 for info in get_log_files().values()
                  if os.path.exists(info["dir"]))

    return render_template_string(
        HTML_TEMPLATE,
        stats=stats,
        total_events=total_events,
        unique_ips=len(unique_ips),
        running=running,
        ssh_logs=ssh_logs,
        web_logs=web_logs,
        creds_logs=creds_logs,
        ics_logs=ics_logs,
        malware_logs=malware_logs,
        db_logs=db_logs,
        rdp_logs=rdp_logs,
        now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


@app.route("/api/stats")
def api_stats():
    """JSON endpoint for stats"""
    stats, total_events, unique_ips = get_stats()
    return jsonify({
        "stats": stats,
        "total_events": total_events,
        "unique_ips": len(unique_ips),
        "timestamp": datetime.datetime.now().isoformat()
    })


@app.route("/api/logs/<log_type>")
def api_logs(log_type):
    """JSON endpoint for specific log type"""
    if log_type not in get_log_files():
        return jsonify({"error": "Invalid log type", "types": list(get_log_files().keys())}), 400

    n = request.args.get("n", 20, type=int)
    entries = parse_log_entries(log_type, min(n, 100))
    return jsonify({"type": log_type, "count": len(entries), "entries": entries})


def main():
    print("=" * 50)
    print("  📊 Honeypot Lab Dashboard")
    print("=" * 50)
    print("  Starting web dashboard on http://127.0.0.1:5000")
    print("  View all captured attacks in real-time!")
    print("  Press Ctrl+C to stop")
    print("=" * 50)
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
