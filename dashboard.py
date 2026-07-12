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
Honeypot Lab Dashboard v2.0 — Live monitoring for all 17 honeypots
"""
import os, sys, json, glob, datetime, collections
from flask import Flask, render_template_string, jsonify, request

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(LAB_DIR, "logs")
app = Flask(__name__)

HONEYPOT_TYPES = {
    "ssh": {"dir": "ssh", "pattern": "cowrie.json", "label": "🐚 SSH/Cowrie", "icon": "🐚"},
    "ics": {"dir": "ics", "pattern": "*.jsonl", "label": "🏭 ICS/SCADA", "icon": "🏭"},
    "creds": {"dir": "creds", "pattern": "*.jsonl", "label": "🔑 Credentials", "icon": "🔑"},
    "web": {"dir": "web", "pattern": "*.jsonl", "label": "🌐 Web Traps", "icon": "🌐"},
    "db": {"dir": "db", "pattern": "*.jsonl", "label": "🗄️ DB Traps", "icon": "🗄️"},
    "malware": {"dir": "malware", "pattern": "*.jsonl", "label": "🦠 Malware", "icon": "🦠"},
    "rdp": {"dir": "rdp", "pattern": "*.jsonl", "label": "🖥️ RDP", "icon": "🖥️"},
    "smb": {"dir": "smb", "pattern": "*.jsonl", "label": "📁 SMB", "icon": "📁"},
    "dns": {"dir": "dns", "pattern": "*.jsonl", "label": "🌐 DNS", "icon": "🌐"},
    "sip": {"dir": "sip", "pattern": "*.jsonl", "label": "📞 SIP", "icon": "📞"},
    "redis": {"dir": "redis", "pattern": "*.jsonl", "label": "🔴 Redis", "icon": "🔴"},
    "vnc": {"dir": "vnc", "pattern": "*.jsonl", "label": "🖥️ VNC", "icon": "🖥️"},
    "telnet": {"dir": "telnet", "pattern": "*.jsonl", "label": "📟 Telnet", "icon": "📟"},
    "memcached": {"dir": "memcached", "pattern": "*.jsonl", "label": "📦 Memcached", "icon": "📦"},
    "mqtt": {"dir": "mqtt", "pattern": "*.jsonl", "label": "📡 MQTT", "icon": "📡"},
    "snmp": {"dir": "snmp", "pattern": "*.jsonl", "label": "🌐 SNMP", "icon": "🌐"},
    "ntp": {"dir": "ntp", "pattern": "*.jsonl", "label": "🕐 NTP", "icon": "🕐"},
}

def get_stats():
    stats = {}
    total_events = 0
    unique_ips = set()
    for key, info in HONEYPOT_TYPES.items():
        d = os.path.join(LOGS_DIR, info["dir"])
        count = 0
        if os.path.exists(d):
            for f in glob.glob(os.path.join(d, info["pattern"])):
                try:
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            count += 1
                            try:
                                e = json.loads(line.strip())
                                ip = e.get("source_ip") or e.get("src_ip") or ""
                                if ip: unique_ips.add(ip)
                            except: pass
                except: pass
        stats[key] = {"count": count, "label": info["label"], "icon": info["icon"]}
        total_events += count
    # Count active (has log files)
    running = sum(1 for key in HONEYPOT_TYPES if os.path.exists(os.path.join(LOGS_DIR, HONEYPOT_TYPES[key]["dir"])))
    return stats, total_events, len(unique_ips), running

def get_logs(log_type, n=15):
    info = HONEYPOT_TYPES.get(log_type)
    if not info: return []
    d = os.path.join(LOGS_DIR, info["dir"])
    if not os.path.exists(d): return []
    entries = []
    for f in glob.glob(os.path.join(d, info["pattern"])):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
                for line in lines[-n:]:
                    try:
                        e = json.loads(line.strip())
                        e["_type"] = log_type
                        entries.append(e)
                    except:
                        entries.append({"timestamp": "", "_raw": line.strip()[:150], "source_ip": "[parse error]"})
        except: pass
    entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return entries[:n]

HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>🍯 Honeypot Lab v2.0</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e17;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);padding:20px 30px;border-bottom:2px solid #e94560}
.header h1{font-size:24px;color:#fff}
.header .sub{color:#8899aa;font-size:13px;margin-top:3px}
.header .sub span{color:#e94560}
.header .right{float:right;text-align:right}
.header .right .time{color:#8899aa;font-size:12px}
.stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:6px;padding:12px 20px;background:#111827}
.stat-card{background:#1e293b;padding:8px 10px;border-radius:6px;border-left:3px solid #e94560;text-align:center}
.stat-card .icon{font-size:16px}
.stat-card .count{font-size:18px;font-weight:700;color:#fff}
.stat-card .label{font-size:10px;color:#8899aa;text-transform:uppercase}
.main-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:12px 20px}
.big-stat{background:linear-gradient(135deg,#1e293b,#0f172a);padding:15px;border-radius:10px;text-align:center;border:1px solid #334155}
.big-stat .number{font-size:32px;font-weight:700;color:#e94560}
.big-stat .desc{font-size:11px;color:#8899aa;margin-top:3px}
.nav-tabs{display:flex;gap:5px;padding:8px 20px;background:#111827;flex-wrap:wrap;align-items:center}
.nav-tabs .tab{display:inline-block}
.nav-tabs .tab a{padding:5px 12px;border-radius:4px;text-decoration:none;color:#8899aa;font-size:12px;transition:.2s;display:inline-block}
.nav-tabs .tab a:hover,.nav-tabs .tab a.active{background:#e94560;color:#fff}
.nav-tabs .refresh-toggle{margin-left:auto;color:#8899aa;font-size:12px;display:flex;align-items:center;gap:6px}
.nav-tabs .refresh-toggle input{cursor:pointer}
.content{display:grid;grid-template-columns:1fr 1fr;gap:15px;padding:15px 20px}
.panel{background:#1e293b;border-radius:10px;overflow:hidden;border:1px solid #334155}
.panel.full{grid-column:1/-1}
.panel-header{padding:10px 15px;background:#0f172a;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}
.panel-header h3{font-size:13px;color:#fff}
.panel-header .badge{background:#e94560;color:#fff;padding:2px 8px;border-radius:10px;font-size:10px}
.log-table{width:100%;font-size:11px;border-collapse:collapse}
.log-table th{text-align:left;padding:6px 12px;color:#8899aa;font-weight:600;border-bottom:1px solid #334155;background:#1e293b;position:sticky;top:0}
.log-table td{padding:4px 12px;border-bottom:1px solid #2a3a4e;font-family:'Courier New',monospace;color:#c8d6e5}
.log-table tr:hover td{background:#253544}
.log-table .ip{color:#48dbfb}
.log-table .method{color:#ff9f43}
.log-table .path{color:#54a0ff}
.log-table .ts{color:#5f6c80;white-space:nowrap}
.empty-state{padding:30px;text-align:center;color:#5f6c80;font-size:12px}
.heatmap-grid{display:flex;gap:3px;padding:15px;flex-wrap:wrap;justify-content:center}
.hm-hour{width:28px;text-align:center;font-size:9px;color:#8899aa}
.hm-bar{width:100%;background:#1e293b;border-radius:3px;position:relative;margin-top:2px}
.hm-fill{background:#e94560;border-radius:3px;min-height:3px;transition:height .3s}
@media(max-width:900px){.content{grid-template-columns:1fr}.main-stats{grid-template-columns:1fr 1fr}}
</style></head>
<body>
<div class="header">
<h1>🍯 Honeypot Lab v2.0</h1>
<div class="sub">17 honeypot types · <span>Developed by JOJIN JOHN</span> · Cybersecurity Attack & Defense Lab</div>
<div class="right"><span class="time">Updated: {{ now }}</span></div></div>
<div class="nav-tabs">
<span class="tab"><a href="#" class="active">📊 Overview</a></span>
<span class="tab"><a href="/heatmap">🔥 Heatmap</a></span>
<span class="tab"><a href="/correlation">🔗 Correlation</a></span>
<span class="tab"><a href="/api/stats">📡 API</a></span>
<span class="refresh-toggle">🔄 Auto: <input type="checkbox" id="autoR" checked onchange="autoR.checked&&setTimeout(()=>location.reload(),5000)"></span>
</div>
<div class="stats-bar">
{% for key,info in stats.items() %}
<div class="stat-card"><div class="icon">{{ info.icon }}</div><div class="count">{{ info.count }}</div><div class="label">{{ info.label }}</div></div>
{% endfor %}
</div>
<div class="main-stats">
<div class="big-stat"><div class="number">{{ total_events }}</div><div class="desc">Total Events</div></div>
<div class="big-stat"><div class="number">{{ unique_ips }}</div><div class="desc">Unique IPs</div></div>
<div class="big-stat"><div class="number">17</div><div class="desc">Honeypot Types</div></div>
<div class="big-stat"><div class="number">{{ "🟢 Active" if total_events > 0 else "⏹️ Idle" }}</div><div class="desc">Lab Status</div></div>
</div>
<div class="content">
<div class="panel"><div class="panel-header"><h3>🐚 SSH</h3><span class="badge">{{ ssh|length }}</span></div>{% if ssh %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Event</th></tr></thead><tbody>{% for e in ssh %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.src_ip or e.source_ip or '--' }}</td><td>{{ e.message or e.event or 'connection' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state">⏳ No SSH activity yet</div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>🌐 Web Traps</h3><span class="badge">{{ web|length }}</span></div>{% if web %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th></tr></thead><tbody>{% for e in web %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.source_ip or '--' }}</td><td class="method">{{ e.method or 'GET' }}</td><td class="path">{{ e.path or '/' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state">⏳ No web activity</div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>🔑 Credentials</h3><span class="badge">{{ creds|length }}</span></div>{% if creds %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Protocol</th><th>Creds</th></tr></thead><tbody>{% for e in creds %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.source_ip or '--' }}</td><td>{{ e.protocol or e.service or '--' }}</td><td>{{ e.username or '' }}{{ (':' + e.password) if e.password else '' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state">🔐 No credentials captured</div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>🦠 Malware</h3><span class="badge">{{ malware|length }}</span></div>{% if malware %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Size</th></tr></thead><tbody>{% for e in malware %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.source_ip or '--' }}</td><td>{{ e.method or 'GET' }}</td><td>{{ e.file_size or e.data_length or '-' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state">🦠 No malware captured</div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>📁 SMB / 🖥️ RDP / 📟 Telnet</h3><span class="badge">{{ smb|length + rdp|length + telnet|length }}</span></div>{% if smb or rdp or telnet %}<table class="log-table"><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>{% for e in smb %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📁 SMB</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.note or 'probe' }}</td></tr>{% endfor %}{% for e in rdp %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🖥️ RDP</td><td class="ip">{{ e.source_ip }}</td><td>Conn #{{ e.connection_id or '?' }}</td></tr>{% endfor %}{% for e in telnet %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📟 Telnet</td><td class="ip">{{ e.source_ip }}</td><td>IoT/Mirai probe</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state">No SMB/RDP/Telnet activity</div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>🌐 DNS / 📞 SIP / 📡 MQTT / 🕐 NTP</h3><span class="badge">{{ dns|length + sip|length + mqtt|length + ntp|length }}</span></div>{% if dns or sip or mqtt or ntp %}<table class="log-table"><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>{% for e in dns %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🌐 DNS</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.query or 'query' }} {{ e.query_type or '' }}</td></tr>{% endfor %}{% for e in sip %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📞 SIP</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.method or '' }} {{ e.uri or '' }}</td></tr>{% endfor %}{% for e in mqtt %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📡 MQTT</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.packet_type or '' }} {{ e.topic or '' }}</td></tr>{% endfor %}{% for e in ntp %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🕐 NTP</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data_length or '' }} bytes</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state">No DNS/SIP/MQTT/NTP activity</div>{% endif %}</div>
<div class="panel full"><div class="panel-header"><h3>🏭 ICS / 🗄️ DB / 🔴 Redis / 🖥️ VNC / 📦 Memcached / 🌐 SNMP</h3><span class="badge">{{ ics|length + db|length + redis|length + vnc|length + memcached|length + snmp|length }}</span></div>{% if ics or db or redis or vnc or memcached or snmp %}<table class="log-table"><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>{% for e in ics %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🏭 ICS</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.protocol or 'probe' }}</td></tr>{% endfor %}{% for e in db %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🗄️ DB</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.method or '' }} {{ e.path or '' }}</td></tr>{% endfor %}{% for e in redis %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🔴 Redis</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data[:50] if e.data else 'probe' }}</td></tr>{% endfor %}{% for e in vnc %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🖥️ VNC</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data_length or '' }} bytes</td></tr>{% endfor %}{% for e in memcached %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📦 Memcache</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data_length or '' }} bytes</td></tr>{% endfor %}{% for e in snmp %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🌐 SNMP</td><td class="ip">{{ e.source_ip }}</td><td>community='{{ e.community or '' }}'</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state">No ICS/DB/Redis/VNC/Memcached/SNMP activity</div>{% endif %}</div>
</div>
<script>
let autoR=document.getElementById('autoR');
setInterval(()=>{if(autoR&&autoR.checked)location.reload()},5000);
</script>
</body></html>"""

@app.route("/")
def index():
    stats, total, uips, running = get_stats()
    return render_template_string(HTML, stats=stats, total_events=total, unique_ips=uips, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ssh=get_logs("ssh"), web=get_logs("web"), creds=get_logs("creds"), malware=get_logs("malware"), rdp=get_logs("rdp"), smb=get_logs("smb"), dns=get_logs("dns"), sip=get_logs("sip"), redis=get_logs("redis"), vnc=get_logs("vnc"), telnet=get_logs("telnet"), memcached=get_logs("memcached"), mqtt=get_logs("mqtt"), snmp=get_logs("snmp"), ntp=get_logs("ntp"), ics=get_logs("ics"), db=get_logs("db"))

@app.route("/api/stats")
def api_stats():
    stats, total, uips, running = get_stats()
    return jsonify({"stats": stats, "total_events": total, "unique_ips": uips, "running": running, "timestamp": datetime.datetime.now().isoformat()})

@app.route("/api/logs/<log_type>")
def api_logs(log_type):
    n = request.args.get("n", 20, type=int)
    entries = get_logs(log_type, min(n, 100))
    return jsonify({"type": log_type, "count": len(entries), "entries": entries})

@app.route("/heatmap")
def heatmap():
    try:
        sys.path.insert(0, LAB_DIR)
        from features.heatmap import generate_heatmap_data
        data = generate_heatmap_data()
    except:
        data = {"hourly": {}, "daily": {}, "by_type": {}, "sources": []}
    return jsonify(data)

@app.route("/correlation")
def correlation():
    try:
        sys.path.insert(0, LAB_DIR)
        from features.correlation import correlate
        data = correlate()
    except:
        data = {"error": "correlation not available"}
    return jsonify(data)

if __name__ == "__main__":
    print("="*55)
    print("  📊 Honeypot Lab Dashboard v2.0")
    print("  Developed by JOJIN JOHN")
    print("="*55)
    print(f"  Dashboard: http://127.0.0.1:5000")
    print(f"  All 17 honeypots + live auto-refresh")
    print(f"  Press Ctrl+C to stop")
    print("="*55)
    app.run(host="127.0.0.1", port=5000, debug=False)
