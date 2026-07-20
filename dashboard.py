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

# Import features
sys.path.insert(0, LAB_DIR)
try:
    from features.geoip import lookup_ip as geoip_lookup
except: geoip_lookup = None
try:
    from features.intel import check_abuseipdb, check_virustotal
except: check_abuseipdb = check_virustotal = None
try:
    from features.notifications import notify, notify_config
except: notify = notify_config = None

# Notification alert log
ALERT_LOG = os.path.join(LOGS_DIR, "alerts.jsonl")
def log_alert(alert_type, data):
    ts = datetime.datetime.now().isoformat()
    entry = {"timestamp": ts, "type": alert_type, "source_ip": data.get("source_ip", ""), "detail": str(data)[:200]}
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    if notify:
        try: notify(alert_type, data)
        except: pass

def get_alerts(n=50):
    if not os.path.exists(ALERT_LOG): return []
    try:
        with open(ALERT_LOG, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        entries = []
        for line in lines[-n:]:
            try: entries.append(json.loads(line.strip()))
            except: pass
        entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return entries
    except: return []

def enrich_with_geoip(entries):
    if not geoip_lookup: return entries
    for e in entries:
        ip = e.get("source_ip") or e.get("src_ip") or ""
        if not ip: continue
        if ip.startswith("127.") or ip == "::1":
            e["_country"] = "Local"
            e["_city"] = "Loopback"
            e["_isp"] = "Internal"
            continue
        try:
            geo = geoip_lookup(ip)
            e["_country"] = geo.get("country", "")
            e["_city"] = geo.get("city", "")
            e["_isp"] = geo.get("isp", "")
        except: pass
    return entries

def check_ip_intel(ip):
    results = {}
    if not ip or ip in ("", "127.0.0.1", "::1"): return results
    try:
        if check_abuseipdb:
            key = os.environ.get("ABUSEIPDB_KEY", "")
            if key: results["abuseipdb"] = check_abuseipdb(ip, key)
    except: pass
    try:
        if check_virustotal:
            key = os.environ.get("VIRUSTOTAL_KEY", "")
            if key: results["virustotal"] = check_virustotal(ip, key)
    except: pass
    return results

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
    return enrich_with_geoip(entries[:n])

HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Honeypot Lab v2.0</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--bg-card-hover:#1A2540;--bg-elevated:#1E293B;--border:#1E293B;--border-subtle:#162032;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--accent-glow:rgba(34,211,238,0.25);--danger:#EF4444;--danger-dim:rgba(239,68,68,0.12);--success:#10B981;--success-dim:rgba(16,185,129,0.12);--warning:#F59E0B;--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono','Cascadia Code','Fira Code',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
@media(prefers-reduced-motion:no-preference){@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}.stat-card,.big-stat,.panel{animation:fadeUp .4s ease both}.stat-card:nth-child(2){animation-delay:.03s}.stat-card:nth-child(3){animation-delay:.06s}.stat-card:nth-child(4){animation-delay:.09s}.stat-card:nth-child(5){animation-delay:.12s}.stat-card:nth-child(6){animation-delay:.15s}.stat-card:nth-child(7){animation-delay:.18s}.stat-card:nth-child(8){animation-delay:.21s}.stat-card:nth-child(9){animation-delay:.24s}.stat-card:nth-child(10){animation-delay:.27s}.stat-card:nth-child(11){animation-delay:.30s}.stat-card:nth-child(12){animation-delay:.33s}.stat-card:nth-child(13){animation-delay:.36s}.stat-card:nth-child(14){animation-delay:.39s}.stat-card:nth-child(15){animation-delay:.42s}.stat-card:nth-child(16){animation-delay:.45s}.stat-card:nth-child(17){animation-delay:.48s}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh;-webkit-font-smoothing:antialiased}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.header-left{display:flex;align-items:center;gap:14px}
.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.header-text h1{font-size:17px;font-weight:700;color:var(--text-primary);letter-spacing:-.02em}
.header-text .sub{font-size:12px;color:var(--text-muted);margin-top:1px}
.header-text .sub span{color:var(--accent);font-weight:500}
.header-right{display:flex;align-items:center;gap:16px}
.status-pill{display:flex;align-items:center;gap:6px;background:var(--success-dim);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--success);animation:pulse 2s infinite}
.timestamp{font-size:11px;color:var(--text-dim);font-family:var(--mono)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border);align-items:center}
.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}
.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}
.nav a.active{color:var(--accent);background:var(--accent-dim)}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.auto-label{font-size:11px;color:var(--text-dim);display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
.auto-label input{accent-color:var(--accent);cursor:pointer}
.stats-bar{display:grid;grid-template-columns:repeat(17,1fr);gap:6px;padding:14px 28px;background:var(--bg-base)}
.stat-card{background:var(--bg-card);padding:10px 6px;border-radius:var(--radius-sm);text-align:center;border:1px solid var(--border-subtle);transition:all .2s;cursor:default;position:relative;overflow:hidden}
.stat-card:hover{background:var(--bg-card-hover);border-color:var(--accent);transform:translateY(-1px)}
.stat-card.has-events{border-color:rgba(34,211,238,.3)}
.stat-card.has-events::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.stat-card .icon{font-size:15px;margin-bottom:4px}
.stat-card .count{font-size:20px;font-weight:800;color:var(--text-primary);line-height:1.1;font-family:var(--mono)}
.stat-card.has-events .count{color:var(--accent)}
.stat-card .label{font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.04em;margin-top:3px;font-weight:600}
.big-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:14px 28px}
.big-stat{background:var(--bg-card);padding:18px 16px;border-radius:var(--radius);text-align:center;border:1px solid var(--border-subtle);position:relative;overflow:hidden}
.big-stat::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:.4}
.big-stat .number{font-size:30px;font-weight:800;color:var(--accent);font-family:var(--mono);line-height:1}
.big-stat .desc{font-size:11px;color:var(--text-muted);margin-top:6px;font-weight:500}
.big-stat.status-active .number{color:var(--success)}
.big-stat.status-idle .number{color:var(--text-dim);font-size:22px}
.content{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:6px 28px 28px}
.panel{background:var(--bg-card);border-radius:var(--radius);overflow:hidden;border:1px solid var(--border-subtle);transition:border-color .2s}
.panel:hover{border-color:var(--border)}
.panel.full{grid-column:1/-1}
.panel-header{padding:10px 16px;background:var(--bg-surface);border-bottom:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center}
.panel-header h3{font-size:12px;font-weight:700;color:var(--text-primary);letter-spacing:-.01em}
.panel-header .badge{background:var(--accent-dim);color:var(--accent);padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;font-family:var(--mono)}
.panel-header .badge.zero{background:var(--bg-elevated);color:var(--text-dim)}
.log-table{width:100%;font-size:11px;border-collapse:collapse}
.log-table th{text-align:left;padding:7px 14px;color:var(--text-dim);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border-subtle);background:var(--bg-card);position:sticky;top:0}
.log-table td{padding:6px 14px;border-bottom:1px solid var(--border-subtle);font-family:var(--mono);color:var(--text-secondary);font-size:11px}
.log-table tr:last-child td{border-bottom:none}
.log-table tr:hover td{background:var(--bg-card-hover)}
.log-table .ip{color:var(--accent);font-weight:500}
.log-table .method{color:var(--warning);font-weight:600}
.log-table .path{color:#818CF8}
.log-table .ts{color:var(--text-dim);white-space:nowrap;font-size:10px}
.log-table .event-text{color:var(--text-secondary);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log-table .geo{color:var(--success);font-size:10px;font-family:var(--mono)}
.alert-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700;font-family:var(--mono);text-transform:uppercase}
.alert-badge.critical{background:var(--danger-dim);color:var(--danger)}
.alert-badge.warning{background:rgba(245,158,11,0.12);color:var(--warning)}
.alert-badge.info{background:var(--accent-dim);color:var(--accent)}
.empty-state{padding:28px 16px;text-align:center;color:var(--text-dim);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:6px}
.empty-state .empty-icon{font-size:20px;opacity:.5}
.empty-state .empty-text{color:var(--text-muted)}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:var(--bg-base)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}
@media(max-width:1200px){.stats-bar{grid-template-columns:repeat(9,1fr)}}
@media(max-width:900px){.content{grid-template-columns:1fr}.big-stats{grid-template-columns:1fr 1fr}.stats-bar{grid-template-columns:repeat(6,1fr)}.header{flex-direction:column;align-items:flex-start}}
@media(max-width:600px){.stats-bar{grid-template-columns:repeat(3,1fr)}.big-stats{grid-template-columns:1fr}}
</style></head>
<body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span class="dot"></span> {{ running }}/17 Active</div><div class="timestamp">{{ now }}</div></div></div>
<div class="nav"><a href="/" class="active">Overview</a><a href="/heatmap">Heatmap</a><a href="/correlation">Correlation</a><a href="/api">API</a><a href="/settings">Settings</a><a href="/attack-map">Attack Map</a><a href="/timeline">Timeline</a><a href="/statistics">Statistics</a><div class="nav-right"><label class="auto-label"><input type="checkbox" id="autoR" checked> Auto-refresh</label></div></div>
<div class="stats-bar">{% for key,info in stats.items() %}<div class="stat-card{{ ' has-events' if info.count > 0 else '' }}"><div class="icon">{{ info.icon }}</div><div class="count">{{ info.count }}</div><div class="label">{{ info.label.split(' ', 1)[-1] if ' ' in info.label else info.label }}</div></div>{% endfor %}</div>
<div class="big-stats"><div class="big-stat"><div class="number">{{ total_events }}</div><div class="desc">Total Events</div></div><div class="big-stat"><div class="number">{{ unique_ips }}</div><div class="desc">Unique IPs</div></div><div class="big-stat"><div class="number">17</div><div class="desc">Honeypot Types</div></div><div class="big-stat {{ 'status-active' if total_events > 0 else 'status-idle' }}"><div class="number">{{ "Active" if total_events > 0 else "Idle" }}</div><div class="desc">Lab Status</div></div></div>
<div class="content">
<div class="panel"><div class="panel-header"><h3>SSH / Cowrie</h3><span class="badge{{ ' zero' if not ssh }}">{{ ssh|length }}</span></div>{% if ssh %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Country</th><th>Event</th></tr></thead><tbody>{% for e in ssh %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.src_ip or e.source_ip or '--' }}</td><td class="geo">{{ e._country or '' }}{% if e._city %} · {{ e._city }}{% endif %}</td><td class="event-text">{{ e.message or e.event or 'connection' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">🐚</span><span class="empty-text">No SSH activity yet</span></div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>Web Traps</h3><span class="badge{{ ' zero' if not web }}">{{ web|length }}</span></div>{% if web %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Country</th><th>Method</th><th>Path</th></tr></thead><tbody>{% for e in web %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.source_ip or '--' }}</td><td class="geo">{{ e._country or '' }}{% if e._city %} · {{ e._city }}{% endif %}</td><td class="method">{{ e.method or 'GET' }}</td><td class="path">{{ e.path or '/' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">🌐</span><span class="empty-text">No web activity</span></div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>Credentials</h3><span class="badge{{ ' zero' if not creds }}">{{ creds|length }}</span></div>{% if creds %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Protocol</th><th>Credentials</th></tr></thead><tbody>{% for e in creds %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.source_ip or '--' }}</td><td>{{ e.protocol or e.service or '--' }}</td><td style="color:var(--danger)">{{ e.username or '' }}{{ ':' + e.password if e.password else '' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">🔑</span><span class="empty-text">No credentials captured</span></div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>Malware</h3><span class="badge{{ ' zero' if not malware }}">{{ malware|length }}</span></div>{% if malware %}<table class="log-table"><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Size</th></tr></thead><tbody>{% for e in malware %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td class="ip">{{ e.source_ip or '--' }}</td><td>{{ e.method or 'GET' }}</td><td>{{ e.file_size or e.data_length or '-' }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">🦠</span><span class="empty-text">No malware captured</span></div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>SMB / RDP / Telnet</h3><span class="badge{{ ' zero' if not (smb or rdp or telnet) }}">{{ smb|length + rdp|length + telnet|length }}</span></div>{% if smb or rdp or telnet %}<table class="log-table"><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>{% for e in smb %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📁 SMB</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.note or 'probe' }}</td></tr>{% endfor %}{% for e in rdp %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🖥️ RDP</td><td class="ip">{{ e.source_ip }}</td><td>Conn #{{ e.connection_id or '?' }}</td></tr>{% endfor %}{% for e in telnet %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📟 Telnet</td><td class="ip">{{ e.source_ip }}</td><td>IoT/Mirai probe</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">📁</span><span class="empty-text">No SMB/RDP/Telnet activity</span></div>{% endif %}</div>
<div class="panel"><div class="panel-header"><h3>DNS / SIP / MQTT / NTP</h3><span class="badge{{ ' zero' if not (dns or sip or mqtt or ntp) }}">{{ dns|length + sip|length + mqtt|length + ntp|length }}</span></div>{% if dns or sip or mqtt or ntp %}<table class="log-table"><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>{% for e in dns %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🌐 DNS</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.query or 'query' }} {{ e.query_type or '' }}</td></tr>{% endfor %}{% for e in sip %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📞 SIP</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.method or '' }} {{ e.uri or '' }}</td></tr>{% endfor %}{% for e in mqtt %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📡 MQTT</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.packet_type or '' }} {{ e.topic or '' }}</td></tr>{% endfor %}{% for e in ntp %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🕐 NTP</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data_length or '' }} bytes</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">🌐</span><span class="empty-text">No DNS/SIP/MQTT/NTP activity</span></div>{% endif %}</div>
<div class="panel full"><div class="panel-header"><h3>ICS / DB / Redis / VNC / Memcached / SNMP</h3><span class="badge{{ ' zero' if not (ics or db or redis or vnc or memcached or snmp) }}">{{ ics|length + db|length + redis|length + vnc|length + memcached|length + snmp|length }}</span></div>{% if ics or db or redis or vnc or memcached or snmp %}<table class="log-table"><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>{% for e in ics %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🏭 ICS</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.protocol or 'probe' }}</td></tr>{% endfor %}{% for e in db %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🗄️ DB</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.method or '' }} {{ e.path or '' }}</td></tr>{% endfor %}{% for e in redis %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🔴 Redis</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data[:50] if e.data else 'probe' }}</td></tr>{% endfor %}{% for e in vnc %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🖥️ VNC</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data_length or '' }} bytes</td></tr>{% endfor %}{% for e in memcached %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>📦 Memcache</td><td class="ip">{{ e.source_ip }}</td><td>{{ e.data_length or '' }} bytes</td></tr>{% endfor %}{% for e in snmp %}<tr><td class="ts">{{ e.timestamp[:19] if e.timestamp else '--' }}</td><td>🌐 SNMP</td><td class="ip">{{ e.source_ip }}</td><td>community='{{ e.community or '' }}'</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">🏭</span><span class="empty-text">No ICS/DB/Redis/VNC/Memcached/SNMP activity</span></div>{% endif %}</div>
<div class="panel full"><div class="panel-header"><h3>Recent Alerts</h3><span class="badge{{ ' zero' if not alerts }}">{{ alerts|length }}</span></div>{% if alerts %}<table class="log-table"><thead><tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr></thead><tbody>{% for a in alerts %}<tr><td class="ts">{{ a.timestamp[:19] if a.timestamp else '--' }}</td><td><span class="alert-badge critical">{{ a.type }}</span></td><td class="ip">{{ a.source_ip }}</td><td class="event-text">{{ a.detail[:100] }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty-state"><span class="empty-icon">🔔</span><span class="empty-text">No alerts yet — enable notifications in config.ini</span></div>{% endif %}</div>
</div>
<script>let c=document.getElementById('autoR');setInterval(()=>{if(c&&c.checked)location.reload()},5000);</script>
</body></html>"""

HEATMAP_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Heatmap - Honeypot Lab</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--bg-card-hover:#1A2540;--bg-elevated:#1E293B;--border:#1E293B;--border-subtle:#162032;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--success:#10B981;--success-dim:rgba(16,185,129,0.12);--danger:#EF4444;--warning:#F59E0B;--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono','Cascadia Code','Fira Code',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
@media(prefers-reduced-motion:no-preference){@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}.panel,.big-stat{animation:fadeUp .4s ease both}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh;-webkit-font-smoothing:antialiased}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.header-left{display:flex;align-items:center;gap:14px}
.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.header-text h1{font-size:17px;font-weight:700;color:var(--text-primary);letter-spacing:-.02em}
.header-text .sub{font-size:12px;color:var(--text-muted);margin-top:1px}
.header-text .sub span{color:var(--accent);font-weight:500}
.header-right{display:flex;align-items:center;gap:16px}
.status-pill{display:flex;align-items:center;gap:6px;background:var(--success-dim);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--success);animation:pulse 2s infinite}
.timestamp{font-size:11px;color:var(--text-dim);font-family:var(--mono)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border);align-items:center}
.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}
.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}
.nav a.active{color:var(--accent);background:var(--accent-dim)}
.page-body{padding:20px 28px}
.section-title{font-size:14px;font-weight:700;color:var(--text-primary);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.section-title .dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.panel{background:var(--bg-card);border-radius:var(--radius);overflow:hidden;border:1px solid var(--border-subtle);margin-bottom:16px}
.panel-header{padding:10px 16px;background:var(--bg-surface);border-bottom:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center}
.panel-header h3{font-size:12px;font-weight:700;color:var(--text-primary)}
.panel-body{padding:20px}
.hm-grid{display:grid;grid-template-columns:60px repeat(24,1fr);gap:3px;align-items:center}
.hm-label{font-size:10px;color:var(--text-dim);text-align:right;padding-right:8px;font-family:var(--mono)}
.hm-header{font-size:9px;color:var(--text-dim);text-align:center;font-family:var(--mono);font-weight:600}
.hm-cell{aspect-ratio:1;border-radius:3px;position:relative;cursor:default;transition:transform .15s}
.hm-cell:hover{transform:scale(1.3);z-index:2}
.hm-0{background:var(--bg-elevated)}
.hm-1{background:rgba(34,211,238,0.15)}
.hm-2{background:rgba(34,211,238,0.3)}
.hm-3{background:rgba(34,211,238,0.5)}
.hm-4{background:rgba(34,211,238,0.7)}
.hm-5{background:var(--accent)}
.type-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.type-bar{background:var(--bg-elevated);border-radius:var(--radius-sm);padding:10px 12px;display:flex;align-items:center;gap:8px}
.type-bar .t-icon{font-size:16px}
.type-bar .t-name{font-size:11px;color:var(--text-secondary);flex:1}
.type-bar .t-count{font-size:14px;font-weight:800;color:var(--accent);font-family:var(--mono)}
.type-bar .t-bar{height:3px;background:var(--bg-base);border-radius:2px;margin-top:6px;overflow:hidden}
.type-bar .t-fill{height:100%;background:var(--accent);border-radius:2px;transition:width .3s}
.legend{display:flex;gap:12px;align-items:center;margin-top:12px;justify-content:center}
.legend-item{display:flex;align-items:center;gap:4px;font-size:10px;color:var(--text-dim)}
.legend-swatch{width:12px;height:12px;border-radius:2px}
.empty-state{padding:40px;text-align:center;color:var(--text-dim);font-size:13px}
</style></head>
<body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span class="dot"></span> {{ running }}/17 Active</div><div class="timestamp">{{ now }}</div></div></div>
<div class="nav"><a href="/">Overview</a><a href="/heatmap" class="active">Heatmap</a><a href="/correlation">Correlation</a><a href="/api">API</a><a href="/settings">Settings</a><a href="/attack-map">Attack Map</a><a href="/timeline">Timeline</a><a href="/statistics">Statistics</a></div>
<div class="page-body">
<div class="section-title"><span class="dot"></span> Activity Heatmap</div>
<div class="panel"><div class="panel-header"><h3>Hourly Attack Activity (Last 7 Days)</h3></div><div class="panel-body">
{% if hm_data.hourly %}
<div class="hm-grid">
  <div class="hm-label"></div>{% for h in range(24) %}<div class="hm-header">{{ "%02d"|format(h) }}</div>{% endfor %}
  {% for day_label, day_data in hm_data.daily.items() %}
  <div class="hm-label">{{ day_label }}</div>
  {% for h in range(24) %}{% set key = day_label ~ ':' ~ '%02d'|format(h) %}{% set val = hm_data.hourly.get(key, 0) %}{% set level = [5, val // 1, 4, val // 3, 3, val // 6, 2, val // 10, 1, 0] %}<div class="hm-cell hm-{{ [level[1] if val > 0 else 0, 5] | min }}" title="{{ day_label }} {{ '%02d'|format(h) }}:00 — {{ val }} events"></div>{% endfor %}
  {% endfor %}
</div>
<div class="legend">
  <div class="legend-item"><div class="legend-swatch hm-0"></div> 0</div>
  <div class="legend-item"><div class="legend-swatch hm-1"></div> 1-2</div>
  <div class="legend-item"><div class="legend-swatch hm-2"></div> 3-5</div>
  <div class="legend-item"><div class="legend-swatch hm-3"></div> 6-10</div>
  <div class="legend-item"><div class="legend-swatch hm-4"></div> 11-20</div>
  <div class="legend-item"><div class="legend-swatch hm-5"></div> 20+</div>
</div>
{% else %}<div class="empty-state">No heatmap data available yet. Start generating traffic with the test scanner.</div>{% endif %}
</div></div>

<div class="section-title"><span class="dot"></span> Events by Honeypot Type</div>
<div class="panel"><div class="panel-body">
{% if hm_data.by_type %}
<div class="type-grid">
  {% set max_count = hm_data.by_type.values()|max if hm_data.by_type.values()|list else 1 %}
  {% for t, c in hm_data.by_type.items()|sort(attribute='1', reverse=true) %}
  <div class="type-bar"><span class="t-name">{{ t }}</span><span class="t-count">{{ c }}</span></div>
  <div class="type-bar" style="grid-column:1/-1;margin-top:-4px"><div class="t-bar"><div class="t-fill" style="width:{{ (c / max_count * 100)|int }}%"></div></div></div>
  {% endfor %}
</div>
{% else %}<div class="empty-state">No type breakdown available yet.</div>{% endif %}
</div></div>
</div>
</body></html>"""

CORRELATION_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Correlation - Honeypot Lab</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--bg-card-hover:#1A2540;--bg-elevated:#1E293B;--border:#1E293B;--border-subtle:#162032;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--success:#10B981;--success-dim:rgba(16,185,129,0.12);--danger:#EF4444;--warning:#F59E0B;--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono','Cascadia Code','Fira Code',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
@media(prefers-reduced-motion:no-preference){@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}.panel,.big-stat{animation:fadeUp .4s ease both}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh;-webkit-font-smoothing:antialiased}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.header-left{display:flex;align-items:center;gap:14px}
.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.header-text h1{font-size:17px;font-weight:700;color:var(--text-primary);letter-spacing:-.02em}
.header-text .sub{font-size:12px;color:var(--text-muted);margin-top:1px}
.header-text .sub span{color:var(--accent);font-weight:500}
.header-right{display:flex;align-items:center;gap:16px}
.status-pill{display:flex;align-items:center;gap:6px;background:var(--success-dim);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--success);animation:pulse 2s infinite}
.timestamp{font-size:11px;color:var(--text-dim);font-family:var(--mono)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border);align-items:center}
.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}
.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}
.nav a.active{color:var(--accent);background:var(--accent-dim)}
.page-body{padding:20px 28px}
.section-title{font-size:14px;font-weight:700;color:var(--text-primary);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.section-title .dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.big-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px}
.big-stat{background:var(--bg-card);padding:18px 16px;border-radius:var(--radius);text-align:center;border:1px solid var(--border-subtle);position:relative;overflow:hidden}
.big-stat::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:.4}
.big-stat .number{font-size:30px;font-weight:800;color:var(--accent);font-family:var(--mono);line-height:1}
.big-stat .desc{font-size:11px;color:var(--text-muted);margin-top:6px;font-weight:500}
.panel{background:var(--bg-card);border-radius:var(--radius);overflow:hidden;border:1px solid var(--border-subtle);margin-bottom:16px}
.panel-header{padding:10px 16px;background:var(--bg-surface);border-bottom:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center}
.panel-header h3{font-size:12px;font-weight:700;color:var(--text-primary)}
.panel-header .badge{background:var(--accent-dim);color:var(--accent);padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;font-family:var(--mono)}
.log-table{width:100%;font-size:11px;border-collapse:collapse}
.log-table th{text-align:left;padding:7px 14px;color:var(--text-dim);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border-subtle);background:var(--bg-card)}
.log-table td{padding:6px 14px;border-bottom:1px solid var(--border-subtle);font-family:var(--mono);color:var(--text-secondary);font-size:11px}
.log-table tr:last-child td{border-bottom:none}
.log-table tr:hover td{background:var(--bg-card-hover)}
.log-table .ip{color:var(--accent);font-weight:500}
.log-table .count-badge{background:var(--danger-dim);color:var(--danger);padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;font-family:var(--mono)}
.empty-state{padding:40px;text-align:center;color:var(--text-dim);font-size:13px;display:flex;flex-direction:column;align-items:center;gap:8px}
.empty-state .ei{font-size:28px;opacity:.4}
.service-tags{display:flex;flex-wrap:wrap;gap:4px}
.service-tag{background:var(--accent-dim);color:var(--accent);padding:2px 8px;border-radius:4px;font-size:10px;font-family:var(--mono);font-weight:600}
</style></head>
<body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span class="dot"></span> {{ running }}/17 Active</div><div class="timestamp">{{ now }}</div></div></div>
<div class="nav"><a href="/">Overview</a><a href="/heatmap">Heatmap</a><a href="/correlation" class="active">Correlation</a><a href="/api">API</a><a href="/settings">Settings</a><a href="/attack-map">Attack Map</a><a href="/timeline">Timeline</a><a href="/statistics">Statistics</a></div>
<div class="page-body">
<div class="section-title"><span class="dot"></span> Attack Correlation</div>
<div class="big-stats">
  <div class="big-stat"><div class="number">{{ corr.total_events or total_events }}</div><div class="desc">Total Events</div></div>
  <div class="big-stat"><div class="number">{{ corr.unique_ips or unique_ips }}</div><div class="desc">Unique IPs</div></div>
  <div class="big-stat"><div class="number">{{ corr.multi_service_attackers or 0 }}</div><div class="desc">Multi-Service Attackers</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>Multi-Service Attackers</h3><span class="badge">{{ corr.multi_service|length if corr.multi_service else 0 }}</span></div>
{% if corr.multi_service %}
<table class="log-table"><thead><tr><th>Attacker IP</th><th>Services Hit</th><th>Honeypots</th></tr></thead><tbody>
{% for a in corr.multi_service %}<tr>
  <td class="ip">{{ a.ip }}</td>
  <td><span class="count-badge">{{ a.count }}</span></td>
  <td><div class="service-tags">{% for s in a.services %}<span class="service-tag">{{ s }}</span>{% endfor %}</div></td>
</tr>{% endfor %}
</tbody></table>
{% else %}<div class="empty-state"><span class="ei">🔗</span>No multi-service attackers detected yet.<br>Run the full attack simulation to generate correlated traffic.</div>{% endif %}
</div>
<div class="panel"><div class="panel-header"><h3>Top Attackers</h3><span class="badge">{{ corr.top_attackers|length if corr.top_attackers else 0 }}</span></div>
{% if corr.top_attackers %}
<table class="log-table"><thead><tr><th>#</th><th>Attacker IP</th><th>Events</th></tr></thead><tbody>
{% for a in corr.top_attackers %}<tr>
  <td style="color:var(--text-dim)">{{ loop.index }}</td>
  <td class="ip">{{ a.ip }}</td>
  <td><span class="count-badge">{{ a.count }}</span></td>
</tr>{% endfor %}
</tbody></table>
{% else %}<div class="empty-state"><span class="ei">🎯</span>No attacker data available yet.</div>{% endif %}
</div>
</div>
</body></html>"""

API_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>API - Honeypot Lab</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--bg-card-hover:#1A2540;--bg-elevated:#1E293B;--border:#1E293B;--border-subtle:#162032;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--success:#10B981;--success-dim:rgba(16,185,129,0.12);--danger:#EF4444;--warning:#F59E0B;--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono','Cascadia Code','Fira Code',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
@media(prefers-reduced-motion:no-preference){@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}.panel{animation:fadeUp .4s ease both}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh;-webkit-font-smoothing:antialiased}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.header-left{display:flex;align-items:center;gap:14px}
.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.header-text h1{font-size:17px;font-weight:700;color:var(--text-primary);letter-spacing:-.02em}
.header-text .sub{font-size:12px;color:var(--text-muted);margin-top:1px}
.header-text .sub span{color:var(--accent);font-weight:500}
.header-right{display:flex;align-items:center;gap:16px}
.status-pill{display:flex;align-items:center;gap:6px;background:var(--success-dim);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--success);animation:pulse 2s infinite}
.timestamp{font-size:11px;color:var(--text-dim);font-family:var(--mono)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border);align-items:center}
.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}
.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}
.nav a.active{color:var(--accent);background:var(--accent-dim)}
.page-body{padding:20px 28px}
.section-title{font-size:14px;font-weight:700;color:var(--text-primary);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.section-title .dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.panel{background:var(--bg-card);border-radius:var(--radius);overflow:hidden;border:1px solid var(--border-subtle);margin-bottom:16px}
.panel-header{padding:10px 16px;background:var(--bg-surface);border-bottom:1px solid var(--border-subtle)}
.panel-header h3{font-size:12px;font-weight:700;color:var(--text-primary)}
.log-table{width:100%;font-size:11px;border-collapse:collapse}
.log-table th{text-align:left;padding:7px 14px;color:var(--text-dim);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border-subtle);background:var(--bg-card)}
.log-table td{padding:8px 14px;border-bottom:1px solid var(--border-subtle);font-size:11px}
.log-table tr:last-child td{border-bottom:none}
.log-table tr:hover td{background:var(--bg-card-hover)}
.method-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700;font-family:var(--mono);text-transform:uppercase}
.method-get{background:rgba(34,211,238,0.12);color:var(--accent)}
.path-cell{font-family:var(--mono);color:var(--accent);font-weight:500}
.desc-cell{color:var(--text-secondary)}
.try-btn{display:inline-block;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:600;text-decoration:none;background:var(--accent-dim);color:var(--accent);border:1px solid rgba(34,211,238,0.2);transition:all .15s;cursor:pointer}
.try-btn:hover{background:var(--accent);color:var(--bg-base)}
.note{font-size:11px;color:var(--text-dim);margin-top:16px;padding:12px 16px;background:var(--bg-elevated);border-radius:var(--radius-sm);border-left:3px solid var(--accent)}
.note code{font-family:var(--mono);color:var(--accent);background:var(--accent-dim);padding:1px 5px;border-radius:3px;font-size:10px}
</style></head>
<body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span class="dot"></span> {{ running }}/17 Active</div><div class="timestamp">{{ now }}</div></div></div>
<div class="nav"><a href="/">Overview</a><a href="/heatmap">Heatmap</a><a href="/correlation">Correlation</a><a href="/api" class="active">API</a><a href="/settings">Settings</a><a href="/attack-map">Attack Map</a><a href="/timeline">Timeline</a><a href="/statistics">Statistics</a></div>
<div class="page-body">
<div class="section-title"><span class="dot"></span> REST API Endpoints</div>
<div class="panel"><div class="panel-header"><h3>Available Endpoints</h3></div>
<table class="log-table"><thead><tr><th>Method</th><th>Endpoint</th><th>Description</th><th></th></tr></thead><tbody>
{% for ep in endpoints %}<tr>
  <td><span class="method-badge method-{{ ep.method|lower }}">{{ ep.method }}</span></td>
  <td class="path-cell">{{ ep.path }}</td>
  <td class="desc-cell">{{ ep.desc }}</td>
  <td><a class="try-btn" href="{{ ep.path }}" target="_blank">Try it</a></td>
</tr>{% endfor %}
</tbody></table></div>
<div class="note">All endpoints return JSON. Use <code>?n=N</code> to limit log results (max 100). Example: <code>/api/logs/ssh?n=50</code></div>
</div>
</body></html>"""

SETTINGS_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Settings - Honeypot Lab</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--bg-elevated:#1E293B;--border:#1E293B;--border-subtle:#162032;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--success:#10B981;--success-dim:rgba(16,185,129,0.12);--danger:#EF4444;--warning:#F59E0B;--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between}.header-left{display:flex;align-items:center;gap:14px}.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}.header-text h1{font-size:17px;font-weight:700}.header-text .sub{font-size:12px;color:var(--text-muted)}.header-text .sub span{color:var(--accent)}.header-right{display:flex;align-items:center;gap:16px}.status-pill{display:flex;align-items:center;gap:6px;background:var(--success-dim);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border)}.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}.nav a.active{color:var(--accent);background:var(--accent-dim)}
.page-body{padding:20px 28px;max-width:900px}.section-title{font-size:14px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}.section-title .dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.settings-section{background:var(--bg-card);border-radius:var(--radius);border:1px solid var(--border-subtle);margin-bottom:15px;overflow:hidden}
.settings-section h3{padding:12px 16px;background:var(--bg-surface);border-bottom:1px solid var(--border-subtle);font-size:12px;font-weight:700}
.settings-section .body{padding:16px}
.form-row{display:grid;grid-template-columns:160px 1fr;gap:10px;align-items:center;margin-bottom:10px}
.form-row label{font-size:11px;color:var(--text-muted);font-weight:600}
.form-row input[type="text"],.form-row input[type="password"],.form-row input[type="email"],.form-row input[type="number"],.form-row select{width:100%;padding:8px 12px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--mono);outline:none;transition:border-color .15s}
.form-row input:focus{border-color:var(--accent)}
.form-row .hint{font-size:10px;color:var(--text-dim);grid-column:2}
.toggle-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.toggle{width:36px;height:20px;background:var(--bg-elevated);border-radius:10px;position:relative;cursor:pointer;border:1px solid var(--border);transition:all .2s}
.toggle.on{background:var(--accent);border-color:var(--accent)}
.toggle::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:white;transition:transform .2s}
.toggle.on::after{transform:translateX(16px)}
.toggle-label{font-size:11px;color:var(--text-muted)}
.btn{padding:8px 20px;border-radius:var(--radius-sm);font-size:12px;font-weight:600;cursor:pointer;border:none;transition:all .15s}
.btn-primary{background:var(--accent);color:var(--bg-base)}.btn-primary:hover{opacity:.9}
.btn-danger{background:var(--danger);color:white}.btn-danger:hover{opacity:.9}
.btn-secondary{background:var(--bg-elevated);color:var(--text-muted);border:1px solid var(--border)}.btn-secondary:hover{border-color:var(--accent);color:var(--accent)}
.success-msg{background:var(--success-dim);color:var(--success);padding:10px 16px;border-radius:var(--radius-sm);font-size:12px;margin-bottom:15px;border:1px solid rgba(16,185,129,.2)}
.btn-row{display:flex;gap:10px;margin-top:15px}
</style></head><body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span style="width:7px;height:7px;border-radius:50%;background:var(--success)"></span> {{ running }}/17 Active</div></div></div>
<div class="nav"><a href="/">Overview</a><a href="/heatmap">Heatmap</a><a href="/correlation">Correlation</a><a href="/api">API</a><a href="/settings" class="active">Settings</a><a href="/attack-map">Attack Map</a><a href="/timeline">Timeline</a><a href="/statistics">Statistics</a></div>
<div class="page-body">
<div class="section-title"><span class="dot"></span> Settings</div>
{% if message %}<div class="success-msg">{{ message }}</div>{% endif %}
<form method="POST">
<div class="settings-section"><h3>Threat Intelligence API Keys</h3><div class="body">
<div class="form-row"><label>AbuseIPDB Key</label><input type="text" name="abuseipdb_key" value="{{ config.get('abuseipdb_key', '') }}" placeholder="Enter your AbuseIPDB API key"></div>
<div class="form-row"><label>VirusTotal Key</label><input type="text" name="virustotal_key" value="{{ config.get('virustotal_key', '') }}" placeholder="Enter your VirusTotal API key"></div>
<div class="form-row"><label>Shodan Key</label><input type="text" name="shodan_key" value="{{ config.get('shodan_key', '') }}" placeholder="Enter your Shodan API key"></div>
<div class="form-row"><label>GreyNoise Key</label><input type="text" name="greynoise_key" value="{{ config.get('greynoise_key', '') }}" placeholder="Enter your GreyNoise API key"></div>
</div></div>

<div class="settings-section"><h3>Notifications</h3><div class="body">
<div class="toggle-row"><div class="toggle {{ 'on' if config.get('enable_notifications') == 'yes' }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Enable Notifications</span><input type="hidden" name="enable_notifications" value="{{ config.get('enable_notifications', 'no') }}"></div>
<div class="toggle-row"><div class="toggle {{ 'on' if notify_cfg.get('telegram', {}).get('enabled') }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Telegram Alerts</span><input type="hidden" name="telegram_enabled" value="on" id="tg_en"></div>
<div class="form-row"><label>Bot Token</label><input type="text" name="telegram_token" value="{{ notify_cfg.get('telegram', {}).get('bot_token', '') }}" placeholder="123456:ABC-DEF"></div>
<div class="form-row"><label>Chat ID</label><input type="text" name="telegram_chatid" value="{{ notify_cfg.get('telegram', {}).get('chat_id', '') }}" placeholder="-1001234567890"></div>
<div class="toggle-row"><div class="toggle {{ 'on' if notify_cfg.get('discord', {}).get('enabled') }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Discord Alerts</span><input type="hidden" name="discord_enabled" value="on" id="dc_en"></div>
<div class="form-row"><label>Webhook URL</label><input type="text" name="discord_webhook" value="{{ notify_cfg.get('discord', {}).get('webhook_url', '') }}" placeholder="https://discord.com/api/webhooks/..."></div>
<div class="toggle-row"><div class="toggle {{ 'on' if notify_cfg.get('slack', {}).get('enabled') }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Slack Alerts</span><input type="hidden" name="slack_enabled" value="on" id="sl_en"></div>
<div class="form-row"><label>Webhook URL</label><input type="text" name="slack_webhook" value="{{ notify_cfg.get('slack', {}).get('webhook_url', '') }}" placeholder="https://hooks.slack.com/services/..."></div>
<div class="toggle-row"><div class="toggle {{ 'on' if notify_cfg.get('email', {}).get('enabled') }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Email Alerts</span><input type="hidden" name="email_enabled" value="on" id="em_en"></div>
<div class="form-row"><label>SMTP Server</label><input type="text" name="email_smtp" value="{{ notify_cfg.get('email', {}).get('smtp_server', '') }}" placeholder="smtp.gmail.com"></div>
<div class="form-row"><label>SMTP Port</label><input type="number" name="email_port" value="{{ notify_cfg.get('email', {}).get('smtp_port', 587) }}"></div>
<div class="form-row"><label>Username</label><input type="text" name="email_user" value="{{ notify_cfg.get('email', {}).get('username', '') }}"></div>
<div class="form-row"><label>Password</label><input type="password" name="email_pass" value="{{ notify_cfg.get('email', {}).get('password', '') }}"></div>
<div class="form-row"><label>From</label><input type="email" name="email_from" value="{{ notify_cfg.get('email', {}).get('from', '') }}"></div>
<div class="form-row"><label>To</label><input type="email" name="email_to" value="{{ notify_cfg.get('email', {}).get('to', '') }}"></div>
</div></div>

<div class="settings-section"><h3>Feature Toggles</h3><div class="body">
<div class="toggle-row"><div class="toggle {{ 'on' if config.get('enable_geoip') == 'yes' }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">GeoIP Tracking</span><input type="hidden" name="enable_geoip" value="{{ config.get('enable_geoip', 'yes') }}"></div>
<div class="toggle-row"><div class="toggle {{ 'on' if config.get('enable_correlation') == 'yes' }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Attack Correlation</span><input type="hidden" name="enable_correlation" value="{{ config.get('enable_correlation', 'yes') }}"></div>
<div class="toggle-row"><div class="toggle {{ 'on' if config.get('enable_log_rotation') == 'yes' }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Log Rotation</span><input type="hidden" name="enable_log_rotation" value="{{ config.get('enable_log_rotation', 'yes') }}"></div>
<div class="toggle-row"><div class="toggle {{ 'on' if config.get('enable_intel_feeds') == 'yes' }}" onclick="this.classList.toggle('on')"></div><span class="toggle-label">Threat Intel Feeds</span><input type="hidden" name="enable_intel_feeds" value="{{ config.get('enable_intel_feeds', 'no') }}"></div>
</div></div>

<div class="settings-section"><h3>Backup & Restore</h3><div class="body">
<div class="btn-row">
<a href="/api/backup" class="btn btn-primary" download>Download Backup (ZIP)</a>
<a href="/api/report/pdf" class="btn btn-primary" download>Download Report (PDF)</a>
</div>
</div></div>

<div class="btn-row"><button type="submit" class="btn btn-primary">Save Settings</button></div>
</form>
</div>
<script>
document.querySelectorAll('.toggle').forEach(t=>{
t.addEventListener('click',function(){
var input=this.nextElementSibling.nextElementSibling;
if(input&&input.type==='hidden'){input.value=this.classList.contains('on')?'yes':'no'}
});
});
</script>
</body></html>"""

@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    stats, total, uips, running = get_stats()
    config_path = os.path.join(LAB_DIR, "config.ini")
    notify_path = os.path.join(LAB_DIR, "notify_config.json")
    message = ""

    if request.method == "POST":
        # Save API keys to config.ini
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_text = f.read()
            for key in ["abuseipdb_key", "virustotal_key", "shodan_key", "greynoise_key"]:
                val = request.form.get(key, "")
                import re
                if re.search(rf"^{key}\s*=.*$", config_text, re.MULTILINE):
                    config_text = re.sub(rf"^{key}\s*=.*$", f"{key} = {val}", config_text, flags=re.MULTILINE)
                else:
                    config_text += f"\n{key} = {val}"
            # Save feature toggles
            for key in ["enable_notifications", "enable_intel_feeds", "enable_geoip", "enable_correlation", "enable_log_rotation"]:
                val = request.form.get(key, "no")
                if re.search(rf"^{key}\s*=.*$", config_text, re.MULTILINE):
                    config_text = re.sub(rf"^{key}\s*=.*$", f"{key} = {val}", config_text, flags=re.MULTILINE)
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(config_text)

            # Save notification config
            notify_cfg = {
                "telegram": {"enabled": request.form.get("telegram_enabled") == "on", "bot_token": request.form.get("telegram_token", ""), "chat_id": request.form.get("telegram_chatid", "")},
                "discord": {"enabled": request.form.get("discord_enabled") == "on", "webhook_url": request.form.get("discord_webhook", "")},
                "slack": {"enabled": request.form.get("slack_enabled") == "on", "webhook_url": request.form.get("slack_webhook", "")},
                "email": {"enabled": request.form.get("email_enabled") == "on", "smtp_server": request.form.get("email_smtp", ""), "smtp_port": int(request.form.get("email_port", "587")), "username": request.form.get("email_user", ""), "password": request.form.get("email_pass", ""), "from": request.form.get("email_from", ""), "to": request.form.get("email_to", "")}
            }
            with open(notify_path, "w", encoding="utf-8") as f:
                json.dump(notify_cfg, f, indent=2)

            # Set env vars for threat intel
            os.environ["ABUSEIPDB_KEY"] = request.form.get("abuseipdb_key", "")
            os.environ["VIRUSTOTAL_KEY"] = request.form.get("virustotal_key", "")

            message = "Settings saved successfully!"
        except Exception as e:
            message = f"Error saving: {e}"

    # Read current config
    config = {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#") and not line.startswith("["):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    except: pass

    notify_cfg = {}
    try:
        with open(notify_path, "r", encoding="utf-8") as f:
            notify_cfg = json.load(f)
    except: pass

    return render_template_string(SETTINGS_HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), config=config, notify_cfg=notify_cfg, message=message)

@app.route("/")
def index():
    stats, total, uips, running = get_stats()
    return render_template_string(HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ssh=get_logs("ssh"), web=get_logs("web"), creds=get_logs("creds"), malware=get_logs("malware"), rdp=get_logs("rdp"), smb=get_logs("smb"), dns=get_logs("dns"), sip=get_logs("sip"), redis=get_logs("redis"), vnc=get_logs("vnc"), telnet=get_logs("telnet"), memcached=get_logs("memcached"), mqtt=get_logs("mqtt"), snmp=get_logs("snmp"), ntp=get_logs("ntp"), ics=get_logs("ics"), db=get_logs("db"), alerts=get_alerts())

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
    stats, total, uips, running = get_stats()
    try:
        sys.path.insert(0, LAB_DIR)
        from features.heatmap import generate_heatmap_data
        data = generate_heatmap_data()
    except:
        data = {"hourly": {}, "daily": {}, "by_type": {}, "sources": []}
    return render_template_string(HEATMAP_HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), hm_data=data)

@app.route("/correlation")
def correlation():
    stats, total, uips, running = get_stats()
    try:
        sys.path.insert(0, LAB_DIR)
        from features.correlation import correlate
        data = correlate()
    except:
        data = {"multi_service": [], "multi_service_attackers": 0, "top_attackers": [], "total_events": total, "unique_ips": uips}
    return render_template_string(CORRELATION_HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), corr=data)

@app.route("/api")
def api_page():
    stats, total, uips, running = get_stats()
    endpoints = [
        {"method": "GET", "path": "/api/stats", "desc": "Live event counts per honeypot + unique attacker IPs"},
        {"method": "GET", "path": "/api/logs/ssh", "desc": "Last N log entries for SSH honeypot (append ?n=50)"},
        {"method": "GET", "path": "/api/logs/web", "desc": "Last N log entries for Web traps"},
        {"method": "GET", "path": "/api/logs/creds", "desc": "Last N log entries for Credential capture"},
        {"method": "GET", "path": "/api/logs/malware", "desc": "Last N log entries for Malware capture"},
        {"method": "GET", "path": "/api/logs/ics", "desc": "Last N log entries for ICS/SCADA"},
        {"method": "GET", "path": "/api/logs/db", "desc": "Last N log entries for Database traps"},
        {"method": "GET", "path": "/api/logs/rdp", "desc": "Last N log entries for RDP trap"},
        {"method": "GET", "path": "/api/logs/smb", "desc": "Last N log entries for SMB trap"},
        {"method": "GET", "path": "/api/logs/dns", "desc": "Last N log entries for DNS trap"},
        {"method": "GET", "path": "/api/logs/sip", "desc": "Last N log entries for SIP trap"},
        {"method": "GET", "path": "/api/logs/redis", "desc": "Last N log entries for Redis trap"},
        {"method": "GET", "path": "/api/logs/vnc", "desc": "Last N log entries for VNC trap"},
        {"method": "GET", "path": "/api/logs/telnet", "desc": "Last N log entries for Telnet trap"},
        {"method": "GET", "path": "/api/logs/memcached", "desc": "Last N log entries for Memcached trap"},
        {"method": "GET", "path": "/api/logs/mqtt", "desc": "Last N log entries for MQTT trap"},
        {"method": "GET", "path": "/api/logs/snmp", "desc": "Last N log entries for SNMP trap"},
        {"method": "GET", "path": "/api/logs/ntp", "desc": "Last N log entries for NTP trap"},
        {"method": "GET", "path": "/heatmap", "desc": "Hourly/daily activity heatmap data (JSON)"},
        {"method": "GET", "path": "/correlation", "desc": "Attackers seen hitting multiple honeypots (JSON)"},
        {"method": "GET", "path": "/api/alerts", "desc": "Recent notification alerts (append ?n=100)"},
        {"method": "GET", "path": "/api/geoip/<ip>", "desc": "GeoIP lookup for an IP address"},
        {"method": "GET", "path": "/api/intel/<ip>", "desc": "Threat intel lookup (AbuseIPDB, VirusTotal)"},
        {"method": "GET", "path": "/api/export?format=json|csv", "desc": "Export all logs as JSON or CSV"},
    ]
    return render_template_string(API_HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), endpoints=endpoints)

@app.route("/api/alerts")
def api_alerts():
    n = request.args.get("n", 50, type=int)
    return jsonify({"alerts": get_alerts(min(n, 200))})

@app.route("/api/intel/<ip>")
def api_intel(ip):
    return jsonify(check_ip_intel(ip))

@app.route("/api/geoip/<ip>")
def api_geoip(ip):
    if geoip_lookup:
        return jsonify(geoip_lookup(ip))
    return jsonify({"ip": ip, "country": "GeoIP unavailable", "city": "", "isp": ""})

@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "json")
    data = {}
    for key in HONEYPOT_TYPES:
        data[key] = get_logs(key, 1000)
    if fmt == "csv":
        import io, csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["type", "timestamp", "source_ip", "country", "city", "isp", "detail"])
        for log_type, entries in data.items():
            for e in entries:
                ip = e.get("source_ip") or e.get("src_ip") or ""
                writer.writerow([log_type, e.get("timestamp", ""), ip, e.get("_country", ""), e.get("_city", ""), e.get("_isp", ""), str(e)[:200]])
        return output.getvalue(), 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=honeypot_export.csv"}
    return jsonify(data)

# ============================================================
# FEATURE 1: PDF Report Export
# ============================================================
@app.route("/api/report/pdf")
def api_report_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        return jsonify({"error": "reportlab not installed. Run: pip install reportlab"}), 500

    import io
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=22, spaceAfter=6, textColor=colors.HexColor('#0F172A'))
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor('#64748B'), spaceAfter=20)
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, spaceBefore=16, spaceAfter=8, textColor=colors.HexColor('#0F172A'))
    body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#475569'), spaceAfter=6)
    stat_style = ParagraphStyle('Stat', parent=styles['Normal'], fontSize=24, textColor=colors.HexColor('#0891B2'), alignment=TA_CENTER)
    stat_label = ParagraphStyle('StatLabel', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#94A3B8'), alignment=TA_CENTER)

    elements = []

    # === PAGE 1: Executive Summary ===
    elements.append(Paragraph("Honeypot Lab — Threat Analysis Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%B %d, %Y at %H:%M:%S')} | Developed by JOJIN JOHN", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0')))
    elements.append(Spacer(1, 15))

    # Key metrics
    stats, total, uips, running = get_stats()
    metrics_data = [
        [Paragraph(str(total), stat_style), Paragraph(str(uips), stat_style), Paragraph(f"{running}/17", stat_style), Paragraph("Active" if total > 0 else "Idle", stat_style)],
        [Paragraph("Total Events", stat_label), Paragraph("Unique IPs", stat_label), Paragraph("Honeypots", stat_label), Paragraph("Status", stat_label)]
    ]
    mt = Table(metrics_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
    mt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,0), 15),
        ('BOTTOMPADDING', (0,1), (-1,1), 10),
    ]))
    elements.append(mt)
    elements.append(Spacer(1, 15))

    # Executive summary text
    active_count = sum(1 for v in stats.values() if v["count"] > 0)
    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(Paragraph(f"This report summarizes threat activity captured by the Honeypot Lab across {running} active honeypot services. A total of {total} events were recorded from {uips} unique IP address(es). {active_count} out of 17 honeypot types captured traffic during this reporting period.", body_style))
    elements.append(Spacer(1, 10))

    # === Honeypot Breakdown ===
    elements.append(Paragraph("Honeypot Activity Breakdown", heading_style))
    table_data = [["Service", "Events", "Status", "Risk Level"]]
    for key, info in sorted(stats.items(), key=lambda x: -x[1]["count"]):
        status = "Active" if info["count"] > 0 else "Idle"
        risk = "High" if info["count"] > 50 else "Medium" if info["count"] > 10 else "Low" if info["count"] > 0 else "None"
        table_data.append([info["label"].split(" ", 1)[-1] if " " in info["label"] else info["label"], str(info["count"]), status, risk])
    t = Table(table_data, colWidths=[2.2*inch, 1*inch, 1*inch, 1.2*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(t)
    elements.append(PageBreak())

    # === PAGE 2: Attack Analysis ===
    elements.append(Paragraph("Attack Analysis", title_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0')))
    elements.append(Spacer(1, 15))

    # Top attackers
    all_entries = []
    for key in HONEYPOT_TYPES:
        all_entries.extend(get_logs(key, 1000))
    ip_counter = collections.Counter()
    ip_types = {}
    for e in all_entries:
        ip = e.get("source_ip") or e.get("src_ip") or ""
        if ip:
            ip_counter[ip] += 1
            if ip not in ip_types: ip_types[ip] = set()
            ip_types[ip].add(e.get("_type", ""))

    if ip_counter:
        elements.append(Paragraph("Top Attackers", heading_style))
        atk_data = [["#", "IP Address", "Events", "Services Hit", "Risk"]]
        for i, (ip, cnt) in enumerate(ip_counter.most_common(20), 1):
            services = len(ip_types.get(ip, set()))
            risk = "Critical" if cnt > 100 else "High" if cnt > 50 else "Medium" if cnt > 10 else "Low"
            atk_data.append([str(i), ip, str(cnt), str(services), risk])
        at = Table(atk_data, colWidths=[0.4*inch, 1.8*inch, 0.8*inch, 1*inch, 0.8*inch])
        at.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('ALIGN', (0,0), (0,-1), 'CENTER'),
            ('ALIGN', (2,0), (4,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(at)
        elements.append(Spacer(1, 15))

    # Attack distribution
    elements.append(Paragraph("Attack Distribution by Type", heading_style))
    type_counter = collections.Counter()
    for e in all_entries:
        t = e.get("_type", "unknown")
        type_counter[t] += 1
    if type_counter:
        dist_data = [["Type", "Events", "Percentage"]]
        for t, cnt in type_counter.most_common():
            pct = f"{cnt/total*100:.1f}%" if total else "0%"
            dist_data.append([t, str(cnt), pct])
        dt = Table(dist_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        dt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('ALIGN', (1,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(dt)
        elements.append(PageBreak())

    # === PAGE 3: Recent Events & Recommendations ===
    elements.append(Paragraph("Recent Events & Recommendations", title_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0')))
    elements.append(Spacer(1, 15))

    # Recent events (last 20)
    elements.append(Paragraph("Recent Attack Events (Last 20)", heading_style))
    recent = sorted(all_entries, key=lambda x: x.get("timestamp", ""), reverse=True)[:20]
    if recent:
        evt_data = [["Time", "Type", "IP", "Detail"]]
        for e in recent:
            ts = e.get("timestamp", "")[:19] if e.get("timestamp") else "--"
            tp = e.get("_type", "?")
            ip = e.get("source_ip") or e.get("src_ip") or "--"
            detail = str(e.get("message") or e.get("method") or e.get("protocol") or e.get("path") or "")[:50]
            evt_data.append([ts, tp, ip, detail])
        et = Table(evt_data, colWidths=[1.5*inch, 0.8*inch, 1.2*inch, 2.5*inch])
        et.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(et)
        elements.append(Spacer(1, 20))

    # Recommendations
    elements.append(Paragraph("Recommendations", heading_style))
    recommendations = []
    if total > 100:
        recommendations.append("High event volume detected — review firewall rules and consider IP blocking for persistent attackers.")
    if active_count < 10:
        recommendations.append("Several honeypots are idle — verify network configuration and port accessibility.")
    if uips == 1:
        recommendations.append("Only local traffic detected — deploy to a public-facing network for real attacker data.")
    if not recommendations:
        recommendations.append("Lab is operating normally. Continue monitoring for unusual patterns.")
    recommendations.append("Enable Telegram/Discord notifications for real-time alerts.")
    recommendations.append("Configure AbuseIPDB/VirusTotal API keys for threat intelligence enrichment.")
    recommendations.append("Export regular PDF reports for compliance and documentation.")

    for i, rec in enumerate(recommendations, 1):
        elements.append(Paragraph(f"{i}. {rec}", body_style))

    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0')))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Generated by Honeypot Lab v2.0 | Developed by JOJIN JOHN", subtitle_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue(), 200, {"Content-Type": "application/pdf", "Content-Disposition": "attachment; filename=honeypot_report.pdf"}

# ============================================================
# FEATURE 2: Attack Map
# ============================================================
ATTACK_MAP_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Attack Map - Honeypot Lab</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--border:#1E293B;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--success:#10B981;--success-dim:rgba(16,185,129,0.12);--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between}
.header-left{display:flex;align-items:center;gap:14px}.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}
.header-text h1{font-size:17px;font-weight:700}.header-text .sub{font-size:12px;color:var(--text-muted)}.header-text .sub span{color:var(--accent)}
.header-right{display:flex;align-items:center;gap:16px}.status-pill{display:flex;align-items:center;gap:6px;background:var(--success-dim);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border)}.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}.nav a.active{color:var(--accent);background:var(--accent-dim)}
.map-container{padding:20px 28px}.map-panel{background:var(--bg-card);border-radius:var(--radius);border:1px solid var(--border);padding:20px;position:relative;overflow:hidden}
.map-panel h3{font-size:14px;font-weight:700;margin-bottom:15px}
.world-map{width:100%;height:500px;position:relative;background:var(--bg-elevated);border-radius:var(--radius-sm);overflow:hidden}
.map-dot{position:absolute;width:12px;height:12px;border-radius:50%;background:var(--accent);border:2px solid rgba(34,211,238,0.5);animation:pulse 2s infinite;cursor:pointer;z-index:2}
.map-dot:hover{transform:scale(1.5);z-index:3}
.map-dot .tooltip{display:none;position:absolute;bottom:20px;left:50%;transform:translateX(-50%);background:var(--bg-surface);border:1px solid var(--border);padding:8px 12px;border-radius:6px;font-size:11px;white-space:nowrap;z-index:10}
.map-dot:hover .tooltip{display:block}
.map-legend{display:flex;gap:20px;margin-top:15px;flex-wrap:wrap}.legend-item{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-muted)}
.legend-dot{width:10px;height:10px;border-radius:50%}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(1.2)}}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:15px}
.stat-mini{background:var(--bg-elevated);padding:12px;border-radius:var(--radius-sm);text-align:center}
.stat-mini .num{font-size:24px;font-weight:800;color:var(--accent);font-family:var(--mono)}
.stat-mini .lbl{font-size:10px;color:var(--text-dim);margin-top:4px}
</style></head><body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span class="dot" style="width:7px;height:7px;border-radius:50%;background:var(--success);animation:pulse 2s infinite"></span> {{ running }}/17 Active</div></div></div>
<div class="nav"><a href="/">Overview</a><a href="/heatmap">Heatmap</a><a href="/correlation">Correlation</a><a href="/api">API</a><a href="/settings">Settings</a><a href="/attack-map" class="active">Attack Map</a><a href="/timeline">Timeline</a><a href="/statistics">Statistics</a></div>
<div class="map-container">
<div class="map-panel"><h3>World Attack Map</h3>
<div class="world-map" id="worldMap">
<svg viewBox="0 0 1000 500" width="100%" height="100%" style="opacity:0.15">
<path d="M150,120 Q200,100 250,115 T350,110 Q380,105 400,120 L420,180 Q400,200 380,190 L350,200 Q320,220 280,210 L250,220 Q220,240 180,220 L160,180 Z" fill="var(--accent)" opacity="0.3"/>
<path d="M420,80 Q500,60 580,80 T700,90 Q750,100 780,130 L800,200 Q780,250 750,240 L700,250 Q650,270 600,250 L550,260 Q500,280 450,250 L420,200 Q410,150 420,80 Z" fill="var(--accent)" opacity="0.2"/>
<path d="M200,250 Q250,230 300,240 T400,250 Q430,260 440,290 L430,350 Q410,380 380,370 L340,380 Q300,400 260,380 L230,350 Q200,320 200,250 Z" fill="var(--accent)" opacity="0.25"/>
<path d="M700,150 Q750,130 800,140 T900,160 Q930,180 920,220 L900,280 Q880,310 850,300 L810,310 Q780,330 740,310 L720,280 Q700,240 700,150 Z" fill="var(--accent)" opacity="0.2"/>
<path d="M500,300 Q550,280 600,290 T700,310 Q730,330 720,370 L700,420 Q680,450 650,440 L610,450 Q570,470 530,450 L510,410 Q490,370 500,300 Z" fill="var(--accent)" opacity="0.2"/>
</svg>
{% for dot in map_dots %}
<div class="map-dot" style="left:{{ dot.x }}%;top:{{ dot.y }}%"><div class="tooltip">{{ dot.ip }} — {{ dot.country }}<br>{{ dot.count }} events · {{ dot.services }}</div></div>
{% endfor %}
</div>
<div class="map-legend">
<div class="legend-item"><div class="legend-dot" style="background:var(--accent)"></div>Attacker Location</div>
<div class="legend-item"><div class="legend-dot" style="background:var(--success)"></div>Low Activity</div>
<div class="legend-item"><div class="legend-dot" style="background:var(--warning)"></div>Medium Activity</div>
<div class="legend-item"><div class="legend-dot" style="background:var(--danger)"></div>High Activity</div>
</div>
<div class="stats-row">
<div class="stat-mini"><div class="num">{{ total_events }}</div><div class="lbl">Total Events</div></div>
<div class="stat-mini"><div class="num">{{ unique_ips }}</div><div class="lbl">Unique IPs</div></div>
<div class="stat-mini"><div class="num">{{ countries|length }}</div><div class="lbl">Countries</div></div>
<div class="stat-mini"><div class="num">{{ map_dots|length }}</div><div class="lbl">Attack Sources</div></div>
</div>
</div></div>
<script>setTimeout(()=>location.reload(),10000)</script>
</body></html>"""

@app.route("/attack-map")
def attack_map():
    stats, total, uips, running = get_stats()
    all_entries = []
    for key in HONEYPOT_TYPES:
        all_entries.extend(get_logs(key, 500))
    ip_data = {}
    for e in all_entries:
        ip = e.get("source_ip") or e.get("src_ip") or ""
        if not ip: continue
        country = e.get("_country", "Local") if ip.startswith("127.") else e.get("_country", "Unknown")
        city = e.get("_city", "Loopback") if ip.startswith("127.") else e.get("_city", "")
        if ip not in ip_data:
            ip_data[ip] = {"ip": ip, "country": country, "city": city, "count": 0, "services": set(), "lat": 0, "lon": 0}
        ip_data[ip]["count"] += 1
        ip_data[ip]["services"].add(e.get("_type", ""))
    # Simple geo mapping (approximate)
    map_dots = []
    for ip, d in ip_data.items():
        x = hash(ip) % 80 + 10
        y = hash(ip + "y") % 60 + 20
        map_dots.append({"ip": d["ip"], "country": d["country"], "city": d["city"], "count": d["count"], "services": ", ".join(sorted(d["services"] - {""})), "x": x, "y": y})
    countries = set(d["country"] for d in map_dots if d["country"] and d["country"] != "Unknown")
    return render_template_string(ATTACK_MAP_HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), map_dots=map_dots, countries=countries)

# ============================================================
# FEATURE 3: Dark/Light Theme
# ============================================================
THEME_TOGGLE_JS = """<script>
function toggleTheme(){const b=document.body;if(b.dataset.theme==='light'){b.dataset.theme='';localStorage.removeItem('theme')}else{b.dataset.theme='light';localStorage.theme='light'}
document.querySelectorAll('.theme-btn').forEach(e=>e.textContent=b.dataset.theme==='light'?'🌙':'☀️')}
if(localStorage.theme==='light')document.body.dataset.theme='light';
</script>
<style>
[data-theme="light"]{--bg-base:#F8FAFC;--bg-surface:#FFFFFF;--bg-card:#FFFFFF;--bg-card-hover:#F1F5F9;--bg-elevated:#E2E8F0;--border:#E2E8F0;--border-subtle:#F1F5F9;--accent:#0891B2;--accent-dim:rgba(8,145,178,0.1);--text-primary:#0F172A;--text-secondary:#475569;--text-muted:#94A3B8;--text-dim:#CBD5E1}
[data-theme="light"] .header,[data-theme="light"] .nav{background:var(--bg-surface);border-color:var(--border)}
[data-theme="light"] .log-table th{background:var(--bg-card);color:var(--text-dim)}
[data-theme="light"] .panel-header{background:var(--bg-surface)}
.theme-btn{background:none;border:1px solid var(--border);color:var(--text-muted);padding:4px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:14px;transition:all .15s}.theme-btn:hover{border-color:var(--accent);color:var(--accent)}
</style>"""

# ============================================================
# FEATURE 4: Attack Timeline
# ============================================================
TIMELINE_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Timeline - Honeypot Lab</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--bg-elevated:#1E293B;--border:#1E293B;--border-subtle:#162032;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--danger:#EF4444;--warning:#F59E0B;--success:#10B981;--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between}.header-left{display:flex;align-items:center;gap:14px}.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}.header-text h1{font-size:17px;font-weight:700}.header-text .sub{font-size:12px;color:var(--text-muted)}.header-text .sub span{color:var(--accent)}.header-right{display:flex;align-items:center;gap:16px}.status-pill{display:flex;align-items:center;gap:6px;background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border)}.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}.nav a.active{color:var(--accent);background:var(--accent-dim)}
.page-body{padding:20px 28px}.section-title{font-size:14px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}.section-title .dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.timeline{position:relative;padding-left:30px}.timeline::before{content:'';position:absolute;left:10px;top:0;bottom:0;width:2px;background:var(--border)}
.tl-item{position:relative;margin-bottom:12px;padding:10px 14px;background:var(--bg-card);border-radius:var(--radius-sm);border:1px solid var(--border-subtle);transition:border-color .15s}.tl-item:hover{border-color:var(--accent)}
.tl-item::before{content:'';position:absolute;left:-24px;top:14px;width:10px;height:10px;border-radius:50%;background:var(--accent);border:2px solid var(--bg-base)}
.tl-item.attack::before{background:var(--danger)}.tl-item.warning::before{background:var(--warning)}.tl-item.info::before{background:var(--success)}
.tl-time{font-size:10px;color:var(--text-dim);font-family:var(--mono)}.tl-type{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;font-family:var(--mono);text-transform:uppercase;margin-left:8px}.tl-type.ssh{background:rgba(34,211,238,0.12);color:var(--accent)}.tl-type.web{background:rgba(245,158,11,0.12);color:var(--warning)}.tl-type.creds{background:rgba(239,68,68,0.12);color:var(--danger)}.tl-type.malware{background:rgba(16,185,129,0.12);color:var(--success)}.tl-type.default{background:var(--bg-elevated);color:var(--text-dim)}
.tl-ip{color:var(--accent);font-family:var(--mono);font-weight:500;margin-left:8px}.tl-detail{color:var(--text-secondary);font-size:11px;margin-top:4px}
.filter-bar{display:flex;gap:6px;margin-bottom:15px;flex-wrap:wrap}.filter-btn{padding:4px 12px;border-radius:var(--radius-sm);border:1px solid var(--border-subtle);background:var(--bg-card);color:var(--text-muted);font-size:11px;cursor:pointer;transition:all .15s}.filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
</style></head><body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span style="width:7px;height:7px;border-radius:50%;background:var(--success)"></span> {{ running }}/17 Active</div></div></div>
<div class="nav"><a href="/">Overview</a><a href="/heatmap">Heatmap</a><a href="/correlation">Correlation</a><a href="/api">API</a><a href="/settings">Settings</a><a href="/attack-map">Attack Map</a><a href="/timeline" class="active">Timeline</a><a href="/statistics">Statistics</a></div>
<div class="page-body">
<div class="section-title"><span class="dot"></span> Attack Timeline</div>
<div class="filter-bar">
<button class="filter-btn active" onclick="filterTL('all')">All</button>
<button class="filter-btn" onclick="filterTL('ssh')">SSH</button>
<button class="filter-btn" onclick="filterTL('web')">Web</button>
<button class="filter-btn" onclick="filterTL('creds')">Creds</button>
<button class="filter-btn" onclick="filterTL('malware')">Malware</button>
<button class="filter-btn" onclick="filterTL('rdp')">RDP</button>
<button class="filter-btn" onclick="filterTL('smb')">SMB</button>
<button class="filter-btn" onclick="filterTL('dns')">DNS</button>
</div>
<div class="timeline">
{% for e in timeline %}
<div class="tl-item {{ 'attack' if e._type in ['ssh','malware','creds'] else 'warning' if e._type in ['web','rdp','smb'] else 'info' }}" data-type="{{ e._type }}">
<span class="tl-time">{{ e.timestamp[:19] if e.timestamp else '--' }}</span>
<span class="tl-type {{ e._type }}">{{ e._type }}</span>
<span class="tl-ip">{{ e.source_ip or e.src_ip or '--' }}</span>
<div class="tl-detail">{{ e.message or e.method or e.protocol or e.detail or e.note or e.event or '' }} {{ e.path or '' }}</div>
</div>
{% endfor %}
</div>
{% if not timeline %}<div style="text-align:center;padding:40px;color:var(--text-dim)">No events yet</div>{% endif %}
</div>
<script>
function filterTL(type){document.querySelectorAll('.tl-item').forEach(e=>{e.style.display=(type==='all'||e.dataset.type===type)?'block':'none'});document.querySelectorAll('.filter-btn').forEach(b=>{b.classList.toggle('active',b.textContent.toLowerCase()===type||b.textContent==='All'&&type==='all')})}
</script></body></html>"""

@app.route("/timeline")
def timeline_page():
    stats, total, uips, running = get_stats()
    all_entries = []
    # Take balanced entries from each type (15 each, like overview)
    for key in HONEYPOT_TYPES:
        entries = get_logs(key, 15)
        for e in entries:
            e["_type"] = key
        all_entries.extend(entries)
    all_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return render_template_string(TIMELINE_HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), timeline=all_entries)

# ============================================================
# FEATURE 5: IP Blacklist
# ============================================================
BLACKLIST_FILE = os.path.join(LAB_DIR, "blacklist.json")

def load_blacklist():
    try:
        with open(BLACKLIST_FILE, encoding="utf-8") as f: return json.load(f)
    except: return {"blocked": [], "allowed": []}

def save_blacklist(data):
    with open(BLACKLIST_FILE, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)

@app.route("/api/blacklist", methods=["GET", "POST"])
def api_blacklist():
    if request.method == "POST":
        data = request.get_json() or {}
        if "add_block" in data:
            bl = load_blacklist()
            if data["add_block"] not in bl["blocked"]:
                bl["blocked"].append(data["add_block"])
                save_blacklist(bl)
        elif "remove_block" in data:
            bl = load_blacklist()
            bl["blocked"] = [ip for ip in bl["blocked"] if ip != data["remove_block"]]
            save_blacklist(bl)
        elif "add_allow" in data:
            bl = load_blacklist()
            if data["add_allow"] not in bl["allowed"]:
                bl["allowed"].append(data["add_allow"])
                save_blacklist(bl)
        elif "remove_allow" in data:
            bl = load_blacklist()
            bl["allowed"] = [ip for ip in bl["allowed"] if ip != data["remove_allow"]]
            save_blacklist(bl)
    return jsonify(load_blacklist())

# ============================================================
# FEATURE 6: Real-time Updates (SSE)
# ============================================================
@app.route("/api/events/stream")
def event_stream():
    import time
    def generate():
        last_count = 0
        while True:
            stats, total, uips, running = get_stats()
            if total != last_count:
                data = json.dumps({"total_events": total, "unique_ips": uips, "running": running, "timestamp": datetime.datetime.now().isoformat()})
                yield f"data: {data}\n\n"
                last_count = total
            time.sleep(2)
    return generate(), 200, {"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"}

# ============================================================
# FEATURE 7: Dashboard Login
# ============================================================
LOGIN_FILE = os.path.join(LAB_DIR, "login.json")
app.secret_key = os.urandom(24)

def load_login_config():
    try:
        with open(LOGIN_FILE, encoding="utf-8") as f: return json.load(f)
    except: return {"enabled": False, "username": "admin", "password": "honeypot123"}

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    cfg = load_login_config()
    if not cfg["enabled"]:
        return jsonify({"status": "ok", "message": "Login disabled"})
    if data.get("username") == cfg["username"] and data.get("password") == cfg["password"]:
        return jsonify({"status": "ok", "message": "Authenticated"})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route("/api/login/config", methods=["GET", "POST"])
def api_login_config():
    if request.method == "POST":
        data = request.get_json() or {}
        cfg = load_login_config()
        if "enabled" in data: cfg["enabled"] = data["enabled"]
        if "username" in data: cfg["username"] = data["username"]
        if "password" in data: cfg["password"] = data["password"]
        with open(LOGIN_FILE, "w", encoding="utf-8") as f: json.dump(cfg, f, indent=2)
    return jsonify(load_login_config())

# ============================================================
# FEATURE 8: Scheduled Reports
# ============================================================
SCHEDULE_FILE = os.path.join(LAB_DIR, "schedule.json")

@app.route("/api/schedule", methods=["GET", "POST"])
def api_schedule():
    if request.method == "POST":
        data = request.get_json() or {}
        with open(SCHEDULE_FILE, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
        return jsonify({"status": "ok", "message": "Schedule saved"})
    try:
        with open(SCHEDULE_FILE, encoding="utf-8") as f: return jsonify(json.load(f))
    except: return jsonify({"enabled": False, "frequency": "daily", "time": "09:00", "email": "", "format": "pdf"})

# ============================================================
# FEATURE 9: Attack Statistics Charts
# ============================================================
STATISTICS_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Statistics - Honeypot Lab</title>
<style>
:root{--bg-base:#0B0F19;--bg-surface:#111827;--bg-card:#151D2E;--bg-elevated:#1E293B;--border:#1E293B;--border-subtle:#162032;--accent:#22D3EE;--accent-dim:rgba(34,211,238,0.12);--danger:#EF4444;--warning:#F59E0B;--success:#10B981;--text-primary:#F1F5F9;--text-secondary:#94A3B8;--text-muted:#64748B;--text-dim:#475569;--mono:'SF Mono',Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;--radius:10px;--radius-sm:6px}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:var(--sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh}
.header{background:var(--bg-surface);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;justify-content:space-between}.header-left{display:flex;align-items:center;gap:14px}.logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#06B6D4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}.header-text h1{font-size:17px;font-weight:700}.header-text .sub{font-size:12px;color:var(--text-muted)}.header-text .sub span{color:var(--accent)}.header-right{display:flex;align-items:center;gap:16px}.status-pill{display:flex;align-items:center;gap:6px;background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,.2);padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;color:var(--success)}
.nav{display:flex;gap:2px;padding:6px 28px;background:var(--bg-surface);border-bottom:1px solid var(--border)}.nav a{padding:6px 14px;border-radius:var(--radius-sm);text-decoration:none;color:var(--text-muted);font-size:12px;font-weight:500;transition:all .15s}.nav a:hover{color:var(--text-secondary);background:var(--bg-elevated)}.nav a.active{color:var(--accent);background:var(--accent-dim)}
.page-body{padding:20px 28px}.section-title{font-size:14px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}.section-title .dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:15px}
.chart-card{background:var(--bg-card);border-radius:var(--radius);border:1px solid var(--border-subtle);padding:20px}
.chart-card h3{font-size:12px;font-weight:700;margin-bottom:15px;color:var(--text-primary)}
.bar-chart{display:flex;flex-direction:column;gap:6px}
.bar-row{display:flex;align-items:center;gap:10px}
.bar-label{width:100px;font-size:11px;color:var(--text-muted);text-align:right;font-family:var(--mono)}
.bar-track{flex:1;height:20px;background:var(--bg-elevated);border-radius:3px;overflow:hidden;position:relative}
.bar-fill{height:100%;border-radius:3px;transition:width .5s ease;display:flex;align-items:center;justify-content:flex-end;padding-right:6px;font-size:9px;font-weight:700;color:var(--bg-base)}
.bar-fill.ssh{background:var(--accent)}.bar-fill.web{background:var(--warning)}.bar-fill.db{background:#818CF8}.bar-fill.malware{background:var(--success)}.bar-fill.rdp{background:var(--danger)}.bar-fill.default{background:var(--text-dim)}
.pie-chart{display:flex;flex-wrap:wrap;gap:8px;justify-content:center}
.pie-item{display:flex;align-items:center;gap:4px;font-size:10px;color:var(--text-muted)}
.pie-dot{width:8px;height:8px;border-radius:50%}
.timeline-chart{display:flex;align-items:flex-end;gap:2px;height:120px;padding:10px 0}
.timeline-bar{flex:1;background:var(--accent);border-radius:2px 2px 0 0;min-height:2px;transition:height .3s;position:relative;cursor:pointer}
.timeline-bar:hover{opacity:.8}
.timeline-bar .tt{display:none;position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:var(--bg-surface);border:1px solid var(--border);padding:4px 8px;border-radius:4px;font-size:9px;white-space:nowrap}
.timeline-bar:hover .tt{display:block}
.timeline-labels{display:flex;justify-content:space-between;font-size:9px;color:var(--text-dim);margin-top:4px}
</style></head><body>
<div class="header"><div class="header-left"><div class="logo">🍯</div><div class="header-text"><h1>Honeypot Lab v2.0</h1><div class="sub">Cybersecurity Attack & Defense Lab · <span>Developed by JOJIN JOHN</span></div></div></div><div class="header-right"><div class="status-pill"><span style="width:7px;height:7px;border-radius:50%;background:var(--success)"></span> {{ running }}/17 Active</div></div></div>
<div class="nav"><a href="/">Overview</a><a href="/heatmap">Heatmap</a><a href="/correlation">Correlation</a><a href="/api">API</a><a href="/settings">Settings</a><a href="/attack-map">Attack Map</a><a href="/timeline">Timeline</a><a href="/statistics" class="active">Statistics</a></div>
<div class="page-body">
<div class="section-title"><span class="dot"></span> Attack Statistics</div>
<div class="chart-grid">
<div class="chart-card"><h3>Events by Honeypot Type</h3>
<div class="bar-chart">{% for item in type_stats %}<div class="bar-row"><div class="bar-label">{{ item.name }}</div><div class="bar-track"><div class="bar-fill {{ item.name }}" style="width:{{ item.pct }}%">{{ item.count }}</div></div></div>{% endfor %}</div></div>
<div class="chart-card"><h3>Attack Distribution</h3>
<div class="pie-chart">{% for item in type_stats %}<div class="pie-item"><div class="pie-dot" style="background:{{ item.color }}"></div>{{ item.name }}: {{ item.count }}</div>{% endfor %}</div></div>
<div class="chart-card" style="grid-column:1/-1"><h3>Hourly Activity (Last 24h)</h3>
<div class="timeline-chart">{% for h in hourly_data %}<div class="timeline-bar" style="height:{{ h.pct }}%"><div class="tt">{{ h.hour }}:00 — {{ h.count }} events</div></div>{% endfor %}</div>
<div class="timeline-labels"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span></div></div>
</div></div>
<script>setTimeout(()=>location.reload(),15000)</script>
</body></html>"""

@app.route("/statistics")
def statistics_page():
    stats, total, uips, running = get_stats()
    type_stats = []
    colors = {"ssh":"#22D3EE","web":"#F59E0B","db":"#818CF8","malware":"#10B981","rdp":"#EF4444","creds":"#EC4899","smb":"#F97316","dns":"#06B6D4","sip":"#8B5CF6","redis":"#EF4444","vnc":"#10B981","telnet":"#6366F1","memcached":"#F59E0B","mqtt":"#EC4899","snmp":"#06B6D4","ntp":"#8B5CF6","ics":"#F97316"}
    max_count = max((v["count"] for v in stats.values()), default=1) or 1
    for key, info in sorted(stats.items(), key=lambda x: -x[1]["count"]):
        pct = (info["count"] / max_count * 100) if max_count else 0
        type_stats.append({"name": key, "count": info["count"], "pct": pct, "color": colors.get(key, "#64748B")})
    hourly_data = []
    all_entries = []
    for key in HONEYPOT_TYPES:
        all_entries.extend(get_logs(key, 1000))
    hour_counts = collections.Counter()
    for e in all_entries:
        ts = e.get("timestamp", "")
        if ts and len(ts) >= 13:
            try: hour_counts[ts[11:13]] += 1
            except: pass
    max_h = max(hour_counts.values(), default=1) or 1
    for h in range(24):
        hk = f"{h:02d}"
        cnt = hour_counts.get(hk, 0)
        hourly_data.append({"hour": hk, "count": cnt, "pct": int(cnt / max_h * 100) if max_h else 0})
    return render_template_string(STATISTICS_HTML, stats=stats, total_events=total, unique_ips=uips, running=running, now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), type_stats=type_stats, hourly_data=hourly_data)

# ============================================================
# FEATURE 10: Malware Analysis
# ============================================================
@app.route("/api/malware/analyze")
def api_malware_analyze():
    malware_dir = os.path.join(LOGS_DIR, "malware")
    downloads_dir = os.path.join(LOGS_DIR, "ssh", "downloads")
    results = []
    import hashlib
    for d in [malware_dir, downloads_dir]:
        if not os.path.exists(d): continue
        for f in os.listdir(d):
            fpath = os.path.join(d, f)
            if os.path.isfile(fpath) and f not in (".gitkeep",):
                try:
                    with open(fpath, "rb") as fh:
                        data = fh.read()
                    results.append({
                        "filename": f, "size": len(data),
                        "md5": hashlib.md5(data).hexdigest(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "first_bytes": data[:16].hex() if data else "",
                    })
                except: pass
    return jsonify({"files": results, "total": len(results)})

# ============================================================
# FEATURE 11: Backup/Restore
# ============================================================
@app.route("/api/backup")
def api_backup():
    import zipfile, io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(LOGS_DIR):
            for f in files:
                if f.endswith(('.jsonl', '.json', '.csv', '.log')):
                    fpath = os.path.join(root, f)
                    arcname = os.path.relpath(fpath, LAB_DIR)
                    zf.write(fpath, arcname)
        zf.write(os.path.join(LAB_DIR, "config.ini"), "config.ini")
    buffer.seek(0)
    return buffer.getvalue(), 200, {"Content-Type": "application/zip", "Content-Disposition": "attachment; filename=honeypot_backup.zip"}

@app.route("/api/restore", methods=["POST"])
def api_restore():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    import zipfile, io
    try:
        with zipfile.ZipFile(io.BytesIO(f.read())) as zf:
            zf.extractall(LAB_DIR)
        return jsonify({"status": "ok", "message": "Backup restored successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
# FEATURE 12: Custom Alert Rules
# ============================================================
RULES_FILE = os.path.join(LAB_DIR, "alert_rules.json")

def load_rules():
    try:
        with open(RULES_FILE, encoding="utf-8") as f: return json.load(f)
    except: return {"rules": [{"name": "High event rate", "condition": "events > 100", "action": "alert", "enabled": True}]}

@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "POST":
        data = request.get_json() or {}
        with open(RULES_FILE, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
        return jsonify({"status": "ok"})
    return jsonify(load_rules())

@app.route("/api/rules/check")
def api_rules_check():
    rules = load_rules().get("rules", [])
    triggered = []
    stats, total, uips, running = get_stats()
    for rule in rules:
        if not rule.get("enabled", True): continue
        cond = rule.get("condition", "")
        try:
            if "events >" in cond:
                threshold = int(cond.split(">")[1].strip())
                if total > threshold:
                    triggered.append({"rule": rule["name"], "condition": cond, "current": total, "action": rule.get("action", "alert")})
            elif "unique_ips >" in cond:
                threshold = int(cond.split(">")[1].strip())
                if uips > threshold:
                    triggered.append({"rule": rule["name"], "condition": cond, "current": uips, "action": rule.get("action", "alert")})
            elif "type ==" in cond:
                rule_type = cond.split("==")[1].strip().strip("'\"")
                if stats.get(rule_type, {}).get("count", 0) > 0:
                    triggered.append({"rule": rule["name"], "condition": cond, "current": stats[rule_type]["count"], "action": rule.get("action", "alert")})
        except: pass
    return jsonify({"triggered": triggered, "total_rules": len(rules), "checked_at": datetime.datetime.now().isoformat()})

# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("="*55)
    print("  📊 Honeypot Lab Dashboard v2.0")
    print("  Developed by JOJIN JOHN")
    print("="*55)
    print(f"  Dashboard: http://127.0.0.1:5000")
    print(f"  All 17 honeypots + 12 features")
    print(f"  Press Ctrl+C to stop")
    print("="*55)
    app.run(host="127.0.0.1", port=5000, debug=False)
