#!/usr/bin/env python3
"""
Shared alert helper — logs alerts to alerts.jsonl and triggers notifications.
Import this in any honeypot script: from alert_helper import log_alert
"""
import os, json, datetime, sys

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_LOG = os.path.join(LAB_DIR, "logs", "alerts.jsonl")

def log_alert(alert_type, source_ip, detail=""):
    ts = datetime.datetime.now().isoformat()
    entry = {"timestamp": ts, "type": alert_type, "source_ip": source_ip, "detail": str(detail)[:300]}
    os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    # Try to send notifications
    try:
        sys.path.insert(0, LAB_DIR)
        from features.notifications import notify
        notify(alert_type, {"source_ip": source_ip, "detail": detail})
    except: pass
