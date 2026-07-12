#!/usr/bin/env python3
"""
Feature: Attack Heatmap — Shows attacker activity over time + geography
"""
import os, sys, json, glob, datetime, collections

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(LAB_DIR, "logs")

def generate_heatmap_data():
    data = {"hourly": {}, "daily": {}, "by_type": {}, "sources": []}
    hourly = collections.Counter()
    daily = collections.Counter()
    by_type = collections.Counter()

    patterns = [("ssh", "cowrie.json"), ("web", "*.jsonl"), ("creds", "*.jsonl"), ("db", "*.jsonl"), ("malware", "*.jsonl"), ("rdp", "*.jsonl"), ("smb", "*.jsonl"), ("dns", "*.jsonl"), ("sip", "*.jsonl"), ("redis", "*.jsonl"), ("vnc", "*.jsonl"), ("telnet", "*.jsonl"), ("memcached", "*.jsonl"), ("mqtt", "*.jsonl"), ("snmp", "*.jsonl"), ("ntp", "*.jsonl")]

    for subdir, pattern in patterns:
        d = os.path.join(LOGS_DIR, subdir)
        if not os.path.exists(d): continue
        count = 0
        for f in glob.glob(os.path.join(d, pattern)):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        count += 1
                        try:
                            e = json.loads(line.strip())
                            ts = e.get("timestamp", "")
                            if ts and len(ts) >= 16:
                                try:
                                    dt = datetime.datetime.fromisoformat(ts[:19])
                                    hourly[f"{dt.hour:02d}:00"] += 1
                                    daily[dt.strftime("%Y-%m-%d")] += 1
                                except: pass
                        except: pass
            except: pass
        by_type[subdir] = count

    data["hourly"] = dict(sorted(hourly.items()))
    data["daily"] = dict(sorted(daily.items()))
    data["by_type"] = dict(by_type.most_common())
    return data

if __name__ == "__main__":
    import json
    data = generate_heatmap_data()
    print(json.dumps(data, indent=2))
