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
Feature: Attack Correlation Engine — Links attacker IPs across multiple services
"""
import os, sys, json, glob, datetime, collections

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(LAB_DIR, "logs")

def load_all_events(limit=10000):
    events = []
    patterns = [("ssh", "cowrie.json", "src_ip"), ("web", "*.jsonl", "source_ip"), ("creds", "*.jsonl", "source_ip"), ("creds", "*.json", "source_ip"), ("db", "*.jsonl", "source_ip"), ("malware", "*.jsonl", "source_ip"), ("rdp", "*.jsonl", "source_ip"), ("smb", "*.jsonl", "source_ip"), ("dns", "*.jsonl", "source_ip"), ("sip", "*.jsonl", "source_ip"), ("redis", "*.jsonl", "source_ip"), ("vnc", "*.jsonl", "source_ip"), ("telnet", "*.jsonl", "source_ip"), ("memcached", "*.jsonl", "source_ip"), ("mqtt", "*.jsonl", "source_ip"), ("snmp", "*.jsonl", "source_ip"), ("ntp", "*.jsonl", "source_ip"), ("ics", "*.jsonl", "source_ip")]
    for subdir, pattern, key in patterns:
        d = os.path.join(LOGS_DIR, subdir)
        if not os.path.exists(d): continue
        for f in glob.glob(os.path.join(d, pattern)):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line: continue
                        try:
                            e = json.loads(line)
                            e["_source_file"] = f
                            e["_honeypot_type"] = subdir
                            events.append(e)
                            if len(events) >= limit: break
                        except: pass
                    if len(events) >= limit: break
            except: pass
    return events

def correlate():
    """Find attackers hitting multiple services"""
    events = load_all_events()
    ip_services = collections.defaultdict(set)
    ip_count = collections.Counter()
    for e in events:
        ip = e.get("src_ip") or e.get("source_ip") or ""
        if not ip or ip in ("::1", "unknown"): continue
        ip_services[ip].add(e.get("_honeypot_type", "unknown"))
        ip_count[ip] += 1
    multi_service = {ip: svc for ip, svc in ip_services.items() if len(svc) >= 2}
    top_list = [{"ip": ip, "count": cnt} for ip, cnt in ip_count.most_common(20)]
    multi_list = [{"ip": ip, "count": ip_count[ip], "services": sorted(list(svc))} for ip, svc in sorted(multi_service.items(), key=lambda x: len(x[1]), reverse=True)[:20]]
    return {"total_events": len(events), "unique_ips": len(ip_count), "multi_service_attackers": len(multi_service), "top_attackers": top_list, "multi_service": multi_list}

def print_report():
    r = correlate()
    print(f"\n  🔗 ATTACK CORRELATION REPORT\n  {'='*40}")
    print(f"  Total events:         {r['total_events']}")
    print(f"  Unique IPs:           {r['unique_ips']}")
    print(f"  Multi-service attackers: {r['multi_service_attackers']}")
    if r['multi_service']:
        print(f"\n  🔴 Attackers hitting MULTIPLE services:")
        for ip, services in r['multi_service'][:10]:
            print(f"    {ip:>20} -> {', '.join(sorted(services))}")

if __name__ == "__main__":
    print_report()
