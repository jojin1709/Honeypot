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
Blue Team: Honeypot Log Analyzer — All 17 honeypots
Analyze captured attack data across all services.
"""
import os, sys, json, glob, datetime, collections

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(LAB_DIR, "logs")

LOG_SOURCES = [
    ("ssh", "cowrie.json", "src_ip"), ("ics", "*.jsonl", "source_ip"), ("creds", "*.jsonl", "source_ip"), ("web", "*.jsonl", "source_ip"), ("db", "*.jsonl", "source_ip"), ("malware", "*.jsonl", "source_ip"), ("rdp", "*.jsonl", "source_ip"), ("smb", "*.jsonl", "source_ip"), ("dns", "*.jsonl", "source_ip"), ("sip", "*.jsonl", "source_ip"), ("redis", "*.jsonl", "source_ip"), ("vnc", "*.jsonl", "source_ip"), ("telnet", "*.jsonl", "source_ip"), ("memcached", "*.jsonl", "source_ip"), ("mqtt", "*.jsonl", "source_ip"), ("snmp", "*.jsonl", "source_ip"), ("ntp", "*.jsonl", "source_ip"),
]

HONEYPOT_NAMES = {"ssh":"🐚 SSH","ics":"🏭 ICS","creds":"🔑 Creds","web":"🌐 Web","db":"🗄️ DB","malware":"🦠 Malware","rdp":"🖥️ RDP","smb":"📁 SMB","dns":"🌐 DNS","sip":"📞 SIP","redis":"🔴 Redis","vnc":"🖥️ VNC","telnet":"📟 Telnet","memcached":"📦 Memcache","mqtt":"📡 MQTT","snmp":"🌐 SNMP","ntp":"🕐 NTP"}

def analyze_all():
    totals = {}
    all_ips = collections.Counter()
    hourly = collections.Counter()
    daily = collections.Counter()
    total_events = 0

    for subdir, pattern, ip_key in LOG_SOURCES:
        d = os.path.join(LOGS_DIR, subdir)
        count = 0
        ips = collections.Counter()
        paths = collections.Counter()
        log_files = []
        for f in glob.glob(os.path.join(d, pattern)):
            log_files.append(f)
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line: continue
                        count += 1
                        try:
                            e = json.loads(line)
                            ip = e.get(ip_key) or e.get("source_ip") or ""
                            if ip and ip not in ("127.0.0.1","::1","unknown"):
                                all_ips[ip] += 1
                                ips[ip] += 1
                                total_events += 1
                            ts = e.get("timestamp","")
                            if ts and len(ts) >= 16:
                                try:
                                    dt = datetime.datetime.fromisoformat(ts[:19])
                                    hourly[f"{dt.hour:02d}:00"] += 1
                                    daily[dt.strftime("%Y-%m-%d")] += 1
                                except: pass
                                path = e.get("path","")
                                if path: paths[path] += 1
                        except: pass
            except: pass
        totals[subdir] = {"count": count, "log_files": len(log_files), "unique_ips": len(ips), "top_ips": ips.most_common(5)}

    return totals, all_ips, total_events, hourly, daily

def generate_report():
    print("=" * 70)
    print("  📊 HONEYPOT LAB — Threat Analysis Report v2.0")
    print(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Developed by JOJIN JOHN")
    print("=" * 70)

    totals, all_ips, total_events, hourly, daily = analyze_all()

    print(f"\n  📈 GLOBAL STATS")
    print(f"  {'─'*50}")
    print(f"  Total events:        {total_events}")
    print(f"  Unique IPs:          {len(all_ips)}")

    print(f"\n  🏗️  PER-HONEYPOT BREAKDOWN")
    print(f"  {'─'*50}")
    for subdir, info in totals.items():
        name = HONEYPOT_NAMES.get(subdir, subdir)
        print(f"  {name:<15} {info['count']:>6} events  |  {info['unique_ips']:>3} IPs  |  {info['log_files']} log files")

    print(f"\n  🎯 TOP ATTACKERS (ALL SERVICES)")
    print(f"  {'─'*50}")
    print(f"  {'IP':>20}  {'Events':>8}  {'%':>8}")
    for ip, count in all_ips.most_common(15):
        pct = (count / total_events * 100) if total_events else 0
        print(f"  {ip:>20}  {count:>8}  {pct:>7.1f}%")

    if hourly:
        print(f"\n  🕐 HOURLY ACTIVITY")
        print(f"  {'─'*50}")
        max_h = max(hourly.values()) if hourly else 1
        for h in sorted(hourly.keys()):
            bar = "█" * int((hourly[h] / max_h) * 30)
            print(f"    {h}  {bar} {hourly[h]}")

    if daily:
        print(f"\n  📅 DAILY ACTIVITY")
        print(f"  {'─'*50}")
        for d, count in sorted(daily.items()):
            print(f"    {d}  {count} events")

    # Save report
    report = {"generated": datetime.datetime.now().isoformat(), "total_events": total_events, "unique_ips": len(all_ips), "top_attackers": all_ips.most_common(50), "per_honeypot": {k: {"events": v["count"], "unique_ips": v["unique_ips"], "log_files": v["log_files"]} for k, v in totals.items()}}
    report_path = os.path.join(LAB_DIR, "analysis_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  💾 Full JSON report: {report_path}")
    print("=" * 70)

def main():
    print("=" * 70)
    print("  🔵 HONEYPOT LAB — Blue Team Analysis Tools")
    print("=" * 70)
    while True:
        print("\nOptions:")
        print("  1) Generate full analysis report (all 17 honeypots)")
        print("  2) Show top attackers")
        print("  3) Show activity timeline")
        print("  4) Analyze specific honeypot")
        print("  5) Export all data to JSON")
        print("  0) Exit")
        choice = input("  Choice: ")
        if choice == "1": generate_report()
        elif choice == "2":
            _, all_ips, total, _, _ = analyze_all()
            print(f"\n  🎯 TOP ATTACKERS\n{'─'*50}")
            for ip, count in all_ips.most_common(20):
                print(f"  {ip:>20}  {count} events")
        elif choice == "3":
            _, _, _, hourly, daily = analyze_all()
            if hourly:
                print(f"\n  🕐 Hourly:\n{'─'*30}")
                for h in sorted(hourly.keys()): print(f"  {h}  {'█'*min(hourly[h],40)} {hourly[h]}")
            if daily:
                print(f"\n  📅 Daily:\n{'─'*30}")
                for d, c in sorted(daily.items()): print(f"  {d}  {c} events")
        elif choice == "4":
            print("\n  Select honeypot:")
            for i, (subdir, _, _) in enumerate(LOG_SOURCES, 1):
                print(f"    {i}) {HONEYPOT_NAMES.get(subdir, subdir)}")
            try:
                idx = int(input("  Choice: ")) - 1
                if 0 <= idx < len(LOG_SOURCES):
                    subdir, pattern, ip_key = LOG_SOURCES[idx]
                    d = os.path.join(LOGS_DIR, subdir)
                    files = glob.glob(os.path.join(d, pattern))
                    print(f"\n  📊 {HONEYPOT_NAMES.get(subdir, subdir)}")
                    print(f"  Log files: {len(files)}")
                    for f in files[:10]:
                        size = os.path.getsize(f)
                        print(f"    {os.path.basename(f)} ({size:,} bytes)")
                    print()
                    # Show last 10 entries
                    entries = []
                    for f in files:
                        try:
                            with open(f, encoding="utf-8", errors="replace") as fh:
                                for line in fh:
                                    try: entries.append(json.loads(line.strip()))
                                    except: pass
                        except: pass
                    entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                    for e in entries[:10]:
                        ip = e.get(ip_key) or e.get("source_ip") or "?"
                        ts = e.get("timestamp", "")[:19]
                        print(f"    {ts} | {ip}")
                else: print("  Invalid choice")
            except: pass
        elif choice == "5":
            generate_report()
            print("  ✅ Exported!")
        elif choice == "0": break

if __name__ == "__main__":
    main()
