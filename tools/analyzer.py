#!/usr/bin/env python3
"""
Blue Team: Honeypot Log Analyzer
Analyze captured attack data — find patterns, top attackers, trends.
"""
import os
import sys
import json
import glob
import datetime
import collections
from collections import Counter, defaultdict

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(os.path.dirname(LAB_DIR), "logs")


def load_json_logs(filepath):
    """Load JSON objects from a file (one JSON per line)"""
    entries = []
    if not os.path.exists(filepath):
        return entries
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except:
        pass
    return entries


def analyze_ssh():
    """Analyze SSH honeypot logs"""
    ssh_dir = os.path.join(LOGS_DIR, "ssh")
    entries = []
    for f in glob.glob(os.path.join(ssh_dir, "cowrie.json")):
        entries.extend(load_json_logs(f))

    stats = {"total_connections": len(entries)}
    ip_counts = Counter()
    event_types = Counter()

    for e in entries:
        src_ip = e.get("src_ip", e.get("source_ip", "unknown"))
        ip_counts[src_ip] += 1
        event_types[e.get("eventid", e.get("event", "unknown"))] += 1

    stats["unique_ips"] = len(ip_counts)
    stats["top_attackers"] = ip_counts.most_common(10)
    stats["event_types"] = event_types.most_common(10)

    return stats


def analyze_web():
    """Analyze web honeypot logs"""
    web_dir = os.path.join(LOGS_DIR, "web")
    entries = []
    for f in glob.glob(os.path.join(web_dir, "*.jsonl")):
        entries.extend(load_json_logs(f))

    stats = {"total_requests": len(entries)}
    ip_counts = Counter()
    path_counts = Counter()
    method_counts = Counter()
    ua_counts = Counter()

    for e in entries:
        ip_counts[e.get("source_ip", "unknown")] += 1
        path_counts[e.get("path", "/")] += 1
        method_counts[e.get("method", "GET")] += 1
        ua_counts[e.get("user_agent", "none")[:40]] += 1

    stats["unique_ips"] = len(ip_counts)
    stats["top_ips"] = ip_counts.most_common(10)
    stats["top_paths"] = path_counts.most_common(10)
    stats["methods"] = dict(method_counts.most_common())
    stats["top_user_agents"] = ua_counts.most_common(10)

    return stats


def analyze_creds():
    """Analyze credential capture logs"""
    creds_dir = os.path.join(LOGS_DIR, "creds")
    entries = []

    # Try multiple log formats
    for pattern in ["*.json", "*.jsonl"]:
        for f in glob.glob(os.path.join(creds_dir, pattern)):
            entries.extend(load_json_logs(f))

    stats = {"total_attempts": len(entries)}
    ip_counts = Counter()
    protocol_counts = Counter()
    username_counts = Counter()

    for e in entries:
        ip_counts[e.get("source_ip", e.get("remote", "unknown"))] += 1
        protocol_counts[e.get("protocol", e.get("service", "unknown"))] += 1

        # Try to extract username/password
        for field in ["username", "user", "login"]:
            if field in e:
                username_counts[str(e[field])] += 1

    stats["unique_ips"] = len(ip_counts)
    stats["top_ips"] = ip_counts.most_common(10)
    stats["protocols"] = dict(protocol_counts.most_common())
    if username_counts:
        stats["common_usernames"] = username_counts.most_common(10)

    return stats


def analyze_db():
    """Analyze database honeypot logs"""
    db_dir = os.path.join(LOGS_DIR, "db")
    entries = []
    for f in glob.glob(os.path.join(db_dir, "*.jsonl")):
        entries.extend(load_json_logs(f))

    stats = {"total_probes": len(entries)}
    ip_counts = Counter()
    path_counts = Counter()

    for e in entries:
        ip_counts[e.get("source_ip", "unknown")] += 1
        path_counts[e.get("path", "/")] += 1

    stats["unique_ips"] = len(ip_counts)
    stats["top_ips"] = ip_counts.most_common(10)
    stats["top_paths"] = path_counts.most_common(10)

    return stats


def analyze_malware():
    """Analyze malware capture logs"""
    malware_dir = os.path.join(LOGS_DIR, "malware")
    entries = []
    for f in glob.glob(os.path.join(malware_dir, "*.jsonl")):
        entries.extend(load_json_logs(f))

    stats = {"total_requests": len(entries), "total_files": 0}
    ip_counts = Counter()

    for e in entries:
        ip_counts[e.get("source_ip", "unknown")] += 1
        if e.get("file_hash"):
            stats["total_files"] += 1

    stats["unique_ips"] = len(ip_counts)
    stats["top_ips"] = ip_counts.most_common(10)

    # Count captured files
    captured_dir = os.path.join(malware_dir, "captured_files")
    if os.path.exists(captured_dir):
        stats["captured_file_count"] = len(os.listdir(captured_dir))

    return stats


def analyze_rdp():
    """Analyze RDP honeypot logs"""
    rdp_dir = os.path.join(LOGS_DIR, "rdp")
    entries = []
    for f in glob.glob(os.path.join(rdp_dir, "*.jsonl")):
        entries.extend(load_json_logs(f))

    stats = {"total_connections": len(entries)}
    ip_counts = Counter()

    for e in entries:
        ip_counts[e.get("source_ip", "unknown")] += 1

    stats["unique_ips"] = len(ip_counts)
    stats["top_ips"] = ip_counts.most_common(10)

    return stats


def generate_report():
    """Generate a comprehensive analysis report"""
    print("=" * 70)
    print("  📊 HONEYPOT LAB - Threat Analysis Report")
    print(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # SSH Analysis
    print("\n🐚  SSH HONEYPOT\n" + "-" * 50)
    s = analyze_ssh()
    print(f"  Total connections:    {s['total_connections']}")
    print(f"  Unique attacker IPs:  {s['unique_ips']}")
    if s.get('top_attackers'):
        print(f"  Top attackers:")
        for ip, count in s['top_attackers'][:5]:
            print(f"    {ip:>20}  -  {count} connections")

    # Web Analysis
    print("\n🌐  WEB TRAPS\n" + "-" * 50)
    w = analyze_web()
    print(f"  Total requests:       {w['total_requests']}")
    print(f"  Unique IPs:           {w['unique_ips']}")
    if w.get('top_paths'):
        print(f"  Most attacked paths:")
        for path, count in w['top_paths'][:5]:
            print(f"    {path:<35} {count} hits")
    if w.get('methods'):
        print(f"  HTTP methods:         {w['methods']}")

    # Credential Analysis
    print("\n🔑  CREDENTIAL CAPTURE\n" + "-" * 50)
    c = analyze_creds()
    print(f"  Total login attempts: {c['total_attempts']}")
    print(f"  Unique IPs:           {c['unique_ips']}")
    if c.get('protocols'):
        print(f"  Protocols attacked:   {c['protocols']}")
    if c.get('common_usernames'):
        print(f"  Most used usernames:")
        for user, count in c['common_usernames'][:5]:
            print(f"    '{user}'  -  {count} attempts")

    # Malware Analysis
    print("\n🦠  MALWARE CAPTURE\n" + "-" * 50)
    m = analyze_malware()
    print(f"  Total interactions:   {m['total_requests']}")
    print(f"  Files captured:       {m.get('captured_file_count', 0)}")
    print(f"  Unique IPs:           {m['unique_ips']}")

    # ICS/SCADA
    print("\n🏭  ICS/SCADA\n" + "-" * 50)
    ics_dir = os.path.join(LOGS_DIR, "ics")
    ics_files = glob.glob(os.path.join(ics_dir, "*"))
    print(f"  Log files:            {len(ics_files)}")
    print(f"  Check {ics_dir} for detailed probe logs")

    # Database
    print("\n🗄️  DATABASE TRAPS\n" + "-" * 50)
    d = analyze_db()
    print(f"  Total probes:         {d['total_probes']}")
    print(f"  Unique IPs:           {d['unique_ips']}")

    # RDP
    print("\n🖥️  RDP TRAP\n" + "-" * 50)
    r = analyze_rdp()
    print(f"  Total connections:    {r['total_connections']}")
    print(f"  Unique IPs:           {r['unique_ips']}")

    # Summary
    print("\n" + "=" * 70)
    print("  📈  SUMMARY")
    print("=" * 70)
    total = s['total_connections'] + w['total_requests'] + c['total_attempts'] + \
            m['total_requests'] + d['total_probes'] + r['total_connections']
    all_ips = set()
    for analyzer in [analyze_ssh, analyze_web, analyze_creds, analyze_db, analyze_malware, analyze_rdp]:
        data = analyzer()
        for ip, _ in data.get('top_ips', data.get('top_attackers', [])):
            all_ips.add(ip)

    print(f"  Total events logged:     {total}")
    print(f"  Total unique IPs seen:   {len(all_ips)}")
    print(f"  Attack surface:          7 honeypot types")
    print(f"  Log directory:           {LOGS_DIR}")
    print(f"  Dashboard:               python dashboard.py")
    print("=" * 70)

    # Generate JSON report
    report = {
        "generated": datetime.datetime.now().isoformat(),
        "summary": {
            "total_events": total,
            "unique_ips": len(all_ips),
            "ssh": s,
            "web": w,
            "credentials": c,
            "malware": m,
            "database": d,
            "rdp": r,
        }
    }

    report_path = os.path.join(LAB_DIR, "analysis_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  💾  Full report saved to: {report_path}")

    return report


def show_top_attackers(n=10):
    """Show top attackers across all honeypots"""
    print(f"\n  🎯 Top {n} Attackers (All Honeypots)\n" + "-" * 50)

    all_ips = Counter()

    for pattern, key in [
        (os.path.join(LOGS_DIR, "web", "*.jsonl"), "source_ip"),
        (os.path.join(LOGS_DIR, "db", "*.jsonl"), "source_ip"),
        (os.path.join(LOGS_DIR, "rdp", "*.jsonl"), "source_ip"),
        (os.path.join(LOGS_DIR, "malware", "*.jsonl"), "source_ip"),
        (os.path.join(LOGS_DIR, "creds", "*.json"), "source_ip"),
        (os.path.join(LOGS_DIR, "ssh", "cowrie.json"), "src_ip"),
    ]:
        for f in glob.glob(pattern):
            entries = load_json_logs(f)
            for e in entries:
                ip = e.get(key, "unknown")
                if ip and ip != "unknown":
                    all_ips[ip] += 1

    print(f"  {'IP Address':>20}  {'Events':>8}  {'% of Total':>10}")
    print(f"  {'-'*20}  {'-'*8}  {'-'*10}")
    total = sum(all_ips.values())
    for ip, count in all_ips.most_common(n):
        pct = (count / total) * 100 if total > 0 else 0
        print(f"  {ip:>20}  {count:>8}  {pct:>9.1f}%")

    return all_ips


def timeline_analysis():
    """Show activity over time"""
    print(f"\n  📅 Activity Timeline\n" + "-" * 50)

    hourly = Counter()
    daily = Counter()

    for pattern in [
        os.path.join(LOGS_DIR, "web", "*.jsonl"),
        os.path.join(LOGS_DIR, "db", "*.jsonl"),
        os.path.join(LOGS_DIR, "rdp", "*.jsonl"),
        os.path.join(LOGS_DIR, "malware", "*.jsonl"),
    ]:
        for f in glob.glob(pattern):
            entries = load_json_logs(f)
            for e in entries:
                ts = e.get("timestamp", "")
                if ts and len(ts) >= 16:
                    try:
                        dt = datetime.datetime.fromisoformat(ts[:19])
                        hourly[f"{dt.hour:02d}:00"] += 1
                        daily[dt.strftime("%Y-%m-%d")] += 1
                    except:
                        pass

    if hourly:
        print("  Hourly Activity:")
        for hour in sorted(hourly.keys()):
            bar = "█" * min(hourly[hour], 50)
            print(f"    {hour}  {bar} {hourly[hour]}")

    if daily:
        print("\n  Daily Activity:")
        for day, count in sorted(daily.items()):
            print(f"    {day}  {count} events")
    else:
        print("  No timeline data available yet.")


def main():
    print("=" * 70)
    print("  🔵  HONEYPOT LAB - Blue Team Analysis Tools")
    print("=" * 70)

    while True:
        print("\nOptions:")
        print("  1) Generate full analysis report")
        print("  2) Show top attackers")
        print("  3) Show activity timeline")
        print("  4) Analyze specific honeypot")
        print("  5) Export all data to JSON")
        print("  0) Exit")

        choice = input("\n  Choice: ")

        if choice == "1":
            generate_report()
        elif choice == "2":
            show_top_attackers()
        elif choice == "3":
            timeline_analysis()
        elif choice == "4":
            print("\n  Select honeypot:")
            print("    1) 🐚 SSH (Cowrie)")
            print("    2) 🌐 Web Traps")
            print("    3) 🔑 Credentials (Heralding)")
            print("    4) 🏭 ICS (Conpot)")
            print("    5) 🗄️ Database")
            print("    6) 🦠 Malware")
            print("    7) 🖥️ RDP")
            sub = input("  Choice: ")
            analyzers = {"1": ("SSH", analyze_ssh), "2": ("Web", analyze_web),
                         "3": ("Credentials", analyze_creds), "5": ("Database", analyze_db),
                         "6": ("Malware", analyze_malware), "7": ("RDP", analyze_rdp)}
            if sub in analyzers:
                name, func = analyzers[sub]
                data = func()
                print(f"\n  📊 {name} Analysis:")
                for k, v in data.items():
                    print(f"    {k}: {v}")
            elif sub == "4":
                print("\n  🏭 ICS (Conpot)")
                ics_dir = os.path.join(LOGS_DIR, "ics")
                log_files = glob.glob(os.path.join(ics_dir, "*"))
                print(f"    Log files: {len(log_files)}")
                for lf in log_files[:10]:
                    size = os.path.getsize(lf)
                    print(f"    {os.path.basename(lf)} ({size} bytes)")
        elif choice == "5":
            report = generate_report()
            print(f"  ✅ JSON report exported")
        elif choice == "0":
            break


if __name__ == "__main__":
    main()
