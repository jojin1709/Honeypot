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
Feature: Log Rotation — Prevents disk from filling up with honeypot logs
"""
import os, sys, glob, gzip, shutil, datetime, time, threading

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(LAB_DIR, "logs")

# Defaults used for standalone/CLI use; start_all.py overrides these from
# config.ini's [features] log_max_size_mb / log_retention_days via configure().
MAX_LOG_SIZE = 50 * 1024 * 1024  # 50MB per file before rotation
MAX_LOG_AGE_DAYS = 30  # Delete logs older than this
CHECK_INTERVAL = 3600  # Check every hour

def configure(max_size_mb=None, retention_days=None, check_interval=None):
    """Override the module-level thresholds, normally called with values
    read from config.ini so the [features] section actually has an effect."""
    global MAX_LOG_SIZE, MAX_LOG_AGE_DAYS, CHECK_INTERVAL
    if max_size_mb is not None:
        MAX_LOG_SIZE = int(max_size_mb) * 1024 * 1024
    if retention_days is not None:
        MAX_LOG_AGE_DAYS = int(retention_days)
    if check_interval is not None:
        CHECK_INTERVAL = int(check_interval)

def rotate_file(filepath):
    """Rotate a single log file"""
    if not os.path.exists(filepath): return
    size = os.path.getsize(filepath)
    if size < MAX_LOG_SIZE: return
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    rotated = f"{filepath}.{timestamp}.gz"
    try:
        with open(filepath, "rb") as f_in:
            with gzip.open(rotated, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        open(filepath, "w", encoding="utf-8").close()
        print(f"  📦 Rotated: {os.path.basename(filepath)} -> {os.path.basename(rotated)}")
    except: pass

def clean_old_logs():
    """Delete rotated logs older than MAX_LOG_AGE_DAYS"""
    cutoff = time.time() - (MAX_LOG_AGE_DAYS * 86400)
    for root, dirs, files in os.walk(LOGS_DIR):
        for f in files:
            fp = os.path.join(root, f)
            try:
                if os.path.getmtime(fp) < cutoff and fp.endswith(".gz"):
                    os.remove(fp)
                    print(f"  🗑️  Deleted old log: {f}")
            except: pass

def rotate_all():
    """Rotate all log files"""
    for root, dirs, files in os.walk(LOGS_DIR):
        for f in files:
            if f.endswith((".log", ".json", ".jsonl", ".csv")):
                rotate_file(os.path.join(root, f))

def run_loop():
    """Run rotation in background"""
    while True:
        rotate_all()
        clean_old_logs()
        time.sleep(CHECK_INTERVAL)

def start_background(max_size_mb=None, retention_days=None):
    configure(max_size_mb=max_size_mb, retention_days=retention_days)
    threading.Thread(target=run_loop, daemon=True).start()
    print(f"  📦 Log rotation active — max {MAX_LOG_SIZE//1024//1024}MB/file, keep {MAX_LOG_AGE_DAYS} days")

if __name__ == "__main__":
    rotate_all()
    clean_old_logs()
    print("✅ Log rotation complete")
