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
Feature: Notifications — Sends alerts to Telegram, Discord, Slack, or Email.
"""
import os, json, datetime, urllib.request, urllib.error, smtplib, threading
from email.message import EmailMessage

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "notify_config.json")
DEFAULT_CONFIG = {"telegram": {"enabled": False, "bot_token": "", "chat_id": ""}, "discord": {"enabled": False, "webhook_url": ""}, "slack": {"enabled": False, "webhook_url": ""}, "email": {"enabled": False, "smtp_server": "", "smtp_port": 587, "username": "", "password": "", "to": "", "from": ""}}

notify_config = DEFAULT_CONFIG.copy()
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f: notify_config.update(json.load(f))
    except: pass

def save_config():
    with open(CONFIG_FILE, "w", encoding="utf-8") as f: json.dump(notify_config, f, indent=2)

def send_telegram(message):
    if not notify_config["telegram"]["enabled"]: return
    try:
        token = notify_config["telegram"]["bot_token"]
        chat_id = notify_config["telegram"]["chat_id"]
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = json.dumps({"chat_id": chat_id, "text": message, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except: pass

def send_discord(message):
    if not notify_config["discord"]["enabled"]: return
    try:
        url = notify_config["discord"]["webhook_url"]
        data = json.dumps({"content": message}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except: pass

def send_slack(message):
    if not notify_config["slack"]["enabled"]: return
    try:
        url = notify_config["slack"]["webhook_url"]
        data = json.dumps({"text": message}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except: pass

def send_email(subject, body):
    if not notify_config["email"]["enabled"]: return
    try:
        c = notify_config["email"]
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = c["from"]
        msg["To"] = c["to"]
        with smtplib.SMTP(c["smtp_server"], c["smtp_port"]) as s:
            s.starttls()
            s.login(c["username"], c["password"])
            s.send_message(msg)
    except: pass

def notify(alert_type, data):
    """Send notification via all enabled channels"""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msgs = {"ssh": f"🔴 SSH Attack!\n{ts}\nIP: {data.get('source_ip','')}\nUser: {data.get('username','')}", "web": f"🌐 Web Attack!\n{ts}\nIP: {data.get('source_ip','')}\nPath: {data.get('path','')}", "creds": f"🔑 Credentials Captured!\n{ts}\nIP: {data.get('source_ip','')}\nProtocol: {data.get('protocol','')}\nUser: {data.get('username','')}:{data.get('password','')}", "rdp": f"🖥️ RDP Attempt!\n{ts}\nIP: {data.get('source_ip','')}", "malware": f"🦠 Malware Upload!\n{ts}\nIP: {data.get('source_ip','')}\nSize: {data.get('file_size',0)} bytes", "smb": f"📁 SMB Probe!\n{ts}\nIP: {data.get('source_ip','')}\nNote: {data.get('note','')}"}
    message = msgs.get(alert_type, f"⚠️ Alert: {alert_type}\n{ts}\nIP: {data.get('source_ip','')}")
    threading.Thread(target=send_telegram, args=(message,), daemon=True).start()
    threading.Thread(target=send_discord, args=(message,), daemon=True).start()
    threading.Thread(target=send_slack, args=(message,), daemon=True).start()
    if alert_type in ["ssh", "malware", "creds"]:
        threading.Thread(target=send_email, args=(f"[Honeypot] {alert_type.upper()} Alert", message), daemon=True).start()

def setup_interactive():
    """Interactive setup for notification config"""
    print("=" * 50)
    print("  🔔 Notification Setup")
    print("=" * 50)
    if input("\nEnable Telegram? (y/n): ").lower() == "y":
        notify_config["telegram"]["enabled"] = True
        notify_config["telegram"]["bot_token"] = input("  Bot Token: ")
        notify_config["telegram"]["chat_id"] = input("  Chat ID: ")
    if input("Enable Discord? (y/n): ").lower() == "y":
        notify_config["discord"]["enabled"] = True
        notify_config["discord"]["webhook_url"] = input("  Webhook URL: ")
    if input("Enable Slack? (y/n): ").lower() == "y":
        notify_config["slack"]["enabled"] = True
        notify_config["slack"]["webhook_url"] = input("  Webhook URL: ")
    if input("Enable Email? (y/n): ").lower() == "y":
        notify_config["email"]["enabled"] = True
        notify_config["email"]["smtp_server"] = input("  SMTP Server: ")
        notify_config["email"]["smtp_port"] = int(input("  SMTP Port (587): ") or "587")
        notify_config["email"]["username"] = input("  Username: ")
        notify_config["email"]["password"] = input("  Password: ")
        notify_config["email"]["from"] = input("  From: ")
        notify_config["email"]["to"] = input("  To: ")
    save_config()
    print("  ✅ Notification config saved!")

if __name__ == "__main__":
    setup_interactive()
