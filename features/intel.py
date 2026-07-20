#!/usr/bin/env python3
"""
Feature: Threat Intel Integration — Checks attacker IPs against known threat feeds
"""
import os, json, urllib.request, datetime, threading

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "threat_intel_cache.json")
cache = {}
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, encoding="utf-8") as f: cache = json.load(f)
    except: cache = {}

def check_abuseipdb(ip, api_key=""):
    if not api_key: return {}
    if ip in cache: return cache[ip]
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            result = data.get("data", {})
            cache[ip] = result
            with open(CACHE_FILE, "w", encoding="utf-8") as f: json.dump(cache, f)
            return result
    except: return {}

def check_virustotal(ip, api_key=""):
    if not api_key: return {}
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except: return {}

def check_shodan(ip, api_key=""):
    if not api_key: return {}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())
    except: return {}

def check_greynoise(ip, api_key=""):
    if not api_key: return {}
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())
    except: return {}
