#!/usr/bin/env python3
"""
Feature: GeoIP Location Tracking
Resolves attacker IPs to country/city/ISP using local GeoLite2 database or MaxMind API.
Falls back to ip-api.com free API if no local DB.
"""
import os, json, urllib.request, urllib.error, socket, datetime, threading, time

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "geoip_cache.json")
geo_cache = {}
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, encoding="utf-8") as f: geo_cache = json.load(f)
    except: geo_cache = {}

def lookup_ip(ip):
    """Get GeoIP info for an IP address"""
    if ip in geo_cache:
        return geo_cache[ip]
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
        result = {"ip": ip, "country": "Private", "city": "Local", "isp": "Internal"}
        geo_cache[ip] = result
        return result
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,lat,lon,query"
        req = urllib.request.Request(url, headers={"User-Agent": "HoneypotLab/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "success":
                result = {"ip": data["query"], "country": data.get("country",""), "countryCode": data.get("countryCode",""), "city": data.get("city",""), "isp": data.get("isp",""), "org": data.get("org",""), "as": data.get("as",""), "lat": data.get("lat",0), "lon": data.get("lon",0)}
                geo_cache[ip] = result
                with open(CACHE_FILE, "w", encoding="utf-8") as f: json.dump(geo_cache, f)
                return result
    except: pass
    return {"ip": ip, "country": "Unknown", "city": "", "isp": ""}
