#!/usr/bin/env python3
"""
IP geolocation & intel tool — multi-source with failover, risk flags, export.
Deps:  pip install requests
Run:   python3 geoip.py 8.8.8.8
       python3 geoip.py 1.1.1.1 2606:4700::1111 --json
       python3 geoip.py -f ips.txt -o report --csv --json
       cat ips.txt | python3 geoip.py
"""
from __future__ import annotations
import argparse, csv, ipaddress, json, socket, sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict, field

import requests

# ----------------------------- data model ----------------------------- #
@dataclass
class IPIntel:
    query: str
    success: bool = False
    sources: list = field(default_factory=list)
    country: str = None        # ISO-2
    country_name: str = None
    region: str = None
    city: str = None
    zip: str = None
    lat: float = None
    lon: float = None
    timezone: str = None
    asn: str = None            # AS15169
    org: str = None
    isp: str = None
    hostname: str = None       # reverse DNS / PTR
    network: str = None        # CIDR block
    is_proxy: bool = None
    is_vpn: bool = None
    is_tor: bool = None
    is_hosting: bool = None    # datacenter / cloud
    is_anonymous: bool = None
    mobile: bool = None

# ----------------------------- HTTP helper ---------------------------- #
def _get(url, timeout=6.0):
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "geoip-intel/1.0"})
        return r.json() if r.status_code == 200 else {}
    except requests.RequestException:
        return {}

# ------------------------- source adapters ---------------------------- #
def src_ip_api(ip):   # no key, HTTP, 45 req/min free
    return _get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                f"region,regionName,city,zip,lat,lon,timezone,isp,org,as,"
                f"reverse,mobile,proxy,hosting,query")

def src_ipwho(ip):    # no key, HTTPS, has vpn/tor flags
    return _get(f"https://ipwho.is/{ip}")

def src_ipinfo(ip, token=None):   # HTTPS, needs free token for privacy fields
    u = f"https://ipinfo.io/{ip}/json" + (f"?token={token}" if token else "")
    return _get(u)

def src_ipapi_co(ip):  # needs free email key for reliable/HTTPS v6
    return _get(f"https://ipapi.co/{ip}/json/")

# --------------------------- normalizers ------------------------------ #
def _norm(d):
    out = {}
    out["country"]  = d.get("countryCode") or d.get("country_code")
    out["country_name"] = d.get("country_name") or d.get("country")
    out["region"]   = d.get("regionName") or d.get("region") or d.get("state")
    out["city"]     = d.get("city")
    out["zip"]      = d.get("zip") or d.get("postal")
    out["timezone"] = d.get("timezone")
    out["asn"]      = d.get("as") or d.get("asn")
    out["org"]      = d.get("org") or d.get("organization")
    out["isp"]      = d.get("isp")
    out["hostname"] = d.get("reverse") or d.get("hostname")
    out["network"]  = d.get("network")
    try:  out["lat"] = float(d.get("lat") or d.get("latitude"))
    except (TypeError, ValueError): pass
    try:  out["lon"] = float(d.get("lon") or d.get("longitude"))
    except (TypeError, ValueError): pass
    pv = d.get("privacy", {}) if isinstance(d.get("privacy"), dict) else {}
    out["is_proxy"] = bool(d.get("proxy") or pv.get("proxy") or pv.get("vpn"))
    out["is_vpn"]   = bool(d.get("vpn") or pv.get("vpn"))
    out["is_tor"]   = bool(d.get("tor") or pv.get("tor"))
    out["is_hosting"] = bool(d.get("hosting") or pv.get("hosting"))
    out["is_anonymous"] = bool(pv.get("proxy") or pv.get("vpn") or pv.get("tor"))
    out["mobile"]   = bool(d.get("mobile"))
    return {k: v for k, v in out.items() if v not in (None, "", False)}

# --------------------------- orchestrator ----------------------------- #
def resolve(ip):
    res = IPIntel(query=ip)
    if not _valid(ip):
        try:
            ip = socket.gethostbyname(ip.strip())
            res.query = ip
        except socket.gaierror:
            return res

    merged, used = {}, []
    for name, fn in [("ipwho", src_ipwho),
                     ("ip-api", src_ip_api),
                     ("ipinfo", lambda i: src_ipinfo(i)),
                     ("ipapi.co", src_ipapi_co)]:
        data = fn(ip) or {}
        if data:
            merged.update(data); used.append(name)
        # stop when we have location + network + risk signal
        if (any(merged.get(k) for k in ("lat", "lon", "city", "country"))
                and any(merged.get(k) for k in ("asn", "org", "isp"))
                and any(merged.get(k) in (True, False) for k in
                        ("proxy", "vpn", "tor", "hosting"))):
            break

    if not merged:
        return res
    for k, v in _norm(merged).items():
        setattr(res, k, v)
    res.sources, res.success = used, True
    return res

def _valid(s):
    try:
        ipaddress.ip_address(s.strip()); return True
    except ValueError:
        return False

# ---------------------------- display/io ------------------------------ #
def line(r):
    loc = " / ".join(x for x in (r.city, r.region, r.country_name or r.country) if x)
    net = r.org or r.isp or r.asn or "-"
    f = ",".join(t for t, v in (("TOR", r.is_tor), ("VPN", r.is_vpn),
                                ("PROXY", r.is_proxy), ("DC", r.is_hosting),
                                ("MOB", r.mobile)) if v)
    return f"{r.query:<16} {loc:<36} {net:<28} {('['+f+']') if f else ''}"

def save_csv(rows, path):
    fs = [f.name for f in asdict(IPIntel("")).keys() and [] or
          [k for k in asdict(IPIntel("")) if k not in ("raw", "sources", "query")]]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fs); w.writeheader()
        for r in rows:
            w.writerow({k: getattr(r, k) for k in fs})

def save_json(rows, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in rows], fh, indent=2)

# ------------------------------- main --------------------------------- #
def main():
    p = argparse.ArgumentParser(description="IP geolocation & intel")
    p.add_argument("ips", nargs="*")
    p.add_argument("-f", "--file")
    p.add_argument("-o", "--out")
    p.add_argument("--csv", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("-t", "--threads", type=int, default=8)
    a = p.parse_args()

    targets = list(a.ips)
    if a.file:
        targets += [l.strip() for l in open(a.file) if l.strip()]
    if not targets:
        targets = [l.strip() for l in sys.stdin if l.strip()]
    if not targets:
        p.print_help(); return 1

    rows = []
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        for r in ex.map(resolve, targets):
            rows.append(r)
            print(line(r))

    ok = sum(1 for x in rows if x.success)
    print(f"\n[+] resolved {ok}/{len(rows)}")

    if a.out:
        save_csv(rows, a.out + ".csv")
        save_json(rows, a.out + ".json")
        print(f"[+] wrote {a.out}.csv / {a.out}.json")
    elif a.csv or a.json:
        print("[+] use -o BASENAME to enable file export")
    return 0

if __name__ == "__main__":
    sys.exit(main())
