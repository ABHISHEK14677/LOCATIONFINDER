#!/usr/bin/env python3
"""
iploc.py — advanced IP geolocation & OSINT recon tool (authorized use)

Queries multiple public IP-intel providers in parallel with failover,
then normalizes and cross-checks the results.

Providers (free tiers, no key required):
  ip-api.com   (http only on free)   https://members.ip-api.com/
  ipwho.is                            https://ipwho.is/
  ipapi.co                            https://ipapi.co/
  ipinfo.io    (rate-limited)         https://ipinfo.io/
  freeipapi.com                       https://freeipapi.com/

Optional (stronger accuracy): MaxMind GeoLite2-City.mmdb
  -> download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Usage:
  python3 iploc.py 8.8.8.8                     # one IP
  python3 iploc.py 8.8.8.8 1.1.1.1 9.9.9.9     # multiple
  python3 iploc.py -f targets.txt              # from file
  python3 iploc.py myip                        # your own public IP
  python3 iploc.py                             # interactive prompt
"""

import argparse
import concurrent.futures
import json
import socket
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

# ----------------------------------------------------------------------
# generic JSON GET with timeout + TLS verification
# ----------------------------------------------------------------------
def http_json(url, timeout=6):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "iploc-osint/1.0 (security research)"},
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# ----------------------------------------------------------------------
# provider adapters — each returns a normalized dict or raises on failure
# ----------------------------------------------------------------------
def q_ipapi(ip):
    # ip-api free tier: HTTPS is paid-only; falls back over http
    data = http_json(f"http://ip-api.com/json/{ip}?fields=status,message,"
                     "continent,country,countryCode,region,regionName,city,"
                     "zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,"
                     "proxy,hosting,query")
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "ip-api failed"))
    def _b(k): return None if not isinstance(data.get(k), bool) else data[k]
    return {
        "source": "ip-api.com", "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"), "region_code": data.get("region"),
        "city": data.get("city"), "zip": data.get("zip"),
        "lat": data.get("lat"), "lon": data.get("lon"),
        "timezone": data.get("timezone"), "isp": data.get("isp"),
        "org": data.get("org"), "asn": data.get("as"), "as_name": data.get("asname"),
        "reverse_dns": data.get("reverse"),
        "flags": {"mobile": _b("mobile"), "proxy": _b("proxy"), "hosting": _b("hosting")},
    }


def q_ipwho(ip):
    d = http_json(f"https://ipwho.is/{ip}")
    if d.get("success") is False:
        raise RuntimeError(d.get("message", "ipwho.is failed"))
    c = d.get("connection", {}) or {}
    f = d.get("flag", {}) or {}
    s = d.get("security", {}) or {}
    return {
        "source": "ipwho.is", "country": d.get("country"),
        "country_code": d.get("country_code"), "region": d.get("region"),
        "region_code": d.get("region_code"), "city": d.get("city"),
        "zip": d.get("postal"), "lat": d.get("latitude"), "lon": d.get("longitude"),
        "timezone": d.get("timezone", {}).get("id") if isinstance(d.get("timezone"), dict) else d.get("timezone"),
        "isp": c.get("isp"), "org": c.get("org"),
        "asn": c.get("asn"), "as_name": c.get("asn") and f"AS{c.get('asn')}" or None,
        "reverse_dns": None,
        "flags": {
            "mobile": c.get("type") == "mobile",
            "proxy": s.get("proxy"), "hosting": s.get("hosting"),
            "tor": s.get("tor"),
        },
        "extra": {
            "currency": (d.get("currency") or {}).get("code"),
            "call_code": (d.get("calling_code") or {}).get("code") or (d.get("calling_code") or {}).get("prefix"),
            "region_flag": f.get("emoji"),
        },
    }


def q_ipapi_co(ip):
    d = http_json(f"https://ipapi.co/{ip}/json/")
    if d.get("error"):
        raise RuntimeError(d.get("reason", "ipapi.co failed"))
    return {
        "source": "ipapi.co", "country": d.get("country_name"),
        "country_code": d.get("country_code"), "region": d.get("region"),
        "region_code": d.get("region_code"), "city": d.get("city"),
        "zip": d.get("postal"), "lat": d.get("latitude"), "lon": d.get("longitude"),
        "timezone": d.get("timezone"), "isp": d.get("org"),
        "org": d.get("org"), "asn": d.get("asn"), "as_name": d.get("asn"),
        "reverse_dns": None, "flags": {},
    }


def q_ipinfo(ip):
    d = http_json(f"https://ipinfo.io/{ip}/json")
    loc = (d.get("loc") or "").split(",")
    return {
        "source": "ipinfo.io", "country": d.get("country"),
        "country_code": d.get("country"), "region": d.get("region"),
        "region_code": None, "city": d.get("city"), "zip": d.get("postal"),
        "lat": float(loc[0]) if len(loc) > 1 and loc[0] else None,
        "lon": float(loc[1]) if len(loc) > 1 and loc[1] else None,
        "timezone": d.get("timezone"), "isp": d.get("org"),
        "org": d.get("org"), "asn": (d.get("org") or "").split(" ")[0] if d.get("org") else None,
        "as_name": d.get("org"), "reverse_dns": d.get("hostname"),
        "flags": {},
    }


def q_freeipapi(ip):
    d = http_json(f"https://freeipapi.com/api/json/{ip}")
    return {
        "source": "freeipapi.com", "country": d.get("countryName"),
        "country_code": d.get("countryCode"), "region": d.get("regionName"),
        "region_code": d.get("regionCode") or None,
        "city": d.get("cityName"), "zip": d.get("zipCode"),
        "lat": d.get("latitude"), "lon": d.get("longitude"),
        "timezone": d.get("timeZone"), "isp": None, "org": d.get("org"),
        "asn": None, "as_name": None, "reverse_dns": None, "flags": {},
    }


# optional local MaxMind fallback / cross-check
def q_maxmind(ip, db_path):
    import geoip2.database  # pip install geoip2
    with geoip2.database.Reader(db_path) as r:
        c = r.city(ip)
        a = r.asn(ip)
    return {
        "source": "MaxMind GeoLite2", "country": c.country.name,
        "country_code": c.country.iso_code,
        "region": c.subdivisions.most_specific.name if c.subdivisions else None,
        "region_code": c.subdivisions.most_specific.iso_code if c.subdivisions else None,
        "city": c.city.name, "zip": c.postal.code,
        "lat": c.location.latitude, "lon": c.location.longitude,
        "timezone": c.location.time_zone, "isp": None, "org": None,
        "asn": f"AS{a.autonomous_system_number}" if a.autonomous_system_number else None,
        "as_name": a.autonomous_system_organization if a.autonomous_system_organization else None,
        "reverse_dns": None, "flags": {},
    }


PROVIDERS = {
    "ipwho": q_ipwho,
    "ipapi": q_ipapi,
    "ipapi.co": q_ipapi_co,
    "freeipapi": q_freeipapi,
    "ipinfo": q_ipinfo,
}


def get_my_ip():
    """Discover our own public IP using several independent echo services."""
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for u in urls:
        try:
            return http_json(u, timeout=5) if False else \
                urllib.request.urlopen(u, timeout=5).read().decode().strip()
        except Exception:
            continue
    sys.exit("[!] could not determine your public IP")


# ----------------------------------------------------------------------
# validation & fetching
# ----------------------------------------------------------------------
def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)   # IPv4
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)  # IPv6
        return True
    except OSError:
        return False


def fetch_all(ip, extra_callables=None):
    """Query all providers in parallel. Returns list of (provider, result)"""
    results, errors = [], []
    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PROVIDERS) + len(extra_callables or [])) as ex:
        for name, fn in PROVIDERS.items():
            jobs[ex.submit(fn, ip)] = name
        for name, fn in (extra_callables or {}).items():
            jobs[ex.submit(fn, ip)] = name
        for fut in concurrent.futures.as_completed(jobs):
            name = jobs[fut]
            try:
                results.append((name, fut.result()))
            except Exception as e:
                errors.append((name, str(e)))
    return results, errors


# ----------------------------------------------------------------------
# consensus merging + pretty report
# ----------------------------------------------------------------------
def merge(results):
    """Build a best-effort consensus row from whatever providers returned."""
    m = {"lat": [], "lon": [], "tz": set(), "codes": set(), "flags": {}}
    by_city = {}
    for _, r in results:
        if r.get("lat") is not None: m["lat"].append(r["lat"])
        if r.get("lon") is not None: m["lon"].append(r["lon"])
        if r.get("timezone"): m["tz"].add(r["timezone"])
        if r.get("country_code"): m["codes"].add(r["country_code"])
        key = (r.get("country"), r.get("region"), r.get("city"))
        by_city[key] = by_city.get(key, 0) + 1
        for k, v in (r.get("flags") or {}).items():
            if v: m["flags"][k] = True
    def med(vals):
        vals = sorted(vals)
        n = len(vals)
        return vals[n // 2] if n else None
    consensus = {
        "lat": med(m["lat"]), "lon": med(m["lon"]),
        "timezone": max(m["tz"], key=len) if m["tz"] else None,
        "country_code": "/".join(sorted(m["codes"])) if m["codes"] else None,
        "agree_city": max(by_city, key=by_city.get) if by_city else None,
    }
    return consensus


def fmt_line(label, value, width=22):
    if value in (None, "", [], {}):
        return f"  {label:<{width}}: -"
    return f"  {label:<{width}}: {value}"


def report(ip, results, errors):
    line = "=" * 60
    print(f"\n{line}\n  TARGET IP : {ip}\n{line}")
    # consensus
    c = merge(results)
    lat, lon = c["lat"], c["lon"]
    print("  -- CONSENSUS (across providers) --")
    print(fmt_line("Coordinates", f"{lat}, {lon}" if lat is not None else None))
    if lat is not None and lon is not None:
        print(fmt_line("Maps link", f"https://maps.google.com/?q={lat},{lon}"))
    print(fmt_line("Timezone", c["timezone"]))
    print(fmt_line("Country code(s)", c["country_code"]))
    if c["agree_city"] and any(c["agree_city"]):
        print(fmt_line("Agreed location", ", ".join(x for x in c["agree_city"] if x)))

    print(f"\n  -- PER-PROVIDER DETAILS --")
    for name, r in results:
        print(f"  [{name}]")
        print(fmt_line("Country", f"{r.get('country')} ({r.get('country_code')})"))
        print(fmt_line("Region / City",
                       f"{r.get('region')}, {r.get('city')} {r.get('zip') or ''}".strip()))
        print(fmt_line("Coordinates", f"{r.get('lat')}, {r.get('lon')}"))
        print(fmt_line("Timezone", r.get("timezone")))
        print(fmt_line("ISP / ASN", f"{r.get('isp') or r.get('org')}"))
        print(fmt_line("AS number", r.get("asn")))
        print(fmt_line("AS org name", r.get("as_name")))
        print(fmt_line("Reverse DNS", r.get("reverse_dns")))
        fl = r.get("flags") or {}
        flags = [k for k, v in fl.items() if v]
        print(fmt_line("Flags", ", ".join(flags) if flags else "clean"))
        ex = (r.get("extra") or {})
        if ex:
            print(fmt_line("Extra", "; ".join(f"{k}={v}" for k, v in ex.items() if v)))
        print()
    if errors:
        print("  -- PROVIDERS UNAVAILABLE --")
        for name, err in errors:
            print(f"  {name}: {err[:90]}")
    print(line)


# ----------------------------------------------------------------------
# entry points
# ----------------------------------------------------------------------
def process_ips(ips, mmdb=None, quiet=False):
    extra = {}
    if mmdb:
        try:
            extra["maxmind"] = lambda ip: q_maxmind(ip, mmdb)
        except Exception:
            pass
    for ip in ips:
        if not is_valid_ip(ip):
            print(f"[!] skipping invalid IP: {ip}")
            continue
        results, errors = fetch_all(ip, extra)
        if not results and not quiet:
            print(f"[!] all providers failed for {ip}")
            continue
        report(ip, results, errors)


def interactive():
    print("IP Location / OSINT Recon".center(60))
    print("=" * 60)
    tgt = input("IP address (or 'myip' / 'd' for a domain, blank=quit): ").strip()
    if not tgt:
        return
    ip = tgt
    if tgt.lower() == "myip":
        ip = get_my_ip()
        print(f"[+] your public IP: {ip}")
    elif not is_valid_ip(tgt):
        # allow hostname/domain resolution
        try:
            ip = socket.gethostbyname(tgt)
            print(f"[+] resolved {tgt} -> {ip}")
        except Exception:
            print(f"[!] not an IP and could not resolve '{tgt}'")
            return
    mmdb = input("Path to GeoLite2-City.mmdb (blank to skip): ").strip() or None
    process_ips([ip], mmdb)


def main():
    ap = argparse.ArgumentParser(description="advanced IP geolocation / OSINT tool")
    ap.add_argument("targets", nargs="*", help="IPs, hostnames, 'myip', or blank for file")
    ap.add_argument("-f", "--file", help="file with one IP/host per line")
    ap.add_argument("-m", "--mmdb", help="path to MaxMind GeoLite2-City.mmdb for local lookup")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    ips = list(args.targets)
    if args.file:
        try:
            with open(args.file) as fh:
                ips += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"[!] cannot read {args.file}: {e}")
    if not ips:
        interactive()
        return

    resolved = []
    for t in ips:
        if t.lower() == "myip":
            resolved.append(get_my_ip())
        elif is_valid_ip(t):
            resolved.append(t)
        else:
            try:
                resolved.append(socket.gethostbyname(t))
                print(f"[+] resolved {t} -> {resolved[-1]}")
            except Exception:
                print(f"[!] could not resolve: {t}")
    process_ips(resolved, args.mmdb, args.quiet)


if __name__ == "__main__":
    main()
