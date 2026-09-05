#!/usr/bin/env python3
"""
geoip_intel.py — Advanced IP Geolocation & Intelligence Enrichment

Features:
  * Multi-source enrichment (ip-api.com, ipinfo.io, ipwho.is, ipapi.co)
  * Automatic source failover with result merging
  * Optional offline MaxMind GeoLite2 (.mmdb) lookups via geoip2
  * Proxy / VPN / Tor / hosting(ASN) detection
  * Threat-lite checks (abuse contact, anonymous flag)
  * Threaded batch scanning from a file, CSV + JSON export
  * Pure-stdlib + requests (no heavy deps unless you add geoip2)

Usage:
  python3 geoip_intel.py 8.8.8.8
  python3 geoip_intel.py 8.8.8.8 1.1.1.1 2606:4700::1111 --json
  python3 geoip_intel.py -f ips.txt -o report --csv --json
  python3 geoip_intel.py 8.8.8.8 --maxmind /path/to/GeoLite2-City.mmdb
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Dict, Iterable, List, Optional

try:
    import requests
except ImportError:
    sys.exit("[-] Missing dependency. Install with: pip install requests")

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class IPIntel:
    query: str
    success: bool = False
    sources: List[str] = field(default_factory=list)

    # Location
    country: Optional[str] = None          # ISO-2 code, e.g. "US"
    country_name: Optional[str] = None
    region: Optional[str] = None           # state / province
    region_code: Optional[str] = None
    city: Optional[str] = None
    zip: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    timezone: Optional[str] = None
    postal: Optional[str] = None

    # Network ownership (who owns the block)
    asn: Optional[str] = None              # e.g. "AS15169"
    org: Optional[str] = None              # e.g. "Google LLC"
    isp: Optional[str] = None
    hostname: Optional[str] = None          # reverse DNS
    network: Optional[str] = None           # CIDR block

    # Risk / classification
    is_proxy: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_datacenter: Optional[bool] = None
    is_anonymous: Optional[bool] = None
    is_abuser: Optional[bool] = None
    is_hosting: Optional[bool] = None
    mobile: Optional[bool] = None

    raw: Dict = field(default_factory=dict)

# --------------------------------------------------------------------------- #
# Source adapters — each is a pure function ip -> dict (or {} on failure)
# Keep them lazy so we never hit more APIs than needed.
# --------------------------------------------------------------------------- #

def _si_get(url: str, timeout: float = 6.0) -> dict:
    """GET json with light retry; returns {} on any failure."""
    for attempt in range(2):
        try:
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": "geoip-intel/1.0"})
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            pass
    return {}

def src_ip_api(ip: str) -> dict:
    """ip-api.com — free, no key, batchable. HTTP only for non-commercial."""
    return _si_get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                   f"region,regionName,city,zip,lat,lon,timezone,isp,org,as,"
                   f"asname,reverse,mobile,proxy,hosting,query")

def src_ipwho(ip: str) -> dict:
    """ipwho.is — free tier, HTTPS, includes proxy/vpn/tor flags."""
    return _si_get(f"https://ipwho.is/{ip}")

def src_ipinfo(ip: str, token: Optional[str] = None) -> dict:
    """ipinfo.io — 50k/mo free w/ token; includes abuse & privacy fields."""
    h = {"Accept": "application/json"}
    u = f"https://ipinfo.io/{ip}/json"
    if token:
        u = f"https://ipinfo.io/{ip}/json?token={token}"
    return _si_get(u) if False else _get(u, h)  # placehold replaced below

def _get(url: str, headers: dict) -> dict:
    try:
        r = requests.get(url, headers=headers, timeout=6.0)
        return r.json() if r.status_code == 200 else {}
    except requests.RequestException:
        return {}

def src_ipapi_co(ip: str) -> dict:
    """ipapi.co — free with email signup key (also supports IPv6)."""
    return _get(f"https://ipapi.co/{ip}/json/", {})

# --------------------------------------------------------------------------- #
# Normalizers — map each provider's schema onto our IPIntel model
# --------------------------------------------------------------------------- #

def _norm_common(d: dict) -> Dict:
    """Extract the intersection of fields most providers agree on."""
    out: Dict = {}
    out["country"]       = d.get("countryCode") or d.get("country_code") or (d.get("country") if isinstance(d.get("country"), str) and len(d["country"]) == 2 else None)
    out["country_name"]  = d.get("country_name") or (d.get("country") if not out["country"] else d.get("country"))
    out["region"]        = d.get("regionName") or d.get("region") or d.get("state")
    out["region_code"]   = d.get("region_code")
    out["city"]          = d.get("city")
    out["zip"]           = d.get("zip") or d.get("postal")
    out["postal"]        = out["zip"]
    out["timezone"]      = d.get("timezone")
    out["asn"]           = d.get("as") or d.get("asn")
    out["org"]           = d.get("org") or d.get("organization")
    out["isp"]           = d.get("isp")
    out["hostname"]      = d.get("reverse") or d.get("hostname")
    out["network"]       = d.get("network") or d.get("range")

    try:
        out["lat"] = float(d.get("lat") or d.get("latitude"))
    except (TypeError, ValueError):
        out["lat"] = None
    try:
        out["lon"] = float(d.get("lon") or d.get("longitude"))
    except (TypeError, ValueError):
        out["lon"] = None

    # risk / flags
    out["is_proxy"]     = d.get("proxy") or d.get("is_proxy")
    out["is_vpn"]       = d.get("vpn") or d.get("privacy", {}).get("vpn")
    out["is_tor"]       = d.get("tor") or d.get("privacy", {}).get("tor")
    out["is_hosting"]   = d.get("hosting") or d.get("privacy", {}).get("hosting")
    out["is_anonymous"] = d.get("privacy", {}).get("proxy") or d.get("is_anonymous")
    out["is_abuser"]    = d.get("abuse", {}).get("is_abuser") or d.get("is_abuser")
    out["is_datacenter"]= d.get("privacy", {}).get("service") == "hosting"
    out["mobile"]       = d.get("mobile")
    return out

# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #

class GeoIPResolver:
    def __init__(self, maxmind_path: Optional[str] = None,
                 ipinfo_token: Optional[str] = None, prefer: Iterable[str] = ()):
        self.ipinfo_token = ipinfo_token
        self.prefer = list(prefer) or ["ip-api", "ipwho"]
        self.reader = None
        if maxmind_path:
            try:
                import geoip2.database            # optional heavy dep
                self.reader = geoip2.database.Reader(maxmind_path)
            except ImportError:
                print("[-] geoip2 not installed; ignoring --maxmind "
                      "(pip install geoip2 maxminddb)")
            except Exception as e:
                print(f"[-] Could not open MMDB {maxmind_path}: {e}")

    # -- private source registry ------------------------------------------ #
    def _providers(self) -> Dict[str, callable]:
        return {
            "ip-api":  src_ip_api,
            "ipwho":   src_ipwho,
            "ipinfo":  lambda ip: src_ipinfo(ip, self.ipinfo_token),
            "ipapi.co": src_ipapi_co,
        }

    def _maxmind(self, ip: str) -> Optional[Dict]:
        """Offline city/country + ASN via MaxMind DB files."""
        if not self.reader:
            return None
        try:
            d: Dict = {}
            c = self.reader.city(ip)
            d["country"] = c.country.iso_code
            d["country_name"] = c.country.name
            d["region"] = c.subdivisions.most_specific.name
            d["region_code"] = c.subdivisions.most_specific.iso_code
            d["city"] = c.city.name
            d["zip"] = c.postal.code
            d["lat"] = c.location.latitude
            d["lon"] = c.location.longitude
            d["timezone"] = c.location.time_zone
            return d
        except Exception:
            try:  # ASN db variant
                a = self.reader.asn(ip)
                return {"asn": a.autonomous_system_number,
                        "org": a.autonomous_system_organization}
            except Exception:
                return None

    # -- single-IP resolution --------------------------------------------- #
    def resolve(self, ip: str, ip_type: int = 0) -> IPIntel:
        """Resolve one IP. ip_type: 0=auto, 4=ipv4, 6=ipv6."""
        res = IPIntel(query=ip)

        # validate / normalize input (accept hostnames too)
        if not _is_valid_ip(ip):
            try:
                ip = socket.gethostbyname(ip.strip())
                res.query = ip
            except socket.gaierror:
                res.success = False
                return res

        # merge providers in preference order
        merged: Dict = {}
        seen: set = set()
        providers = self._providers()

        order = [p for p in self.prefer if p in providers] + \
                [p for p in providers if p not in self.prefer]
        for name in order:
            try:
                data = providers[name](ip)
            except Exception:
                data = {}
            if data:
                res.sources.append(name)
                merged = {**merged, **data}          # later wins, cheap merge
                seen.add(name)
            # Stop early once we have location + network + risk
            if _sufficient(merged):
                break

        # offline MaxMind fallback enriches if present (authoritative-ish)
        mm = self._maxmind(ip)
        if mm:
            res.sources.append("maxmind")
            merged = {**merged, **mm}

        if not merged:
            return res

        norm = _norm_common(merged)
        # merge onto result, respecting already-present fields
        for k, v in norm.items():
            if v is not None and getattr(res, k) is None:
                setattr(res, k, v)
        res.success = True
        return res

    # -- batch ------------------------------------------------------------ #
    def resolve_many(self, ips: Iterable[str], threads: int = 8,
                     quiet: bool = False) -> List[IPIntel]:
        ips = [i for i in ips if i and i.strip()]
        results: List[IPIntel] = []
        lock = threading.Lock()

        def _w(i: str):
            r = self.resolve(i)
            with lock:
                results.append(r)
                if not quiet:
                    print(_line(r))

        with ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(_w, ips))
        return sorted(results, key=lambda x: x.query)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False

def _sufficient(d: dict) -> bool:
    """True when we have enough signal to stop querying more APIs."""
    has_loc = any(d.get(k) for k in ("lat", "lon", "city", "country"))
    has_net = any(d.get(k) for k in ("asn", "org", "isp"))
    has_risk = any(d.get(k) is not None for k in
                   ("proxy", "vpn", "tor", "hosting", "privacy"))
    return has_loc and has_net and has_risk

def _line(r: IPIntel) -> str:
    loc = " / ".join(x for x in (r.city, r.region, r.country_name or r.country) if x)
    net = r.org or r.isp or r.asn or "-"
    flags = []
    if r.is_tor:   flags.append("TOR")
    if r.is_vpn:   flags.append("VPN")
    if r.is_proxy: flags.append("PROXY")
    if r.is_hosting or r.is_datacenter: flags.append("DC/HOST")
    if r.mobile:   flags.append("MOBILE")
    f = (" [" + ",".join(flags) + "]") if flags else ""
    return f"{r.query:<16} {loc:<38} {net:<30}{f}"

# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #

def to_csv(rows: List[IPIntel], path: str) -> None:
    fields = list(asdict(IPIntel("")).keys())
    fields.remove("raw"); fields.remove("sources")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))

def to_json(rows: List[IPIntel], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, indent=2)

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> int:
    p = argparse.ArgumentParser(description="Advanced IP geolocation & intel")
    p.add_argument("ips", nargs="*", help="IPs / hostnames to resolve")
    p.add_argument("-f", "--file", help="file with one IP per line")
    p.add_argument("-o", "--out", help="output basename (enables export)")
    p.add_argument("--csv", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("-t", "--threads", type=int, default=8)
    p.add_argument("--maxmind", help="path to GeoLite2-City.mmdb / .asn.mmdb")
    p.add_argument("--ipinfo-token", help="ipinfo.io API token")
    p.add_argument("--prefer", nargs="*", default=[],
                   help="source priority, e.g. ipwho ip-api ipinfo ipapi.co")
    p.add_argument("--quiet", action="store_true")
    a = p.parse_args()

    targets = list(a.ips)
    if a.file:
        try:
            with open(a.file) as f:
                targets += [l.strip() for l in f if l.strip()]
        except OSError as e:
            print(f"[-] Cannot read {a.file}: {e}")
            return 1

    if not targets:
        # echo stdin
        targets = [l.strip() for l in sys.stdin if l.strip()]
    if not targets:
        p.print_help()
        return 1

    r = GeoIPResolver(maxmind_path=a.maxmind,
                      ipinfo_token=a.ipinfo_token,
                      prefer=a.prefer)

    rows = r.resolve_many(targets, threads=a.threads, quiet=a.quiet)
    ok = sum(1 for x in rows if x.success)
    print(f"\n[+] Resolved {ok}/{len(rows)} targets "
          f"(sources used: ip-api, ipwho, ipinfo, ipapi.co, maxmind)")

    if a.out:
        base = a.out
        if a.csv:  to_csv(rows, base + ".csv")
        if a.json: to_json(rows, base + ".json")
        if not a.csv and not a.json:
            to_csv(rows, base + ".csv"); to_json(rows, base + ".json")
        print(f"[+] Reports written to {base}.{{csv,json}}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
