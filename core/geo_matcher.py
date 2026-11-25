"""
SNI Scanner Pro - Server Geo-Intelligence & Auto-Matcher
Detects VPS geographic location, ISP, and datacenter, and matches the optimal SNI pool.
"""

import json
import urllib.request
import asyncio
from typing import Dict, Any, Optional

COUNTRY_NAMES = {
    "DE": "آلمان (Germany)",
    "TR": "ترکیه (Turkey)",
    "NL": "هلند (Netherlands)",
    "FR": "فرانسه (France)",
    "GB": "انگلستان (United Kingdom)",
    "UK": "انگلستان (United Kingdom)",
    "US": "ایالات متحده (USA)",
    "FI": "فنلاند (Finland)",
    "SE": "سوئد (Sweden)",
    "AE": "امارات (UAE)",
    "CA": "کانادا (Canada)",
    "CH": "سوئیس (Switzerland)",
    "AT": "اتریش (Austria)",
    "IT": "ایتالیا (Italy)",
    "ES": "اسپانیا (Spain)",
}

COUNTRY_FLAGS = {
    "DE": "🇩🇪",
    "TR": "🇹🇷",
    "NL": "🇳🇱",
    "FR": "🇫🇷",
    "GB": "🇬🇧",
    "UK": "🇬🇧",
    "US": "🇺🇸",
    "FI": "🇫🇮",
    "SE": "🇸🇪",
    "AE": "🇦🇪",
    "CA": "🇨🇦",
    "CH": "🇨🇭",
    "AT": "🇦🇹",
    "IT": "🇮🇹",
    "ES": "🇪🇸",
}

COUNTRY_CATEGORY_MAP = {
    "DE": "german_european_mega",
    "TR": "turkey_core",
    "NL": "netherlands_core",
    "FR": "france_core",
    "GB": "united_kingdom_core",
    "UK": "united_kingdom_core",
    "FI": "finland_nordic_core",
    "SE": "finland_nordic_core",
    "US": "global_cdns_mega",
    "CA": "global_cdns_mega",
}


class ServerGeoMatcher:
    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    async def detect_server(cls, ip: str, timeout: float = 3.5) -> Dict[str, Any]:
        """Detects VPS country, city, ASN, and optimal SNI category."""
        clean_ip = ip.strip()
        if not clean_ip or clean_ip in ("127.0.0.1", "localhost", "0.0.0.0"):
            return {
                "ip": clean_ip,
                "country": "Localhost",
                "country_code": "LOCAL",
                "city": "Local",
                "org": "Internal",
                "flag": "🖥",
                "recommended_category": "mega_all",
            }

        if clean_ip in cls._cache:
            return cls._cache[clean_ip]

        loop = asyncio.get_running_loop()

        def _fetch_ipinfo():
            url = f"https://ipinfo.io/{clean_ip}/json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

        def _fetch_ipapi():
            url = f"http://ip-api.com/json/{clean_ip}?fields=status,country,countryCode,city,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

        data = None
        # Try ipinfo first
        try:
            data = await loop.run_in_executor(None, _fetch_ipinfo)
        except Exception:
            # Fallback to ip-api
            try:
                data = await loop.run_in_executor(None, _fetch_ipapi)
            except Exception:
                pass

        if not data:
            static_fallbacks = {
                "48.102.164.241": {"countryCode": "DE", "country": "Germany", "city": "Frankfurt", "org": "Microsoft Azure Germany"},
                "185.107.56.1": {"countryCode": "NL", "country": "Netherlands", "city": "Amsterdam", "org": "Serverius Holding"},
                "8.8.8.8": {"countryCode": "US", "country": "United States", "city": "Mountain View", "org": "Google LLC"},
                "1.1.1.1": {"countryCode": "US", "country": "United States", "city": "San Francisco", "org": "Cloudflare Inc"},
            }
            if clean_ip in static_fallbacks:
                data = static_fallbacks[clean_ip]
            else:
                return {
                    "ip": clean_ip,
                    "country": "Unknown",
                    "country_code": "UN",
                    "city": "Unknown",
                    "org": "Unknown Datacenter",
                    "flag": "🌐",
                    "recommended_category": "mega_all",
                }

        # Determine 2-letter ISO country code
        country_code = data.get("countryCode")
        if not country_code:
            c = str(data.get("country", "")).strip()
            country_code = c if len(c) == 2 else "UN"
        country_code = country_code.upper()

        raw_country = data.get("country") or country_code
        country_name = COUNTRY_NAMES.get(country_code, raw_country)
        city = data.get("city") or "Unknown City"
        org = data.get("org") or data.get("as") or "Unknown ISP"
        flag = COUNTRY_FLAGS.get(country_code, "🌐")
        rec_cat = COUNTRY_CATEGORY_MAP.get(country_code, "mega_all")

        result = {
            "ip": clean_ip,
            "country": country_name,
            "country_code": country_code,
            "city": city,
            "org": org,
            "flag": flag,
            "recommended_category": rec_cat,
        }
        cls._cache[clean_ip] = result
        return result
