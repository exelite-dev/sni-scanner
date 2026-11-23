"""
Vortex SNI Hunter Pro - Massive Multi-Source Aggregator & Domain Sanitizer
Provides access to massive offline databases, Tranco Top 1M ZIP archives, live GitHub feeds, and custom imports.
"""

import json
import os
import re
import urllib.request
import asyncio
import zipfile
from typing import List, Dict, Any, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
CURATED_DATA_PATH = os.path.join(DATA_DIR, "curated_snis.json")

def get_tranco_zip_path() -> Optional[str]:
    """Finds Tranco 1M zip file dynamically across relative data dir or user Downloads."""
    candidates = [
        os.path.join(DATA_DIR, "top-1m-incl-subdomains.csv.zip"),
        os.path.join(os.path.expanduser("~"), "Downloads", "Compressed", "top-1m-incl-subdomains.csv.zip"),
        os.path.join(os.path.expanduser("~"), "Downloads", "top-1m-incl-subdomains.csv.zip"),
        r"C:\Users\Pouiya\Downloads\Compressed\top-1m-incl-subdomains.csv.zip",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None

DEFAULT_TRANCO_ZIP_PATH = get_tranco_zip_path() or os.path.join(DATA_DIR, "top-1m-incl-subdomains.csv.zip")

ONLINE_REPOSITORIES = {
    "amir_clean_sni": {
        "title": "AmirH3bashi Clean SNIs (GitHub Feed)",
        "url": "https://raw.githubusercontent.com/amirH3bashi/SNI_Checker/main/sni.txt",
        "description": "Curated clean international SNI list from Iranian bypass research.",
    },
    "v2fly_apple": {
        "title": "v2fly Apple Worldwide CDN Network",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple",
        "description": "Comprehensive Apple services and CDN endpoints.",
    },
    "v2fly_cloudflare": {
        "title": "v2fly Cloudflare Clean Edge Domains",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cloudflare",
        "description": "High-speed Cloudflare network endpoints.",
    },
    "v2fly_microsoft": {
        "title": "v2fly Microsoft & Azure Global Infrastructure",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/microsoft",
        "description": "Azure, Office, and Microsoft enterprise endpoints.",
    },
}


class DomainSanitizer:
    """Cleans, normalizes, and filters domain lists for VLESS Reality scanning."""

    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    @classmethod
    def sanitize_one(cls, raw: str) -> Optional[str]:
        if not raw:
            return None
        text = raw.strip().lower()
        # Remove comments
        if text.startswith("#") or text.startswith("//"):
            return None
        # Remove prefixes
        for prefix in ["include:", "full:", "domain:", "keyword:"]:
            if text.startswith(prefix):
                text = text[len(prefix) :].strip()
        # Remove protocol
        if "://" in text:
            text = text.split("://", 1)[1]
        # Remove path and query
        text = text.split("/")[0].split("?")[0].split("#")[0]
        # Remove port
        text = text.split(":")[0]
        text = text.strip(". ")

        # Filter out .ir and domestic Iranian domains
        if text.endswith(".ir"):
            return None

        # Validate domain format
        if cls.DOMAIN_REGEX.match(text) and len(text) <= 253:
            return text
        return None

    @classmethod
    def sanitize_list(cls, raw_list: List[str]) -> List[str]:
        cleaned = []
        seen = set()
        for item in raw_list:
            dom = cls.sanitize_one(item)
            if dom and dom not in seen:
                seen.add(dom)
                cleaned.append(dom)
        return cleaned


class DomainSourceManager:
    """Manages loading domains from local mega database, Tranco 1M zip, online feeds, or custom sources."""

    @staticmethod
    def get_local_categories() -> Dict[str, Any]:
        cats = {}
        if os.path.exists(CURATED_DATA_PATH):
            try:
                with open(CURATED_DATA_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cats = data.get("categories", {})
            except Exception:
                pass

        # Check if Tranco ZIP exists on laptop
        if os.path.exists(DEFAULT_TRANCO_ZIP_PATH):
            cats["tranco_top_1m"] = {
                "title": "🏆 Tranco Top 1M (آرشیو لوکال ۱ میلیون دامنه شامل ساب‌دامین‌ها)",
                "description": "فایل فشرده لوکال با ۱،۰۰۰،۰۰۰ دامنه برتر جهانی و زیردامنه‌ها بدون نیاز به اینترنت.",
                "count": 1000000,
                "is_zip": True,
            }

        return cats

    @classmethod
    def load_from_tranco_zip(
        cls,
        zip_path: str = DEFAULT_TRANCO_ZIP_PATH,
        limit: Optional[int] = 200,
        offset: int = 0,
    ) -> List[str]:
        """Reads and streams domains from Tranco 1M CSV zip without loading all into memory."""
        if not os.path.exists(zip_path):
            return []

        domains = []
        seen = set()
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                csv_files = [n for n in z.namelist() if n.endswith(".csv")]
                if not csv_files:
                    return []
                with z.open(csv_files[0]) as f:
                    skipped = 0
                    for line_bytes in f:
                        line = line_bytes.decode("utf-8", errors="ignore").strip()
                        if not line:
                            continue
                        parts = line.split(",", 1)
                        raw_dom = parts[1].strip() if len(parts) >= 2 else parts[0].strip()
                        clean = DomainSanitizer.sanitize_one(raw_dom)
                        if clean and clean not in seen:
                            seen.add(clean)
                            if skipped < offset:
                                skipped += 1
                                continue
                            domains.append(clean)
                            if limit and len(domains) >= limit:
                                break
        except Exception as e:
            print(f"[!] Warning reading Tranco ZIP '{zip_path}': {e}")
        return domains

    @classmethod
    def get_domains_from_category(cls, category: str, limit: Optional[int] = None) -> List[str]:
        if category == "tranco_top_1m":
            return cls.load_from_tranco_zip(limit=limit or 200)

        cats = cls.get_local_categories()
        if category in ("all", "mega_all"):
            all_domains = []
            for k, c in cats.items():
                if k != "tranco_top_1m":
                    all_domains.extend(c.get("domains", []))
            return DomainSanitizer.sanitize_list(all_domains)
        elif category in cats:
            return DomainSanitizer.sanitize_list(cats[category].get("domains", []))
        return []

    @classmethod
    async def fetch_online_source(cls, source_key: str, timeout: float = 6.0) -> List[str]:
        """Fetches domains from a pre-configured online GitHub repository."""
        if source_key not in ONLINE_REPOSITORIES:
            return []
        url = ONLINE_REPOSITORIES[source_key]["url"]
        return await cls.fetch_url(url, timeout=timeout)

    @classmethod
    async def fetch_url(cls, url: str, timeout: float = 6.0) -> List[str]:
        """Fetches and extracts clean domains from any raw HTTP/HTTPS URL."""
        loop = asyncio.get_running_loop()

        def _blocking_download():
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                lines = [line.strip() for line in content.splitlines() if line.strip()]
                return lines

        try:
            raw_lines = await loop.run_in_executor(None, _blocking_download)
            return DomainSanitizer.sanitize_list(raw_lines)
        except Exception as e:
            print(f"[!] Warning: Failed to fetch online source '{url}': {e}")
            return []

    @classmethod
    def load_from_file(cls, file_path: str, limit: Optional[int] = None) -> List[str]:
        """Loads and cleans domains from a local text, CSV, JSON, or ZIP file."""
        if not os.path.exists(file_path):
            return []

        # Handle ZIP file
        if file_path.lower().endswith(".zip"):
            return cls.load_from_tranco_zip(zip_path=file_path, limit=limit)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Check if JSON
                if content.strip().startswith("[") or content.strip().startswith("{"):
                    try:
                        parsed = json.loads(content)
                        if isinstance(parsed, list):
                            raw = [
                                (item["domain"] if isinstance(item, dict) and "domain" in item else str(item))
                                for item in parsed
                            ]
                            return DomainSanitizer.sanitize_list(raw)
                    except Exception:
                        pass
                lines = [l.strip() for l in content.splitlines() if l.strip()]
                return DomainSanitizer.sanitize_list(lines)
        except Exception as e:
            print(f"[!] Warning: Failed to load file '{file_path}': {e}")
            return []

    @classmethod
    async def resolve_domain_pool(
        cls,
        category: str = "mega_all",
        custom_domains: Optional[str] = None,
        custom_url: Optional[str] = None,
        file_path: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[str]:
        """Unified resolution pipeline with automatic fallback and slicing."""
        domains: List[str] = []

        # 1. Custom explicit domains
        if custom_domains:
            parts = [d.strip() for d in re.split(r"[,;\n\r\t]+", custom_domains) if d.strip()]
            domains.extend(DomainSanitizer.sanitize_list(parts))

        # 2. Local file / Zip
        elif file_path:
            domains.extend(cls.load_from_file(file_path, limit=limit))

        # 3. Tranco 1M zip direct selection
        elif category == "tranco_top_1m":
            domains.extend(cls.load_from_tranco_zip(limit=limit or 200))

        # 4. Custom URL
        elif custom_url:
            online = await cls.fetch_url(custom_url)
            domains.extend(online)

        # 5. Online preset repository
        elif category.startswith("online_"):
            source_key = category.replace("online_", "")
            online = await cls.fetch_online_source(source_key)
            if online:
                domains.extend(online)
            else:
                domains.extend(cls.get_domains_from_category("mega_all"))

        # 6. Local database category
        else:
            cat_domains = cls.get_domains_from_category(category, limit=limit)
            if not cat_domains:
                cat_domains = cls.get_domains_from_category("mega_all", limit=limit)
            domains.extend(cat_domains)

        # Deduplicate preserving order
        unique = list(dict.fromkeys(domains))

        # Apply limit if requested
        if limit and limit > 0:
            return unique[:limit]
        return unique
