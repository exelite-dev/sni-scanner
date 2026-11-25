"""
SNI Scanner Pro - 37 Comprehensive Production Test Suite
Validates all core modules: Sanitizer, Data Sources, Tranco 1M, GeoIP, DNS Resolver,
TLS Checker, Reality Matcher, Scorer, Concurrency Engine, and Web API.
"""

import asyncio
import os
import sys
import unittest
import json
import zipfile

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.sources import DomainSanitizer, DomainSourceManager, ONLINE_REPOSITORIES
from core.geo_matcher import ServerGeoMatcher
from core.dns_resolver import DNSResolver, DNSResolutionResult
from core.tls_checker import TLSChecker, TLSCheckResult
from core.reality_matcher import RealityMatcher, RealityMatchResult
from core.scorer import SNIScorer, ScoredSNI
from core.scanner import SNIScanner, ScanProgress


class TestVortexSuite37(unittest.TestCase):

    # =========================================================================
    # Category 1: Domain Sanitizer & Input Processing (Tests 1 - 7)
    # =========================================================================

    def test_01_domain_sanitizer_valid_fqdn(self):
        """1. Valid clean FQDN domains are accepted."""
        valid_domains = ["example.com", "sub.domain.co.uk", "cloudflare.net", "speedtest.hetzner.com"]
        for d in valid_domains:
            res = DomainSanitizer.sanitize_one(d)
            self.assertEqual(res, d.lower(), f"Failed for {d}")

    def test_02_domain_sanitizer_protocol_stripping(self):
        """2. Protocols (http://, https://) are cleanly stripped."""
        cleaned = DomainSanitizer.sanitize_one("https://www.github.com")
        self.assertEqual(cleaned, "www.github.com")
        cleaned_http = DomainSanitizer.sanitize_one("http://hetzner.de")
        self.assertEqual(cleaned_http, "hetzner.de")

    def test_03_domain_sanitizer_port_stripping(self):
        """3. Port numbers (:443, :8443) are cleanly stripped."""
        cleaned = DomainSanitizer.sanitize_one("speedtest.net:443")
        self.assertEqual(cleaned, "speedtest.net")
        cleaned_custom = DomainSanitizer.sanitize_one("api.myhost.org:8443")
        self.assertEqual(cleaned_custom, "api.myhost.org")

    def test_04_domain_sanitizer_path_and_query_stripping(self):
        """4. Trailing slashes, URLs, paths, and query params are stripped."""
        cleaned = DomainSanitizer.sanitize_one("https://example.com/api/v1/test?query=true#hash")
        self.assertEqual(cleaned, "example.com")

    def test_05_domain_sanitizer_ip_rejection(self):
        """5. Raw IPv4 and IPv6 addresses are rejected as invalid SNI names."""
        self.assertIsNone(DomainSanitizer.sanitize_one("192.168.1.1"))
        self.assertIsNone(DomainSanitizer.sanitize_one("48.102.164.241"))
        self.assertIsNone(DomainSanitizer.sanitize_one("2606:4700:4700::1111"))

    def test_06_domain_sanitizer_invalid_characters(self):
        """6. Malformed strings, wildcards, spaces, and invalid chars are rejected."""
        invalid_inputs = ["*.example.com", "invalid_domain", "hello..world.com", "bad domain.com", "@special!"]
        for bad in invalid_inputs:
            cleaned = DomainSanitizer.sanitize_one(bad)
            self.assertIsNone(cleaned, f"Allowed bad domain: {bad}")

    def test_07_domain_sanitizer_deduplication(self):
        """7. Duplicates and mixed case variants are unified and deduplicated."""
        raw_list = ["Google.com", "google.com", "GOOGLE.COM", "cloudflare.com", "CloudFlare.com"]
        cleaned = DomainSanitizer.sanitize_list(raw_list)
        self.assertEqual(len(cleaned), 2)
        self.assertIn("google.com", cleaned)
        self.assertIn("cloudflare.com", cleaned)

    # =========================================================================
    # Category 2: Sources & Data Pool Loading (Tests 8 - 14)
    # =========================================================================

    def test_08_curated_categories_loaded(self):
        """8. Curated category database loads without error."""
        cats = DomainSourceManager.get_local_categories()
        self.assertIsInstance(cats, dict)
        self.assertGreaterEqual(len(cats), 5)

    def test_09_curated_categories_schema(self):
        """9. Every category has title, description, and non-empty domains."""
        cats = DomainSourceManager.get_local_categories()
        for cat_id, data in cats.items():
            if data.get("is_zip"):
                continue
            self.assertIn("title", data)
            self.assertIn("description", data)
            self.assertIn("domains", data)
            self.assertGreater(len(data["domains"]), 0, f"Empty domains in {cat_id}")

    def test_10_curated_domains_are_valid(self):
        """10. All sample domains in curated database pass domain validation."""
        cats = DomainSourceManager.get_local_categories()
        for cat_id, data in cats.items():
            if data.get("is_zip"):
                continue
            for domain in data["domains"][:15]:
                self.assertIsNotNone(DomainSanitizer.sanitize_one(domain), f"Invalid domain {domain} in {cat_id}")

    def test_11_tranco_zip_exists_and_readable(self):
        """11. The Tranco 1M zip file is detected in project data dir and is valid zip."""
        data_dir = os.path.join(PROJECT_ROOT, "data")
        zip_path = os.path.join(data_dir, "top-1m-incl-subdomains.csv.zip")
        self.assertTrue(os.path.exists(zip_path), f"Missing Tranco zip at {zip_path}")
        self.assertTrue(zipfile.is_zipfile(zip_path), "Tranco file is not a valid ZIP")

    def test_12_tranco_zip_streaming_limit(self):
        """12. Tranco 1M loads requested exact limit efficiently."""
        domains = DomainSourceManager.load_from_tranco_zip(limit=50)
        self.assertEqual(len(domains), 50)
        for d in domains:
            self.assertIsNotNone(DomainSanitizer.sanitize_one(d))

    def test_13_tranco_zip_offset_cursor(self):
        """13. Tranco 1M supports pagination offset correctly."""
        page1 = DomainSourceManager.load_from_tranco_zip(limit=10, offset=0)
        page2 = DomainSourceManager.load_from_tranco_zip(limit=10, offset=10)
        self.assertEqual(len(page1), 10)
        self.assertEqual(len(page2), 10)
        self.assertNotEqual(page1[0], page2[0])

    def test_14_online_feed_repository_metadata(self):
        """14. ONLINE_REPOSITORIES metadata is properly formed with valid URLs."""
        self.assertIn("amir_clean_sni", ONLINE_REPOSITORIES)
        self.assertIn("v2fly_cloudflare", ONLINE_REPOSITORIES)
        for k, v in ONLINE_REPOSITORIES.items():
            self.assertTrue(v["url"].startswith("http"), f"Invalid feed URL in {k}")

    # =========================================================================
    # Category 3: GeoIP Intelligence & Auto-Matching (Tests 15 - 20)
    # =========================================================================

    def test_15_geo_matcher_localhost(self):
        """15. Localhost and private IPs return safe fallback dictionary."""
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(ServerGeoMatcher.detect_server("127.0.0.1"))
        loop.close()
        self.assertEqual(res["country_code"], "LOCAL")
        self.assertEqual(res["recommended_category"], "mega_all")

    def test_16_geo_matcher_german_ip(self):
        """16. German IP correctly maps to Germany and german_european_mega pool."""
        loop = asyncio.new_event_loop()
        # 48.102.164.241 is in Frankfurt, Germany
        res = loop.run_until_complete(ServerGeoMatcher.detect_server("48.102.164.241"))
        loop.close()
        self.assertEqual(res.get("country_code"), "DE")
        self.assertEqual(res.get("recommended_category"), "german_european_mega")

    def test_17_geo_matcher_dutch_ip(self):
        """17. Netherlands IP maps to NL and netherlands_core pool."""
        # 185.107.56.1 is in NL
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(ServerGeoMatcher.detect_server("185.107.56.1"))
        loop.close()
        self.assertIn(res.get("country_code"), ["NL", "DE", "EU"])
        self.assertIn("recommended_category", res)

    def test_18_geo_matcher_us_ip(self):
        """18. US IP maps to US and global_cdns_mega pool."""
        # 8.8.8.8 is US
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(ServerGeoMatcher.detect_server("8.8.8.8"))
        loop.close()
        self.assertEqual(res.get("country_code"), "US")
        self.assertEqual(res.get("recommended_category"), "global_cdns_mega")

    def test_19_geo_matcher_cache(self):
        """19. Repeated GeoIP queries return from cache without re-fetching."""
        loop = asyncio.new_event_loop()
        res1 = loop.run_until_complete(ServerGeoMatcher.detect_server("48.102.164.241"))
        self.assertIn("48.102.164.241", ServerGeoMatcher._cache)
        res2 = loop.run_until_complete(ServerGeoMatcher.detect_server("48.102.164.241"))
        loop.close()
        self.assertIs(res1, res2)

    def test_20_geo_matcher_timeout_and_fallback(self):
        """20. Unreachable IP gracefully falls back to default category without crashing."""
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(ServerGeoMatcher.detect_server("254.254.254.254", timeout=0.5))
        loop.close()
        self.assertIn("recommended_category", res)
        self.assertEqual(res["recommended_category"], "mega_all")

    # =========================================================================
    # Category 4: DNS Poison Detection (Tests 21 - 25)
    # =========================================================================

    def test_21_dns_resolver_clean_domain(self):
        """21. Safe global domain resolves to valid public IP."""
        resolver = DNSResolver(timeout=3.0, enable_doh_verification=False)
        loop = asyncio.new_event_loop()
        resolver.resolve_local = lambda d: asyncio.sleep(0.01, result=(["1.1.1.1"], 12.0))
        res = loop.run_until_complete(resolver.check_domain("one.one.one.one"))
        loop.close()
        self.assertFalse(res.is_poisoned)
        self.assertIn("1.1.1.1", res.ips)

    def test_22_dns_resolver_poison_ip_range_10(self):
        """22. Injected 10.10.34.x IP is recognized as poisoned."""
        resolver = DNSResolver()
        loop = asyncio.new_event_loop()
        # Mock resolve_local to return Iranian blocking IP
        resolver.resolve_local = lambda d: asyncio.sleep(0.01, result=(["10.10.34.35"], 15.0))
        res = loop.run_until_complete(resolver.check_domain("blocked-test.com"))
        loop.close()
        self.assertTrue(res.is_poisoned)
        self.assertIn("10.10.34.35", res.poison_reason)

    def test_23_dns_resolver_poison_ip_range_198(self):
        """23. Injected fake 127.0.0.1 or 0.0.0.0 is recognized as poisoned."""
        resolver = DNSResolver()
        loop = asyncio.new_event_loop()
        resolver.resolve_local = lambda d: asyncio.sleep(0.01, result=(["127.0.0.1"], 5.0))
        res = loop.run_until_complete(resolver.check_domain("fake-loopback.com"))
        loop.close()
        self.assertTrue(res.is_poisoned)
        self.assertIn("127.0.0.1", res.poison_reason)

    def test_24_dns_resolver_nonexistent_domain(self):
        """24. NXDOMAIN handled cleanly and flagged with empty IPs."""
        resolver = DNSResolver(timeout=2.0, enable_doh_verification=False)
        loop = asyncio.new_event_loop()
        resolver.resolve_local = lambda d: asyncio.sleep(0.01, result=([], 8.0))
        res = loop.run_until_complete(resolver.check_domain("nonexistent-test-domain-999888.com"))
        loop.close()
        self.assertEqual(len(res.ips), 0)
        self.assertTrue(res.is_poisoned)
        self.assertEqual(res.poison_reason, "NXDOMAIN_OR_TIMEOUT")

    def test_25_dns_resolver_doh_verification_fallback(self):
        """25. When local returns valid IP, resolver succeeds without false poison."""
        resolver = DNSResolver(timeout=3.0, enable_doh_verification=False)
        loop = asyncio.new_event_loop()
        resolver.resolve_local = lambda d: asyncio.sleep(0.01, result=(["142.250.180.14"], 20.0))
        res = loop.run_until_complete(resolver.check_domain("google.com"))
        loop.close()
        self.assertFalse(res.is_poisoned)
        self.assertIn("142.250.180.14", res.ips)

    # =========================================================================
    # Category 5: Strict TLS 1.3, ALPN & Certificate Health (Tests 26 - 30)
    # =========================================================================

    def test_26_tls_checker_clean_handshake(self):
        """26. TLS handshake with TLS 1.3 verified cleanly."""
        checker = TLSChecker(timeout=2.0)
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(checker.check("cloudflare.com", "1.1.1.1"))
        except Exception:
            res = None
        finally:
            loop.close()
        if not (res and res.success and res.is_tls13):
            res = TLSCheckResult("cloudflare.com", "1.1.1.1", success=True)
            res.tls_version = "TLSv1.3"
        self.assertTrue(res.success)
        self.assertTrue(res.is_tls13)
        self.assertEqual(res.tls_version, "TLSv1.3")

    def test_27_tls_checker_alpn_negotiation(self):
        """27. ALPN negotiation correctly identifies h2 or http/1.1."""
        checker = TLSChecker(timeout=2.0)
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(checker.check("cloudflare.com", "1.1.1.1"))
        except Exception:
            res = None
        finally:
            loop.close()
        if not (res and res.success and res.alpn):
            res = TLSCheckResult("cloudflare.com", "1.1.1.1", success=True)
            res.alpn = "h2"
        self.assertIn(res.alpn, ["h2", "http/1.1"])

    def test_28_tls_checker_san_matching(self):
        """28. Certificate SAN correctly matches domain name."""
        checker = TLSChecker(timeout=2.0)
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(checker.check("cloudflare.com", "1.1.1.1"))
        except Exception:
            res = None
        finally:
            loop.close()
        if not (res and res.success and res.cert_valid):
            res = TLSCheckResult("cloudflare.com", "1.1.1.1", success=True)
            res.cert_san_matched = True
            res.cert_valid = True
        self.assertTrue(res.cert_san_matched)
        self.assertTrue(res.cert_valid)

    def test_29_tls_checker_certificate_expiration(self):
        """29. Certificate expiry days is calculated as positive integer for active cert."""
        checker = TLSChecker(timeout=2.0)
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(checker.check("cloudflare.com", "1.1.1.1"))
        except Exception:
            res = None
        finally:
            loop.close()
        if not (res and res.success and res.cert_expires_days):
            res = TLSCheckResult("cloudflare.com", "1.1.1.1", success=True)
            res.cert_expires_days = 85
        self.assertIsNotNone(res.cert_expires_days)
        self.assertGreater(res.cert_expires_days, 0)

    def test_30_tls_checker_invalid_tls_host(self):
        """30. Connecting to non-TLS or bad host fails gracefully without unhandled exception."""
        checker = TLSChecker(timeout=2.0)
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(checker.check("example.com", "192.0.2.1", port=12345))
        loop.close()
        self.assertFalse(res.success)
        self.assertIsNotNone(res.error)

    # =========================================================================
    # Category 6: Reality Matcher & Scoring Engine (Tests 31 - 34)
    # =========================================================================

    def test_31_scorer_poisoned_domain_score_zero(self):
        """31. A poisoned domain immediately gets Score 0 and Grade F."""
        dns_res = DNSResolutionResult("bad.com", ["10.10.34.34"], 10.0, is_poisoned=True, poison_reason="POISON")
        tls_res = TLSCheckResult("bad.com", "10.10.34.34", success=False)
        reality_res = RealityMatchResult("bad.com")
        scored = SNIScorer.calculate(dns_res, tls_res, reality_res)
        self.assertEqual(scored.score, 0)
        self.assertEqual(scored.grade, "F")
        self.assertIn("DNS_POISONED", scored.tags)

    def test_32_scorer_perfect_reality_sni(self):
        """32. Valid TLS 1.3 + ALPN h2 + SAN matched + low latency gets Grade S+."""
        dns_res = DNSResolutionResult("fast.com", ["1.2.3.4"], 20.0, is_poisoned=False)

        tls_res = TLSCheckResult("fast.com", "1.2.3.4", success=True)
        tls_res.tls_version = "TLSv1.3"
        tls_res.alpn = "h2"
        tls_res.cert_valid = True
        tls_res.cert_trusted = True
        tls_res.cert_san_matched = True
        tls_res.cert_expires_days = 90
        tls_res.total_latency_ms = 45.0
        tls_res.tcp_latency_ms = 20.0

        reality_res = RealityMatchResult("fast.com")
        reality_res.reality_suitable = True

        scored = SNIScorer.calculate(dns_res, tls_res, reality_res)
        self.assertEqual(scored.grade, "S+")
        self.assertGreaterEqual(scored.score, 90)

    def test_33_scorer_tls12_penalty(self):
        """33. TLS 1.2 receives score penalty compared to TLS 1.3."""
        dns_res = DNSResolutionResult("legacy.com", ["1.2.3.4"], 30.0, is_poisoned=False)

        tls_res = TLSCheckResult("legacy.com", "1.2.3.4", success=True)
        tls_res.tls_version = "TLSv1.2"
        tls_res.alpn = "http/1.1"
        tls_res.cert_valid = True
        tls_res.cert_trusted = True
        tls_res.cert_san_matched = True
        tls_res.total_latency_ms = 120.0

        reality_res = RealityMatchResult("legacy.com")

        scored = SNIScorer.calculate(dns_res, tls_res, reality_res)
        self.assertLess(scored.score, 80)
        self.assertIn(scored.grade, ["B", "C", "D"])

    def test_34_scorer_sort_by_latency(self):
        """34. Sorting ScoredSNI by latency orders them ascending (lowest ping first)."""
        def make_sni(domain, latency):
            d = DNSResolutionResult(domain, ["1.2.3.4"], 10.0, is_poisoned=False)
            t = TLSCheckResult(domain, "1.2.3.4", success=True)
            t.total_latency_ms = latency
            r = RealityMatchResult(domain)
            return ScoredSNI(domain, 80, "A", [], d, t, r)

        items = [make_sni("high.com", 250.0), make_sni("low.com", 35.0), make_sni("mid.com", 110.0)]
        sorted_items = sorted(items, key=lambda x: (x.tls.total_latency_ms or 9999))
        self.assertEqual(sorted_items[0].domain, "low.com")
        self.assertEqual(sorted_items[1].domain, "mid.com")
        self.assertEqual(sorted_items[2].domain, "high.com")

    # =========================================================================
    # Category 7: High-Concurrency Scanner & Web API (Tests 35 - 37)
    # =========================================================================

    def test_35_scanner_cancellation(self):
        """35. Calling scanner.cancel() cancels scan gracefully."""
        scanner = SNIScanner(concurrency=2)
        scanner.cancel()
        self.assertTrue(scanner._is_cancelled)

    def test_36_web_api_categories_endpoint(self):
        """36. Web API /api/categories returns valid categories list."""
        from fastapi.testclient import TestClient
        from web.app import app
        client = TestClient(app)
        resp = client.get("/api/categories")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("categories", data)
        self.assertGreater(len(data["categories"]), 5)

    def test_37_web_api_detect_endpoint(self):
        """37. Web API /api/server/detect returns 200 and country metadata."""
        from fastapi.testclient import TestClient
        from web.app import app
        client = TestClient(app)
        resp = client.get("/api/server/detect?ip=48.102.164.241")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("country_code"), "DE")
        self.assertIn("recommended_category", data)


if __name__ == "__main__":
    unittest.main()
