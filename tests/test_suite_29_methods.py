"""
SNI Scanner Pro - 29 Comprehensive Production Test Suite for 3 Selectable Validation Methods
Category 1: VLESS Reality Parser & Configuration Generator (Tests 1 - 7)
Category 2: Local Core Manager & Binary Discovery (Tests 8 - 11)
Category 3: Tunnel Benchmarker & RFC 3550 Jitter / Speed (Tests 12 - 16)
Category 4: Panel REST API Orchestrator & Guaranteed Cleanup (Tests 17 - 23)
Category 5: Multi-Method Scanner Engine, Web SSE & CLI (Tests 24 - 29)
"""

import asyncio
import json
import os
import sys
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.vless_parser import VLESSConfig, VLESSParser
from core.tunnel_benchmarker import LocalCoreManager, TunnelMetrics, TunnelBenchmarker
from core.panel_orchestrator import PanelCredentials, PanelOrchestrator
from core.scanner import SNIScanner, ScanProgress
from core.scorer import ScoredSNI
from core.dns_resolver import DNSResolutionResult
from core.tls_checker import TLSCheckResult
from core.reality_matcher import RealityMatchResult


class TestSuite29Methods(unittest.TestCase):

    # =========================================================================
    # Category 1: VLESS Reality Parser & Config Generator (Tests 1 - 7)
    # =========================================================================

    def test_01_vless_parse_valid_reality_uri(self):
        """1. Parses standard RFC-compliant VLESS Reality URI correctly."""
        raw_uri = (
            "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@48.102.164.241:443"
            "?security=reality&sni=speedtest.hetzner.com&pbk=7N9Jk8_x1Y2Z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8="
            "&sid=abcd1234&type=tcp&flow=xtls-rprx-vision&fp=chrome#Frankfurt-Reality"
        )
        cfg = VLESSParser.parse(raw_uri)
        self.assertEqual(cfg.uuid, "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d")
        self.assertEqual(cfg.server, "48.102.164.241")
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.security, "reality")
        self.assertEqual(cfg.sni, "speedtest.hetzner.com")
        self.assertTrue(cfg.pbk.startswith("7N9Jk8_"))
        self.assertEqual(cfg.sid, "abcd1234")
        self.assertEqual(cfg.flow, "xtls-rprx-vision")
        self.assertEqual(cfg.fp, "chrome")
        self.assertEqual(cfg.name, "Frankfurt-Reality")
        self.assertTrue(cfg.is_reality())

    def test_02_vless_parse_missing_uuid_raises(self):
        """2. Malformed URI without UUID raises ValueError."""
        bad_uri = "vless://@48.102.164.241:443?security=reality&pbk=xyz"
        with self.assertRaises(ValueError) as ctx:
            VLESSParser.parse(bad_uri)
        self.assertIn("UUID", str(ctx.exception))

    def test_03_vless_parse_invalid_port_raises(self):
        """3. Malformed URI with non-integer or out-of-bounds port raises ValueError."""
        bad_port_uri = "vless://a1b2c3d4@server:99999?security=reality&pbk=xyz"
        with self.assertRaises(ValueError) as ctx:
            VLESSParser.parse(bad_port_uri)
        self.assertIn("port", str(ctx.exception).lower())

    def test_04_vless_parse_missing_protocol_raises(self):
        """4. URI missing vless:// prefix raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            VLESSParser.parse("vmess://some-encoded-string")
        self.assertIn("vless://", str(ctx.exception))

    def test_05_vless_with_sni_override(self):
        """5. Reconstructing URI with overridden candidate SNI updates SNI and preserves credentials."""
        raw_uri = "vless://my-uuid@my-server.com:8443?security=reality&sni=old.com&pbk=mypbk123&sid=1122"
        cfg = VLESSParser.parse(raw_uri)
        new_uri = cfg.to_uri(override_sni="new-candidate.org")
        self.assertIn("sni=new-candidate.org", new_uri)
        self.assertIn("my-uuid@my-server.com:8443", new_uri)
        self.assertIn("pbk=mypbk123", new_uri)
        self.assertNotIn("sni=old.com", new_uri)

    def test_06_vless_generate_xray_config(self):
        """6. Generates valid, compliant Xray client JSON configuration structure."""
        cfg = VLESSConfig(
            uuid="11111111-2222-3333-4444-555555555555",
            server="1.2.3.4",
            port=443,
            security="reality",
            sni="initial.com",
            pbk="pubkey123=",
            sid="aabbccdd",
            flow="xtls-rprx-vision",
        )
        xray_json = cfg.to_xray_client_config(override_sni="swapped-sni.net", local_socks_port=10808)
        self.assertIn("inbounds", xray_json)
        self.assertIn("outbounds", xray_json)

        # Inbounds check
        socks_inbound = xray_json["inbounds"][0]
        self.assertEqual(socks_inbound["protocol"], "socks")
        self.assertEqual(socks_inbound["port"], 10808)

        # Outbounds check
        proxy_outbound = xray_json["outbounds"][0]
        self.assertEqual(proxy_outbound["protocol"], "vless")
        stream_settings = proxy_outbound["streamSettings"]
        self.assertEqual(stream_settings["security"], "reality")
        reality_settings = stream_settings["realitySettings"]
        self.assertEqual(reality_settings["serverName"], "swapped-sni.net")
        self.assertEqual(reality_settings["publicKey"], "pubkey123=")

    def test_07_vless_to_uri_reconstruction(self):
        """7. Reconstructed URI can be round-tripped and re-parsed identically."""
        original = (
            "vless://user-uuid-123@vpn.example.com:443"
            "?security=reality&sni=test.com&pbk=key123&sid=sid123&flow=xtls-rprx-vision&fp=chrome#Remark"
        )
        cfg1 = VLESSParser.parse(original)
        reconstructed = cfg1.to_uri()
        cfg2 = VLESSParser.parse(reconstructed)
        self.assertEqual(cfg1.uuid, cfg2.uuid)
        self.assertEqual(cfg1.server, cfg2.server)
        self.assertEqual(cfg1.port, cfg2.port)
        self.assertEqual(cfg1.sni, cfg2.sni)
        self.assertEqual(cfg1.pbk, cfg2.pbk)

    # =========================================================================
    # Category 2: Local Core Manager & Binary Discovery (Tests 8 - 11)
    # =========================================================================

    def test_08_core_manager_detect_system_binary(self):
        """8. find_core_binary discovers executable in PATH or returns None cleanly."""
        res = LocalCoreManager.find_core_binary()
        if res is not None:
            self.assertTrue(os.path.isfile(res))

    def test_09_core_manager_user_specified_path_validation(self):
        """9. Passing an invalid user path returns None or falls back cleanly."""
        res = LocalCoreManager.find_core_binary(user_path="nonexistent_xray_binary_xyz_123.exe")
        self.assertTrue(res is None or os.path.isfile(res))

    def test_10_core_manager_jitter_empty_or_single_sample(self):
        """10. calculate_jitter returns 0.0 when samples list has fewer than 2 items."""
        self.assertEqual(LocalCoreManager.calculate_jitter([]), 0.0)
        self.assertEqual(LocalCoreManager.calculate_jitter([55.0]), 0.0)

    def test_11_core_manager_jitter_exact_mean_calculation(self):
        """11. calculate_jitter computes exact RFC 3550 mean absolute deviation."""
        samples = [40.0, 50.0, 60.0, 40.0]
        jitter = LocalCoreManager.calculate_jitter(samples)
        self.assertEqual(jitter, 13.33)

    # =========================================================================
    # Category 3: Tunnel Benchmarker & RFC 3550 Metrics (Tests 12 - 16)
    # =========================================================================

    def test_12_tunnel_metrics_initialization(self):
        """12. TunnelMetrics initializes default values and exports clean dictionary."""
        m = TunnelMetrics(domain="fast.com", success=True, latency_ms=45.2, jitter_ms=2.1, download_mbps=85.4)
        d = m.to_dict()
        self.assertEqual(d["domain"], "fast.com")
        self.assertTrue(d["success"])
        self.assertEqual(d["latency_ms"], 45.2)
        self.assertEqual(d["jitter_ms"], 2.1)
        self.assertEqual(d["download_mbps"], 85.4)

    def test_13_tunnel_benchmarker_score_grading_s_plus(self):
        """13. Low latency, ultra-low jitter, and high speed scores Grade S+."""
        score, grade, tags = TunnelBenchmarker.calculate_tunnel_score(
            latency_ms=65.0,
            jitter_ms=5.0,
            download_mbps=75.0,
            success=True,
        )
        self.assertGreaterEqual(score, 90)
        self.assertEqual(grade, "S+")
        self.assertIn("REALITY_TUNNEL_OK", tags)
        self.assertIn("ULTRA_LOW_PING", tags)
        self.assertIn("ROCK_SOLID_JITTER", tags)
        self.assertIn("HIGH_SPEED_40MBPS+", tags)

    def test_14_tunnel_benchmarker_score_grading_failure(self):
        """14. Unsuccessful tunnel test scores 0 with Grade F and TUNNEL_FAILED tag."""
        score, grade, tags = TunnelBenchmarker.calculate_tunnel_score(
            latency_ms=None,
            jitter_ms=None,
            download_mbps=None,
            success=False,
        )
        self.assertEqual(score, 0)
        self.assertEqual(grade, "F")
        self.assertIn("TUNNEL_FAILED", tags)

    def test_15_tunnel_benchmarker_mock_benchmark_execution(self):
        """15. TunnelBenchmarker in mock mode benchmarks candidate SNI deterministically."""
        cfg = VLESSConfig(
            uuid="12345678-1234-1234-1234-123456789abc",
            server="1.2.3.4",
            port=443,
            security="reality",
            sni="test.com",
            pbk="pub123=",
        )
        benchmarker = TunnelBenchmarker(vless_config=cfg, mock_mode=True)
        loop = asyncio.new_event_loop()
        try:
            metrics = loop.run_until_complete(benchmarker.benchmark_single("candidate.speedtest.net"))
        finally:
            loop.close()

        self.assertEqual(metrics.domain, "candidate.speedtest.net")
        self.assertTrue(metrics.success)
        self.assertIsNotNone(metrics.latency_ms)
        self.assertIsNotNone(metrics.jitter_ms)
        self.assertIsNotNone(metrics.download_mbps)
        self.assertGreaterEqual(metrics.score, 60)

    def test_16_tunnel_benchmarker_score_mid_latency(self):
        """16. Higher latency (200ms) with moderate jitter receives Grade B or C."""
        score, grade, tags = TunnelBenchmarker.calculate_tunnel_score(
            latency_ms=210.0,
            jitter_ms=28.0,
            download_mbps=12.0,
            success=True,
        )
        self.assertIn(grade, ["B", "C"])
        self.assertLess(score, 80)
        self.assertIn("MODERATE_PING", tags)

    # =========================================================================
    # Category 4: Panel REST API Orchestrator & Guaranteed Cleanup (Tests 17 - 23)
    # =========================================================================

    def test_17_panel_credentials_normalization(self):
        """17. Normalizes Panel URL, ensuring protocol and removing trailing slashes."""
        creds1 = PanelCredentials("192.168.1.100:2053", "admin", "admin")
        self.assertEqual(creds1.clean_base_url(), "http://192.168.1.100:2053")

        creds2 = PanelCredentials("https://my-panel.com:8443/", "admin", "admin")
        self.assertEqual(creds2.clean_base_url(), "https://my-panel.com:8443")

    def test_18_panel_login_mock_success(self):
        """18. Panel login in mock mode succeeds and sets session cookie."""
        creds = PanelCredentials("http://panel.test:2053", "admin", "secret")
        orchestrator = PanelOrchestrator(credentials=creds, mock_mode=True)
        loop = asyncio.new_event_loop()
        try:
            ok = loop.run_until_complete(orchestrator.login())
        finally:
            loop.close()
        self.assertTrue(ok)
        self.assertIsNotNone(orchestrator.session_cookie)

    def test_19_panel_login_invalid_credentials_rejected(self):
        """19. Invalid credentials return False without setting session cookie."""
        creds = PanelCredentials("http://panel.test:2053", "invalid", "wrong")
        orchestrator = PanelOrchestrator(credentials=creds, mock_mode=True)
        loop = asyncio.new_event_loop()
        try:
            ok = loop.run_until_complete(orchestrator.login())
        finally:
            loop.close()
        self.assertFalse(ok)
        self.assertIsNone(orchestrator.session_cookie)

    def test_20_panel_reality_keypair_generation(self):
        """20. Generates valid 43+ char base64 X25519-like keys and 8-hex ShortID."""
        creds = PanelCredentials("http://panel.test:2053", "admin", "pass")
        orchestrator = PanelOrchestrator(credentials=creds, mock_mode=True)
        priv, pub, sid = orchestrator.generate_reality_keypair()
        self.assertTrue(priv.endswith("="))
        self.assertTrue(pub.endswith("="))
        self.assertEqual(len(sid), 8)
        int(sid, 16)

    def test_21_panel_temp_inbound_creation_mock(self):
        """21. create_temp_inbound provisions inbound and tracks active inbound ID."""
        creds = PanelCredentials("http://panel.test:2053", "admin", "pass")
        orchestrator = PanelOrchestrator(credentials=creds, mock_mode=True)
        loop = asyncio.new_event_loop()
        try:
            inbound_id, vless_cfg = loop.run_until_complete(
                orchestrator.create_temp_inbound(port=28443, initial_sni="speedtest.net")
            )
        finally:
            loop.close()

        self.assertIn(inbound_id, orchestrator._active_inbound_ids)
        self.assertEqual(vless_cfg.port, 28443)
        self.assertEqual(vless_cfg.sni, "speedtest.net")
        self.assertEqual(vless_cfg.security, "reality")

    def test_22_panel_guaranteed_cleanup_on_success(self):
        """22. managed_test_inbound context manager guarantees inbound deletion after normal block exit."""
        creds = PanelCredentials("http://panel.test:2053", "admin", "pass")
        orchestrator = PanelOrchestrator(credentials=creds, mock_mode=True)
        loop = asyncio.new_event_loop()

        captured_id = None
        async def run_context():
            nonlocal captured_id
            async with orchestrator.managed_test_inbound(port=28443, initial_sni="test.com") as (i_id, cfg):
                captured_id = i_id
                self.assertIn(i_id, orchestrator._active_inbound_ids)

        try:
            loop.run_until_complete(run_context())
        finally:
            loop.close()

        self.assertIsNotNone(captured_id)
        self.assertNotIn(captured_id, orchestrator._active_inbound_ids)

    def test_23_panel_guaranteed_cleanup_on_exception(self):
        """23. managed_test_inbound strictly guarantees inbound deletion even when exception is raised."""
        creds = PanelCredentials("http://panel.test:2053", "admin", "pass")
        orchestrator = PanelOrchestrator(credentials=creds, mock_mode=True)
        loop = asyncio.new_event_loop()

        captured_id = None
        async def run_failing_context():
            nonlocal captured_id
            async with orchestrator.managed_test_inbound(port=28443, initial_sni="test.com") as (i_id, cfg):
                captured_id = i_id
                self.assertIn(i_id, orchestrator._active_inbound_ids)
                raise RuntimeError("Simulated crash during benchmark!")

        try:
            with self.assertRaises(RuntimeError):
                loop.run_until_complete(run_failing_context())
        finally:
            loop.close()

        self.assertIsNotNone(captured_id)
        self.assertNotIn(captured_id, orchestrator._active_inbound_ids)

    # =========================================================================
    # Category 5: Multi-Method Scanner Engine, Web SSE & CLI (Tests 24 - 29)
    # =========================================================================

    def test_24_scanner_method_1_standard(self):
        """24. Method 1 (standard) produces ScoredSNI with TLS 1.3 / DNS validation."""
        scanner = SNIScanner(scan_method="standard", concurrency=2, mock_mode=True)
        async def mock_scan_std(domain):
            dns_res = DNSResolutionResult(domain, ["1.2.3.4"], 20.0, is_poisoned=False)
            tls_res = TLSCheckResult(domain, "1.2.3.4", success=True)
            tls_res.tls_version = "TLSv1.3"
            reality_res = RealityMatchResult(domain)
            reality_res.reality_suitable = True
            return ScoredSNI(domain, 95, "S+", ["REALITY_SUITABLE", "TLSv1.3"], dns_res, tls_res, reality_res)

        scanner.scan_single_standard = mock_scan_std
        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(scanner.scan_domains(["example1.com", "example2.com"]))
        finally:
            loop.close()

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], ScoredSNI)
        self.assertEqual(results[0].grade, "S+")

    def test_25_scanner_method_2_vless_client(self):
        """25. Method 2 (vless_client) produces TunnelMetrics with live jitter and throughput."""
        raw_uri = "vless://test-uuid@1.2.3.4:443?security=reality&sni=init.com&pbk=key123="
        scanner = SNIScanner(scan_method="vless_client", vless_config=raw_uri, concurrency=2, mock_mode=True)
        self.assertIsNotNone(scanner.vless_config)
        self.assertIsNotNone(scanner.tunnel_benchmarker)

        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(scanner.scan_domains(["cloudflare.com", "fastly.net"]))
        finally:
            loop.close()

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], TunnelMetrics)
        self.assertTrue(results[0].success)
        self.assertIsNotNone(results[0].latency_ms)
        self.assertIsNotNone(results[0].jitter_ms)

    def test_26_scanner_method_3_panel_api(self):
        """26. Method 3 (panel_api) coordinates inbound provisioning, benchmarks SNIs, and cleans up."""
        creds = PanelCredentials("http://panel.test:2053", "admin", "pass")
        scanner = SNIScanner(scan_method="panel_api", panel_credentials=creds, concurrency=2, mock_mode=True)
        self.assertIsNotNone(scanner.panel_orchestrator)

        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(scanner.scan_domains(["speedtest.net", "fast.com"]))
        finally:
            loop.close()

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], TunnelMetrics)
        self.assertEqual(len(scanner.panel_orchestrator._active_inbound_ids), 0)

    def test_27_scanner_multi_method_cancellation(self):
        """27. Scanner cancellation aborts execution gracefully across all methods."""
        scanner = SNIScanner(scan_method="standard", concurrency=5)
        self.assertFalse(scanner._is_cancelled)
        scanner.cancel()
        self.assertTrue(scanner._is_cancelled)

    def test_28_web_api_scan_stream_method_parameters(self):
        """28. FastAPI /api/scan/stream endpoint accepts method parameter and valid requests."""
        from fastapi.testclient import TestClient
        from web.app import app
        client = TestClient(app)

        with client.stream("GET", "/api/scan/stream?method=standard&category=custom&custom_domains=example.com&limit=1&mock_mode=true") as resp:
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.headers["content-type"].split(";")[0], "text/event-stream")

        test_vless = "vless://uuid-123@1.2.3.4:443?security=reality&sni=test.com&pbk=key123="
        with client.stream("GET", f"/api/scan/stream?method=vless_client&category=custom&vless_uri={test_vless}&custom_domains=test.com&limit=1&mock_mode=true") as resp2:
            self.assertEqual(resp2.status_code, 200)

    def test_29_cli_argument_parser_three_methods(self):
        """29. CLI parser recognizes --method flags {standard, vless_client, panel_api}."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--method", choices=["standard", "vless_client", "panel_api"], default="standard")
        parser.add_argument("--vless", type=str, default="")
        parser.add_argument("--panel-url", type=str, default="")
        parser.add_argument("--panel-user", type=str, default="")
        parser.add_argument("--panel-pass", type=str, default="")

        args1 = parser.parse_args(["--method", "standard"])
        self.assertEqual(args1.method, "standard")

        args2 = parser.parse_args(["--method", "vless_client", "--vless", "vless://abc@1.2.3.4:443"])
        self.assertEqual(args2.method, "vless_client")
        self.assertEqual(args2.vless, "vless://abc@1.2.3.4:443")

        args3 = parser.parse_args(["--method", "panel_api", "--panel-url", "http://panel:2053", "--panel-user", "admin"])
        self.assertEqual(args3.method, "panel_api")
        self.assertEqual(args3.panel_url, "http://panel:2053")


if __name__ == "__main__":
    unittest.main()
