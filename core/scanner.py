"""
SNI Scanner Pro - High-Throughput Asynchronous Scanner Engine
Coordinates DNS, TLS, and Reality checks across multiple workers,
supporting 3 Selectable Validation Methods:
Method 1: Standard Passwordless SNI Scan (Fast TLS 1.3 + ALPN + Ping)
Method 2: Live Reality Tunnel Test with User VLESS Client Config (Jitter, Speed, Ping)
Method 3: Automated Live Test via Panel API (3X-UI / vpn-ui with guaranteed cleanup)
"""

import asyncio
import csv
import json
import os
import time
from typing import List, Dict, Any, Optional, Callable, Union

from .dns_resolver import DNSResolver
from .tls_checker import TLSChecker
from .reality_matcher import RealityMatcher
from .scorer import SNIScorer, ScoredSNI
from .vless_parser import VLESSConfig, VLESSParser
from .tunnel_benchmarker import TunnelBenchmarker, TunnelMetrics
from .panel_orchestrator import PanelOrchestrator, PanelCredentials


class ScanProgress:
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.success_count = 0
        self.failed_count = 0
        self.current_domain: str = ""
        self.start_time: float = time.time()

    @property
    def percent(self) -> float:
        return (self.completed / self.total * 100.0) if self.total > 0 else 0.0

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "completed": self.completed,
            "success_count": self.success_count,
            "failed_count": self.failed_count,
            "percent": round(self.percent, 1),
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "current_domain": self.current_domain,
        }


class SNIScanner:
    def __init__(
        self,
        concurrency: int = 15,
        timeout: float = 3.5,
        enable_doh: bool = True,
        target_server_ip: Optional[str] = None,
        target_server_port: int = 7,
        scan_method: str = "standard",  # "standard", "vless_client", "panel_api"
        vless_config: Optional[Union[VLESSConfig, str]] = None,
        panel_credentials: Optional[PanelCredentials] = None,
        core_path: Optional[str] = None,
        mock_mode: bool = False,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.scan_method = scan_method.lower().strip()
        self.mock_mode = mock_mode

        # Method 1 Components
        self.dns_resolver = DNSResolver(timeout=timeout, enable_doh_verification=enable_doh)
        self.tls_checker = TLSChecker(timeout=timeout)
        self.reality_matcher = RealityMatcher(timeout=timeout)
        self.target_server_ip = target_server_ip
        self.target_server_port = target_server_port

        # Method 2 & 3 Components
        if isinstance(vless_config, str):
            self.vless_config: Optional[VLESSConfig] = VLESSParser.parse(vless_config)
        else:
            self.vless_config = vless_config

        self.panel_credentials = panel_credentials
        self.core_path = core_path

        self.tunnel_benchmarker: Optional[TunnelBenchmarker] = None
        if self.vless_config:
            self.tunnel_benchmarker = TunnelBenchmarker(
                vless_config=self.vless_config,
                core_path=core_path,
                mock_mode=mock_mode,
            )

        self.panel_orchestrator: Optional[PanelOrchestrator] = None
        if self.panel_credentials:
            self.panel_orchestrator = PanelOrchestrator(
                credentials=self.panel_credentials,
                mock_mode=mock_mode,
            )

        self.results: List[Union[ScoredSNI, TunnelMetrics]] = []
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    async def scan_single_standard(self, domain: str) -> ScoredSNI:
        """Method 1: Standard Passwordless TLS/DNS/Reality check."""
        dns_res = await self.dns_resolver.check_domain(domain)
        if dns_res.is_poisoned or not dns_res.ips:
            tls_res = await self.tls_checker.check(domain, "0.0.0.0")
            reality_res = await self.reality_matcher.evaluate(domain, "0.0.0.0")
            return SNIScorer.calculate(dns_res, tls_res, reality_res)

        primary_ip = dns_res.ips[0]
        tls_res = await self.tls_checker.check(domain, primary_ip)
        reality_res = await self.reality_matcher.evaluate(
            domain=domain,
            target_ip=primary_ip,
            user_server_ip=self.target_server_ip,
            user_server_port=self.target_server_port,
        )
        return SNIScorer.calculate(dns_res, tls_res, reality_res)

    async def scan_single_vless_client(self, domain: str) -> TunnelMetrics:
        """Method 2: Live Reality Tunnel test using user VLESS client configuration."""
        if not self.tunnel_benchmarker:
            if not self.vless_config:
                raise ValueError("Method 2 requires a valid VLESS client configuration (vless_config).")
            self.tunnel_benchmarker = TunnelBenchmarker(
                vless_config=self.vless_config,
                core_path=self.core_path,
                mock_mode=self.mock_mode,
            )
        return await self.tunnel_benchmarker.benchmark_single(domain, timeout=self.timeout)

    async def scan_single(self, domain: str) -> Union[ScoredSNI, TunnelMetrics]:
        """Routes single domain check based on selected validation method."""
        if self.scan_method == "vless_client" or self.scan_method == "method_2":
            return await self.scan_single_vless_client(domain)
        elif self.scan_method == "panel_api" or self.scan_method == "method_3":
            return await self.scan_single_vless_client(domain)
        else:
            return await self.scan_single_standard(domain)

    async def scan_domains(
        self,
        domains: List[str],
        on_progress: Optional[Callable[[ScanProgress, Union[ScoredSNI, TunnelMetrics]], None]] = None,
        sort_by: str = "latency",
    ) -> List[Union[ScoredSNI, TunnelMetrics]]:
        """Scans domain list with semaphore-bounded concurrency."""
        self.results = []
        self._is_cancelled = False

        # Pre-execution setup for Method 3 (Automated Panel API)
        if (self.scan_method == "panel_api" or self.scan_method == "method_3") and self.panel_orchestrator:
            logged_in = await self.panel_orchestrator.login()
            if not logged_in:
                raise RuntimeError("Failed to authenticate with Panel API. Please check panel URL and credentials.")

            # Guarantee cleanup with context manager
            async with self.panel_orchestrator.managed_test_inbound(initial_sni=domains[0] if domains else "speedtest.net") as (inbound_id, generated_vless):
                self.vless_config = generated_vless
                self.tunnel_benchmarker = TunnelBenchmarker(
                    vless_config=generated_vless,
                    core_path=self.core_path,
                    mock_mode=self.mock_mode,
                )
                return await self._execute_scan_loop(domains, on_progress, sort_by)

        return await self._execute_scan_loop(domains, on_progress, sort_by)

    async def _execute_scan_loop(
        self,
        domains: List[str],
        on_progress: Optional[Callable[[ScanProgress, Union[ScoredSNI, TunnelMetrics]], None]],
        sort_by: str,
    ) -> List[Union[ScoredSNI, TunnelMetrics]]:
        effective_concurrency = min(self.concurrency, 5) if self.scan_method in ["vless_client", "panel_api", "method_2", "method_3"] else self.concurrency
        sem = asyncio.Semaphore(effective_concurrency)
        progress = ScanProgress(total=len(domains))

        async def worker(domain: str):
            if self._is_cancelled:
                return None
            async with sem:
                if self._is_cancelled:
                    return None
                progress.current_domain = domain
                result_item = await self.scan_single(domain)
                self.results.append(result_item)
                progress.completed += 1

                score = result_item.score
                if score >= 50:
                    progress.success_count += 1
                else:
                    progress.failed_count += 1

                if on_progress:
                    try:
                        on_progress(progress, result_item)
                    except Exception:
                        pass
                return result_item

        tasks = [worker(d) for d in domains]
        await asyncio.gather(*tasks, return_exceptions=True)

        def get_sort_key(item: Union[ScoredSNI, TunnelMetrics]):
            if isinstance(item, ScoredSNI):
                is_healthy = item.tls.success and not item.dns.is_poisoned
                lat = item.tls.total_latency_ms if (item.tls.success and item.tls.total_latency_ms) else 999999
                score = item.score
            else:
                is_healthy = item.success
                lat = item.latency_ms if (item.success and item.latency_ms is not None) else 999999
                score = item.score

            if sort_by == "score":
                return (-score, lat)
            return (0 if is_healthy else 1, lat, -score)

        self.results.sort(key=get_sort_key)
        return self.results

    def export_json(self, output_path: str):
        """Exports scan results to JSON supporting all 3 methods."""
        data = [r.to_dict() for r in self.results]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def export_csv(self, output_path: str):
        """Exports scan results to CSV supporting all 3 methods."""
        if not self.results:
            return

        if self.scan_method in ["vless_client", "panel_api", "method_2", "method_3"]:
            fields = ["domain", "success", "latency_ms", "jitter_ms", "download_mbps", "score", "grade", "tags", "error"]
        else:
            fields = [
                "domain", "score", "grade", "tags", "primary_ip", "is_tls13",
                "tls_version", "alpn", "latency_ms", "issuer", "dns_poisoned", "server_reachable", "error"
            ]

        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in self.results:
                row = r.to_dict()
                row["tags"] = "; ".join(row.get("tags", []))
                writer.writerow({k: row.get(k) for k in fields})
