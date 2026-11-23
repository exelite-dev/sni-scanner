"""
SNI Scanner Pro - High-Throughput Asynchronous Scanner Engine
Coordinates DNS, TLS, and Reality checks across multiple workers.
"""

import asyncio
import csv
import json
import os
import time
from typing import List, Dict, Any, Optional, Callable
from .dns_resolver import DNSResolver
from .tls_checker import TLSChecker
from .reality_matcher import RealityMatcher
from .scorer import SNIScorer, ScoredSNI


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
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.dns_resolver = DNSResolver(timeout=timeout, enable_doh_verification=enable_doh)
        self.tls_checker = TLSChecker(timeout=timeout)
        self.reality_matcher = RealityMatcher(timeout=timeout)
        self.target_server_ip = target_server_ip
        self.target_server_port = target_server_port
        self.results: List[ScoredSNI] = []
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    async def scan_single(self, domain: str) -> ScoredSNI:
        """Executes full audit pipeline for one domain."""
        # 1. DNS Resolution & Poison Detection
        dns_res = await self.dns_resolver.check_domain(domain)

        if dns_res.is_poisoned or not dns_res.ips:
            tls_res = await self.tls_checker.check(domain, "0.0.0.0")
            reality_res = await self.reality_matcher.evaluate(domain, "0.0.0.0")
            return SNIScorer.calculate(dns_res, tls_res, reality_res)

        primary_ip = dns_res.ips[0]

        # 2. TLS Handshake & Cipher Check
        tls_res = await self.tls_checker.check(domain, primary_ip)

        # 3. Reality & Server Probe
        reality_res = await self.reality_matcher.evaluate(
            domain=domain,
            target_ip=primary_ip,
            user_server_ip=self.target_server_ip,
            user_server_port=self.target_server_port,
        )

        # 4. Final Scoring
        return SNIScorer.calculate(dns_res, tls_res, reality_res)

    async def scan_domains(
        self,
        domains: List[str],
        on_progress: Optional[Callable[[ScanProgress, ScoredSNI], None]] = None,
        sort_by: str = "latency",
    ) -> List[ScoredSNI]:
        """Scans domain list with semaphore-bounded concurrency."""
        self.results = []
        self._is_cancelled = False
        sem = asyncio.Semaphore(self.concurrency)
        progress = ScanProgress(total=len(domains))

        async def worker(domain: str):
            if self._is_cancelled:
                return None
            async with sem:
                if self._is_cancelled:
                    return None
                progress.current_domain = domain
                scored = await self.scan_single(domain)
                self.results.append(scored)
                progress.completed += 1
                if scored.score >= 50:
                    progress.success_count += 1
                else:
                    progress.failed_count += 1

                if on_progress:
                    try:
                        on_progress(progress, scored)
                    except Exception:
                        pass
                return scored

        tasks = [worker(d) for d in domains]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Sort results: Default lowest ping (latency ascending) for working domains
        if sort_by == "score":
            self.results.sort(
                key=lambda x: (
                    -x.score,
                    x.tls.total_latency_ms if (x.tls.success and x.tls.total_latency_ms) else 999999,
                )
            )
        else:
            # Sort by lowest latency (Ping) first for healthy/working domains
            self.results.sort(
                key=lambda x: (
                    0 if (x.tls.success and not x.dns.is_poisoned) else 1,
                    x.tls.total_latency_ms if (x.tls.success and x.tls.total_latency_ms) else 999999,
                    -x.score,
                )
            )
        return self.results

    def export_json(self, output_path: str):
        """Exports ranked scan results to JSON."""
        data = [r.to_dict() for r in self.results]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def export_csv(self, output_path: str):
        """Exports ranked scan results to CSV."""
        if not self.results:
            return
        fields = [
            "domain",
            "score",
            "grade",
            "tags",
            "primary_ip",
            "is_tls13",
            "tls_version",
            "alpn",
            "latency_ms",
            "issuer",
            "dns_poisoned",
            "server_reachable",
            "error",
        ]
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in self.results:
                row = r.to_dict()
                row["tags"] = "; ".join(row.get("tags", []))
                writer.writerow({k: row.get(k) for k in fields})
