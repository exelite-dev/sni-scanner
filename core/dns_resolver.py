"""
Vortex SNI Hunter Pro - DNS Resolver & Poisoning Detector
Supports Local Async Resolution & Secure DoH (Cloudflare / Google)
"""

import asyncio
import socket
import time
from typing import List, Tuple, Dict, Any, Optional
import aiohttp

IRAN_BLOCKING_IPS = {
    "10.10.34.34",
    "10.10.34.35",
    "10.10.34.36",
    "10.10.34.37",
    "10.10.34.38",
    "10.10.34.39",
    "10.10.34.40",
    "10.10.34.41",
    "10.10.34.42",
    "10.10.34.43",
    "10.10.34.44",
    "10.10.34.45",
    "10.10.34.46",
    "10.10.34.47",
    "10.10.34.48",
    "10.10.34.49",
    "10.10.34.50",
    "127.0.0.1",
    "0.0.0.0",
}


class DNSResolutionResult:
    def __init__(
        self,
        domain: str,
        ips: List[str],
        latency_ms: float,
        is_poisoned: bool,
        poison_reason: Optional[str] = None,
        doh_ips: Optional[List[str]] = None,
    ):
        self.domain = domain
        self.ips = ips
        self.latency_ms = latency_ms
        self.is_poisoned = is_poisoned
        self.poison_reason = poison_reason
        self.doh_ips = doh_ips or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "ips": self.ips,
            "primary_ip": self.ips[0] if self.ips else None,
            "latency_ms": round(self.latency_ms, 2),
            "is_poisoned": self.is_poisoned,
            "poison_reason": self.poison_reason,
            "doh_ips": self.doh_ips,
        }


class DNSResolver:
    def __init__(self, timeout: float = 3.0, enable_doh_verification: bool = True):
        self.timeout = timeout
        self.enable_doh_verification = enable_doh_verification

    async def resolve_local(self, domain: str) -> Tuple[List[str], float]:
        """Resolves domain using local system DNS asynchronously."""
        loop = asyncio.get_running_loop()
        start = time.perf_counter()
        try:
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(
                    domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
                ),
                timeout=self.timeout,
            )
            latency = (time.perf_counter() - start) * 1000.0
            ips = list(dict.fromkeys([info[4][0] for info in addr_info]))
            return ips, latency
        except Exception:
            latency = (time.perf_counter() - start) * 1000.0
            return [], latency

    async def resolve_doh(self, domain: str) -> List[str]:
        """Resolves domain via Cloudflare / Google DoH to verify against tampering."""
        doh_urls = [
            f"https://1.1.1.1/dns-query?name={domain}&type=A",
            f"https://dns.google/resolve?name={domain}&type=A",
        ]
        headers = {"Accept": "application/dns-json"}
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for url in doh_urls:
                try:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            answers = data.get("Answer", [])
                            ips = [
                                ans.get("data")
                                for ans in answers
                                if ans.get("type") == 1
                            ]
                            if ips:
                                return ips
                except Exception:
                    continue
        return []

    async def check_domain(self, domain: str) -> DNSResolutionResult:
        """Performs full DNS check including poison detection."""
        local_ips, latency = await self.resolve_local(domain)

        # Check for empty resolution
        if not local_ips:
            return DNSResolutionResult(
                domain=domain,
                ips=[],
                latency_ms=latency,
                is_poisoned=True,
                poison_reason="NXDOMAIN_OR_TIMEOUT",
            )

        # Check for known Iranian filtering/spoofing IPs
        for ip in local_ips:
            if ip in IRAN_BLOCKING_IPS:
                return DNSResolutionResult(
                    domain=domain,
                    ips=local_ips,
                    latency_ms=latency,
                    is_poisoned=True,
                    poison_reason=f"REDIRECT_TO_BLOCK_IP_{ip}",
                )

        # Check against DoH if enabled
        doh_ips = []
        if self.enable_doh_verification:
            try:
                doh_ips = await self.resolve_doh(domain)
                if doh_ips:
                    # If DoH succeeded and completely differs from local resolution with no overlap
                    has_overlap = any(ip in doh_ips for ip in local_ips)
                    if not has_overlap and local_ips[0].startswith("10."):
                        return DNSResolutionResult(
                            domain=domain,
                            ips=local_ips,
                            latency_ms=latency,
                            is_poisoned=True,
                            poison_reason="DOH_MISMATCH_SUSPECTED_SPOOF",
                            doh_ips=doh_ips,
                        )
            except Exception:
                pass

        return DNSResolutionResult(
            domain=domain,
            ips=local_ips,
            latency_ms=latency,
            is_poisoned=False,
            poison_reason=None,
            doh_ips=doh_ips,
        )
