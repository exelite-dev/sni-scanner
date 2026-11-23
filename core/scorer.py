"""
SNI Scanner Pro - Quality Scorer & Recommendation Engine
Calculates a 0-100 Reality Compatibility Score and assigns Quality Grades based on
DNS, TLS 1.3, ALPN, Certificate Health (Validity, Trust, SAN match, Expiry), and Latency.
"""

from typing import Dict, Any, List
from .dns_resolver import DNSResolutionResult
from .tls_checker import TLSCheckResult
from .reality_matcher import RealityMatchResult


class ScoredSNI:
    def __init__(
        self,
        domain: str,
        score: int,
        grade: str,
        tags: List[str],
        dns_res: DNSResolutionResult,
        tls_res: TLSCheckResult,
        reality_res: RealityMatchResult,
    ):
        self.domain = domain
        self.score = score
        self.grade = grade
        self.tags = tags
        self.dns = dns_res
        self.tls = tls_res
        self.reality = reality_res

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "tags": self.tags,
            "primary_ip": self.dns.ips[0] if self.dns.ips else None,
            "is_tls13": self.tls.is_tls13,
            "tls_version": self.tls.tls_version,
            "alpn": self.tls.alpn,
            "cipher": self.tls.cipher_name,
            "cert_valid": self.tls.cert_valid,
            "cert_trusted": self.tls.cert_trusted,
            "cert_san_matched": self.tls.cert_san_matched,
            "issuer": self.tls.cert_issuer,
            "cert_subject_cn": self.tls.cert_subject_cn,
            "cert_expires_days": self.tls.cert_expires_days,
            "cert_not_after": self.tls.cert_not_after,
            "latency_ms": round(self.tls.total_latency_ms, 2) if self.tls.success else None,
            "tcp_latency_ms": round(self.tls.tcp_latency_ms, 2) if self.tls.success else None,
            "dns_poisoned": self.dns.is_poisoned,
            "server_reachable": self.reality.server_reachable,
            "error": self.tls.error or self.dns.poison_reason,
        }


class SNIScorer:
    @staticmethod
    def calculate(
        dns_res: DNSResolutionResult,
        tls_res: TLSCheckResult,
        reality_res: RealityMatchResult,
    ) -> ScoredSNI:
        domain = dns_res.domain
        score = 0
        tags = []

        # Instant disqualifier 1: Poisoned DNS
        if dns_res.is_poisoned:
            return ScoredSNI(
                domain,
                0,
                "F",
                ["DNS_POISONED"],
                dns_res,
                tls_res,
                reality_res,
            )

        # Instant disqualifier 2: TLS failure
        if not tls_res.success:
            return ScoredSNI(
                domain,
                0,
                "F",
                ["TLS_FAILED", tls_res.error or "UNKNOWN_ERROR"],
                dns_res,
                tls_res,
                reality_res,
            )

        # Instant disqualifier 3: Expired Certificate
        if tls_res.cert_expires_days is not None and tls_res.cert_expires_days <= 0:
            return ScoredSNI(
                domain,
                0,
                "F",
                ["CERT_EXPIRED", f"Expired on {tls_res.cert_not_after}"],
                dns_res,
                tls_res,
                reality_res,
            )

        # 1. TLS 1.3 Strict Check (Mandatory for modern VLESS Reality)
        if tls_res.is_tls13:
            score += 30
            tags.append("TLS_1.3")
        else:
            tags.append(f"TLS_{tls_res.tls_version}")

        # 2. ALPN HTTP/2 Check
        if tls_res.is_h2:
            score += 20
            tags.append("HTTP/2")
        elif tls_res.alpn == "http/1.1":
            score += 10
            tags.append("HTTP/1.1")
        else:
            tags.append("NO_ALPN")

        # 3. Clean DNS & Resolution speed
        if not dns_res.is_poisoned and dns_res.ips:
            score += 10
            tags.append("CLEAN_DNS")

        # 4. Latency Scoring (Lower is better)
        lat = tls_res.total_latency_ms
        if lat > 0:
            if lat < 120:
                score += 20
                tags.append("ULTRA_LOW_PING")
            elif lat < 220:
                score += 15
                tags.append("LOW_PING")
            elif lat < 380:
                score += 8
                tags.append("MODERATE_PING")
            else:
                score += 3
                tags.append("HIGH_PING")

        # 5. Certificate Health & Trust Validation
        if tls_res.cert_trusted:
            score += 10
            tags.append("CA_TRUSTED")
        elif tls_res.cert_trusted is False:
            score -= 25
            tags.append("CERT_UNTRUSTED")

        if tls_res.cert_san_matched:
            score += 5
            tags.append("SAN_MATCHED")
        elif tls_res.cert_san and not tls_res.cert_san_matched:
            score -= 30
            tags.append("SAN_MISMATCH")

        if tls_res.cert_expires_days is not None:
            if tls_res.cert_expires_days > 30:
                tags.append(f"EXP_{tls_res.cert_expires_days}D")
            elif tls_res.cert_expires_days > 0:
                score -= 10
                tags.append(f"EXPIRING_SOON_{tls_res.cert_expires_days}D")

        # 6. Destination & Server Reachability
        if reality_res.compatible:
            score += 5
            tags.append("CLEAN_DEST")

        if reality_res.server_reachable is True:
            score += 5
            tags.append("SERVER_VERIFIED")
        elif reality_res.server_reachable is False:
            tags.append("SERVER_PORT_UNREACHABLE")

        score = max(0, min(100, score))

        # Assign Grade
        if score >= 90:
            grade = "S+"
        elif score >= 80:
            grade = "A"
        elif score >= 65:
            grade = "B"
        elif score >= 50:
            grade = "C"
        else:
            grade = "F"

        return ScoredSNI(
            domain=domain,
            score=score,
            grade=grade,
            tags=tags,
            dns_res=dns_res,
            tls_res=tls_res,
            reality_res=reality_res,
        )
