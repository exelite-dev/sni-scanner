"""
SNI Scanner Pro - TLS 1.3, ALPN & Deep X.509 Certificate Verifier
Performs strict TLS handshake, ALPN negotiation, CA trust validation, and SAN matching.
"""

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List


def check_san_match(target_domain: str, sans: List[str], common_name: Optional[str] = None) -> bool:
    """Verifies whether the target domain is covered by certificate SANs or Common Name."""
    target = target_domain.lower().strip()
    candidates = list(sans)
    if common_name:
        candidates.append(common_name)

    for cand in candidates:
        c = cand.lower().strip()
        if c == target:
            return True
        if c.startswith("*."):
            base = c[2:]
            parts_target = target.split(".")
            parts_base = base.split(".")
            if len(parts_target) == len(parts_base) + 1 and target.endswith("." + base):
                return True
    return False


class TLSCheckResult:
    def __init__(
        self,
        domain: str,
        ip: str,
        success: bool,
        tls_version: Optional[str] = None,
        alpn: Optional[str] = None,
        cipher_name: Optional[str] = None,
        cert_valid: bool = False,
        cert_trusted: bool = False,
        cert_issuer: Optional[str] = None,
        cert_subject_cn: Optional[str] = None,
        cert_san: Optional[List[str]] = None,
        cert_san_matched: bool = False,
        cert_expires_days: Optional[int] = None,
        cert_not_after: Optional[str] = None,
        tcp_latency_ms: float = 0.0,
        tls_latency_ms: float = 0.0,
        total_latency_ms: float = 0.0,
        error: Optional[str] = None,
    ):
        self.domain = domain
        self.ip = ip
        self.success = success
        self.tls_version = tls_version
        self.alpn = alpn
        self.cipher_name = cipher_name
        self.cert_valid = cert_valid
        self.cert_trusted = cert_trusted
        self.cert_issuer = cert_issuer
        self.cert_subject_cn = cert_subject_cn
        self.cert_san = cert_san or []
        self.cert_san_matched = cert_san_matched
        self.cert_expires_days = cert_expires_days
        self.cert_not_after = cert_not_after
        self.tcp_latency_ms = tcp_latency_ms
        self.tls_latency_ms = tls_latency_ms
        self.total_latency_ms = total_latency_ms
        self.error = error

    @property
    def is_tls13(self) -> bool:
        return self.tls_version == "TLSv1.3"

    @property
    def is_h2(self) -> bool:
        return self.alpn == "h2"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "success": self.success,
            "tls_version": self.tls_version,
            "is_tls13": self.is_tls13,
            "alpn": self.alpn,
            "is_h2": self.is_h2,
            "cipher_name": self.cipher_name,
            "cert_valid": self.cert_valid,
            "cert_trusted": self.cert_trusted,
            "cert_issuer": self.cert_issuer,
            "cert_subject_cn": self.cert_subject_cn,
            "cert_san": self.cert_san[:8],
            "cert_san_matched": self.cert_san_matched,
            "cert_expires_days": self.cert_expires_days,
            "cert_not_after": self.cert_not_after,
            "tcp_latency_ms": round(self.tcp_latency_ms, 2),
            "tls_latency_ms": round(self.tls_latency_ms, 2),
            "total_latency_ms": round(self.total_latency_ms, 2),
            "error": self.error,
        }


class TLSChecker:
    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout

    async def _measure_tcp(self, ip: str, port: int) -> float:
        """Measures raw TCP handshake latency."""
        loop = asyncio.get_running_loop()
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=self.timeout)
            latency = (time.perf_counter() - start) * 1000.0
            sock.close()
            return latency
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return 0.0

    async def check(self, domain: str, ip: str, port: int = 443) -> TLSCheckResult:
        """Performs full TLS 1.3 handshake, certificate health check, and latency profiling."""
        start_total = time.perf_counter()
        tcp_latency = await self._measure_tcp(ip, port)

        # 1. Try strict TLS handshake with CA validation & ALPN
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass

        cert_trusted = False
        cert_valid = False
        error_msg = None
        ssl_obj = None
        cert_dict = None

        tls_start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=domain),
                timeout=self.timeout,
            )
            tls_latency = (time.perf_counter() - tls_start) * 1000.0
            total_latency = (time.perf_counter() - start_total) * 1000.0

            ssl_obj = writer.get_extra_info("ssl_object")
            cert_dict = ssl_obj.getpeercert()
            cert_trusted = True
            cert_valid = True

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except ssl.SSLCertVerificationError as e:
            tls_latency = (time.perf_counter() - tls_start) * 1000.0
            total_latency = (time.perf_counter() - start_total) * 1000.0
            error_msg = f"CERT_UNTRUSTED: {e.verify_message or type(e).__name__}"
            cert_trusted = False

            # Diagnostic fallback with CERT_NONE to read attributes anyway
            try:
                diag_ctx = ssl.create_default_context()
                diag_ctx.check_hostname = False
                diag_ctx.verify_mode = ssl.CERT_NONE
                d_reader, d_writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=diag_ctx, server_hostname=domain),
                    timeout=2.0,
                )
                ssl_obj = d_writer.get_extra_info("ssl_object")
                d_writer.close()
                try:
                    await d_writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass

        except asyncio.TimeoutError:
            return TLSCheckResult(
                domain=domain,
                ip=ip,
                success=False,
                error="TLS_TIMEOUT",
                tcp_latency_ms=tcp_latency,
                total_latency_ms=(time.perf_counter() - start_total) * 1000.0,
            )
        except Exception as e:
            return TLSCheckResult(
                domain=domain,
                ip=ip,
                success=False,
                error=f"TLS_FAIL: {type(e).__name__}",
                tcp_latency_ms=tcp_latency,
                total_latency_ms=(time.perf_counter() - start_total) * 1000.0,
            )

        if not ssl_obj:
            return TLSCheckResult(
                domain=domain,
                ip=ip,
                success=False,
                error=error_msg or "HANDSHAKE_FAILED",
                tcp_latency_ms=tcp_latency,
                total_latency_ms=(time.perf_counter() - start_total) * 1000.0,
            )

        # Protocol & Cipher extraction
        tls_version = ssl_obj.version()
        alpn = ssl_obj.selected_alpn_protocol()
        cipher_tuple = ssl_obj.cipher()
        cipher_name = cipher_tuple[0] if cipher_tuple else None

        # Certificate details parsing
        cert_issuer = None
        cert_subject_cn = None
        cert_sans = []
        cert_expires_days = None
        cert_not_after = None
        cert_san_matched = False

        if cert_dict:
            # Issuer
            for rdn in cert_dict.get("issuer", ()):
                for k, v in rdn:
                    if k in ("organizationName", "commonName"):
                        cert_issuer = v
                        break
                if cert_issuer:
                    break

            # Subject CN
            for rdn in cert_dict.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        cert_subject_cn = v
                        break

            # SANs
            cert_sans = [v for t, v in cert_dict.get("subjectAltName", ()) if t == "DNS"]

            # Expiry calculation
            not_after_str = cert_dict.get("notAfter")
            if not_after_str:
                cert_not_after = not_after_str
                try:
                    exp_dt = datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (exp_dt - datetime.now(timezone.utc)).days
                    cert_expires_days = days_left
                    if days_left <= 0:
                        cert_valid = False
                        error_msg = "CERT_EXPIRED"
                except Exception:
                    pass

            # SAN matching
            cert_san_matched = check_san_match(domain, cert_sans, cert_subject_cn)
            if not cert_san_matched:
                cert_valid = False
                error_msg = f"SAN_MISMATCH: Cert covers {cert_sans[:3]} but requested {domain}"

        return TLSCheckResult(
            domain=domain,
            ip=ip,
            success=True,
            tls_version=tls_version,
            alpn=alpn,
            cipher_name=cipher_name,
            cert_valid=cert_valid,
            cert_trusted=cert_trusted,
            cert_issuer=cert_issuer,
            cert_subject_cn=cert_subject_cn,
            cert_san=cert_sans,
            cert_san_matched=cert_san_matched,
            cert_expires_days=cert_expires_days,
            cert_not_after=cert_not_after,
            tcp_latency_ms=tcp_latency,
            tls_latency_ms=tls_latency,
            total_latency_ms=total_latency,
            error=error_msg,
        )
