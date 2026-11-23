"""
SNI Scanner Pro - Reality Protocol Matcher & Server Prober
Validates destination website behavior and tests reachability to target server IP.
"""

import asyncio
import socket
import ssl
import time
from typing import Dict, Any, Optional


class RealityMatchResult:
    def __init__(
        self,
        domain: str,
        http_status: Optional[int] = None,
        is_redirect: bool = False,
        redirect_location: Optional[str] = None,
        server_reachable: Optional[bool] = None,
        server_latency_ms: Optional[float] = None,
        compatible: bool = False,
        details: Optional[str] = None,
    ):
        self.domain = domain
        self.http_status = http_status
        self.is_redirect = is_redirect
        self.redirect_location = redirect_location
        self.server_reachable = server_reachable
        self.server_latency_ms = server_latency_ms
        self.compatible = compatible
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "http_status": self.http_status,
            "is_redirect": self.is_redirect,
            "redirect_location": self.redirect_location,
            "server_reachable": self.server_reachable,
            "server_latency_ms": round(self.server_latency_ms, 2)
            if self.server_latency_ms is not None
            else None,
            "compatible": self.compatible,
            "details": self.details,
        }


class RealityMatcher:
    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    async def probe_destination_http(self, domain: str, ip: str) -> Dict[str, Any]:
        """Probes the target website with a lightweight TLS HTTP HEAD/GET request."""
        loop = asyncio.get_running_loop()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=domain),
                timeout=self.timeout,
            )

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode("utf-8"))
            await writer.drain()

            response_bytes = await asyncio.wait_for(
                reader.read(1024), timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            response_text = response_bytes.decode("latin1", errors="replace")
            status_code = None
            location = None

            lines = response_text.split("\r\n")
            if lines and lines[0].startswith("HTTP/"):
                parts = lines[0].split(" ")
                if len(parts) >= 2 and parts[1].isdigit():
                    status_code = int(parts[1])

            for line in lines[1:]:
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
                    break

            is_redirect = status_code in (301, 302, 307, 308)
            return {
                "success": True,
                "status_code": status_code,
                "is_redirect": is_redirect,
                "location": location,
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)[:60],
            }

    async def probe_server_with_sni(
        self, server_ip: str, server_port: int, domain: str
    ) -> Dict[str, Any]:
        """Tests connecting to user's server port with this specific SNI in ClientHello."""
        start = time.perf_counter()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    server_ip, server_port, ssl=ctx, server_hostname=domain
                ),
                timeout=self.timeout,
            )
            latency = (time.perf_counter() - start) * 1000.0
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"reachable": True, "latency_ms": latency}
        except ssl.SSLError:
            # An SSL Error (e.g. handshake rejection or unknown cert) means TCP succeeded and server responded!
            latency = (time.perf_counter() - start) * 1000.0
            return {"reachable": True, "latency_ms": latency}
        except (asyncio.TimeoutError, ConnectionResetError, ConnectionRefusedError) as e:
            return {"reachable": False, "error": type(e).__name__}
        except Exception as e:
            return {"reachable": False, "error": str(e)[:40]}

    async def evaluate(
        self,
        domain: str,
        target_ip: str,
        user_server_ip: Optional[str] = None,
        user_server_port: Optional[int] = 7,
    ) -> RealityMatchResult:
        """Complete evaluation of destination suitability and optionally server handshake."""
        # 1. Probe destination
        dest_probe = await self.probe_destination_http(domain, target_ip)

        http_status = dest_probe.get("status_code")
        is_redirect = dest_probe.get("is_redirect", False)
        location = dest_probe.get("location")

        # 2. Probe user server if IP provided
        server_reachable = None
        server_latency = None

        if user_server_ip:
            srv_probe = await self.probe_server_with_sni(
                user_server_ip, user_server_port or 7, domain
            )
            server_reachable = srv_probe.get("reachable", False)
            server_latency = srv_probe.get("latency_ms")

        # Compatibility logic
        compatible = True
        details = []

        if not dest_probe.get("success"):
            compatible = False
            details.append("Dest HTTP probe failed")
        elif is_redirect and location and ("blocked" in location or "10.10." in location):
            compatible = False
            details.append("Redirects to blocked target")
        else:
            details.append(f"HTTP Status: {http_status}")

        if server_reachable is not None:
            if not server_reachable:
                details.append("Server handshake filtered")
            else:
                details.append(f"Server Reachable ({round(server_latency, 1)}ms)")

        return RealityMatchResult(
            domain=domain,
            http_status=http_status,
            is_redirect=is_redirect,
            redirect_location=location,
            server_reachable=server_reachable,
            server_latency_ms=server_latency,
            compatible=compatible,
            details=" | ".join(details),
        )
