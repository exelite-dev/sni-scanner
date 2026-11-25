"""
SNI Scanner Pro - VLESS Reality URI Parser and Client Config Generator
Supports standard VLESS Reality URIs (vless://uuid@server:port?params#name)
and generates compliant Xray client configurations for local tunnel testing.
"""

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


@dataclass
class VLESSConfig:
    uuid: str
    server: str
    port: int
    security: str = "reality"
    sni: str = ""
    pbk: str = ""  # Reality Public Key
    sid: str = ""  # Reality Short ID
    flow: Optional[str] = "xtls-rprx-vision"
    fp: str = "chrome"  # Fingerprint
    spx: str = ""  # SpiderX
    type: str = "tcp"  # Network type
    header_type: str = "none"
    name: str = "VLESS-Reality"
    raw_params: Dict[str, str] = field(default_factory=dict)

    def is_reality(self) -> bool:
        return self.security.lower() == "reality" and bool(self.pbk)

    def to_uri(self, override_sni: Optional[str] = None) -> str:
        """Reconstructs the VLESS URI, optionally overriding the SNI."""
        sni_to_use = override_sni if override_sni is not None else self.sni
        params = dict(self.raw_params)
        params["security"] = self.security
        params["sni"] = sni_to_use
        params["type"] = self.type
        if self.pbk:
            params["pbk"] = self.pbk
        if self.sid:
            params["sid"] = self.sid
        if self.flow:
            params["flow"] = self.flow
        if self.fp:
            params["fp"] = self.fp
        if self.spx:
            params["spx"] = self.spx

        query_str = urllib.parse.urlencode(params)
        name_part = f"#{urllib.parse.quote(self.name)}" if self.name else ""
        return f"vless://{self.uuid}@{self.server}:{self.port}?{query_str}{name_part}"

    def to_xray_client_config(
        self,
        override_sni: Optional[str] = None,
        local_socks_port: int = 10808,
        local_http_port: int = 10809,
    ) -> Dict[str, Any]:
        """
        Generates a complete, valid Xray-core client config JSON dictionary
        for local tunnel testing on local loopback ports.
        """
        sni_to_use = override_sni if override_sni is not None else self.sni
        reality_settings: Dict[str, Any] = {
            "show": False,
            "fingerprint": self.fp or "chrome",
            "serverName": sni_to_use,
            "publicKey": self.pbk,
            "shortId": self.sid or "",
            "spiderX": self.spx or "",
        }

        user_obj: Dict[str, Any] = {
            "id": self.uuid,
            "encryption": "none",
        }
        if self.flow:
            user_obj["flow"] = self.flow

        stream_settings: Dict[str, Any] = {
            "network": self.type or "tcp",
            "security": self.security or "reality",
            "realitySettings": reality_settings,
        }

        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "tag": "socks-in",
                    "port": local_socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                },
                {
                    "tag": "http-in",
                    "port": local_http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {"allowTransparent": False},
                },
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": self.server,
                                "port": self.port,
                                "users": [user_obj],
                            }
                        ]
                    },
                    "streamSettings": stream_settings,
                },
                {"tag": "direct", "protocol": "freedom"},
            ],
        }


class VLESSParser:
    @staticmethod
    def parse(uri: str) -> VLESSConfig:
        """
        Parses a vless:// URI string into a strongly-typed VLESSConfig dataclass.
        Raises ValueError if the URI is malformed or missing critical components.
        """
        if not uri or not isinstance(uri, str):
            raise ValueError("VLESS URI must be a non-empty string.")

        clean_uri = uri.strip()
        if not clean_uri.startswith("vless://"):
            raise ValueError("Invalid URI protocol: Expected 'vless://'.")

        without_proto = clean_uri[len("vless://") :]

        # Extract remark name if present after '#'
        name = "VLESS-Reality"
        if "#" in without_proto:
            without_proto, raw_name = without_proto.split("#", 1)
            name = urllib.parse.unquote(raw_name.strip())

        # Split user info and server/query
        if "@" not in without_proto:
            raise ValueError("Malformed VLESS URI: missing '@' separator for UUID.")

        uuid, rest = without_proto.split("@", 1)
        uuid = uuid.strip()
        if not uuid:
            raise ValueError("Malformed VLESS URI: UUID is empty.")

        # Split host:port and query parameters
        if "?" in rest:
            host_port, query_str = rest.split("?", 1)
        else:
            host_port, query_str = rest, ""

        if ":" not in host_port:
            raise ValueError(f"Malformed VLESS URI: Missing port in '{host_port}'.")

        server, raw_port = host_port.rsplit(":", 1)
        server = server.strip()
        if not server:
            raise ValueError("Malformed VLESS URI: Server host is empty.")

        try:
            port = int(raw_port.strip())
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            raise ValueError(f"Invalid VLESS port: '{raw_port}'. Must be between 1 and 65535.")

        # Parse query params
        params: Dict[str, str] = {}
        if query_str:
            parsed_query = urllib.parse.parse_qs(query_str, keep_blank_values=True)
            for k, v in parsed_query.items():
                params[k.lower()] = v[0] if v else ""

        security = params.get("security", "reality").lower()
        sni = params.get("sni", "").strip()
        pbk = params.get("pbk", "").strip()
        sid = params.get("sid", "").strip()
        flow = params.get("flow", "").strip() or None
        fp = params.get("fp", "chrome").strip()
        spx = params.get("spx", "").strip()
        net_type = params.get("type", "tcp").strip().lower()
        header_type = params.get("header_type", "none").strip()

        return VLESSConfig(
            uuid=uuid,
            server=server,
            port=port,
            security=security,
            sni=sni,
            pbk=pbk,
            sid=sid,
            flow=flow,
            fp=fp,
            spx=spx,
            type=net_type,
            header_type=header_type,
            name=name,
            raw_params=params,
        )
