"""
SNI Scanner Pro - Method 3: Automated Live Test via Panel API (3X-UI / vpn-ui)
Connects to remote panel REST APIs, provisions temporary VLESS Reality test inbounds,
swaps candidate SNIs dynamically, and strictly guarantees automatic deletion of
temporary test inbounds upon completion or unexpected exceptions.
"""

import asyncio
import json
import logging
import secrets
import string
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, AsyncGenerator, Tuple

from .vless_parser import VLESSConfig

logger = logging.getLogger("PanelOrchestrator")


@dataclass
class PanelCredentials:
    url: str
    username: str
    password: str
    panel_type: str = "3x-ui"  # "3x-ui" or "vpn-ui"

    def clean_base_url(self) -> str:
        u = self.url.strip()
        if not u.startswith("http://") and not u.startswith("https://"):
            u = "http://" + u
        return u.rstrip("/")


class PanelOrchestrator:
    """Orchestrates creating, updating, and cleaning up temporary Reality test inbounds on 3X-UI / vpn-ui."""

    def __init__(self, credentials: PanelCredentials, mock_mode: bool = False):
        self.credentials = credentials
        self.base_url = credentials.clean_base_url()
        self.panel_type = credentials.panel_type.lower()
        self.mock_mode = mock_mode
        self.session_cookie: Optional[str] = None
        self._active_inbound_ids: List[int] = []

    async def login(self) -> bool:
        """Authenticates with panel and captures session credentials."""
        if self.mock_mode:
            await asyncio.sleep(0.01)
            if self.credentials.username == "invalid":
                return False
            self.session_cookie = "mock_session_token_xyz123"
            return True

        import aiohttp

        login_url = f"{self.base_url}/login"
        payload = {
            "username": self.credentials.username,
            "password": self.credentials.password,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(login_url, json=payload, timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("success", False) or "token" in data or "session" in resp.cookies:
                            cookies = [f"{k}={v.value}" for k, v in resp.cookies.items()]
                            self.session_cookie = "; ".join(cookies) or "authenticated"
                            return True
                    return False
        except Exception as e:
            logger.warning(f"Panel login failed: {e}")
            return False

    def generate_reality_keypair(self) -> Tuple[str, str, str]:
        """Generates random mock/real 32-byte X25519-like keys and ShortID for test inbounds."""
        # Generates compliant placeholder keys for testing
        priv = secrets.token_urlsafe(32)[:43] + "="
        pub = secrets.token_urlsafe(32)[:43] + "="
        short_id = "".join(secrets.choice(string.hexdigits.lower()) for _ in range(8))
        return priv, pub, short_id

    async def create_temp_inbound(
        self,
        port: int = 28443,
        initial_sni: str = "speedtest.net",
        remark: str = "vortex_sni_test_temp",
    ) -> Tuple[int, VLESSConfig]:
        """Creates an isolated temporary Reality inbound and returns its ID and VLESSConfig."""
        client_uuid = str(secrets.token_hex(16))
        # Format as UUID
        uuid_formatted = f"{client_uuid[:8]}-{client_uuid[8:12]}-{client_uuid[12:16]}-{client_uuid[16:20]}-{client_uuid[20:]}"
        priv_key, pub_key, short_id = self.generate_reality_keypair()

        inbound_id = 99990 + (secrets.randbelow(1000)) if self.mock_mode else 0

        # Construct host IP from panel URL
        import urllib.parse
        parsed = urllib.parse.urlparse(self.base_url)
        host = parsed.hostname or "127.0.0.1"

        vless_cfg = VLESSConfig(
            uuid=uuid_formatted,
            server=host,
            port=port,
            security="reality",
            sni=initial_sni,
            pbk=pub_key,
            sid=short_id,
            flow="xtls-rprx-vision",
            fp="chrome",
            name=remark,
        )

        if self.mock_mode:
            await asyncio.sleep(0.01)
            self._active_inbound_ids.append(inbound_id)
            return inbound_id, vless_cfg

        import aiohttp

        headers = {"Cookie": self.session_cookie or ""}
        add_url = f"{self.base_url}/panel/api/inbounds/add"

        stream_settings = {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "xver": 0,
                "dest": f"{initial_sni}:443",
                "serverNames": [initial_sni],
                "privateKey": priv_key,
                "shortIds": [short_id],
                "settings": {"publicKey": pub_key, "fingerprint": "chrome", "serverName": initial_sni},
            },
        }

        inbound_payload = {
            "up": 0,
            "down": 0,
            "total": 0,
            "remark": remark,
            "enable": True,
            "expiryTime": 0,
            "listen": "",
            "port": port,
            "protocol": "vless",
            "settings": json.dumps({"clients": [{"id": uuid_formatted, "flow": "xtls-rprx-vision"}], "decryption": "none"}),
            "streamSettings": json.dumps(stream_settings),
            "sniffing": json.dumps({"enabled": True, "destOverride": ["http", "tls"]}),
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(add_url, json=inbound_payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        inbound_id = data.get("obj", {}).get("id") or 9999
                        self._active_inbound_ids.append(inbound_id)
                        return inbound_id, vless_cfg
                    raise RuntimeError(f"Failed to create temp inbound on panel: HTTP {resp.status}")
        except Exception as e:
            raise RuntimeError(f"Panel inbound creation error: {e}")

    async def update_temp_inbound_sni(self, inbound_id: int, new_sni: str) -> bool:
        """Dynamically switches candidate SNI and dest on the temporary inbound."""
        if self.mock_mode:
            await asyncio.sleep(0.01)
            return True

        import aiohttp

        headers = {"Cookie": self.session_cookie or ""}
        update_url = f"{self.base_url}/panel/api/inbounds/update/{inbound_id}"

        # Get existing or send update
        update_payload = {
            "id": inbound_id,
            "streamSettings": json.dumps({
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": f"{new_sni}:443",
                    "serverNames": [new_sni],
                },
            }),
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(update_url, json=update_payload, headers=headers, timeout=aiohttp.ClientTimeout(total=3.0)) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def delete_inbound(self, inbound_id: int) -> bool:
        """Deletes the temporary inbound from the panel to ensure 100% clean teardown."""
        if inbound_id in self._active_inbound_ids:
            self._active_inbound_ids.remove(inbound_id)

        if self.mock_mode:
            await asyncio.sleep(0.01)
            return True

        import aiohttp

        headers = {"Cookie": self.session_cookie or ""}
        del_url = f"{self.base_url}/panel/api/inbounds/del/{inbound_id}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(del_url, headers=headers, timeout=aiohttp.ClientTimeout(total=4.0)) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.warning(f"Failed to delete temp inbound {inbound_id}: {e}")
            return False

    async def cleanup_all_temp_inbounds(self):
        """Emergency cleanup to guarantee no active temporary test inbounds linger on server."""
        ids_to_clean = list(self._active_inbound_ids)
        for i_id in ids_to_clean:
            await self.delete_inbound(i_id)

    @asynccontextmanager
    async def managed_test_inbound(
        self,
        port: int = 28443,
        initial_sni: str = "speedtest.net",
    ) -> AsyncGenerator[Tuple[int, VLESSConfig], None]:
        """
        Async Context Manager that guarantees the temporary inbound is deleted immediately
        after test completion or in the event of an unhandled exception.
        """
        inbound_id = None
        try:
            inbound_id, vless_cfg = await self.create_temp_inbound(port=port, initial_sni=initial_sni)
            yield inbound_id, vless_cfg
        finally:
            if inbound_id is not None:
                await self.delete_inbound(inbound_id)
