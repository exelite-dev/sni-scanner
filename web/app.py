"""
SNI Scanner Pro - FastAPI Web Application
Provides REST API, Server-Sent Events (SSE), GeoIP Auto-Detection, Tranco 1M support,
and 3 Selectable Validation Methods:
Method 1: Standard Passwordless SNI Scan (Fast TLS 1.3 + ALPN + Ping)
Method 2: Live Reality Tunnel Test with User VLESS Client Config (Jitter, Speed, Ping)
Method 3: Automated Live Test via Panel API (3X-UI / vpn-ui with guaranteed cleanup)
"""

import asyncio
import json
import os
from typing import List, Optional, Union
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from core.scanner import SNIScanner, ScanProgress
from core.scorer import ScoredSNI
from core.sources import DomainSourceManager, ONLINE_REPOSITORIES
from core.geo_matcher import ServerGeoMatcher
from core.vless_parser import VLESSConfig, VLESSParser
from core.tunnel_benchmarker import TunnelMetrics
from core.panel_orchestrator import PanelCredentials

app = FastAPI(title="SNI Scanner Pro", version="2.3.0")

BASE_DIR = os.path.dirname(__file__)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

ACTIVE_SCANNER: Optional[SNIScanner] = None
LATEST_RESULTS: List[dict] = []
IS_SCANNING = False


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    template_path = os.path.join(BASE_DIR, "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/categories")
async def get_categories():
    cats = DomainSourceManager.get_local_categories()
    categories_list = [
        {
            "id": k,
            "title": v.get("title", k),
            "description": v.get("description", ""),
            "count": v.get("count") or len(v.get("domains", [])),
            "is_online": False,
        }
        for k, v in cats.items()
    ]

    for k, v in ONLINE_REPOSITORIES.items():
        categories_list.append(
            {
                "id": f"online_{k}",
                "title": f"🌐 {v['title']}",
                "description": v["description"],
                "count": 500,
                "is_online": True,
            }
        )

    return {"categories": categories_list}


@app.get("/api/server/detect")
async def detect_server_endpoint(ip: str):
    return await ServerGeoMatcher.detect_server(ip)


@app.post("/api/scan/stop")
async def stop_scan():
    global ACTIVE_SCANNER, IS_SCANNING
    if ACTIVE_SCANNER:
        ACTIVE_SCANNER.cancel()
    IS_SCANNING = False
    return {"status": "stopped"}


@app.get("/api/scan/stream")
async def stream_scan(
    method: str = "standard",
    category: str = "auto",
    custom_domains: Optional[str] = None,
    custom_url: Optional[str] = None,
    limit: Optional[int] = 100,
    sort_by: str = "latency",
    server_ip: Optional[str] = "48.102.164.241",
    server_port: int = 7,
    concurrency: int = 20,
    timeout: float = 3.5,
    # Method 2 params
    vless_uri: Optional[str] = None,
    core_path: Optional[str] = None,
    # Method 3 params
    panel_url: Optional[str] = None,
    panel_user: Optional[str] = None,
    panel_pass: Optional[str] = None,
    panel_type: str = "3x-ui",
    mock_mode: bool = False,
):
    global ACTIVE_SCANNER, LATEST_RESULTS, IS_SCANNING

    # Auto-match category based on Server GeoIP if category is 'auto'
    if category == "auto" and server_ip and method == "standard":
        geo = await ServerGeoMatcher.detect_server(server_ip)
        category = geo.get("recommended_category", "mega_all")

    # Resolve domains from pool / Tranco zip / online
    domains = await DomainSourceManager.resolve_domain_pool(
        category=category,
        custom_domains=custom_domains,
        custom_url=custom_url,
        limit=limit if (limit and limit > 0) else None,
    )

    if not domains:
        domains = ["speedtest.net", "hetzner.com", "gateway.icloud.com", "cloudflare.com"]

    # Parse Method 2 / 3 configurations
    parsed_vless = None
    if vless_uri:
        try:
            parsed_vless = VLESSParser.parse(vless_uri)
        except Exception:
            pass

    panel_creds = None
    if panel_url and panel_user and panel_pass:
        panel_creds = PanelCredentials(
            url=panel_url,
            username=panel_user,
            password=panel_pass,
            panel_type=panel_type,
        )

    ACTIVE_SCANNER = SNIScanner(
        concurrency=concurrency,
        timeout=timeout,
        enable_doh=True,
        target_server_ip=server_ip if server_ip else None,
        target_server_port=server_port,
        scan_method=method,
        vless_config=parsed_vless or vless_uri,
        panel_credentials=panel_creds,
        core_path=core_path,
        mock_mode=mock_mode,
    )
    LATEST_RESULTS = []
    IS_SCANNING = True

    async def event_generator():
        global IS_SCANNING
        event_queue = asyncio.Queue()

        def on_progress(prog: ScanProgress, item: Union[ScoredSNI, TunnelMetrics]):
            item_dict = item.to_dict()
            item_dict["method"] = method
            item_dict["panel_config"] = {
                "target": f"{item_dict['domain']}:443",
                "sni": item_dict["domain"],
                "alpn": item_dict.get("alpn") or "h2",
                "fingerprint": "chrome",
            }
            data = {
                "type": "result",
                "progress": prog.to_dict(),
                "item": item_dict,
            }
            LATEST_RESULTS.append(item_dict)
            event_queue.put_nowait(data)

        scan_task = asyncio.create_task(
            ACTIVE_SCANNER.scan_domains(domains, on_progress=on_progress, sort_by=sort_by)
        )

        while not scan_task.done() or not event_queue.empty():
            try:
                data = await asyncio.wait_for(event_queue.get(), timeout=0.2)
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            except asyncio.TimeoutError:
                yield f": keepalive\n\n"

        IS_SCANNING = False

        def _sort_key(x):
            is_healthy = bool(x.get("success", False) or (x.get("is_tls13") and not x.get("dns_poisoned")))
            lat = x.get("latency_ms") or 999999
            return (0 if is_healthy else 1, lat, -x.get("score", 0))

        if sort_by == "score":
            sorted_results = sorted(
                LATEST_RESULTS, key=lambda x: (-x.get("score", 0), x.get("latency_ms") or 999999)
            )
        else:
            sorted_results = sorted(LATEST_RESULTS, key=_sort_key)

        final_payload = {
            "type": "finished",
            "method": method,
            "total_scanned": len(LATEST_RESULTS),
            "top_sni": sorted_results[0] if sorted_results else None,
            "results": sorted_results,
        }
        yield f"data: {json.dumps(final_payload, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/results")
async def get_results(sort_by: str = "latency"):
    global LATEST_RESULTS

    def _sort_key(x):
        is_healthy = bool(x.get("success", False) or (x.get("is_tls13") and not x.get("dns_poisoned")))
        lat = x.get("latency_ms") or 999999
        return (0 if is_healthy else 1, lat, -x.get("score", 0))

    if sort_by == "score":
        sorted_results = sorted(
            LATEST_RESULTS, key=lambda x: (-x.get("score", 0), x.get("latency_ms") or 999999)
        )
    else:
        sorted_results = sorted(LATEST_RESULTS, key=_sort_key)

    return {"count": len(sorted_results), "results": sorted_results}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.app:app", host="127.0.0.1", port=8787, reload=False)
