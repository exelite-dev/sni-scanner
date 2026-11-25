"""
SNI Scanner Pro - Elite CLI Interface
High-speed terminal SNI scanner supporting 3 Selectable Validation Methods:
Method 1: Standard Passwordless SNI Scan (Fast TLS 1.3 + ALPN + Ping)
Method 2: Live Reality Tunnel Test with User VLESS Client Config (Jitter, Speed, Ping)
Method 3: Automated Live Test via Panel API (3X-UI / vpn-ui with guaranteed cleanup)
"""

import argparse
import asyncio
import json
import os
import sys
from typing import List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Import core modules
from core.scanner import SNIScanner, ScanProgress
from core.scorer import ScoredSNI
from core.sources import DomainSourceManager
from core.vless_parser import VLESSConfig, VLESSParser
from core.tunnel_benchmarker import TunnelMetrics
from core.panel_orchestrator import PanelCredentials

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def format_grade(grade: str) -> str:
    if not HAS_RICH:
        return f"[{grade}]"
    colors = {
        "S+": "[bold green]S+[/bold green]",
        "A": "[cyan]A[/cyan]",
        "B": "[blue]B[/blue]",
        "C": "[yellow]C[/yellow]",
        "F": "[red]F[/red]",
    }
    return colors.get(grade, grade)


async def run_cli(args):
    console = Console(legacy_windows=False, highlight=False) if HAS_RICH else None

    # Normalize method
    method_map = {
        "1": "standard",
        "standard": "standard",
        "2": "vless_client",
        "vless": "vless_client",
        "vless_client": "vless_client",
        "3": "panel_api",
        "panel": "panel_api",
        "panel_api": "panel_api",
    }
    selected_method = method_map.get(str(args.method).lower(), "standard")

    # 1. Determine domains from unified source manager
    domains = await DomainSourceManager.resolve_domain_pool(
        category=args.category,
        custom_domains=args.domains,
        custom_url=args.url,
        file_path=args.file,
        limit=args.limit if (args.limit and args.limit > 0) else None,
    )

    if not domains:
        print(f"Error: No domains found to scan. Category '{args.category}' empty or source unreachable.")
        sys.exit(1)

    # Validate method-specific prerequisites
    parsed_vless = None
    if selected_method == "vless_client":
        if not args.vless:
            print("Error: Method 2 (vless_client) requires --vless 'vless://uuid@host:port?...' or file path.")
            sys.exit(1)
        vless_str = args.vless
        if os.path.isfile(vless_str):
            with open(vless_str, "r", encoding="utf-8") as vf:
                vless_str = vf.read().strip()
        try:
            parsed_vless = VLESSParser.parse(vless_str)
        except Exception as e:
            print(f"Error parsing VLESS URI: {e}")
            sys.exit(1)

    panel_creds = None
    if selected_method == "panel_api":
        if not (args.panel_url and args.panel_user and args.panel_pass):
            print("Error: Method 3 (panel_api) requires --panel-url, --panel-user, and --panel-pass.")
            sys.exit(1)
        panel_creds = PanelCredentials(
            url=args.panel_url,
            username=args.panel_user,
            password=args.panel_pass,
            panel_type=args.panel_type or "3x-ui",
        )

    # Header Panel
    method_titles = {
        "standard": "Method 1: Standard Passwordless SNI Scan",
        "vless_client": "Method 2: Live VLESS Client Reality Tunnel Benchmark",
        "panel_api": "Method 3: Automated Panel API Live Benchmark",
    }

    if HAS_RICH:
        banner = f"""[bold cyan]S N I   S C A N N E R   P R O[/bold cyan]
[dim]{method_titles[selected_method]}[/dim]
[yellow]Target Server:[/yellow] [bold white]{args.target_server or (parsed_vless.server if parsed_vless else 'Auto')}[/bold white] | [yellow]Source Pool:[/yellow] [bold white]{len(domains)} domains[/bold white] | [yellow]Sort By:[/yellow] [bold green]{args.sort_by}[/bold green] | [yellow]Concurrency:[/yellow] [bold white]{args.concurrency}[/bold white]"""
        console.print(Panel(banner, border_style="cyan"))
    else:
        print(f"=== SNI SCANNER PRO ({method_titles[selected_method]}) ===")
        print(f"Target Server: {args.target_server} | Domains: {len(domains)} | Sort: {args.sort_by}")

    scanner = SNIScanner(
        concurrency=args.concurrency,
        timeout=args.timeout,
        enable_doh=not args.disable_doh,
        target_server_ip=args.target_server,
        target_server_port=args.target_port,
        scan_method=selected_method,
        vless_config=parsed_vless,
        panel_credentials=panel_creds,
        core_path=args.core_path,
        mock_mode=args.mock_mode,
    )

    if HAS_RICH:
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("[cyan]Benchmarking SNIs...", total=len(domains))

            def on_progress(p: ScanProgress, item):
                score = item.score
                if score >= 80:
                    status_text = f"[bold green]{item.domain}[/bold green]"
                elif score >= 50:
                    status_text = f"[yellow]{item.domain}[/yellow]"
                else:
                    status_text = f"[red]{item.domain}[/red]"

                prog.update(task, completed=p.completed, description=f"Scanning: {status_text}")

            results = await scanner.scan_domains(domains, on_progress=on_progress, sort_by=args.sort_by)
    else:
        results = await scanner.scan_domains(domains, sort_by=args.sort_by)

    # Format Results Table
    if HAS_RICH:
        table = Table(title=f"Top Reality SNI Candidates ({method_titles[selected_method]})", border_style="blue", header_style="bold cyan")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Domain / SNI", justify="left", style="bold white", no_wrap=True)

        if selected_method in ["vless_client", "panel_api"]:
            table.add_column("Ping (RTT)", justify="center", no_wrap=True)
            table.add_column("Jitter", justify="center", no_wrap=True)
            table.add_column("Download", justify="center", no_wrap=True)
            table.add_column("Score", justify="center", no_wrap=True)
            table.add_column("Grade", justify="center", no_wrap=True)
            table.add_column("Tunnel Status", justify="center", no_wrap=True)

            for idx, r in enumerate(results[: args.top_limit], 1):
                score_color = "bold green" if r.score >= 80 else "yellow" if r.score >= 50 else "red"
                lat_str = f"[bold green]{round(r.latency_ms)} ms[/bold green]" if r.latency_ms else "[red]Fail[/red]"
                jitter_str = f"[cyan]{round(r.jitter_ms)} ms[/cyan]" if r.jitter_ms else "--"
                dl_str = f"[bold white]{round(r.download_mbps, 1)} Mbps[/bold white]" if r.download_mbps else "--"
                status_str = "[bold green]TUNNEL OK[/bold green]" if r.success else f"[red]{(r.error or 'Failed')[:20]}[/red]"

                table.add_row(
                    str(idx),
                    r.domain,
                    lat_str,
                    jitter_str,
                    dl_str,
                    f"[{score_color}]{r.score}/100[/{score_color}]",
                    format_grade(r.grade),
                    status_str,
                )
        else:
            table.add_column("Ping (ms)", justify="center", no_wrap=True)
            table.add_column("Cert Health", justify="center", no_wrap=True)
            table.add_column("Score", justify="center", no_wrap=True)
            table.add_column("Grade", justify="center", no_wrap=True)
            table.add_column("TLS", justify="center", no_wrap=True)
            table.add_column("ALPN", justify="center", no_wrap=True)
            table.add_column("Clean IP", justify="left", no_wrap=True)
            table.add_column("Reality", justify="center", no_wrap=True)

            for idx, r in enumerate(results[: args.top_limit], 1):
                score_color = "bold green" if r.score >= 80 else "yellow" if r.score >= 50 else "red"
                tls_str = "[green]1.3[/green]" if r.tls.is_tls13 else f"[yellow]{r.tls.tls_version or 'Fail'}[/yellow]"
                alpn_str = "[cyan]h2[/cyan]" if r.tls.is_h2 else f"[dim]{r.tls.alpn or 'None'}[/dim]"

                if r.tls.success and r.tls.total_latency_ms:
                    ms = round(r.tls.total_latency_ms)
                    p_color = "bold green" if ms < 150 else "cyan" if ms < 300 else "yellow"
                    lat_str = f"[{p_color}]{ms} ms[/{p_color}]"
                else:
                    lat_str = "[red]Timeout[/red]"

                if r.tls.cert_valid and r.tls.cert_trusted:
                    iss = (r.tls.cert_issuer or "CA")[:12]
                    days = f"{r.tls.cert_expires_days}d" if r.tls.cert_expires_days is not None else "OK"
                    cert_str = f"[green]PASS[/green] [dim]({iss}, {days})[/dim]"
                elif r.tls.cert_expires_days is not None and r.tls.cert_expires_days <= 0:
                    cert_str = "[bold red]EXPIRED[/bold red]"
                elif not r.tls.cert_trusted:
                    cert_str = "[yellow]UNTRUSTED[/yellow]"
                else:
                    cert_str = "[dim]None[/dim]"

                ip_str = r.dns.ips[0] if r.dns.ips else "None"
                reality_status = "[bold green]PASS[/bold green]" if r.score >= 65 and r.tls.is_tls13 and r.tls.cert_valid else "[red]FAIL[/red]"

                table.add_row(
                    str(idx),
                    r.domain,
                    lat_str,
                    cert_str,
                    f"[{score_color}]{r.score}/100[/{score_color}]",
                    format_grade(r.grade),
                    tls_str,
                    alpn_str,
                    ip_str,
                    reality_status,
                )

        console.print("\n")
        console.print(table)
    else:
        print("\n--- SCAN RESULTS SUMMARY ---")
        for idx, r in enumerate(results[: args.top_limit], 1):
            score_val = r.score
            print(f"{idx}. {r.domain:25} | Score: {score_val:3}/100 | Grade: {r.grade}")

    # Exports
    if args.export_json:
        scanner.export_json(args.export_json)
        print(f"\n[+] Exported results to JSON: {args.export_json}")
    if args.export_csv:
        scanner.export_csv(args.export_csv)
        print(f"[+] Exported results to CSV: {args.export_csv}")


def main():
    parser = argparse.ArgumentParser(description="SNI Scanner Pro - High-Speed Reality SNI Scanner (3 Methods)")
    parser.add_argument("--method", "-m", default="standard", choices=["1", "2", "3", "standard", "vless_client", "panel_api"], help="Scan Method: standard (1), vless_client (2), panel_api (3)")
    parser.add_argument("--category", "-c", default="mega_all", help="Category: mega_all, german_european_mega, global_cdns_mega, etc.")
    parser.add_argument("--domains", "-d", type=str, help="Comma-separated custom domain list")
    parser.add_argument("--url", "-u", type=str, help="Fetch domains live from custom online URL")
    parser.add_argument("--file", "-f", type=str, help="Path to text or JSON file containing domains")
    parser.add_argument("--limit", "-n", type=int, default=100, help="Maximum number of domains to scan (default 100, 0 for unlimited)")
    parser.add_argument("--sort-by", choices=["latency", "score"], default="latency", help="Sort order: latency (lowest ping first) or score")
    parser.add_argument("--target-server", "-s", type=str, default="48.102.164.241", help="Your VPS Server IP")
    parser.add_argument("--target-port", "-p", type=int, default=7, help="Your Reality inbound port (default 7)")
    parser.add_argument("--concurrency", "-j", type=int, default=20, help="Number of concurrent workers (default 20)")
    parser.add_argument("--timeout", "-t", type=float, default=3.5, help="Network timeout in seconds (default 3.5)")
    parser.add_argument("--top-limit", type=int, default=25, help="Number of results to display in summary table (default 25)")
    parser.add_argument("--disable-doh", action="store_true", help="Disable DoH anti-spoofing verification")
    parser.add_argument("--export-json", type=str, default="sni_results.json", help="Export file path for JSON output")
    parser.add_argument("--export-csv", type=str, help="Export file path for CSV output")

    # Method 2 options
    parser.add_argument("--vless", type=str, help="Method 2: VLESS Reality URI or path to config file")
    parser.add_argument("--core-path", type=str, help="Method 2: Path to local Xray or Sing-box binary")

    # Method 3 options
    parser.add_argument("--panel-url", type=str, help="Method 3: Base URL of 3X-UI or vpn-ui panel")
    parser.add_argument("--panel-user", type=str, help="Method 3: Panel administrator username")
    parser.add_argument("--panel-pass", type=str, help="Method 3: Panel administrator password")
    parser.add_argument("--panel-type", type=str, default="3x-ui", choices=["3x-ui", "vpn-ui"], help="Method 3: Panel type")

    # Testing & simulation
    parser.add_argument("--mock-mode", action="store_true", help="Run in deterministic simulated benchmark mode for testing")

    args = parser.parse_args()
    asyncio.run(run_cli(args))


if __name__ == "__main__":
    main()
