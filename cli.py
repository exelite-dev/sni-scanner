"""
Vortex SNI Hunter Pro - Elite CLI Interface
High-speed terminal SNI scanner with live animated progress and formatted tables.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import List

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

    # Header Panel
    if HAS_RICH:
        banner = """[bold cyan]V O R T E X   S N I   H U N T E R   P R O[/bold cyan]
[dim]Ultimate TLS 1.3, ALPN & Lowest-Ping Reality Scanner for Iran Clean IPs[/dim]
[yellow]Target Server:[/yellow] [bold white]{}:{} [/bold white] | [yellow]Source Pool:[/yellow] [bold white]{} domains[/bold white] | [yellow]Sort By:[/yellow] [bold green]{}[/bold green] | [yellow]Concurrency:[/yellow] [bold white]{}[/bold white]""".format(
            args.target_server or "None", args.target_port, len(domains), args.sort_by, args.concurrency
        )
        console.print(Panel(banner, border_style="cyan"))
    else:
        print(f"=== VORTEX SNI HUNTER PRO ===")
        print(f"Target Server: {args.target_server}:{args.target_port} | Domains: {len(domains)} | Sort: {args.sort_by}")

    scanner = SNIScanner(
        concurrency=args.concurrency,
        timeout=args.timeout,
        enable_doh=not args.disable_doh,
        target_server_ip=args.target_server,
        target_server_port=args.target_port,
    )

    # Execution with Progress Bar
    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            console=console,
        ) as progress_bar:
            task = progress_bar.add_task("[cyan]Scanning SNI targets...", total=len(domains))

            def on_progress(p: ScanProgress, r: ScoredSNI):
                progress_bar.update(task, completed=p.completed, description=f"[cyan]Scanning: [bold]{p.current_domain[:25]}[/bold]")

            results = await scanner.scan_domains(domains, on_progress=on_progress, sort_by=args.sort_by)
    else:
        def on_progress(p: ScanProgress, r: ScoredSNI):
            lat_str = f"{round(r.tls.total_latency_ms)}ms" if r.tls.success else "Timeout"
            print(f"[{p.completed}/{p.total}] {p.current_domain}: Ping={lat_str} Score={r.score} (Grade {r.grade})")

        results = await scanner.scan_domains(domains, on_progress=on_progress, sort_by=args.sort_by)

    # Render Summary Table
    if HAS_RICH:
        title_suffix = "Lowest Ping First" if args.sort_by == "latency" else "Highest Score First"
        table = Table(title=f"[bold green]Ranked SNI Candidates for VLESS Reality ({title_suffix})[/bold green]", show_lines=True)
        table.add_column("#", justify="center", style="dim", no_wrap=True)
        table.add_column("Domain (SNI)", justify="left", style="bold white", no_wrap=True)
        table.add_column("Ping", justify="right", style="bold green", no_wrap=True)
        table.add_column("Cert Health", justify="left", no_wrap=True)
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
            
            # Ping color coding
            if r.tls.success and r.tls.total_latency_ms:
                ms = round(r.tls.total_latency_ms)
                p_color = "bold green" if ms < 150 else "cyan" if ms < 300 else "yellow"
                lat_str = f"[{p_color}]{ms} ms[/{p_color}]"
            else:
                lat_str = "[red]Timeout[/red]"

            # Certificate Health string
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
            lat_str = f"{r.tls.total_latency_ms:.1f}ms" if r.tls.success else "Timeout"
            cert_status = "Valid" if r.tls.cert_valid else "Invalid"
            print(f"{idx}. {r.domain:25} | Ping: {lat_str:10} | Cert: {cert_status} ({r.tls.cert_issuer}) | Score: {r.score:3}/100")

    # Exports
    if args.export_json:
        scanner.export_json(args.export_json)
        print(f"\n[+] Exported results to JSON: {args.export_json}")
    if args.export_csv:
        scanner.export_csv(args.export_csv)
        print(f"[+] Exported results to CSV: {args.export_csv}")

    # Top Recommended SNI (Lowest ping among healthy TLS 1.3 domains with valid certs)
    top_valid = [r for r in results if r.score >= 65 and r.tls.is_tls13 and r.tls.cert_valid and r.tls.total_latency_ms]
    if top_valid:
        best = top_valid[0]
        if HAS_RICH:
            summary = f"""[bold green]* FASTEST RECOMMENDED SNI FOR YOUR SERVER:[/bold green] [bold white]{best.domain}[/bold white]
* Latency: [bold green]{round(best.tls.total_latency_ms)} ms[/bold green] (TCP Ping: {round(best.tls.tcp_latency_ms)} ms)
* Reality Score: [bold cyan]{best.score}/100[/bold cyan] (Grade {best.grade})
* Protocol: [cyan]TLS 1.3[/cyan] | ALPN: [cyan]{best.tls.alpn}[/cyan]
* Certificate: [bold green]VALID & CA-TRUSTED[/bold green] (Issuer: {best.tls.cert_issuer} | Days Left: {best.tls.cert_expires_days})
* Target IP: [white]{best.dns.ips[0] if best.dns.ips else 'N/A'}[/white]
[italic dim]Set this domain as SNI and dest in your Reality panel ({args.target_server or '48.102.164.241'})[/italic dim]"""
            console.print(Panel(summary, border_style="green", title="Recommended Configuration"))
        else:
            print(f"\nFASTEST SNI: {best.domain} (Latency: {best.tls.total_latency_ms:.1f}ms, Score: {best.score}/100)")


def main():
    parser = argparse.ArgumentParser(description="Vortex SNI Hunter Pro - High-Speed Reality SNI Scanner")
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

    args = parser.parse_args()
    asyncio.run(run_cli(args))


if __name__ == "__main__":
    main()
