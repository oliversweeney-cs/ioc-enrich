from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from ioc_enrich.enrichers import AbuseIPDBEnricher, ShodanEnricher, VirusTotalEnricher
from ioc_enrich.models import (
    AbuseIPDBResult,
    EnrichmentResult,
    IoCBundle,
    IoCType,
    ShodanResult,
    detect_ioc_type,
)

load_dotenv()

# Module-level consoles.  main() may replace these with no-color variants
# depending on --no-color flag or TTY auto-detection.
console = Console()
_progress_console = Console(stderr=True)  # progress bar always goes to stderr


# ---------------------------------------------------------------------------
# IoC collection + deduplication
# ---------------------------------------------------------------------------

def _collect_iocs(iocs: tuple[str, ...], file: str | None) -> list[str]:
    """Collect raw IoC strings from CLI args, --file, or stdin.

    Lines starting with '#' and blank lines are silently skipped in both
    file and stdin modes, allowing commented input files.
    """
    results = list(iocs)
    if file:
        with open(file) as fh:
            results.extend(
                line.strip()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            )
    if not results and not sys.stdin.isatty():
        results.extend(
            line.strip()
            for line in sys.stdin
            if line.strip() and not line.strip().startswith("#")
        )
    return results


def _classify_and_dedup(raw: list[str]) -> list[tuple[str, IoCType]]:
    """Classify each IoC, warn about invalids, and deduplicate by exact value."""
    seen: set[str] = set()
    out: list[tuple[str, IoCType]] = []
    for s in raw:
        ioc = s.strip()
        ioc_type = detect_ioc_type(ioc)
        if ioc_type is IoCType.UNKNOWN:
            console.print(f"[yellow]Skipping invalid IOC:[/yellow] {ioc}")
            continue
        if ioc in seen:
            console.print(f"[dim]Deduplicating:[/dim] {ioc}")
            continue
        seen.add(ioc)
        out.append((ioc, ioc_type))
    return out


# ---------------------------------------------------------------------------
# Per-source cell helpers (VT)
# ---------------------------------------------------------------------------

def _verdict_label(r: EnrichmentResult) -> str:
    """Rich-markup verdict string from a VT result."""
    if r.error:
        return "[dim]ERROR[/dim]"
    if r.malicious >= 5:
        return "[bold red]MALICIOUS[/bold red]"
    if r.malicious >= 1:
        return "[bold yellow]SUSPICIOUS[/bold yellow]"
    return "[bold green]CLEAN[/bold green]"


def _verdict_str(r: EnrichmentResult) -> str:
    """Plain-text verdict string (for JSON / CSV)."""
    if r.error:
        return "ERROR"
    if r.malicious >= 5:
        return "MALICIOUS"
    if r.malicious >= 1:
        return "SUSPICIOUS"
    return "CLEAN"


def _detection_cell(r: EnrichmentResult) -> str:
    """Rich-markup 'X/Y' detection ratio, coloured by verdict."""
    if r.error:
        return "[dim]-[/dim]"
    ratio = f"{r.malicious}/{r.total_vendors}"
    if r.malicious >= 5:
        return f"[bold red]{ratio}[/bold red]"
    if r.malicious >= 1:
        return f"[bold yellow]{ratio}[/bold yellow]"
    return f"[bold green]{ratio}[/bold green]"


# ---------------------------------------------------------------------------
# Bundle-level cell helpers
# ---------------------------------------------------------------------------

def _abuse_score_cell(b: IoCBundle) -> str:
    """AIPDB confidence score, or '-' for non-IP / missing enricher."""
    if b.ioc_type is not IoCType.IP or b.abuseipdb is None:
        return "[dim]-[/dim]"
    if b.abuseipdb.error:
        return "[dim]ERR[/dim]"
    score = b.abuseipdb.abuse_confidence
    label = f"{score}%"
    if score >= 75:
        return f"[bold red]{label}[/bold red]"
    if score >= 25:
        return f"[bold yellow]{label}[/bold yellow]"
    return f"[bold green]{label}[/bold green]"


def _ports_cell(b: IoCBundle) -> str:
    """Shodan open port count with contextual indicators.

    Display logic:
      '-'   non-IP type (Shodan doesn't cover these)
      'N/K' IP but no Shodan API key was configured
      'N/A' IP indexed-query returned 404 (not in Shodan)
      'ERR' any other error (timeout, 5xx, auth failure)
      number coloured red (>10) / yellow (1-10) / dim (0)
    """
    if b.ioc_type is not IoCType.IP:
        return "[dim]-[/dim]"
    if not b.shodan_key_present:
        return "[dim]N/K[/dim]"
    if b.shodan is None:
        return "[dim]-[/dim]"      # key present, IP, but enrich() returned None — shouldn't happen
    if b.shodan.error:
        # "Not found in Shodan index" comes from the 404 handler in ShodanEnricher.
        if "Not found" in b.shodan.error:
            return "[dim]N/A[/dim]"
        return "[dim]ERR[/dim]"
    count = len(b.shodan.ports)
    if count > 10:
        return f"[bold red]{count}[/bold red]"
    if count >= 1:
        return f"[bold yellow]{count}[/bold yellow]"
    return "[dim]0[/dim]"


# ---------------------------------------------------------------------------
# Verbose detail renderer
# ---------------------------------------------------------------------------

def _render_verbose(bundles: list[IoCBundle]) -> None:
    """Print extended per-source detail blocks (shown only with --verbose)."""
    for b in bundles:
        console.print(f"\n[bold cyan]{b.ioc}[/bold cyan] [dim]({b.ioc_type.value})[/dim]")

        # --- VirusTotal ---
        vt = b.vt
        if vt and not vt.error:
            console.print("  [bold underline]VirusTotal[/bold underline]")
            # Tags are only shown in verbose mode (removed from default table).
            if vt.tags:
                console.print(f"    [dim]Tags:[/dim] {', '.join(vt.tags)}")
            if vt.reputation is not None:
                console.print(
                    f"    [dim]Reputation:[/dim] {vt.reputation} "
                    f"[dim](community vote — positive = trusted, negative = suspicious)[/dim]"
                )
            if b.ioc_type is IoCType.IP:
                asn = vt.extra.get("asn") or "N/A"
                owner = vt.extra.get("as_owner") or "N/A"
                country = vt.extra.get("country") or "N/A"
                network = vt.extra.get("network") or "N/A"
                console.print(
                    f"    [dim]ASN:[/dim] {asn}   [dim]Owner:[/dim] {owner}   "
                    f"[dim]Country:[/dim] {country}   [dim]Network:[/dim] {network}"
                )
            elif b.ioc_type is IoCType.DOMAIN:
                registrar = vt.extra.get("registrar") or "N/A"
                created = vt.extra.get("creation_date") or "N/A"
                dns_records: list[dict] = vt.extra.get("last_dns_records", [])
                console.print(
                    f"    [dim]Registrar:[/dim] {registrar}   [dim]Created:[/dim] {created}"
                )
                if dns_records:
                    shown = dns_records[:5]
                    dns_str = ",  ".join(
                        f"{rec.get('type', '?')} {rec.get('value', '?')}" for rec in shown
                    )
                    if len(dns_records) > 5:
                        dns_str += f"  … (+{len(dns_records) - 5} more)"
                    console.print(f"    [dim]Last DNS:[/dim] {dns_str}")
            elif b.ioc_type is IoCType.HASH:
                ftype = vt.extra.get("type_description") or "N/A"
                size = vt.extra.get("size")
                size_str = f"{size:,} bytes" if size is not None else "N/A"
                name = vt.extra.get("meaningful_name") or "N/A"
                sig = vt.extra.get("signature_info") or {}
                sig_str = sig.get("description") or sig.get("product") or "N/A" if sig else "N/A"
                console.print(
                    f"    [dim]Type:[/dim] {ftype}   [dim]Size:[/dim] {size_str}   "
                    f"[dim]Name:[/dim] {name}"
                )
                console.print(f"    [dim]Signature:[/dim] {sig_str}")
        elif vt and vt.error:
            console.print(
                f"  [bold underline]VirusTotal[/bold underline]  [dim]Error: {vt.error}[/dim]"
            )

        # --- AbuseIPDB (IP only) ---
        a: AbuseIPDBResult | None = b.abuseipdb
        if a is not None and b.ioc_type is IoCType.IP:
            console.print("  [bold underline]AbuseIPDB[/bold underline]")
            if a.error:
                console.print(f"    [dim]Error: {a.error}[/dim]")
            else:
                last = a.last_reported or "N/A"
                if last and "T" in last:
                    last = last.split("T")[0]
                console.print(
                    f"    [dim]Confidence:[/dim] {a.abuse_confidence}%   "
                    f"[dim]Reports:[/dim] {a.total_reports}   "
                    f"[dim]Last reported:[/dim] {last}"
                )
                console.print(
                    f"    [dim]ISP:[/dim] {a.isp or 'N/A'}   "
                    f"[dim]Usage:[/dim] {a.usage_type or 'N/A'}   "
                    f"[dim]Country:[/dim] {a.country or 'N/A'}"
                )

        # --- Shodan (IP only) ---
        s: ShodanResult | None = b.shodan
        if b.ioc_type is IoCType.IP:
            console.print("  [bold underline]Shodan[/bold underline]")
            if not b.shodan_key_present:
                console.print("    [dim]No API key configured (SHODAN_API_KEY)[/dim]")
            elif s is None:
                console.print("    [dim]No data[/dim]")
            elif s.error:
                # Show the full reason in verbose so the analyst understands what happened.
                console.print(f"    [dim]Error: {s.error}[/dim]")
            else:
                console.print(
                    f"    [dim]Org:[/dim] {s.org or 'N/A'}   "
                    f"[dim]ISP:[/dim] {s.isp or 'N/A'}   "
                    f"[dim]OS:[/dim] {s.os or 'N/A'}   "
                    f"[dim]Country:[/dim] {s.country or 'N/A'}   "
                    f"[dim]City:[/dim] {s.city or 'N/A'}"
                )
                console.print(f"    [dim]Last update:[/dim] {s.last_update or 'N/A'}")
                if s.services:
                    console.print(f"    [dim]Open ports ({len(s.ports)}):[/dim]")
                    for svc in s.services:
                        port = svc.get("port", "?")
                        transport = svc.get("transport", "tcp")
                        product = svc.get("product") or "unknown"
                        version = svc.get("version") or ""
                        banner = svc.get("banner") or ""
                        first_line = banner.split("\n")[0][:80] if banner else ""
                        svc_line = f"      [dim]{port}/{transport}[/dim]  {product} {version}"
                        if first_line:
                            svc_line += f"  [dim]{first_line}[/dim]"
                        console.print(svc_line)
                elif s.ports:
                    console.print(
                        f"    [dim]Open ports:[/dim] {', '.join(str(p) for p in s.ports)}"
                    )


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def _render_table(
    bundles: list[IoCBundle],
    sources: list[str],
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Render enrichment results as a Rich table (default view)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    console.print(f"[dim]Enriched at {ts}[/dim]")
    console.print(f"[dim]Sources: {', '.join(sources)}[/dim]\n")

    if quiet:
        display = [b for b in bundles if (b.vt and b.vt.malicious >= 1) or (b.vt and b.vt.error)]
        hidden = len(bundles) - len(display)
        if hidden:
            console.print(
                f"[dim](Hiding {hidden} CLEAN result{'s' if hidden != 1 else ''})[/dim]\n"
            )
    else:
        display = bundles

    # Column order: IoC, Type, Verdict, VT Detection, AIPDB Score, Shodan Ports, Rep
    # Tags are intentionally omitted here; they appear in --verbose output only.
    table = Table(show_header=True, header_style="bold cyan", show_lines=True)
    table.add_column("IoC", overflow="fold")
    table.add_column("Type", min_width=6, no_wrap=True)
    table.add_column("Verdict", min_width=9, no_wrap=True)
    table.add_column("VT Detection", min_width=7, justify="right", no_wrap=True)
    table.add_column("AIPDB Score", min_width=5, justify="right", no_wrap=True)
    table.add_column("Shodan Ports", min_width=5, justify="right", no_wrap=True)
    table.add_column("VT Rep", min_width=5, justify="right", no_wrap=True)

    for b in display:
        vt = b.vt
        table.add_row(
            b.ioc,
            b.ioc_type.value,
            _verdict_label(vt) if vt else "[dim]-[/dim]",
            _detection_cell(vt) if vt else "[dim]-[/dim]",
            _abuse_score_cell(b),
            _ports_cell(b),
            str(vt.reputation) if vt and vt.reputation is not None else "-",
        )

    console.print(table)
    _print_summary(bundles)

    if verbose:
        _render_verbose(display)


def _render_brief(bundles: list[IoCBundle]) -> None:
    """Minimal table for quick triage: IoC, Verdict, VT Detection only."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    console.print(f"[dim]Enriched at {ts}[/dim]\n")

    table = Table(show_header=True, header_style="bold cyan", show_lines=True)
    table.add_column("IoC", overflow="fold")
    table.add_column("Verdict", min_width=9, no_wrap=True)
    table.add_column("VT Detection", min_width=7, justify="right", no_wrap=True)

    for b in bundles:
        vt = b.vt
        table.add_row(
            b.ioc,
            _verdict_label(vt) if vt else "[dim]-[/dim]",
            _detection_cell(vt) if vt else "[dim]-[/dim]",
        )

    console.print(table)
    _print_summary(bundles)


def _print_summary(bundles: list[IoCBundle]) -> None:
    """Print the one-line summary with verdict counts and highest detection ratio."""
    mal = sum(1 for b in bundles if b.vt and not b.vt.error and b.vt.malicious >= 5)
    sus = sum(1 for b in bundles if b.vt and not b.vt.error and 1 <= b.vt.malicious < 5)
    clean = sum(1 for b in bundles if b.vt and not b.vt.error and b.vt.malicious == 0)

    detected = [b for b in bundles if b.vt and not b.vt.error and b.vt.malicious > 0]
    highest = max(detected, key=lambda b: b.vt.malicious, default=None)  # type: ignore[union-attr]
    highest_str = (
        f"  [dim]Highest detection ratio: "
        f"{highest.vt.malicious}/{highest.vt.total_vendors}[/dim]"  # type: ignore[union-attr]
        if highest
        else ""
    )

    console.print(
        f"{len(bundles)} IOCs enriched: "
        f"[bold red]{mal} MALICIOUS[/bold red], "
        f"[bold yellow]{sus} SUSPICIOUS[/bold yellow], "
        f"[bold green]{clean} CLEAN[/bold green]"
        f"{highest_str}"
    )


def _render_csv(bundles: list[IoCBundle], quiet: bool = False) -> None:
    """Output results as CSV to stdout."""
    display = (
        [b for b in bundles if (b.vt and b.vt.malicious >= 1) or (b.vt and b.vt.error)]
        if quiet
        else bundles
    )
    fieldnames = [
        "ioc", "type", "verdict", "malicious", "total_vendors", "suspicious",
        "harmless", "undetected", "reputation", "tags",
        "abuse_confidence", "abuse_total_reports", "abuse_last_reported",
        "shodan_ports", "error",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for b in display:
        vt = b.vt
        a = b.abuseipdb
        s = b.shodan
        writer.writerow({
            "ioc": b.ioc,
            "type": b.ioc_type.value,
            "verdict": _verdict_str(vt) if vt else "UNKNOWN",
            "malicious": vt.malicious if vt else "",
            "total_vendors": vt.total_vendors if vt else "",
            "suspicious": vt.suspicious if vt else "",
            "harmless": vt.harmless if vt else "",
            "undetected": vt.undetected if vt else "",
            "reputation": vt.reputation if vt and vt.reputation is not None else "",
            "tags": "|".join(vt.tags) if vt else "",
            "abuse_confidence": a.abuse_confidence if a and not a.error else "",
            "abuse_total_reports": a.total_reports if a and not a.error else "",
            "abuse_last_reported": a.last_reported or "" if a and not a.error else "",
            "shodan_ports": "|".join(str(p) for p in s.ports) if s and not s.error else "",
            "error": " | ".join(filter(None, [
                f"vt:{vt.error}" if vt and vt.error else None,
                f"abuseipdb:{a.error}" if a and a.error else None,
                f"shodan:{s.error}" if s and s.error else None,
            ])),
        })


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

_HELP = """\
Enrich Indicators of Compromise (IPs, domains, hashes, URLs) via threat intel APIs.

\b
Examples:
  ioc-enrich 8.8.8.8
  ioc-enrich 8.8.8.8 google.com 44d88612fea8a8f36de82e1278abb02f
  ioc-enrich -f iocs.txt
  cat iocs.txt | ioc-enrich
  ioc-enrich --output json 8.8.8.8
  ioc-enrich --output csv 8.8.8.8
  ioc-enrich -v 8.8.8.8
  ioc-enrich -q 8.8.8.8 1.2.3.4
  ioc-enrich -b 8.8.8.8
"""


@click.command(help=_HELP)
@click.argument("iocs", nargs=-1)
@click.option("-f", "--file", "file", default=None,
              help="Read IoCs from a file (one per line; # comments and blank lines skipped).")
@click.option(
    "-o", "--output",
    type=click.Choice(["table", "json", "csv"]),
    default="table", show_default=True,
    help="Output format.",
)
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Show per-source detail: VT network info, AbuseIPDB ISP/usage/reports, "
                   "Shodan open ports with service banners.  Tags are also shown here.")
@click.option("-q", "--quiet", is_flag=True, default=False,
              help="Only show SUSPICIOUS and MALICIOUS results; hide CLEAN.")
@click.option("-b", "--brief", is_flag=True, default=False,
              help="Minimal table (IoC, Verdict, VT Detection) for quick yes/no triage.")
@click.option("--no-color", "no_color", is_flag=True, default=False,
              help="Disable colour output.  Also auto-enabled when stdout is not a TTY.")
@click.option("--timeout", type=int, default=10, show_default=True,
              help="Per-request timeout in seconds (applies to all enrichers).")
@click.option("--vt-key", envvar="VIRUSTOTAL_API_KEY", default=None,
              help="VirusTotal API key.")
@click.option("--abuseipdb-key", envvar="ABUSEIPDB_API_KEY", default=None,
              help="AbuseIPDB API key (optional; skipped if absent).")
@click.option("--shodan-key", envvar="SHODAN_API_KEY", default=None,
              help="Shodan API key (optional; skipped if absent).")
def main(
    iocs: tuple[str, ...],
    file: str | None,
    output: str,
    verbose: bool,
    quiet: bool,
    brief: bool,
    no_color: bool,
    timeout: int,
    vt_key: str | None,
    abuseipdb_key: str | None,
    shodan_key: str | None,
) -> None:
    # Apply --no-color or auto-detect non-TTY stdout.  We reassign the module-
    # level console so that all downstream helpers pick up the change without
    # needing extra parameters.
    global console, _progress_console
    if no_color or not sys.stdout.isatty():
        console = Console(no_color=True, highlight=False)
        _progress_console = Console(stderr=True, no_color=True, highlight=False)

    raw_iocs = _collect_iocs(iocs, file)

    if not raw_iocs:
        raise click.UsageError("No IoCs provided. Pass them as arguments, --file, or via stdin.")

    if not vt_key:
        raise click.UsageError(
            "VirusTotal API key required. Set VIRUSTOTAL_API_KEY or pass --vt-key."
        )

    valid_iocs = _classify_and_dedup(raw_iocs)
    if not valid_iocs:
        console.print("[yellow]No valid IoCs to enrich.[/yellow]")
        return

    vt_enricher = VirusTotalEnricher(vt_key, timeout=timeout)
    abuse_enricher = AbuseIPDBEnricher(abuseipdb_key, timeout=timeout) if abuseipdb_key else None
    shodan_enricher = ShodanEnricher(shodan_key, timeout=timeout) if shodan_key else None

    sources: list[str] = ["VirusTotal"]
    if abuse_enricher:
        sources.append("AbuseIPDB")
    if shodan_enricher:
        sources.append("Shodan")

    bundles: list[IoCBundle] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=_progress_console,
        transient=True,
    ) as progress:
        task = progress.add_task("Enriching IoCs…", total=len(valid_iocs))
        for ioc, ioc_type in valid_iocs:
            progress.update(task, description=f"Enriching [cyan]{ioc}[/cyan]…")

            vt_result = vt_enricher.enrich(ioc, ioc_type)
            abuse_result = abuse_enricher.enrich(ioc, ioc_type) if abuse_enricher else None
            shodan_result = shodan_enricher.enrich(ioc, ioc_type) if shodan_enricher else None

            bundles.append(IoCBundle(
                ioc=ioc,
                ioc_type=ioc_type,
                vt=vt_result,
                abuseipdb=abuse_result,
                shodan=shodan_result,
                shodan_key_present=shodan_enricher is not None,
            ))
            progress.advance(task)

    if output == "json":
        display = (
            [b for b in bundles if (b.vt and b.vt.malicious >= 1) or (b.vt and b.vt.error)]
            if quiet
            else bundles
        )
        click.echo(
            json.dumps(
                [
                    {
                        "ioc": b.ioc,
                        "type": b.ioc_type.value,
                        "verdict": _verdict_str(b.vt) if b.vt else "UNKNOWN",
                        "virustotal": (
                            {
                                "malicious": b.vt.malicious,
                                "total_vendors": b.vt.total_vendors,
                                "suspicious": b.vt.suspicious,
                                "harmless": b.vt.harmless,
                                "undetected": b.vt.undetected,
                                "reputation": b.vt.reputation,
                                "tags": b.vt.tags,
                                "extra": b.vt.extra,
                                "error": b.vt.error,
                            }
                            if b.vt else None
                        ),
                        "abuseipdb": (
                            {
                                "abuse_confidence": b.abuseipdb.abuse_confidence,
                                "total_reports": b.abuseipdb.total_reports,
                                "last_reported": b.abuseipdb.last_reported,
                                "isp": b.abuseipdb.isp,
                                "usage_type": b.abuseipdb.usage_type,
                                "country": b.abuseipdb.country,
                                "error": b.abuseipdb.error,
                            }
                            if b.abuseipdb else None
                        ),
                        "shodan": (
                            {
                                "ports": b.shodan.ports,
                                "services": b.shodan.services,
                                "os": b.shodan.os,
                                "org": b.shodan.org,
                                "isp": b.shodan.isp,
                                "country": b.shodan.country,
                                "city": b.shodan.city,
                                "last_update": b.shodan.last_update,
                                "error": b.shodan.error,
                            }
                            if b.shodan else None
                        ),
                    }
                    for b in display
                ],
                indent=2,
            )
        )
    elif output == "csv":
        _render_csv(bundles, quiet=quiet)
    elif brief:
        _render_brief(bundles)
    else:
        _render_table(bundles, sources=sources, verbose=verbose, quiet=quiet)
