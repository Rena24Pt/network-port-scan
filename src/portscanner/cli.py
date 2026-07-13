"""Command-line interface for the port scanner."""

from __future__ import annotations

import argparse
import sys
import time
from typing import Optional, Sequence

from . import __version__
from .output import (
    HostReport,
    format_json,
    format_multi_json,
    format_multi_table,
    format_table,
)
from .ports import parse_ports
from .scanner import Scanner
from .synscan import SynScanner
from .targets import expand_targets

_DISCLAIMER = (
    "LEGAL NOTICE: portscanner is for authorised testing and education only.\n"
    "Scan only systems you own or have explicit written permission to test.\n"
    "Unauthorised port scanning may be illegal in your jurisdiction."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="Fast, multithreaded TCP port scanner with banner grabbing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  portscan scanme.nmap.org\n"
            "  portscan 192.168.1.1 -p 1-1024\n"
            "  portscan example.com -p 22,80,443 --json\n"
            "  portscan 10.0.0.5 -p all -w 500 --no-banner -o report.txt\n\n"
            + _DISCLAIMER
        ),
    )
    parser.add_argument("target", help="hostname or IP address to scan")
    parser.add_argument(
        "-p",
        "--ports",
        default="top",
        help="ports to scan: 'top' (default), 'all', a range '1-1024', "
        "or a list '22,80,443'",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="per-port connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="number of concurrent worker threads (default: 100)",
    )
    parser.add_argument(
        "-S",
        "--syn",
        action="store_true",
        help="stealth SYN (half-open) scan using raw sockets; needs root/Linux "
        "and grabs no banners",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="skip banner grabbing (faster and quieter on the network)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output results as JSON instead of a table",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write output to FILE instead of stdout",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress progress output and the legal notice",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _progress(done: int, total: int) -> None:
    pct = done / total * 100
    print(
        f"\rScanning... {done}/{total} ({pct:5.1f}%)",
        end="",
        file=sys.stderr,
        flush=True,
    )


def _scan_host(
    host: str,
    args: argparse.Namespace,
    ports: list,
    index: int,
    total: int,
) -> HostReport:
    """Scan one host and return its report tuple.

    Raises ``ValueError`` if the host cannot be resolved and ``PermissionError``
    if a SYN scan lacks raw-socket privileges — the caller decides how fatal
    each is.
    """
    if args.syn:
        scanner = SynScanner(target=host, timeout=args.timeout)
    else:
        scanner = Scanner(
            target=host,
            timeout=args.timeout,
            workers=args.workers,
            grab_banners=not args.no_banner,
        )

    sweep = total > 1
    if not args.quiet:
        if sweep:
            print(f"[{index}/{total}] scanning {scanner.ip} ...", file=sys.stderr)
        else:
            mode = "SYN (half-open)" if args.syn else "TCP connect"
            print(
                f"Scanning {scanner.target} ({scanner.ip}) — "
                f"{len(ports)} port(s), {mode} scan",
                file=sys.stderr,
            )

    # A per-port progress bar only makes sense for a single host; during a sweep
    # the per-host lines above are the progress indicator.
    use_progress = not args.quiet and not args.json and not sweep
    start = time.perf_counter()
    results = scanner.scan(ports, progress=_progress if use_progress else None)
    duration = time.perf_counter() - start
    if use_progress:
        print(file=sys.stderr)  # terminate the progress line
    return scanner.target, scanner.ip, results, duration


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.quiet:
        print(_DISCLAIMER, file=sys.stderr)
        print(file=sys.stderr)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    if args.timeout <= 0:
        parser.error("timeout must be a positive number")
    if args.workers < 1:
        parser.error("workers must be at least 1")

    try:
        hosts = expand_targets(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    sweep = len(hosts) > 1
    if sweep and not args.quiet:
        mode = "SYN (half-open)" if args.syn else "TCP connect"
        print(
            f"{mode} scan — {len(hosts)} host(s), {len(ports)} port(s) each",
            file=sys.stderr,
        )

    reports: list[HostReport] = []
    for index, host in enumerate(hosts, start=1):
        try:
            reports.append(_scan_host(host, args, ports, index, len(hosts)))
        except ValueError as exc:
            # Host could not be resolved: fatal for a single target, but during a
            # sweep we just skip it and keep going.
            print(f"error: {exc}", file=sys.stderr)
            if not sweep:
                return 2
        except PermissionError as exc:
            # Raw-socket SYN scan without the required privileges — always fatal.
            print(f"\nerror: {exc}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print("\nInterrupted by user.", file=sys.stderr)
            return 130

    if not reports:
        print("No hosts could be scanned.", file=sys.stderr)
        return 2

    if args.json:
        if sweep:
            rendered = format_multi_json(reports)
        else:
            target, ip, results, duration = reports[0]
            rendered = format_json(results, target, ip, duration)
    else:
        # Colour only when writing to an interactive terminal.
        color = sys.stdout.isatty() and not args.output
        if sweep:
            rendered = format_multi_table(reports, color=color)
        else:
            target, ip, results, duration = reports[0]
            rendered = format_table(results, target, ip, duration, color=color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered + "\n")
        if not args.quiet:
            print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
