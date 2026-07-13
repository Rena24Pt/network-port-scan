"""Command-line interface for the port scanner."""

from __future__ import annotations

import argparse
import sys
import time
from typing import Optional, Sequence

from . import __version__
from .output import format_json, format_table
from .ports import parse_ports
from .scanner import Scanner

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
        scanner = Scanner(
            target=args.target,
            timeout=args.timeout,
            workers=args.workers,
            grab_banners=not args.no_banner,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(
            f"Scanning {scanner.target} ({scanner.ip}) — {len(ports)} port(s)",
            file=sys.stderr,
        )

    # Progress goes to stderr; it would corrupt JSON on stdout, and is pointless
    # when the user asked to be quiet.
    show_progress = not args.quiet and not args.json
    start = time.perf_counter()
    try:
        results = scanner.scan(ports, progress=_progress if show_progress else None)
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return 130
    duration = time.perf_counter() - start

    if show_progress:
        print(file=sys.stderr)  # terminate the progress line

    if args.json:
        rendered = format_json(results, scanner.target, scanner.ip, duration)
    else:
        # Colour only when writing to an interactive terminal.
        color = sys.stdout.isatty() and not args.output
        rendered = format_table(
            results, scanner.target, scanner.ip, duration, color=color
        )

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
