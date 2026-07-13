"""Rendering scan results as a human-readable table or machine-readable JSON."""

from __future__ import annotations

import json

from .scanner import ScanResult

# Minimal ANSI colour codes. They are only emitted when the caller asks for
# colour (typically: stdout is a real terminal and we are not writing to a file).
_GREEN = "\033[32m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def format_table(
    results: list[ScanResult],
    target: str,
    ip: str,
    duration: float,
    *,
    color: bool = True,
) -> str:
    """Render open ports as an aligned, optionally coloured text table."""
    open_results = [r for r in results if r.is_open]

    lines = [
        _paint(f"Scan report for {target} ({ip})", _BOLD, color),
        f"Scanned {len(results)} port(s) in {duration:.2f}s — "
        f"{len(open_results)} open",
        "",
    ]

    if not open_results:
        lines.append("No open ports found.")
        return "\n".join(lines)

    # Size columns to their widest content so everything lines up.
    port_w = max(len("PORT"), max(len(f"{r.port}/tcp") for r in open_results))
    svc_w = max(len("SERVICE"), max(len(r.service) for r in open_results))

    header = f"{'PORT':<{port_w}}  {'STATE':<6}  {'SERVICE':<{svc_w}}  BANNER"
    lines.append(_paint(header, _DIM, color))

    for r in open_results:
        port_field = f"{r.port}/tcp"
        # Pad the plain text first, then colour it: ANSI codes are zero-width, so
        # colouring after padding keeps every column aligned.
        state_field = _paint("open".ljust(6), _GREEN, color)
        line = (
            f"{port_field:<{port_w}}  {state_field}  "
            f"{r.service:<{svc_w}}  {r.banner}"
        )
        lines.append(line.rstrip())

    return "\n".join(lines)


# A per-host scan report, as accumulated by the CLI: (target, ip, results, secs).
HostReport = tuple[str, str, list[ScanResult], float]


def _host_payload(
    results: list[ScanResult], target: str, ip: str, duration: float
) -> dict:
    """Build the JSON-serialisable dict describing one host's scan."""
    return {
        "target": target,
        "ip": ip,
        "duration_seconds": round(duration, 3),
        "ports_scanned": len(results),
        "open_count": sum(1 for r in results if r.is_open),
        "open_ports": [
            {
                "port": r.port,
                "protocol": "tcp",
                "state": "open",
                "service": r.service,
                "banner": r.banner,
                "latency_ms": round(r.latency_ms, 2),
            }
            for r in results
            if r.is_open
        ],
    }


def format_json(
    results: list[ScanResult],
    target: str,
    ip: str,
    duration: float,
) -> str:
    """Render a single host's scan as a JSON document."""
    return json.dumps(_host_payload(results, target, ip, duration), indent=2)


def format_multi_json(host_reports: list[HostReport]) -> str:
    """Render a multi-host (subnet) scan as a JSON document."""
    payload = {
        "hosts_scanned": len(host_reports),
        "hosts_with_open_ports": sum(
            1 for _, _, results, _ in host_reports if any(r.is_open for r in results)
        ),
        "hosts": [
            _host_payload(results, target, ip, duration)
            for target, ip, results, duration in host_reports
        ],
    }
    return json.dumps(payload, indent=2)


def format_multi_table(host_reports: list[HostReport], *, color: bool = True) -> str:
    """Render a subnet scan: one table per host that has open ports, + a summary.

    Hosts with no open ports are omitted from the body (they would be noise on a
    large sweep) but still counted in the summary line.
    """
    with_open = [
        report for report in host_reports if any(r.is_open for r in report[2])
    ]
    total = len(host_reports)
    summary = _paint(
        f"Summary: {total} host(s) scanned, {len(with_open)} with open ports.",
        _BOLD,
        color,
    )

    if not with_open:
        return f"No open ports found across {total} host(s)."

    blocks = [
        format_table(results, target, ip, duration, color=color)
        for target, ip, results, duration in with_open
    ]
    return "\n\n".join(blocks) + "\n\n" + summary
