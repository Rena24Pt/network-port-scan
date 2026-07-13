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


def format_json(
    results: list[ScanResult],
    target: str,
    ip: str,
    duration: float,
) -> str:
    """Render the full scan as a JSON document for piping into other tools."""
    payload = {
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
    return json.dumps(payload, indent=2)
