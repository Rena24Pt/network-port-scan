"""Service banner grabbing and identification.

A *banner* is whatever a service says when you first talk to it. Many text-based
protocols greet the client immediately after the TCP handshake (SSH, FTP, SMTP,
POP3, IMAP...), so simply reading from the socket reveals the software and often
its exact version. HTTP servers stay silent until asked, so for web ports we
send a minimal ``HEAD`` request first. For TLS ports we complete a TLS handshake
before probing, then treat the encrypted stream as HTTP.

Banner grabbing is a form of *service and version detection* — the same idea
behind ``nmap -sV`` — and it is often the most useful signal a scan produces.
"""

from __future__ import annotations

import socket
import ssl

from .ports import COMMON_PORTS

# Ports that speak cleartext HTTP: probe them with a HEAD request.
HTTP_PORTS: set[int] = {80, 591, 3000, 8000, 8008, 8080, 8888, 9000}
# Ports that wrap their protocol in TLS: handshake first, then probe as HTTP.
TLS_PORTS: set[int] = {443, 8443}

# Keyword hints used to guess a service when the port number is unknown.
_BANNER_HINTS: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "smtp",
    "http": "http",
    "imap": "imap",
    "pop3": "pop3",
    "mysql": "mysql",
    "redis": "redis",
    "mongodb": "mongodb",
}

_MAX_BANNER_BYTES = 4096


def grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Read a service banner from an already-connected socket.

    The socket must already be connected — the scanner hands over the very
    connection it used to confirm the port is open, which avoids paying for a
    second TCP handshake. Returns a cleaned, single-line banner, or an empty
    string if nothing could be read within *timeout* seconds.
    """
    try:
        sock.settimeout(timeout)
        stream: socket.socket = sock

        if port in TLS_PORTS:
            # We are not validating certificates: the goal is reconnaissance,
            # not establishing a trusted channel, and targets often use
            # self-signed certs. This is why verification is disabled.
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            stream = context.wrap_socket(sock, server_hostname=host)

        if port in HTTP_PORTS or port in TLS_PORTS:
            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: portscanner\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            stream.sendall(request.encode("ascii"))

        data = stream.recv(_MAX_BANNER_BYTES)
        return _summarize(data)
    except (OSError, ssl.SSLError):
        # Timeouts, resets, TLS negotiation failures — all mean "no banner".
        return ""


def identify_service(port: int, banner: str) -> str:
    """Best-effort service name for a port, refined by the banner if needed."""
    service = COMMON_PORTS.get(port)
    if service:
        return service
    lowered = banner.lower()
    for keyword, name in _BANNER_HINTS.items():
        if keyword in lowered:
            return name
    return "unknown"


def _summarize(data: bytes) -> str:
    """Turn a raw byte response into a compact, printable one-liner.

    For HTTP responses we surface the status line and ``Server:`` header (the
    genuinely useful parts). Otherwise we return the first non-empty line.
    Non-printable bytes are stripped so a stray binary protocol cannot corrupt
    the user's terminal.
    """
    if not data:
        return ""
    text = data.decode("latin-1", errors="replace")

    if text.startswith("HTTP/"):
        status = text.splitlines()[0].strip()
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                return f"{status} (Server: {server})"
        return status

    first_line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    return _printable(first_line)[:200]


def _printable(text: str) -> str:
    return "".join(ch for ch in text if ch.isprintable())
