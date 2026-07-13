"""SYN (half-open) scanning with raw sockets.

A SYN scan never completes the TCP three-way handshake. It sends a lone SYN and
inspects the reply:

* **SYN-ACK** -> the port is **open** (we deliberately never send the final ACK,
  so the connection stays *half* open — hence "half-open scan").
* **RST**     -> the port is **closed**.
* *(silence)* -> the port is **filtered**, i.e. a firewall dropped the probe.

Because it half-opens the connection it is stealthier and faster than a full
connect scan, but it has to craft raw TCP packets by hand, which requires
raw-socket privileges (root / ``CAP_NET_RAW``) and, in this implementation,
Linux. No banner can be grabbed here — there is never a full connection to read.

The heavy lifting is split into small pure functions (:func:`tcp_checksum`,
:func:`build_syn_packet`, :func:`parse_tcp_response`) so the packet logic can be
unit-tested without any privileges or real network traffic.
"""

from __future__ import annotations

import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .banner import identify_service
from .scanner import ScanResult, resolve_host

# TCP flag bits.
_FIN = 0x01
_SYN = 0x02
_RST = 0x04
_ACK = 0x10

_TCP_HEADER_LEN = 20


def tcp_checksum(data: bytes) -> int:
    """Compute the 16-bit one's-complement Internet checksum (RFC 1071).

    A correctly checksummed segment has the property that folding this function
    back over the data *including* its own checksum field yields 0.
    """
    if len(data) % 2:
        data += b"\x00"  # pad to a whole number of 16-bit words
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)  # fold carries
    total += total >> 16
    return ~total & 0xFFFF


def build_syn_packet(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int = 0
) -> bytes:
    """Build a bare 20-byte TCP SYN segment (the kernel prepends the IP header).

    The TCP checksum covers a *pseudo-header* — source IP, destination IP,
    protocol and TCP length — followed by the TCP header itself. We build the
    header once with a zero checksum, compute the real value, then rebuild it.
    """
    offset_reserved = 5 << 4  # data offset = 5 32-bit words (20 bytes)
    window = 64240

    def pack(checksum: int) -> bytes:
        return struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            0,  # acknowledgement number
            offset_reserved,
            _SYN,
            window,
            checksum,
            0,  # urgent pointer
        )

    tcp_header = pack(0)
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    return pack(tcp_checksum(pseudo_header + tcp_header))


def parse_tcp_response(
    packet: bytes, target_ip: str, our_port: int
) -> Optional[tuple[int, str]]:
    """Interpret a raw ``IP + TCP`` packet from the receive socket.

    Returns ``(remote_port, state)`` when *packet* is a reply from *target_ip*
    addressed to our ephemeral *our_port*, where state is ``"open"`` (SYN-ACK) or
    ``"closed"`` (RST). Returns ``None`` for anything unrelated.
    """
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0F) * 4  # IP header length lives in the low nibble
    if len(packet) < ihl + _TCP_HEADER_LEN:
        return None
    if socket.inet_ntoa(packet[12:16]) != target_ip:  # source IP field
        return None

    tcp = packet[ihl:ihl + _TCP_HEADER_LEN]
    src_port, dst_port = struct.unpack("!HH", tcp[0:4])
    flags = tcp[13]
    if dst_port != our_port:
        return None
    if flags & _SYN and flags & _ACK:
        return src_port, "open"
    if flags & _RST:
        return src_port, "closed"
    return None


@dataclass
class SynScanner:
    """A TCP SYN (half-open) scanner built on raw sockets.

    Requires raw-socket privileges (run as root / with ``CAP_NET_RAW``) and, in
    this implementation, Linux. ``timeout`` is the total time to wait for
    replies after all SYNs have been sent; ports that never answer are reported
    as ``"filtered"``.
    """

    target: str
    timeout: float = 2.0
    _ip: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self._ip = resolve_host(self.target)

    @property
    def ip(self) -> str:
        return self._ip

    def scan(
        self,
        ports: Iterable[int],
        progress: Optional[Callable[[int, int], None]] = None,
    ) -> list[ScanResult]:
        ports = list(ports)
        if not ports:
            return []

        src_ip = _local_source_ip(self._ip)
        our_port = random.randint(33000, 60000)

        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
        except (PermissionError, OSError) as exc:
            raise PermissionError(
                "SYN scan needs raw-socket privileges — run it as root "
                "(e.g. `sudo portscan <target> --syn`)."
            ) from exc

        # Every port starts as "filtered"; a reply upgrades it to open/closed.
        states: dict[int, str] = {port: "filtered" for port in ports}
        with sock:
            # Fire all the SYNs first. Replies queue in the socket's receive
            # buffer while we send, so we don't miss the fast ones.
            for port in ports:
                packet = build_syn_packet(
                    src_ip, self._ip, our_port, port,
                    seq=random.randint(0, 0xFFFFFFFF),
                )
                sock.sendto(packet, (self._ip, 0))

            pending = set(ports)
            deadline = time.perf_counter() + self.timeout
            while pending:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    break
                parsed = parse_tcp_response(data, self._ip, our_port)
                if parsed is None:
                    continue
                port, state = parsed
                if port in pending:
                    states[port] = state
                    pending.discard(port)
                    if progress is not None:
                        progress(len(ports) - len(pending), len(ports))

        results = [
            ScanResult(
                port=port,
                is_open=(state == "open"),
                service=identify_service(port, "") if state == "open" else "",
                state=state,
            )
            for port, state in states.items()
        ]
        results.sort(key=lambda r: r.port)
        return results


def _local_source_ip(dst_ip: str) -> str:
    """Return the local address the kernel would use to reach *dst_ip*.

    No packets are actually sent: connecting a UDP socket merely fixes its
    destination, which is enough for the OS to select — and reveal, via
    ``getsockname`` — the outgoing interface's IP. We need it for the checksum
    pseudo-header.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((dst_ip, 80))
        return probe.getsockname()[0]
    finally:
        probe.close()
