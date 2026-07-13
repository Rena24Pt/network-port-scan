"""Port specifications and well-known service names.

Everything here is pure data plus a small parser, deliberately dependency-free
so it is trivial to unit test in isolation.
"""

from __future__ import annotations

# A pragmatic subset of IANA well-known / registered ports mapped to the service
# most commonly found on them. Banner grabbing refines this at runtime; this map
# is only the first guess based on the port number alone.
COMMON_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "smtp-submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "ms-sql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-ssl",
    3000: "http-dev",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# A compact "top ports" list — the ports most worth checking on a first pass.
# This is the default when no explicit port specification is given.
TOP_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 3000,
    3306, 3389, 5060, 5432, 5900, 5985, 6379, 6443, 8000, 8008, 8080,
    8443, 8888, 9000, 9200, 11211, 27017,
]

_MAX_PORT = 65535


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification string into a sorted list of unique ports.

    Accepts comma-separated tokens, where each token is either a single port
    (``80``) or an inclusive range (``1-1024``). Two shortcuts are supported:

    * ``all`` / ``-`` / ``*`` — the full ``1-65535`` range.
    * ``top`` — the curated :data:`TOP_PORTS` list.

    >>> parse_ports("22,80,443")
    [22, 80, 443]
    >>> parse_ports("20-22,80")
    [20, 21, 22, 80]

    :raises ValueError: if a token is malformed or a port falls outside 1-65535.
    """
    spec = spec.strip().lower()
    if spec in ("all", "-", "*"):
        return list(range(1, _MAX_PORT + 1))
    if spec == "top":
        return sorted(set(TOP_PORTS))

    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "-" in token:
                start_s, end_s = token.split("-", 1)
                start, end = int(start_s), int(end_s)
                if start > end:  # tolerate reversed ranges like "22-20"
                    start, end = end, start
                ports.update(range(start, end + 1))
            else:
                ports.add(int(token))
        except ValueError:
            raise ValueError(f"invalid port token: {token!r}") from None

    if not ports:
        raise ValueError("no ports parsed from specification")
    out_of_range = [p for p in ports if not 1 <= p <= _MAX_PORT]
    if out_of_range:
        raise ValueError(f"ports out of range (1-{_MAX_PORT}): {sorted(out_of_range)}")
    return sorted(ports)
