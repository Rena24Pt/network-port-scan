"""Expanding a target specification into individual host addresses.

Real scans rarely target a single machine — you sweep a subnet. This module
turns whatever the user typed into a concrete list of hosts:

* a single IP (``10.0.0.5``)         -> ``["10.0.0.5"]``
* a CIDR block (``192.168.1.0/24``)  -> every usable host in the range
* a hostname (``example.com``)       -> returned unchanged, for the scanner to
  resolve later via DNS

For a CIDR block the network and broadcast addresses are skipped (that is what
:meth:`ipaddress.IPv4Network.hosts` does), because you cannot meaningfully scan
them.
"""

from __future__ import annotations

import ipaddress

# Guard-rail: refuse absurdly large sweeps (a stray ``/8`` is ~16 million hosts)
# so a typo cannot kick off a scan that never ends.
MAX_HOSTS = 65536


def expand_targets(spec: str) -> list[str]:
    """Expand a target specification into a list of host address strings.

    :raises ValueError: if a CIDR block expands to more than :data:`MAX_HOSTS`
        hosts.
    """
    spec = spec.strip()
    try:
        # strict=False lets "192.168.1.5/24" mean "the /24 that contains .5"
        # instead of raising because host bits are set.
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        # Not an IP or CIDR literal — assume it is a hostname and let the
        # scanner resolve it with DNS.
        return [spec]

    # A bare address (e.g. "10.0.0.5") parses as a single-address /32 or /128.
    if network.num_addresses == 1:
        return [str(network.network_address)]

    # Check the size *before* materialising the list so a huge range fails fast
    # instead of trying to build millions of strings.
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(
            f"target {spec!r} expands to {network.num_addresses} addresses "
            f"(limit {MAX_HOSTS}); narrow the range"
        )
    return [str(host) for host in network.hosts()]
