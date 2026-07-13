"""Tests for target-specification expansion."""

import pytest

from portscanner.targets import MAX_HOSTS, expand_targets


def test_single_ip_returns_itself():
    assert expand_targets("10.0.0.5") == ["10.0.0.5"]


def test_hostname_is_passed_through_untouched():
    # Not an IP/CIDR literal, so it is left for the scanner to resolve via DNS.
    assert expand_targets("example.com") == ["example.com"]


def test_cidr_excludes_network_and_broadcast():
    hosts = expand_targets("192.168.1.0/24")
    assert len(hosts) == 254
    assert hosts[0] == "192.168.1.1"
    assert hosts[-1] == "192.168.1.254"
    assert "192.168.1.0" not in hosts  # network address
    assert "192.168.1.255" not in hosts  # broadcast address


def test_small_cidr():
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_slash_31_includes_both_addresses():
    # A /31 is a point-to-point link: both addresses are usable.
    assert expand_targets("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]


def test_host_bits_are_tolerated():
    # "192.168.1.5/24" means "the /24 containing .5", not an error.
    hosts = expand_targets("192.168.1.5/24")
    assert hosts[0] == "192.168.1.1"
    assert len(hosts) == 254


def test_oversized_range_is_rejected():
    with pytest.raises(ValueError):
        expand_targets("10.0.0.0/8")  # ~16 million addresses


def test_limit_boundary_is_allowed():
    # A /16 is exactly MAX_HOSTS addresses and must still be accepted.
    hosts = expand_targets("172.16.0.0/16")
    assert len(hosts) == MAX_HOSTS - 2  # minus network and broadcast
