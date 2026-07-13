"""Tests for the port-specification parser."""

import pytest

from portscanner.ports import TOP_PORTS, parse_ports


def test_single_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_inclusive_range():
    assert parse_ports("20-22") == [20, 21, 22]


def test_mixed_and_deduplicated():
    assert parse_ports("80,20-22,80") == [20, 21, 22, 80]


def test_reversed_range_is_tolerated():
    assert parse_ports("22-20") == [20, 21, 22]


def test_whitespace_is_ignored():
    assert parse_ports("  22 , 80 ") == [22, 80]


def test_top_shortcut():
    assert parse_ports("top") == sorted(set(TOP_PORTS))


def test_all_shortcut():
    assert parse_ports("all") == list(range(1, 65536))
    assert parse_ports("-") == list(range(1, 65536))


def test_out_of_range_rejected():
    with pytest.raises(ValueError):
        parse_ports("70000")
    with pytest.raises(ValueError):
        parse_ports("0")


def test_invalid_token_rejected():
    with pytest.raises(ValueError):
        parse_ports("abc")
