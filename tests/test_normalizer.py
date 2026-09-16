"""
Tests for Datetime, IP, and Entity Normalization.
"""

from core.normalizer import Normalizer


def test_timestamp_parsing_epoch():
    # Epoch seconds
    iso, epoch_us, tz, ok = Normalizer.parse_timestamp("1726485002")
    assert ok is True
    assert "2024-" in iso or "2026-" in iso or "19" in iso
    assert epoch_us == 1726485002 * 1_000_000

    # Epoch milliseconds
    iso_ms, epoch_us_ms, _, ok_ms = Normalizer.parse_timestamp("1726485002123")
    assert ok_ms is True
    assert epoch_us_ms == 1726485002123 * 1000


def test_timestamp_parsing_apache():
    raw = "10/Oct/2026:13:55:36 +0530"
    iso, epoch_us, tz, ok = Normalizer.parse_timestamp(raw)
    assert ok is True
    assert "2026-10-10" in iso


def test_timestamp_parsing_iso():
    raw = "2026-09-16T17:15:00.123456Z"
    iso, epoch_us, tz, ok = Normalizer.parse_timestamp(raw)
    assert ok is True
    assert "2026-09-16" in iso


def test_ip_classification():
    # RFC 1918 Private
    ip, is_priv, ver = Normalizer.classify_ip("192.168.1.1")
    assert ip == "192.168.1.1"
    assert is_priv is True
    assert ver == "IPv4"

    # Public IP
    ip_pub, is_priv_pub, _ = Normalizer.classify_ip("8.8.8.8")
    assert ip_pub == "8.8.8.8"
    assert is_priv_pub is False

    # IP with port
    ip_port, _, _ = Normalizer.classify_ip("10.0.0.1:8080")
    assert ip_port == "10.0.0.1"

    # Malformed IP
    ip_bad, is_priv_bad, _ = Normalizer.classify_ip("999.123.456.789")
    assert ip_bad is None
    assert is_priv_bad is None


def test_direction_determination():
    assert Normalizer.determine_direction("192.168.1.5", "8.8.8.8", True, False) == "outbound"
    assert Normalizer.determine_direction("8.8.8.8", "10.0.0.5", False, True) == "inbound"
    assert Normalizer.determine_direction("10.0.0.1", "10.0.0.2", True, True) == "internal"
    assert Normalizer.determine_direction("1.1.1.1", "8.8.8.8", False, False) == "external"


def test_action_normalization():
    assert Normalizer.normalize_action("DROP") == "drop"
    assert Normalizer.normalize_action("Permit") == "allow"
    assert Normalizer.normalize_action("BLOCKED") == "deny"
    assert Normalizer.normalize_action("some_unknown_action") == "unknown"

