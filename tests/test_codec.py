import pytest

from multiaddr.codec import string_to_bytes
from multiaddr.codec import bytes_to_string


def test_string_to_bytes():
    assert string_to_bytes("/ip4/127.0.0.1/udp/1234") == b'047f0000011104d2'
    assert string_to_bytes("/ip4/127.0.0.1/tcp/4321") == b'047f0000010610e1'
    assert (
        string_to_bytes("/ip4/127.0.0.1/udp/1234/ip4/127.0.0.1/tcp/4321") ==
        b'047f0000011104d2047f0000010610e1')


def test_bytes_to_string():
    assert bytes_to_string(b"047f0000011104d2") == "/ip4/127.0.0.1/udp/1234"
    assert bytes_to_string(b"047f0000010610e1") == "/ip4/127.0.0.1/tcp/4321"
    assert (bytes_to_string(b"047f0000011104d2047f0000010610e1") ==
            "/ip4/127.0.0.1/udp/1234/ip4/127.0.0.1/tcp/4321")
