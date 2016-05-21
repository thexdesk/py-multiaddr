import pytest

from multiaddr.codec import size_for_addr
from multiaddr.codec import bytes_split
from multiaddr.codec import string_to_bytes
from multiaddr.codec import bytes_to_string

from multiaddr.protocols import _names_to_protocols


@pytest.mark.parametrize("proto, buf, expected", [
    (_names_to_protocols['https'], b'\x01\x02\x03', 0),
    (_names_to_protocols['ip4'], b'\x01\x02\x03', 4),
    (_names_to_protocols['ipfs'], b'\x40\x50\x60\x51', 65),
        ])
def test_size_for_addr(proto, buf, expected):
    assert size_for_addr(proto, buf) == expected


@pytest.mark.parametrize("buf, expected", [
    (b'047f0000011104d2047f0000010610e1', ['\x04\x7f\x00\x00\x01', '\x11\x04\xd2', '\x04\x7f\x00\x00\x01', '\x06\x10\xe1']),  # "/ip4/127.0.0.1/udp/1234/ip4/127.0.0.1/tcp/4321"
        ])
def test_bytes_split(buf, expected):
    print bytes_split(buf)
    assert (bytes_split(buf) == expected)


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
