import pytest

from multiaddr.codec import size_for_addr
from multiaddr.codec import bytes_split
from multiaddr.codec import string_to_bytes
from multiaddr.codec import bytes_to_string
from multiaddr.codec import address_bytes_to_string
from multiaddr.codec import address_string_to_bytes

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
    assert (bytes_split(buf) == expected)


@pytest.mark.parametrize("proto, buf, expected", [
        (_names_to_protocols['ip4'], b'0a0b0c0d', '10.11.12.13'),
        (_names_to_protocols['ip6'], b'1aa12bb23cc34dd45ee56ff67ab78ac8', '1aa1:2bb2:3cc3:4dd4:5ee5:6ff6:7ab7:8ac8'),
        (_names_to_protocols['tcp'], b'abcd', '43981'),
        (_names_to_protocols['onion'], b'9a18087306369043091f04d2', 'timaq4ygg2iegci7:1234'),
        (_names_to_protocols['ipfs'], b'221220d52ebb89d85b02a284948203a62ff28389c57c9f42beec4ec20db76a68911c0b', 'QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'),
        ])
def test_address_bytes_to_string(proto, buf, expected):
    assert (address_bytes_to_string(proto, buf) == expected)


@pytest.mark.parametrize("proto, expected, string", [
        (_names_to_protocols['ip4'], b'0a0b0c0d', '10.11.12.13'),
        (_names_to_protocols['ip6'], b'1aa12bb23cc34dd45ee56ff67ab78ac8', '1aa1:2bb2:3cc3:4dd4:5ee5:6ff6:7ab7:8ac8'),
        (_names_to_protocols['tcp'], b'abcd', '43981'),
        (_names_to_protocols['onion'], b'9a18087306369043091f04d2', 'timaq4ygg2iegci7:1234'),
        (_names_to_protocols['ipfs'], b'221220d52ebb89d85b02a284948203a62ff28389c57c9f42beec4ec20db76a68911c0b', 'QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'),
        ])
def test_address_string_to_bytes(proto, string, expected):
    assert (address_string_to_bytes(proto, string) == expected)


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
