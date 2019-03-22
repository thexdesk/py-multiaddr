# -*- coding: utf-8 -*-
import binascii
import six
import varint

from .codecs import codec_by_name


# source of protocols https://github.com/multiformats/multicodec/blob/master/table.csv#L382
# replicating table here to:
# 1. avoid parsing the csv
# 2. ensuring errors in the csv don't screw up code.
# 3. changing a number has to happen in two places.
P_IP4 = 0x04
P_IP6 = 0x29
P_IP6ZONE = 0x2A
P_TCP = 0x06
P_UDP = 0x0111
P_DCCP = 0x21
P_SCTP = 0x84
P_UDT = 0x012D
P_UTP = 0x012E
P_P2P = 0x01A5
P_HTTP = 0x01E0
P_HTTPS = 0x01BB
P_QUIC = 0x01CC
P_WS = 0x01DD
P_WSS = 0x01DE
P_ONION = 0x01BC
P_P2P_CIRCUIT = 0x0122
P_DNS = 0x35
P_DNS4 = 0x36
P_DNS6 = 0x37
P_DNSADDR = 0x38
P_P2P_WEBSOCKET_STAR = 0x01DF
P_P2P_WEBRTC_STAR = 0x0113
P_P2P_WEBRTC_DIRECT = 0x0114
P_UNIX = 0x0190

_CODES = [
    P_IP4,
    P_IP6,
    P_IP6ZONE,
    P_TCP,
    P_UDP,
    P_DCCP,
    P_SCTP,
    P_UDT,
    P_UTP,
    P_P2P,
    P_HTTP,
    P_HTTPS,
    P_QUIC,
    P_WS,
    P_WSS,
    P_ONION,
    P_P2P_CIRCUIT,
    P_DNS,
    P_DNS4,
    P_DNS6,
    P_DNSADDR,
    P_P2P_WEBSOCKET_STAR,
    P_P2P_WEBRTC_STAR,
    P_P2P_WEBRTC_DIRECT,
    P_UNIX,
]



class Protocol(object):
    __slots__ = [
        "code",   # int
        "name",   # string
        "codec",  # string
    ]

    def __init__(self, code, name, codec):
        if not isinstance(code, six.integer_types):
            raise ValueError("code must be an integer")
        if not isinstance(name, six.string_types):
            raise ValueError("name must be a string")
        if not isinstance(codec, six.string_types) and not codec is None:
            raise ValueError("codec must be a string or None")

        if code not in _CODES and code != 0:
            raise ValueError("Invalid code '%d'" % code)

        self.code = code
        self.name = name
        self.codec = codec

    @property
    def size(self):
        return codec_by_name(self.codec).SIZE

    @property
    def path(self):
        return codec_by_name(self.codec).IS_PATH

    @property
    def vcode(self):
        return varint.encode(self.code)

    def __eq__(self, other):
        return all((self.code == other.code,
                    self.name == other.name,
                    self.codec == other.codec,
                    self.path == other.path))

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "Protocol(code={code!r}, name={name!r}, codec={codec!r})".format(
            code=self.code,
            name=self.name,
            codec=self.codec,
        )


def _uvarint(buf):
    """Reads a varint from a bytes buffer and returns the value and # bytes"""
    x = 0
    s = 0
    for i, b_str in enumerate(buf):
        if six.PY3:
            b = b_str
        else:
            b = int(binascii.b2a_hex(b_str), 16)
        if b < 0x80:
            if i > 9 or (i == 9 and b > 1):
                raise ValueError("Overflow")
            return (x | b << s, i + 1)
        x |= (b & 0x7f) << s
        s += 7
    return 0, 0


def read_varint_code(buf):
    num, n = _uvarint(buf)
    return int(num), n


# Protocols is the list of multiaddr protocols supported by this module.
PROTOCOLS = [
    Protocol(P_IP4, 'ip4', 'ip4'),
    Protocol(P_TCP, 'tcp', 'uint16be'),
    Protocol(P_UDP, 'udp', 'uint16be'),
    Protocol(P_DCCP, 'dccp', 'uint16be'),
    Protocol(P_IP6, 'ip6', 'ip6'),
    Protocol(P_IP6ZONE, 'ip6zone', '?'),
    Protocol(P_DNS, 'dns', 'idna'),
    Protocol(P_DNS4, 'dns4', 'idna'),
    Protocol(P_DNS6, 'dns6', 'idna'),
    Protocol(P_DNSADDR, 'dnsaddr', 'idna'),
    Protocol(P_SCTP, 'sctp', 'uint16be'),
    Protocol(P_UDT, 'udt', None),
    Protocol(P_UTP, 'utp', None),
    Protocol(P_P2P, 'p2p', 'p2p'),
    Protocol(P_ONION, 'onion', 'onion'),
    Protocol(P_QUIC, 'quic', None),
    Protocol(P_HTTP, 'http', None),
    Protocol(P_HTTPS, 'https', None),
    Protocol(P_WS, 'ws', None),
    Protocol(P_WSS, 'wss', None),
    Protocol(P_P2P_WEBSOCKET_STAR, 'p2p-websocket-star', None),
    Protocol(P_P2P_WEBRTC_STAR, 'p2p-webrtc-star', None),
    Protocol(P_P2P_WEBRTC_DIRECT, 'p2p-webrtc-direct', None),
    Protocol(P_P2P_CIRCUIT, 'p2p-circuit', None),
    Protocol(P_UNIX, 'unix', 'fspath'),
]

_names_to_protocols = dict((proto.name, proto) for proto in PROTOCOLS)
_codes_to_protocols = dict((proto.code, proto) for proto in PROTOCOLS)


def add_protocol(proto):
    if proto.name in _names_to_protocols:
        raise ValueError("protocol by the name %s already exists" % proto.name)

    if proto.code in _codes_to_protocols:
        raise ValueError("protocol code %d already taken by %s" %
                         (proto.code, _codes_to_protocols[proto.code].name))

    PROTOCOLS.append(proto)
    _names_to_protocols[proto.name] = proto
    _codes_to_protocols[proto.code] = proto
    return None


def protocol_with_name(name):
    if name not in _names_to_protocols:
        raise ValueError("No protocol with name %s" % name)
    return _names_to_protocols[name]


def protocol_with_code(code):
    if code not in _codes_to_protocols:
        raise ValueError("No protocol with code %s" % code)
    return _codes_to_protocols[code]


def protocols_with_string(string):
    """Return a list of protocols matching given string."""
    if not string:
        return []

    s = string.strip("/")
    sp = s.split("/")
    if not sp or len(sp) == 0 or sp == ['']:
        return []

    ret = []
    for name in sp:
        try:
            proto = protocol_with_name(name)
        except ValueError:
            raise ValueError("No Protocol with name %s" % name)
        ret.append(proto)
    return ret
