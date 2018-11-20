import binascii
import six
import struct

from .codec import bytes_split
from .multiaddr import Multiaddr


def split(ma):
    """Return the sub-address portions of a multiaddr"""
    addrs = []
    bb = bytes_split(ma.to_bytes())
    for addr in bb:
        addrs.append(Multiaddr(binascii.hexlify(addr)))
    return addrs


def join(multiaddrs):
    bs = []
    for ma in multiaddrs:
        bs.append(ma.to_bytes())
    return Multiaddr(b''.join(bs))


def int_to_hex(i, size):
    """Encode a long value as a hex string, 0-padding to size.

    Note that size is the size of the resulting hex string. So, for a 32Byte
    int, size should be 64 (two hex characters per byte"."""
    f_str = "{0:0%sx}" % size
    buf = f_str.format(i).lower()
    if six.PY3:
        buf = bytes(buf, 'utf-8')

    return buf


def encode_big_endian_32(i):
    """Take an int and return big-endian bytes"""
    return struct.pack('>I', i)[-4:]


def encode_big_endian_16(i):
    """Take an int and return big-endian bytes"""
    return encode_big_endian_32(i)[-2:]


def decode_big_endian_32(b):
    """Take big-endian bytes and return int"""
    b = binascii.unhexlify(binascii.hexlify(b).zfill(8))
    return struct.unpack('>I', b)[0]


def decode_big_endian_16(b):
    ret = decode_big_endian_32(b)
    if ret < 0 or ret > 65535:
        raise ValueError("Not a uint16")
    return ret
