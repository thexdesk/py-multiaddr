from .codec import bytes_split
from .multiaddr import Multiaddr


def split(ma):
    """Return the sub-address portions of a multiaddr"""
    addrs = []
    bb = bytes_split(ma.to_bytes())
    for addr in bb:
        addrs.append(Multiaddr(bytes_addr=addr))
    return addrs


def join(multiaddrs):
    bs = []
    for ma in multiaddrs:
        bs.append(ma.to_bytes())
    return Multiaddr(bytes_addr=b''.join(bs))


def int_to_hex(i, size):
    """Encode a long value as a hex string, 0-padding to size.

    Note that size is the size of the resulting hex string. So, for a 32Byte
    int, size should be 64 (two hex characters per byte"."""
    f_str = "{0:0%sx}" % size
    return f_str.format(i).lower()
