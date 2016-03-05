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
